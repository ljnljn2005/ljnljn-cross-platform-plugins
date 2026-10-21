//! TIFF / EXIF 结构解析（JPEG APP1 `Exif\0\0` 段与 PNG `eXIf` 块共用）。
//!
//! 定位规则与边界：
//! - 所有偏移都以 **TIFF 头（`MM`/`II`）为基准**的相对偏移，本模块对外只报告
//!   这类相对偏移；调用方叠加容器基准（JPEG 的 TIFF 头文件偏移、PNG `eXIf`
//!   的块数据偏移）得到可直接回溯的文件绝对偏移。
//! - 读取越界（IFD 目录项/值区超出 buffer）→ 该文件按失败处理，
//!   原因 `ifd_out_of_bounds`（buffer 本身不足 → `truncated`）。
//! - IFD 链出现重复偏移（循环引用）→ 失败，原因 `ifd_cycle`。
//! - ExifIFD / GPS IFD 的偏移越界、自我指向或成环 → 失败，原因
//!   `ifd_out_of_bounds` / `ifd_cycle`，`TiffError::ifd` 标明出错目录
//!   （该文件不产生部分结果）；重复的指针 tag 以**首个**为准。
//! - 单个 Tag 的类型与数量不一致（RATIONAL 数量为 0、计数×类型长度溢出、
//!   计数过大）视为该 Tag 损坏：跳过并记录 warning，不中断整个 IFD。

use std::collections::HashSet;

/// Reason codes recorded for skipped tags and rejected files.
pub mod reason {
    pub const TRUNCATED: &str = "truncated";
    pub const IFD_OUT_OF_BOUNDS: &str = "ifd_out_of_bounds";
    pub const IFD_CYCLE: &str = "ifd_cycle";
    pub const EXIF_IFD_INVALID: &str = "exif_ifd_invalid";
    pub const GPS_IFD_INVALID: &str = "gps_ifd_invalid";
    pub const TAG_INVALID: &str = "tag_invalid";
    pub const BAD_HEADER: &str = "bad_exif_header";
    pub const BAD_TIFF_HEADER: &str = "bad_tiff_header";
    pub const EMPTY: &str = "empty_exif_block";
    pub const IFD_LIMIT: &str = "too_many_ifds";
}

/// Tag ids used by this parser (TIFF 6.0 / EXIF 2.32).
pub mod tag {
    pub const IMAGE_WIDTH: u16 = 0x0100;
    pub const IMAGE_HEIGHT: u16 = 0x0101;
    pub const IMAGE_DESCRIPTION: u16 = 0x010E;
    pub const MAKE: u16 = 0x010F;
    pub const MODEL: u16 = 0x0110;
    pub const ORIENTATION: u16 = 0x0112;
    pub const SOFTWARE: u16 = 0x0131;
    pub const DATETIME: u16 = 0x0132;
    pub const EXIF_IFD_POINTER: u16 = 0x8769;
    pub const GPS_IFD_POINTER: u16 = 0x8825;
    pub const INTEROP_IFD_POINTER: u16 = 0xA005;
    pub const PIXEL_X_DIMENSION: u16 = 0xA002;
    pub const PIXEL_Y_DIMENSION: u16 = 0xA003;
    pub const USER_COMMENT: u16 = 0x9286;
    pub const DATETIME_ORIGINAL: u16 = 0x9003;
    pub const DATETIME_DIGITIZED: u16 = 0x9004;
    pub const OFFSET_TIME: u16 = 0x9010;
    pub const OFFSET_TIME_ORIGINAL: u16 = 0x9011;
    pub const OFFSET_TIME_DIGITIZED: u16 = 0x9012;
    pub const LENS_MAKE: u16 = 0xA433;
    pub const LENS_MODEL: u16 = 0xA434;
    pub const GPS_LATITUDE_REF: u16 = 0x0001;
    pub const GPS_LATITUDE: u16 = 0x0002;
    pub const GPS_LONGITUDE_REF: u16 = 0x0003;
    pub const GPS_LONGITUDE: u16 = 0x0004;
    pub const GPS_ALTITUDE_REF: u16 = 0x0005;
    pub const GPS_ALTITUDE: u16 = 0x0006;
    pub const GPS_TIMESTAMP: u16 = 0x0007;
    pub const GPS_MAP_DATUM: u16 = 0x0012;
    pub const GPS_SATELLITES: u16 = 0x001C;
    pub const GPS_DATESTAMP: u16 = 0x001D;
}

/// Which IFD a tag was found in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ifd {
    Ifd0,
    Exif,
    Gps,
}

impl Ifd {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ifd0 => "IFD0",
            Self::Exif => "ExifIFD",
            Self::Gps => "GPSIFD",
        }
    }
}

/// One decoded tag plus its location inside the TIFF block.
#[derive(Clone, Debug, PartialEq)]
pub struct TagValue {
    pub ifd: Ifd,
    pub tag: u16,
    /// Offset of the payload relative to the TIFF header (inline values point
    /// at their 4-byte slot inside the directory entry).
    pub value_offset: u32,
    /// Payload length in bytes (inline values: the declared `count × size`).
    pub value_length: usize,
    /// True when the payload is stored at `value_offset` instead of inline.
    pub separate: bool,
    pub kind: ValueKind,
}

/// Decoded tag payload.
#[derive(Clone, Debug, PartialEq)]
pub enum ValueKind {
    Ascii(String),
    Short(Vec<u16>),
    Long(Vec<u32>),
    Rational(Vec<(u32, u32)>),
    SRational(Vec<(i32, i32)>),
    /// Undefined (type 7) and exotic types: raw bytes in hex form.
    Bytes { kind: u16, bytes: Vec<u8> },
}

impl ValueKind {
    /// Human form of the raw value, e.g. `"37/1 30/1 1234/100"`.
    pub fn display(&self) -> String {
        let join = |values: Vec<String>| values.join(" ");
        match self {
            Self::Ascii(text) => text.clone(),
            Self::Short(values) => join(values.iter().map(|v| v.to_string()).collect()),
            Self::Long(values) => join(values.iter().map(|v| v.to_string()).collect()),
            Self::Rational(values) => {
                join(values.iter().map(|(n, d)| format!("{n}/{d}")).collect())
            }
            Self::SRational(values) => {
                join(values.iter().map(|(n, d)| format!("{n}/{d}")).collect())
            }
            Self::Bytes { kind, bytes } => {
                if bytes.is_empty() {
                    format!("type {kind} 空值")
                } else {
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                }
            }
        }
    }

    pub fn ascii(&self) -> Option<&str> {
        match self {
            Self::Ascii(text) => Some(text.as_str()),
            _ => None,
        }
    }

    /// Numeric view; a RATIONAL with a zero denominator yields `None`.
    pub fn numbers_f64(&self) -> Option<Vec<f64>> {
        match self {
            Self::Ascii(_) => None,
            Self::Short(values) => Some(values.iter().map(|v| f64::from(*v)).collect()),
            Self::Long(values) => Some(values.iter().map(|v| f64::from(*v)).collect()),
            Self::Rational(values) => values
                .iter()
                .map(|(n, d)| (*d != 0).then(|| f64::from(*n) / f64::from(*d)))
                .collect(),
            Self::SRational(values) => values
                .iter()
                .map(|(n, d)| (*d != 0).then(|| f64::from(*n) / f64::from(*d)))
                .collect(),
            Self::Bytes { .. } => None,
        }
    }

    /// First integer of a SHORT/LONG value (orientation, pointers).
    pub fn first_u32(&self) -> Option<u32> {
        match self {
            Self::Short(values) => values.first().map(|v| u32::from(*v)),
            Self::Long(values) => values.first().copied(),
            _ => None,
        }
    }
}

/// Parsed TIFF block in read order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TiffBlock {
    pub byte_order: &'static str,
    /// IFD0 offset relative to the TIFF header.
    pub ifd0_offset: u32,
    pub tags: Vec<TagValue>,
    /// Every IFD directory that was walked, in visit order.
    pub ifd_offsets: Vec<(Ifd, u32)>,
    pub warnings: Vec<String>,
}

impl TiffBlock {
    pub fn first(&self, ifd_filter: &[Ifd], tag_id: u16) -> Option<&TagValue> {
        self.tags
            .iter()
            .find(|value| ifd_filter.contains(&value.ifd) && value.tag == tag_id)
    }

    pub fn text(&self, ifd_filter: &[Ifd], tag_id: u16) -> Option<String> {
        self.first(ifd_filter, tag_id)
            .and_then(|value| value.kind.ascii())
            .map(|text| text.trim_matches('\0').trim().to_owned())
            .filter(|text| !text.is_empty())
    }

    pub fn numbers(&self, ifd_filter: &[Ifd], tag_id: u16) -> Option<Vec<f64>> {
        self.first(ifd_filter, tag_id)
            .and_then(|value| value.kind.numbers_f64())
    }

    pub fn shows(&self, ifd_filter: &[Ifd], tag_id: u16) -> Option<String> {
        self.first(ifd_filter, tag_id)
            .map(|value| value.kind.display())
            .filter(|text| !text.is_empty())
    }
}

/// Failure of one TIFF block: stable `reason` code plus Chinese context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TiffError {
    pub reason: &'static str,
    pub ifd: Option<Ifd>,
    pub message: String,
}

impl TiffError {
    pub fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            ifd: None,
            message: message.into(),
        }
    }

    fn in_ifd(mut self, ifd: Ifd) -> Self {
        self.ifd = Some(ifd);
        self
    }
}

/// Bytes one tag value may occupy before the file is treated as corrupt.
const MAX_VALUE_LENGTH: usize = 4 * 1024 * 1024;
/// Directory entries accepted per IFD (a 64 KiB IFD holds at most 8190).
const MAX_ENTRIES_PER_IFD: usize = 4096;
/// IFD directories walked per block (IFD0, ExifIFD, GPS IFD, Interop, IFD1…).
const MAX_IFDS: usize = 16;

struct ParsedIfd {
    tags: Vec<TagValue>,
    /// Offset of the next IFD in the chain (IFD0 → IFD1 → …), if any.
    next_ifd: Option<u32>,
}

/// Parses a TIFF block starting at `data[0]`.
///
/// `exif_prefix = true` expects a JPEG APP1 payload: `Exif\0\0` followed by the
/// TIFF header. `false` expects the TIFF header directly (PNG `eXIf`).
pub fn parse_tiff(data: &[u8], exif_prefix: bool) -> Result<TiffBlock, TiffError> {
    let body: &[u8] = if exif_prefix {
        if data.len() < 6 {
            return Err(TiffError::new(
                reason::TRUNCATED,
                format!("EXIF 段不足 6 字节（实得 {}）", data.len()),
            ));
        }
        if &data[..6] != b"Exif\0\0" {
            return Err(TiffError::new(
                reason::BAD_HEADER,
                format!("段内不是 Exif\\0\\0 头：{}", hex_prefix(data, 6)),
            ));
        }
        &data[6..]
    } else {
        data
    };
    if body.len() < 8 {
        return Err(TiffError::new(
            reason::TRUNCATED,
            format!("TIFF 头不足 8 字节（实得 {} 字节）", body.len()),
        ));
    }
    let byte_order = match &body[..2] {
        b"II" => "little-endian",
        b"MM" => "big-endian",
        other => {
            return Err(TiffError::new(
                reason::BAD_TIFF_HEADER,
                format!("TIFF 字节序标记无效：{}", hex_prefix(other, 2)),
            ))
        }
    };
    let little = byte_order == "little-endian";
    let magic = read_u16(body, 2, little)
        .ok_or_else(|| TiffError::new(reason::TRUNCATED, "TIFF 魔数被截断"))?;
    if magic != 42 {
        return Err(TiffError::new(
            reason::BAD_TIFF_HEADER,
            format!("TIFF 魔数应为 42，实为 {magic}"),
        ));
    }
    let ifd0_offset = read_u32(body, 4, little)
        .ok_or_else(|| TiffError::new(reason::TRUNCATED, "IFD0 偏移被截断"))?;
    let mut block = TiffBlock {
        byte_order,
        ifd0_offset,
        ..TiffBlock::default()
    };
    let mut visited: HashSet<u32> = HashSet::new();
    let mut pending: Vec<(u32, Ifd)> = vec![(ifd0_offset, Ifd::Ifd0)];
    let mut exif_pointer: Option<u32> = None;
    let mut gps_pointer: Option<u32> = None;
    let mut walked = 0usize;
    while let Some((offset, kind)) = pending.pop() {
        walked += 1;
        if visited.contains(&offset) {
            return Err(TiffError::new(
                reason::IFD_CYCLE,
                format!(
                    "{} 的目标偏移 0x{offset:04x} 已在 IFD 链中出现（循环引用）",
                    kind.label()
                ),
            )
            .in_ifd(kind));
        }
        if walked > MAX_IFDS {
            return Err(TiffError::new(
                reason::IFD_LIMIT,
                format!("IFD 数量超过 {MAX_IFDS} 个"),
            ));
        }
        visited.insert(offset);
        block.ifd_offsets.push((kind, offset));
        let parsed = parse_ifd(body, offset, kind, little, &mut block.warnings)?;
        for value in parsed.tags {
            match (kind, value.tag) {
                // The first pointer wins: a duplicate tag must not mask an
                // earlier (possibly out-of-bounds) target, otherwise a corrupt
                // SubIFD offset could be hidden behind a valid one.
                (Ifd::Ifd0, tag::EXIF_IFD_POINTER) => {
                    match value.kind.first_u32() {
                        Some(offset) if exif_pointer.is_none() => exif_pointer = Some(offset),
                        Some(offset) => block.warnings.push(format!(
                            "IFD0 重复的 ExifIFD 指针 0x{offset:04x} 已忽略（采用首个 0x{:04x}）",
                            exif_pointer.unwrap_or_default()
                        )),
                        None => block
                            .warnings
                            .push("IFD0 的 ExifIFD 指针值不可解释，已忽略".to_owned()),
                    }
                    continue;
                }
                (Ifd::Ifd0, tag::GPS_IFD_POINTER) => {
                    match value.kind.first_u32() {
                        Some(offset) if gps_pointer.is_none() => gps_pointer = Some(offset),
                        Some(offset) => block.warnings.push(format!(
                            "IFD0 重复的 GPS IFD 指针 0x{offset:04x} 已忽略（采用首个 0x{:04x}）",
                            gps_pointer.unwrap_or_default()
                        )),
                        None => block
                            .warnings
                            .push("IFD0 的 GPS IFD 指针值不可解释，已忽略".to_owned()),
                    }
                    continue;
                }
                // Interop IFDs are not interpreted; their pointer is not
                // followed (and cannot yield fields), so nothing is emitted.
                (Ifd::Exif, tag::INTEROP_IFD_POINTER) => continue,
                _ => {}
            }
            block.tags.push(value);
        }
        // Visit order for reporting: ExifIFD, then GPS IFD, then IFD1 chain.
        if kind == Ifd::Ifd0 {
            if let Some(offset) = parsed.next_ifd {
                pending.push((offset, Ifd::Ifd0));
            }
            if let Some(offset) = gps_pointer.take() {
                pending.push((offset, Ifd::Gps));
            }
            if let Some(offset) = exif_pointer.take() {
                pending.push((offset, Ifd::Exif));
            }
        } else if let Some(offset) = parsed.next_ifd {
            // Sub-IFD chains are not standard; walk to detect cycles only.
            pending.push((offset, kind));
        }
    }
    Ok(block)
}

fn parse_ifd(
    body: &[u8],
    offset: u32,
    kind: Ifd,
    little: bool,
    warnings: &mut Vec<String>,
) -> Result<ParsedIfd, TiffError> {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let count = read_u16(body, start, little).ok_or_else(|| {
        TiffError::new(
            reason::IFD_OUT_OF_BOUNDS,
            format!(
                "{} 目录项计数偏移 0x{offset:04x} 超出段长 {}",
                kind.label(),
                body.len()
            ),
        )
        .in_ifd(kind)
    })?;
    let entries = usize::from(count);
    let directory_end = start
        .saturating_add(2)
        .saturating_add(entries.saturating_mul(12))
        .saturating_add(4);
    if entries > MAX_ENTRIES_PER_IFD || directory_end > body.len() {
        return Err(TiffError::new(
            reason::IFD_OUT_OF_BOUNDS,
            format!(
                "{} 声明 {entries} 个目录项，目录结束偏移 0x{directory_end:04x} 超出段长 {}",
                kind.label(),
                body.len()
            ),
        )
        .in_ifd(kind));
    }
    let mut tags = Vec::with_capacity(entries);
    for index in 0..entries {
        let entry = start + 2 + index * 12;
        let tag_id = read_u16(body, entry, little).expect("entry bounds checked");
        let type_id = read_u16(body, entry + 2, little).expect("entry bounds checked");
        let count = read_u32(body, entry + 4, little).expect("entry bounds checked");
        let slot = entry + 8;
        match decode_value(body, type_id, count, slot, little) {
            Ok(Decoded {
                kind: value_kind,
                offset: value_offset,
                length,
                separate,
            }) => tags.push(TagValue {
                ifd: kind,
                tag: tag_id,
                value_offset,
                value_length: length,
                separate,
                kind: value_kind,
            }),
            // A malformed tag (unknown type, absurd count) is skipped without
            // losing the rest of the IFD.
            Err(DecodeError::Tag(message)) => warnings.push(format!(
                "{} 目录项 #{} tag 0x{tag_id:04x} 已跳过：{message}",
                kind.label(),
                index
            )),
            // A payload that points outside the block means the directory
            // itself is inconsistent: the whole file is rejected.
            Err(DecodeError::OutOfBounds(message)) => {
                return Err(TiffError::new(
                    reason::IFD_OUT_OF_BOUNDS,
                    format!(
                        "{} 目录项 #{} tag 0x{tag_id:04x} 的值越界：{message}",
                        kind.label(),
                        index
                    ),
                )
                .in_ifd(kind));
            }
        }
    }
    let next_slot = start + 2 + entries * 12;
    let next_ifd = read_u32(body, next_slot, little).filter(|offset| *offset != 0);
    Ok(ParsedIfd { tags, next_ifd })
}

struct Decoded {
    kind: ValueKind,
    offset: u32,
    length: usize,
    separate: bool,
}

/// Why one directory entry could not be decoded.
enum DecodeError {
    /// The value itself is malformed; skip the tag, keep the IFD.
    Tag(String),
    /// The value area lies outside the block; reject the whole file.
    OutOfBounds(String),
}

fn type_size(type_id: u16) -> Option<usize> {
    Some(match type_id {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => return None,
    })
}

fn decode_value(
    body: &[u8],
    type_id: u16,
    count: u32,
    slot: usize,
    little: bool,
) -> Result<Decoded, DecodeError> {
    let size = type_size(type_id)
        .ok_or_else(|| DecodeError::Tag(format!("未知值类型 {type_id}")))?;
    let count = usize::try_from(count).map_err(|_| DecodeError::Tag("数量超出平台范围".to_owned()))?;
    let length = count
        .checked_mul(size)
        .ok_or_else(|| DecodeError::Tag("数量×类型长度溢出".to_owned()))?;
    if length > MAX_VALUE_LENGTH {
        return Err(DecodeError::Tag(format!(
            "值长度 {length} 超过上限 {MAX_VALUE_LENGTH}"
        )));
    }
    let (bytes, offset, separate) = if length <= 4 {
        let end = slot + length;
        let bytes = body
            .get(slot..end)
            .ok_or_else(|| DecodeError::OutOfBounds("内联值超出段长".to_owned()))?;
        (bytes, slot as u32, false)
    } else {
        let offset = read_u32(body, slot, little)
            .ok_or_else(|| DecodeError::OutOfBounds("值偏移被截断".to_owned()))?;
        let start = usize::try_from(offset)
            .map_err(|_| DecodeError::OutOfBounds("值偏移超出平台范围".to_owned()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| DecodeError::OutOfBounds("值区结束偏移溢出".to_owned()))?;
        let bytes = body.get(start..end).ok_or_else(|| {
            DecodeError::OutOfBounds(format!(
                "值区 0x{offset:04x}+{length} 超出段长 {}",
                body.len()
            ))
        })?;
        (bytes, offset, true)
    };
    let kind = match type_id {
        1 | 6 | 7 | 8 => ValueKind::Bytes {
            kind: type_id,
            bytes: bytes.to_vec(),
        },
        2 => {
            let text: String = bytes
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| *byte as char)
                .collect();
            ValueKind::Ascii(text)
        }
        3 => ValueKind::Short(
            bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes_or_le([chunk[0], chunk[1]], little))
                .collect(),
        ),
        4 | 13 => ValueKind::Long(
            bytes
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes_or_le([chunk[0], chunk[1], chunk[2], chunk[3]], little))
                .collect(),
        ),
        5 => ValueKind::Rational(
            bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (
                        u32::from_be_bytes_or_le([chunk[0], chunk[1], chunk[2], chunk[3]], little),
                        u32::from_be_bytes_or_le([chunk[4], chunk[5], chunk[6], chunk[7]], little),
                    )
                })
                .collect(),
        ),
        9 => ValueKind::SRational(
            bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (
                        i32::from_be_bytes_or_le([chunk[0], chunk[1], chunk[2], chunk[3]], little),
                        i32::from_be_bytes_or_le([chunk[4], chunk[5], chunk[6], chunk[7]], little),
                    )
                })
                .collect(),
        ),
        10 => ValueKind::SRational(
            bytes
                .chunks_exact(8)
                .map(|chunk| {
                    (
                        i32::from_be_bytes_or_le([chunk[0], chunk[1], chunk[2], chunk[3]], little),
                        i32::from_be_bytes_or_le([chunk[4], chunk[5], chunk[6], chunk[7]], little),
                    )
                })
                .collect(),
        ),
        _ => ValueKind::Bytes {
            kind: type_id,
            bytes: bytes.to_vec(),
        },
    };
    Ok(Decoded {
        kind,
        offset,
        length,
        separate,
    })
}

trait Endian: Sized {
    fn from_be_bytes_or_le(bytes: [u8; 4], little: bool) -> Self;
}

impl Endian for u32 {
    fn from_be_bytes_or_le(bytes: [u8; 4], little: bool) -> Self {
        if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    }
}

impl Endian for i32 {
    fn from_be_bytes_or_le(bytes: [u8; 4], little: bool) -> Self {
        if little {
            i32::from_le_bytes(bytes)
        } else {
            i32::from_be_bytes(bytes)
        }
    }
}

trait Endian16 {
    fn from_be_bytes_or_le(bytes: [u8; 2], little: bool) -> Self;
}

impl Endian16 for u16 {
    fn from_be_bytes_or_le(bytes: [u8; 2], little: bool) -> Self {
        if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    }
}

fn read_u16(data: &[u8], offset: usize, little: bool) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes_or_le([bytes[0], bytes[1]], little))
}

fn read_u32(data: &[u8], offset: usize, little: bool) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes_or_le(
        [bytes[0], bytes[1], bytes[2], bytes[3]],
        little,
    ))
}

fn hex_prefix(data: &[u8], length: usize) -> String {
    data.iter()
        .take(length)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
