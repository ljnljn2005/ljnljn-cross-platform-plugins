//! 容器解析：JPEG 段扫描、PNG 块扫描、XMP 关键字段提取。
//!
//! 偏移一律使用**文件绝对偏移**（从容器文件第 0 字节算起），便于在结果中回溯。
//! 容器级只负责“找出 EXIF/GPS 的物理位置并交给 TIFF 解析”，不做业务字段解释。

use crate::{exif, exif::reason};

/// Container-level failure (not a JPEG/PNG, or structurally broken).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerError {
    pub reason: &'static str,
    pub message: String,
}

impl ContainerError {
    pub fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

/// One accepted EXIF block and where it lives in the file.
#[derive(Clone, Debug, PartialEq)]
pub struct ExifBlock {
    /// File offset of the EXIF payload start (JPEG APP1 payload / PNG eXIf data).
    pub container_offset: u32,
    /// File offset of the TIFF header (`II`/`MM`).
    pub tiff_offset: u32,
    /// `jpeg-app1` or `png-exif`.
    pub carrier: &'static str,
    pub block: exif::TiffBlock,
}

/// PNG textual metadata (`tEXt` / `iTXt` / `zTXt`), value length capped.
#[derive(Clone, Debug, PartialEq)]
pub struct PngText {
    pub key: String,
    pub value: String,
    pub chunk_type: &'static str,
    pub offset: u32,
    pub truncated: bool,
}

/// A few XMP fields, read as text (never as an authority over EXIF).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct XmpPacket {
    /// File offset of the XMP payload (after any prefix).
    pub offset: u32,
    pub length: usize,
    pub date_created: Option<String>,
    pub creator_tool: Option<String>,
    pub packet_truncated: bool,
}

/// Everything the container level can tell us about one photo file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedContainer {
    /// File offset of every EXIF candidate tried, in order.
    pub exif_candidates: Vec<u32>,
    pub exif: Option<ExifBlock>,
    /// Segments/blocks rejected after a failed parse, with the reason.
    pub exif_skipped: Vec<String>,
    /// First failure reason when no candidate was usable.
    pub exif_error: Option<ContainerError>,
    pub png_texts: Vec<PngText>,
    /// PNG IHDR width/height (independent of EXIF).
    pub png_dimensions: Option<(u32, u32)>,
    pub xmp: Option<XmpPacket>,
}

/// Value bytes kept from a single PNG text chunk.
pub const MAX_PNG_TEXT: usize = 8 * 1024;
/// Bounds for the container walkers.
const MAX_PNG_CHUNKS: usize = 200_000;
const MAX_JPEG_SEGMENTS: usize = 20_000;
/// JPEG APP1 payloads larger than this are not parsed (EXIF blocks are ≤64 KiB).
const MAX_APP1: usize = 4 * 1024 * 1024;

const XMP_JPEG_HEADER: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const XMP_PNG_KEY: &str = "XML:com.adobe.xmp";

/// Walks JPEG markers from SOI. `data` must be the whole declared file.
pub fn scan_jpeg(data: &[u8]) -> Result<ParsedContainer, ContainerError> {
    let mut out = ParsedContainer::default();
    if data.len() < 4 {
        return Err(ContainerError::new(
            reason::TRUNCATED,
            format!("JPEG 不足 4 字节（实得 {}）", data.len()),
        ));
    }
    if !data.starts_with(&[0xFF, 0xD8]) {
        return Err(ContainerError::new(
            reason::BAD_HEADER,
            "缺少 JPEG SOI 标记",
        ));
    }
    let mut cursor = 2usize;
    let mut segments = 0usize;
    let mut first_failure: Option<ContainerError> = None;
    loop {
        segments += 1;
        if segments > MAX_JPEG_SEGMENTS {
            return Err(ContainerError::new(
                "too_many_segments",
                format!("JPEG 段数量超过 {MAX_JPEG_SEGMENTS}"),
            ));
        }
        if cursor >= data.len() {
            // Reaching EOF means SOS/EOI is missing: the file is truncated and
            // must be rejected even when an earlier EXIF segment looked valid.
            return Err(ContainerError::new(
                reason::TRUNCATED,
                format!(
                    "JPEG 段扫描到达文件尾（文件长 {}）仍未遇到 SOS/EOI",
                    data.len()
                ),
            ));
        }
        if data[cursor] != 0xFF {
            return Err(ContainerError::new(
                reason::BAD_HEADER,
                format!(
                    "偏移 0x{cursor:x} 处应为段标记 0xFF，实为 0x{:02x}",
                    data[cursor]
                ),
            ));
        }
        let mut marker_at = cursor;
        while marker_at < data.len() && data[marker_at] == 0xFF {
            marker_at += 1;
        }
        if marker_at >= data.len() {
            return Err(ContainerError::new(
                reason::TRUNCATED,
                "JPEG 标记在文件尾被截断",
            ));
        }
        let marker = data[marker_at];
        let header_end = marker_at + 1;
        if marker == 0x00 {
            return Err(ContainerError::new(
                reason::BAD_HEADER,
                format!("偏移 0x{cursor:x} 处出现填充字节 0xFF00"),
            ));
        }
        // Standalone markers without a length field.
        if matches!(marker, 0xD0..=0xD7 | 0x01 | 0xD8) {
            cursor = header_end;
            continue;
        }
        if marker == 0xD9 {
            break;
        }
        let length_at = header_end;
        let Some(length_bytes) = data.get(length_at..length_at + 2) else {
            return Err(ContainerError::new(
                reason::TRUNCATED,
                format!("偏移 0x{cursor:x} 的段长度被截断"),
            ));
        };
        let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]);
        if length < 2 {
            return Err(ContainerError::new(
                reason::BAD_HEADER,
                format!("偏移 0x{cursor:x} 的段长度 {length} < 2"),
            ));
        }
        let payload_start = length_at + 2;
        let payload_end = length_at.saturating_add(usize::from(length));
        let Some(payload) = data.get(payload_start..payload_end) else {
            return Err(ContainerError::new(
                reason::TRUNCATED,
                format!(
                    "偏移 0x{cursor:x} 的段声明长度 {length}（结束 0x{payload_end:x}）超出文件长 {}",
                    data.len()
                ),
            ));
        };
        match marker {
            0xE1 if payload.starts_with(b"Exif\0\0") => {
                out.exif_candidates.push(payload_start as u32);
                if out.exif.is_some() {
                    out.exif_skipped.push(format!(
                        "0x{payload_start:x} 的 APP1 EXIF 未采用（已取首个有效段）"
                    ));
                } else if payload.len() > MAX_APP1 {
                    out.exif_skipped.push(format!(
                        "0x{payload_start:x} 的 APP1 EXIF 长度 {} 超过上限 {MAX_APP1}，拒绝",
                        payload.len()
                    ));
                } else if let Err(error) =
                    accept_exif(&mut out, payload, payload_start as u32, "jpeg-app1")
                {
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
            0xE1 if payload.starts_with(XMP_JPEG_HEADER) => {
                if out.xmp.is_none() {
                    let body_start = payload_start + XMP_JPEG_HEADER.len();
                    let body = &payload[XMP_JPEG_HEADER.len()..];
                    out.xmp = Some(parse_xmp(body, body_start as u32));
                }
            }
            0xDA => {
                // Entropy-coded data follows. Every 0xFF in a scan is either
                // stuffed (FF00) or a marker, so a missing FF D9 means the file
                // was cut short and must be rejected even with valid EXIF.
                if !data[payload_end..]
                    .windows(2)
                    .any(|pair| pair == [0xFF, 0xD9])
                {
                    return Err(ContainerError::new(
                        reason::TRUNCATED,
                        format!(
                            "偏移 0x{payload_start:x} 的 SOS 之后未找到 EOI（文件长 {}）",
                            data.len()
                        ),
                    ));
                }
                break;
            }
            _ => {}
        }
        cursor = payload_end;
    }
    if out.exif.is_none() {
        out.exif_error = first_failure;
    }
    Ok(out)
}

fn accept_exif(
    out: &mut ParsedContainer,
    payload: &[u8],
    payload_start: u32,
    carrier: &'static str,
) -> Result<(), ContainerError> {
    match exif::parse_tiff(payload, true) {
        Ok(block) => {
            out.exif = Some(ExifBlock {
                container_offset: payload_start,
                tiff_offset: payload_start + 6,
                carrier,
                block,
            });
            Ok(())
        }
        Err(error) => {
            out.exif_skipped.push(format!(
                "0x{payload_start:x} 的 EXIF 解析失败[{}]：{}",
                error.reason, error.message
            ));
            Err(ContainerError::new(error.reason, error.message))
        }
    }
}

/// Walks PNG chunks: `IHDR` dimensions, `eXIf` EXIF, textual metadata.
pub fn scan_png(data: &[u8]) -> Result<ParsedContainer, ContainerError> {
    let mut out = ParsedContainer::default();
    const SIGNATURE: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < SIGNATURE.len() {
        return Err(ContainerError::new(
            reason::TRUNCATED,
            format!("PNG 不足 8 字节（实得 {}）", data.len()),
        ));
    }
    if !data.starts_with(SIGNATURE) {
        return Err(ContainerError::new(reason::BAD_HEADER, "PNG 签名不匹配"));
    }
    let mut cursor = 8usize;
    let mut chunks = 0usize;
    let mut first_failure: Option<ContainerError> = None;
    loop {
        chunks += 1;
        if chunks > MAX_PNG_CHUNKS {
            return Err(ContainerError::new(
                "too_many_chunks",
                format!("PNG 块数量超过 {MAX_PNG_CHUNKS}"),
            ));
        }
        if cursor >= data.len() {
            // A PNG must end with IEND; stopping at EOF means it was cut short.
            return Err(ContainerError::new(
                reason::TRUNCATED,
                format!("PNG 块表在文件尾结束（文件长 {}）但未遇到 IEND", data.len()),
            ));
        }
        let Some(head) = data.get(cursor..cursor + 8) else {
            return Err(ContainerError::new(
                reason::TRUNCATED,
                format!(
                    "偏移 0x{cursor:x} 的 PNG 块头被截断（文件长 {}）",
                    data.len()
                ),
            ));
        };
        let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let chunk_type = [head[4], head[5], head[6], head[7]];
        let data_start = cursor + 8;
        let data_end = data_start.saturating_add(length);
        let crc_end = data_end.saturating_add(4);
        if crc_end > data.len() {
            return Err(ContainerError::new(
                reason::TRUNCATED,
                format!(
                    "偏移 0x{cursor:x} 的块 {} 声明长度 {length}（结束 0x{crc_end:x}）超出文件长 {}",
                    String::from_utf8_lossy(&chunk_type),
                    data.len()
                ),
            ));
        }
        let payload = &data[data_start..data_end];
        match &chunk_type {
            b"IHDR" if payload.len() >= 8 => {
                let width = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let height = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                out.png_dimensions = Some((width, height));
            }
            b"eXIf" => {
                out.exif_candidates.push(data_start as u32);
                if out.exif.is_some() {
                    out.exif_skipped
                        .push(format!("0x{data_start:x} 的 eXIf 未采用（已取首个有效段）"));
                } else if payload.is_empty() {
                    let error = ContainerError::new(reason::EMPTY, "eXIf 块数据为空");
                    out.exif_skipped
                        .push(format!("0x{data_start:x} 的 eXIf 块为空，拒绝"));
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                } else {
                    match exif::parse_tiff(payload, false) {
                        Ok(block) => {
                            out.exif = Some(ExifBlock {
                                container_offset: data_start as u32,
                                tiff_offset: data_start as u32,
                                carrier: "png-exif",
                                block,
                            });
                        }
                        Err(error) => {
                            out.exif_skipped.push(format!(
                                "0x{data_start:x} 的 eXIf 解析失败[{}]：{}",
                                error.reason, error.message
                            ));
                            if first_failure.is_none() {
                                first_failure =
                                    Some(ContainerError::new(error.reason, error.message));
                            }
                        }
                    }
                }
            }
            b"tEXt" | b"iTXt" | b"zTXt" => {
                let chunk_name = match &chunk_type {
                    b"tEXt" => "tEXt",
                    b"iTXt" => "iTXt",
                    _ => "zTXt",
                };
                if let Some(text) = parse_png_text(payload, chunk_name, data_start as u32) {
                    if text.key == XMP_PNG_KEY {
                        if out.xmp.is_none() {
                            out.xmp =
                                Some(parse_xmp(payload_after_key(payload).0, data_start as u32));
                        }
                    } else {
                        out.png_texts.push(text);
                    }
                }
            }
            b"IEND" => break,
            _ => {}
        }
        cursor = crc_end;
    }
    if out.exif.is_none() {
        out.exif_error = first_failure;
    }
    Ok(out)
}

/// Returns the text payload after the keyword and how many bytes it skipped.
fn payload_after_key(payload: &[u8]) -> (&[u8], usize) {
    match payload.iter().position(|byte| *byte == 0) {
        Some(index) => (&payload[index + 1..], index + 1),
        None => (&[], payload.len()),
    }
}

fn parse_png_text(payload: &[u8], chunk_type: &'static str, offset: u32) -> Option<PngText> {
    let Some(separator) = payload.iter().position(|byte| *byte == 0) else {
        return None;
    };
    let key = String::from_utf8_lossy(&payload[..separator]).into_owned();
    if key.is_empty() || key.len() > 79 {
        return None;
    }
    let mut rest = &payload[separator + 1..];
    if chunk_type == "iTXt" {
        // compression flag, compression method, language tag\0, translated key\0
        if rest.len() < 2 {
            return None;
        }
        let compressed = rest[0] != 0;
        rest = &rest[2..];
        for _ in 0..2 {
            let Some(end) = rest.iter().position(|byte| *byte == 0) else {
                return None;
            };
            rest = &rest[end + 1..];
        }
        if compressed {
            // zlib/iTXt-compressed text is not inflated: keep the keyword only.
            return Some(PngText {
                key,
                value: String::new(),
                chunk_type,
                offset,
                truncated: true,
            });
        }
    } else if chunk_type == "zTXt" {
        // compression method byte then zlib data: not inflated.
        return Some(PngText {
            key,
            value: String::new(),
            chunk_type,
            offset,
            truncated: true,
        });
    }
    let truncated = rest.len() > MAX_PNG_TEXT;
    let bytes = &rest[..rest.len().min(MAX_PNG_TEXT)];
    Some(PngText {
        key,
        value: String::from_utf8_lossy(bytes).into_owned(),
        chunk_type,
        offset,
        truncated,
    })
}

/// Extracts a few XMP text fields without an XML library (bounded scan).
pub fn parse_xmp(body: &[u8], offset: u32) -> XmpPacket {
    const MAX_XMP: usize = 64 * 1024;
    let truncated = body.len() > MAX_XMP;
    let text = String::from_utf8_lossy(&body[..body.len().min(MAX_XMP)]).into_owned();
    XmpPacket {
        offset,
        length: body.len(),
        date_created: xmp_field(
            &text,
            &[
                "xmp:CreateDate",
                "photoshop:DateCreated",
                "exif:DateTimeOriginal",
            ],
        ),
        creator_tool: xmp_field(&text, &["xmp:CreatorTool"]),
        packet_truncated: truncated,
    }
}

fn xmp_field(text: &str, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(index) = text.find(name) {
            let after = &text[index + name.len()..];
            let after = after.trim_start();
            let value = if let Some(after) = after.strip_prefix('>') {
                after.split('<').next().unwrap_or("")
            } else if let Some(after) = after.strip_prefix('=') {
                let after = after.trim_start().trim_start_matches('"');
                after.split('"').next().unwrap_or("")
            } else {
                ""
            };
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}
