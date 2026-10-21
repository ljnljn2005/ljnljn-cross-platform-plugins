//! 合成样例构造器：在内存里搭最小 JPEG（含/不含 GPS）、PNG eXIf、截断文件与
//! 伪装成图片的文本文件，供单元测试与集成测试共用；不读写真实检材。
//!
//! 布局方案（统一按“先目录、后值区”的顺序写入）：
//! `TIFF头(8) | IFD0 | IFD1? | ExifIFD? | GPSIFD? | 值区…`
//! 构造时同时返回 [`Layout`]（各 IFD 偏移、每个 tag 的 TIFF 相对 payload 偏移），
//! 测试把它与解析结果比对，从而真正校验“字段值和偏移定位”。

use std::collections::BTreeMap;

/// A tag entry to be written into an IFD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Ascii(u16, String),
    Short(u16, Vec<u16>),
    Long(u16, Vec<u32>),
    Rational(u16, Vec<(u32, u32)>),
    Undefined(u16, Vec<u8>),
}

impl Entry {
    pub fn tag(&self) -> u16 {
        match self {
            Self::Ascii(tag, _)
            | Self::Short(tag, _)
            | Self::Long(tag, _)
            | Self::Rational(tag, _)
            | Self::Undefined(tag, _) => *tag,
        }
    }

    fn type_id(&self) -> u16 {
        match self {
            Self::Ascii(..) => 2,
            Self::Short(..) => 3,
            Self::Long(..) => 4,
            Self::Rational(..) => 5,
            Self::Undefined(..) => 7,
        }
    }

    fn count(&self) -> u32 {
        match self {
            Self::Ascii(_, text) => text.len() as u32 + 1,
            Self::Short(_, values) => values.len() as u32,
            Self::Long(_, values) => values.len() as u32,
            Self::Rational(_, values) => values.len() as u32,
            Self::Undefined(_, bytes) => bytes.len() as u32,
        }
    }

    fn payload(&self, little: bool) -> Vec<u8> {
        let word = |value: u32, out: &mut Vec<u8>| {
            if little {
                out.extend_from_slice(&value.to_le_bytes());
            } else {
                out.extend_from_slice(&value.to_be_bytes());
            }
        };
        let mut out = Vec::new();
        match self {
            Self::Ascii(_, text) => {
                out.extend_from_slice(text.as_bytes());
                out.push(0);
            }
            Self::Short(_, values) => {
                for value in values {
                    if little {
                        out.extend_from_slice(&value.to_le_bytes());
                    } else {
                        out.extend_from_slice(&value.to_be_bytes());
                    }
                }
            }
            Self::Long(_, values) => {
                for value in values {
                    word(*value, &mut out);
                }
            }
            Self::Rational(_, values) => {
                for (numerator, denominator) in values {
                    word(*numerator, &mut out);
                    word(*denominator, &mut out);
                }
            }
            Self::Undefined(_, bytes) => out.extend_from_slice(bytes),
        }
        out
    }
}

/// Where the constructed data landed (TIFF-relative offsets).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub ifd0: u32,
    pub ifd1: Option<u32>,
    pub exif_ifd: Option<u32>,
    pub gps_ifd: Option<u32>,
    /// tag → TIFF-relative offset of its payload (inline slots included).
    pub value_offsets: BTreeMap<u16, u32>,
    /// tag → TIFF-relative offset of payloads stored outside the entry.
    pub separate_values: BTreeMap<u16, u32>,
}

/// All directories and tags of one EXIF block.
#[derive(Clone, Debug, Default)]
pub struct ExifSample {
    pub little_endian: bool,
    pub ifd0: Vec<Entry>,
    pub exif_ifd: Option<Vec<Entry>>,
    pub gps_ifd: Option<Vec<Entry>>,
    /// Add a second IFD (IFD1) chained from IFD0.next.
    pub ifd1: Option<Vec<Entry>>,
    /// Link the last IFD's `next` pointer back to IFD0 (cycle).
    pub cycle: bool,
    /// Override the IFD0 offset written into the TIFF header.
    pub ifd0_offset_override: Option<u32>,
}

impl ExifSample {
    /// Full EXIF sample: IFD0 (make/model/size/orientation/datetime),
    /// ExifIFD (DateTimeOriginal/lens/pixel size) and a GPS IFD.
    pub fn with_gps() -> Self {
        Self {
            little_endian: false, // "MM": exercises big-endian paths
            ifd0: vec![
                Entry::Ascii(0x010F, "TestMake".to_owned()),
                Entry::Ascii(0x0110, "ModelX-100".to_owned()),
                Entry::Short(0x0100, vec![4032]),
                Entry::Short(0x0101, vec![3024]),
                Entry::Short(0x0112, vec![6]),
                Entry::Ascii(0x0132, "2023:08:15 18:30:05".to_owned()),
            ],
            exif_ifd: Some(vec![
                Entry::Ascii(0x9003, "2023:08:15 10:30:00".to_owned()),
                Entry::Ascii(0xA434, "EF24-70mm f/2.8L".to_owned()),
                Entry::Ascii(0x9011, "+08:00".to_owned()),
            ]),
            gps_ifd: Some(vec![
                Entry::Ascii(0x0001, "S".to_owned()),
                Entry::Rational(0x0002, vec![(37, 1), (49, 1), (2287, 100)]),
                Entry::Ascii(0x0003, "E".to_owned()),
                Entry::Rational(0x0004, vec![(144, 1), (57, 1), (4573, 100)]),
                Entry::Undefined(0x0005, vec![0]),
                Entry::Rational(0x0006, vec![(1234, 100)]),
            ]),
            ifd1: None,
            cycle: false,
            ifd0_offset_override: None,
        }
    }

    /// EXIF sample without any GPS IFD.
    pub fn without_gps() -> Self {
        Self {
            little_endian: true,
            ifd0: vec![
                Entry::Ascii(0x010F, "PlainCam".to_owned()),
                Entry::Ascii(0x0110, "NoGps1".to_owned()),
                Entry::Short(0x0100, vec![800]),
                Entry::Short(0x0101, vec![600]),
                Entry::Short(0x0112, vec![1]),
            ],
            exif_ifd: Some(vec![
                Entry::Ascii(0x9003, "2020:01:02 03:04:05".to_owned()),
                Entry::Ascii(0xA434, "Prime 35mm".to_owned()),
            ]),
            gps_ifd: None,
            ifd1: None,
            cycle: false,
            ifd0_offset_override: None,
        }
    }

    /// Builds the TIFF block bytes plus the layout map.
    pub fn build(&self) -> (Vec<u8>, Layout) {
        let little = self.little_endian;
        let mut layout = Layout::default();
        // Directories in write order, each with its tag list.
        let mut directories: Vec<(u32, Vec<Entry>)> = Vec::new();
        let mut cursor = 8u32;
        let ifd0_entries = self.ifd0.clone();
        layout.ifd0 = 8;
        let entry_count = |entries: Vec<Entry>| -> Vec<Entry> {
            let mut entries = entries;
            entries.sort_by_key(Entry::tag);
            entries
        };
        // IFD0 needs pointer slots: reserve two extra entries when sub IFDs exist.
        let pointers = usize::from(self.exif_ifd.is_some()) + usize::from(self.gps_ifd.is_some());
        directories.push((cursor, entry_count(ifd0_entries)));
        cursor += directory_size(self.ifd0.len() + pointers);
        if let Some(ifd1) = &self.ifd1 {
            layout.ifd1 = Some(cursor);
            directories.push((cursor, entry_count(ifd1.clone())));
            cursor += directory_size(ifd1.len());
        }
        if let Some(exif) = &self.exif_ifd {
            layout.exif_ifd = Some(cursor);
            directories.push((cursor, entry_count(exif.clone())));
            cursor += directory_size(exif.len());
        }
        if let Some(gps) = &self.gps_ifd {
            layout.gps_ifd = Some(cursor);
            directories.push((cursor, entry_count(gps.clone())));
            cursor += directory_size(gps.len());
        }
        let directories_end = cursor;
        // Value area payloads first, so directory slots can point at them.
        let mut values: Vec<u8> = Vec::new();
        let payload_offset = |entry: &Entry, layout: &mut Layout, values: &mut Vec<u8>|
         -> Option<u32> {
            let payload = entry.payload(little);
            if payload.len() <= 4 {
                return None;
            }
            let offset = directories_end + values.len() as u32;
            layout.separate_values.insert(entry.tag(), offset);
            values.extend_from_slice(&payload);
            Some(offset)
        };
        let mut ifd0_blocks: Vec<(u16, u16, u32, Vec<u8>, Option<u32>)> = Vec::new();
        for entry in &self.ifd0 {
            let value_offset = payload_offset(entry, &mut layout, &mut values);
            ifd0_blocks.push((
                entry.tag(),
                entry.type_id(),
                entry.count(),
                entry.payload(little),
                value_offset,
            ));
        }
        if let Some(offset) = layout.exif_ifd {
            ifd0_blocks.push((0x8769, 4, 1, Vec::new(), Some(offset)));
        }
        if let Some(offset) = layout.gps_ifd {
            ifd0_blocks.push((0x8825, 4, 1, Vec::new(), Some(offset)));
        }
        ifd0_blocks.sort_by_key(|(tag, ..)| *tag);
        layout.ifd0 = 8;
        let ifd0_offset = self.ifd0_offset_override.unwrap_or(8);

        let mut tiff = vec![0u8; directories_end as usize];
        tiff[0..2].copy_from_slice(if little { b"II" } else { b"MM" });
        write_u16(&mut tiff, 2, 42, little);
        write_u32(&mut tiff, 4, ifd0_offset, little);

        let write_directory =
            |tiff: &mut Vec<u8>,
             offset: u32,
             blocks: &[(u16, u16, u32, Vec<u8>, Option<u32>)],
             next: u32,
             layout: &mut Layout| {
                let start = offset as usize;
                write_u16(tiff, start, blocks.len() as u16, little);
                let mut slot = start + 2;
                for (tag, type_id, count, payload, value_offset) in blocks {
                    write_u16(tiff, slot, *tag, little);
                    write_u16(tiff, slot + 2, *type_id, little);
                    write_u32(tiff, slot + 4, *count, little);
                    match value_offset {
                        Some(value_offset) => {
                            write_u32(tiff, slot + 8, *value_offset, little);
                            layout.value_offsets.insert(*tag, *value_offset);
                        }
                        None => {
                            let copy = payload.len().min(4);
                            tiff[slot + 8..slot + 8 + copy].copy_from_slice(&payload[..copy]);
                            layout.value_offsets.insert(*tag, (slot + 8) as u32);
                        }
                    }
                    slot += 12;
                }
                write_u32(tiff, slot, next, little);
            };
        // IFD1 chain target.
        let ifd1_next = match (&self.ifd1, layout.ifd1) {
            (Some(_), Some(offset)) => offset,
            _ => 0,
        };
        write_directory(&mut tiff, layout.ifd0, &ifd0_blocks, ifd1_next, &mut layout);
        if let (Some(entries), Some(offset)) = (&self.ifd1, layout.ifd1) {
            let mut blocks = Vec::new();
            for entry in entries {
                let value_offset = payload_offset(entry, &mut layout, &mut values);
                blocks.push((
                    entry.tag(),
                    entry.type_id(),
                    entry.count(),
                    entry.payload(little),
                    value_offset,
                ));
            }
            blocks.sort_by_key(|(tag, ..)| *tag);
            let next = if self.cycle { layout.ifd0 } else { 0 };
            write_directory(&mut tiff, offset, &blocks, next, &mut layout);
        }
        for (label, entries) in [("exif", &self.exif_ifd), ("gps", &self.gps_ifd)] {
            let Some(entries) = entries else { continue };
            let offset = if label == "exif" {
                layout.exif_ifd.expect("recorded above")
            } else {
                layout.gps_ifd.expect("recorded above")
            };
            let mut blocks = Vec::new();
            for entry in entries {
                let value_offset = payload_offset(entry, &mut layout, &mut values);
                blocks.push((
                    entry.tag(),
                    entry.type_id(),
                    entry.count(),
                    entry.payload(little),
                    value_offset,
                ));
            }
            blocks.sort_by_key(|(tag, ..)| *tag);
            write_directory(&mut tiff, offset, &blocks, 0, &mut layout);
        }
        tiff.truncate(directories_end as usize);
        tiff.extend_from_slice(&values);
        (tiff, layout)
    }
}

fn directory_size(entries: usize) -> u32 {
    (2 + entries * 12 + 4) as u32
}

fn write_u16(buffer: &mut [u8], offset: usize, value: u16, little: bool) {
    let bytes = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    buffer[offset..offset + 2].copy_from_slice(&bytes);
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32, little: bool) {
    let bytes = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    buffer[offset..offset + 4].copy_from_slice(&bytes);
}

/// Builds a JPEG file from an optional EXIF sample plus optional extra APP1/XMP.
#[derive(Clone, Debug, Default)]
pub struct JpegSample {
    pub exif: Option<ExifSample>,
    /// Extra APP1 `Exif\0\0` segments appended after the first (multi-segment case).
    pub extra_exif: Vec<ExifSample>,
    /// Prepend a JFIF APP0 segment (typical camera-independent JPEG).
    pub with_app0: bool,
    /// Append an XMP APP1 segment with the given body.
    pub xmp: Option<String>,
    /// Append SOS + minimal scan data + EOI.
    pub with_scan: bool,
    /// Cut the produced file at this length (truncation fixture).
    pub truncate_to: Option<usize>,
}

impl JpegSample {
    /// Returns the JPEG bytes, the file offset of the first APP1 payload, and
    /// the TIFF-relative layout of the first EXIF block.
    pub fn build(&self) -> (Vec<u8>, Option<u32>, Option<Layout>) {
        let mut out = vec![0xFF, 0xD8];
        if self.with_app0 {
            let payload = b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0".to_vec();
            push_segment(&mut out, 0xE0, &payload);
        }
        let mut first_payload = None;
        let mut layout = None;
        if let Some(exif) = &self.exif {
            let (tiff, block_layout) = exif.build();
            let mut payload = b"Exif\0\0".to_vec();
            payload.extend_from_slice(&tiff);
            first_payload = Some((out.len() + 4) as u32);
            layout = Some(block_layout);
            push_segment(&mut out, 0xE1, &payload);
        }
        for extra in &self.extra_exif {
            let (tiff, _) = extra.build();
            let mut payload = b"Exif\0\0".to_vec();
            payload.extend_from_slice(&tiff);
            push_segment(&mut out, 0xE1, &payload);
        }
        if let Some(xmp) = &self.xmp {
            let mut payload = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
            payload.extend_from_slice(xmp.as_bytes());
            push_segment(&mut out, 0xE1, &payload);
        }
        if self.with_scan {
            // SOS header, one byte of entropy data, EOI.
            let payload = b"\x01\x01\x00\x00\x3f\x00".to_vec();
            push_segment(&mut out, 0xDA, &payload);
            out.extend_from_slice(&[0x12, 0x34, 0xFF, 0xD9]);
        }
        if let Some(length) = self.truncate_to {
            out.truncate(length);
        }
        (out, first_payload, layout)
    }
}

pub fn push_segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.push(0xFF);
    out.push(marker);
    let length = (payload.len() + 2) as u16;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Builds a PNG file with optional eXIf (TIFF block) and text chunks.
#[derive(Clone, Debug, Default)]
pub struct PngSample {
    pub width: u32,
    pub height: u32,
    pub exif: Option<ExifSample>,
    /// `(keyword, value)` pairs written as `tEXt` chunks.
    pub texts: Vec<(String, String)>,
    /// Extra raw chunks written verbatim (chunk type, data).
    pub extra_chunks: Vec<([u8; 4], Vec<u8>)>,
    pub truncate_to: Option<usize>,
}

impl PngSample {
    /// Returns PNG bytes, the eXIf data offset and the TIFF layout.
    pub fn build(&self) -> (Vec<u8>, Option<u32>, Option<Layout>) {
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&self.width.to_be_bytes());
        ihdr.extend_from_slice(&self.height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        push_chunk(&mut out, b"IHDR", &ihdr);
        for (key, value) in &self.texts {
            let mut data = key.as_bytes().to_vec();
            data.push(0);
            data.extend_from_slice(value.as_bytes());
            push_chunk(&mut out, b"tEXt", &data);
        }
        let mut exif_offset = None;
        let mut layout = None;
        if let Some(exif) = &self.exif {
            let (tiff, block_layout) = exif.build();
            exif_offset = Some((out.len() + 8) as u32);
            layout = Some(block_layout);
            push_chunk(&mut out, b"eXIf", &tiff);
        }
        for (chunk_type, data) in &self.extra_chunks {
            push_chunk(&mut out, chunk_type, data);
        }
        push_chunk(&mut out, b"IEND", &[]);
        if let Some(length) = self.truncate_to {
            out.truncate(length);
        }
        (out, exif_offset, layout)
    }
}

fn push_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let crc = crc32(&[chunk_type.as_slice(), data].concat());
    out.extend_from_slice(&crc.to_be_bytes());
}

/// CRC-32/ISO-HDLC, as required by the PNG specification (chunk CRC).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

