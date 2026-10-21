//! 单张照片的完整解析：格式识别 → 容器扫描 → EXIF 字段解释 → 结论。
//!
//! 该模块是纯函数式的（输入字节 + 逻辑路径，输出结论），
//! 因此可以用合成样例做单元测试，也与 SDK 句柄读取完全解耦。

use crate::container::{self, ContainerError, ExifBlock, ParsedContainer, PngText, XmpPacket};
use crate::exif;
use crate::fields::{self, MetadataFields};
use crate::format::{self, ExtensionKind, RealFormat};
use crate::sha256::Sha256;

/// Outcome of parsing one file.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// A photo with a parsed record (EXIF may be absent).
    Photo(Box<PhotoRecord>),
    /// A candidate file rejected by the container/EXIF layer.
    Rejected(ContainerError),
    /// The extension claimed a photo but the content is not one of the
    /// supported photo formats (text renamed to `.jpg`, …).
    NotPhoto { format: RealFormat, detail: String },
    /// Not a candidate at all (extension outside jpg/jpeg/png/heic/heif).
    NotCandidate,
}

/// Everything we know about one photo file, plus provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct PhotoRecord {
    /// Path relative to the analyzed root (no leading slash).
    pub path: String,
    pub name: String,
    pub root_id: String,
    pub extension: ExtensionKind,
    pub format: RealFormat,
    pub container: String,
    pub extension_mismatch: bool,
    pub size: u64,
    pub sha256: String,
    pub exif_present: bool,
    pub exif_candidates: u64,
    pub exif_block: Option<ExifBlock>,
    pub fields: MetadataFields,
    pub png_texts: Vec<PngText>,
    pub xmp: Option<XmpPacket>,
    pub warnings: Vec<String>,
    pub skipped_exif: Vec<String>,
    pub reason: String,
    pub reason_text: String,
}

impl PhotoRecord {
    pub fn has_gps(&self) -> bool {
        self.fields.has_gps()
    }
}

/// Fingerprints the whole buffer and parses it.
pub fn parse_file(path: &str, bytes: &[u8]) -> Outcome {
    let name = path.rsplit('/').next().unwrap_or(path).to_owned();
    let Some(extension) = ExtensionKind::from_name(&name) else {
        return Outcome::NotCandidate;
    };
    let header_length = bytes.len().min(format::HEADER_PROBE);
    let format = format::sniff(&bytes[..header_length]);
    if format == RealFormat::Unknown {
        return Outcome::NotPhoto {
            format,
            detail: format!(
                "扩展名 {} 声称是照片，但文件头不匹配 JPEG/PNG/HEIC/HEIF 魔数（前 {} 字节：{}）",
                extension.label(),
                header_length,
                hex(&bytes[..header_length])
            ),
        };
    }
    if bytes.is_empty() {
        return Outcome::Rejected(ContainerError::new(exif::reason::TRUNCATED, "文件为空"));
    }
    let mut record = PhotoRecord {
        path: path.to_owned(),
        name,
        root_id: String::new(),
        extension,
        format,
        container: String::new(),
        extension_mismatch: format::mismatches(extension, format),
        size: bytes.len() as u64,
        sha256: Sha256::digest_hex(bytes),
        exif_present: false,
        exif_candidates: 0,
        exif_block: None,
        fields: MetadataFields::default(),
        png_texts: Vec::new(),
        xmp: None,
        warnings: Vec::new(),
        skipped_exif: Vec::new(),
        reason: String::new(),
        reason_text: String::new(),
    };
    let scan = match format {
        RealFormat::Jpeg => container::scan_jpeg(bytes),
        RealFormat::Png => container::scan_png(bytes),
        RealFormat::Heic | RealFormat::Heif => Ok(heic_container()),
        RealFormat::Unknown => unreachable!("unknown formats return NotPhoto above"),
    };
    let ParsedContainer {
        exif_candidates,
        exif,
        exif_skipped,
        exif_error,
        png_texts,
        png_dimensions,
        xmp,
    } = match scan {
        Ok(scan) => scan,
        Err(error) => return Outcome::Rejected(error),
    };
    // Contract: a truncated / out-of-bounds / cyclic EXIF makes the whole file
    // unusable, so the record is rejected instead of carrying empty fields.
    if exif.is_none() {
        if let Some(error) = exif_error {
            let detail = if exif_skipped.is_empty() {
                error.message.clone()
            } else {
                format!("{}（{}）", error.message, exif_skipped.join("；"))
            };
            return Outcome::Rejected(ContainerError::new(error.reason, detail));
        }
    }
    record.container = container_label(format).to_owned();
    record.exif_candidates = exif_candidates.len() as u64;
    record.png_texts = png_texts;
    record.xmp = xmp;
    record.skipped_exif = exif_skipped;
    match &exif {
        Some(block) => {
            record.exif_present = true;
            record.fields =
                fields::interpret(&block.block, block.carrier, u64::from(block.tiff_offset));
            record
                .fields
                .skipped
                .extend(record.skipped_exif.iter().cloned());
            record.fields.png_dimensions = png_dimensions;
            record.exif_block = Some(block.clone());
        }
        None => {
            record.fields.png_dimensions = png_dimensions;
            if format.supports_exif() {
                record.reason = "no_exif".to_owned();
                record.reason_text = "容器内未发现 EXIF 段（按需求输出空字段）".to_owned();
            } else {
                record.reason = "heif_not_parsed".to_owned();
                record.reason_text =
                    "HEIC/HEIF 容器内 EXIF 未解析（本期只做格式识别，见 README 未覆盖部分）"
                        .to_owned();
            }
        }
    }
    if !record.fields.skipped.is_empty() {
        record
            .warnings
            .extend(record.fields.skipped.iter().cloned());
    }
    if record.extension_mismatch {
        record.warnings.push(format!(
            "扩展名声明 {}，真实格式 {}（按真实格式解析）",
            extension.label(),
            format.label()
        ));
    }
    if let Some(xmp) = &record.xmp {
        if xmp.packet_truncated {
            record.warnings.push(format!(
                "XMP 包长度 {} 超过 64 KiB，只解析前 64 KiB",
                xmp.length
            ));
        }
    }
    Outcome::Photo(Box::new(record))
}

/// HEIC/HEIF: format identified, EXIF not extracted (ISO-BMFF not parsed).
fn heic_container() -> ParsedContainer {
    ParsedContainer::default()
}

fn container_label(format: RealFormat) -> &'static str {
    match format {
        RealFormat::Jpeg => "JPEG 段表",
        RealFormat::Png => "PNG 块表",
        RealFormat::Heic | RealFormat::Heif => "ISO-BMFF(未解析)",
        RealFormat::Unknown => "未知",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Counters for the run summary.
///
/// Kept consistent with the outcomes actually produced (see [`accumulate`],
/// [`RunSummary::record_failure`] and [`RunSummary::record_excluded`]):
/// - `total == with_exif + without_exif + failed + excluded_non_image`
/// - `total == with_gps + without_gps`
///
/// `without_gps` therefore covers every counted candidate file that yielded no
/// GPS field, including files rejected by the parser (no GPS evidence either
/// way) and non-image candidates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub total: usize,
    pub with_exif: usize,
    pub with_gps: usize,
    pub without_gps: usize,
    pub without_exif: usize,
    pub failed: usize,
    pub excluded_non_image: usize,
    pub skipped_beyond_limit: usize,
    /// `(reason code, count)` sorted by code.
    pub reasons: Vec<(String, usize)>,
    pub text: String,
}

impl RunSummary {
    pub fn record_reason(&mut self, reason: &str) {
        if reason.is_empty() {
            return;
        }
        match self.reasons.iter_mut().find(|(code, _)| code == reason) {
            Some((_, count)) => *count += 1,
            None => self.reasons.push((reason.to_owned(), 1)),
        }
    }

    /// Counts one candidate file rejected by the container/EXIF layer.
    pub fn record_failure(&mut self, reason: &str) {
        self.total += 1;
        self.failed += 1;
        self.without_gps += 1;
        self.record_reason(reason);
    }

    /// Counts one candidate file excluded because its content is not a photo
    /// (or its extension is outside the photo list).
    pub fn record_excluded(&mut self, reason: &str) {
        self.total += 1;
        self.excluded_non_image += 1;
        self.without_gps += 1;
        self.record_reason(reason);
    }

    pub fn finish(&mut self) {
        self.reasons.sort_by(|left, right| left.0.cmp(&right.0));
        let reasons = if self.reasons.is_empty() {
            "无".to_owned()
        } else {
            self.reasons
                .iter()
                .map(|(code, count)| format!("{code}×{count}"))
                .collect::<Vec<_>>()
                .join("、")
        };
        self.text = format!(
            "文件数 {}；含 EXIF {}；含 GPS {}；无 GPS {}；无 EXIF {}；解析失败 {}；\
             非图片/扩展名不符跳过 {}；超出上限未解析 {}；失败原因 {}",
            self.total,
            self.with_exif,
            self.with_gps,
            self.without_gps,
            self.without_exif,
            self.failed,
            self.excluded_non_image,
            self.skipped_beyond_limit,
            reasons
        );
    }
}

/// Folds one parse outcome into the run summary.
pub fn accumulate(summary: &mut RunSummary, outcome: &Outcome) {
    match outcome {
        Outcome::Photo(record) => {
            summary.total += 1;
            if record.exif_present {
                summary.with_exif += 1;
            } else {
                summary.without_exif += 1;
                summary.record_reason(&record.reason);
            }
            if record.has_gps() {
                summary.with_gps += 1;
            } else {
                summary.without_gps += 1;
            }
        }
        Outcome::Rejected(error) => summary.record_failure(error.reason),
        Outcome::NotPhoto { .. } => summary.record_excluded("not_image"),
        Outcome::NotCandidate => summary.record_excluded("extension_not_photo"),
    }
}
