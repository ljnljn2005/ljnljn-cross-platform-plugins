//! 真实格式识别：文件头魔数优先，扩展名只用于决定「是否进入待解析清单」。
//!
//! 规则（来自需求「按扩展名和文件头魔数识别真实格式，同名的非图片文件跳过并计数」）：
//! 1. 扩展名在 {jpg, jpeg, png, heic, heif} 内的文件才进入候选清单；
//! 2. 候选文件必须先读头部并匹配真实魔数，否则计入「扩展名与内容不符」（跳过并计数）；
//! 3. 扩展名与真实格式不一致（如 `.jpg` 里实际是 PNG）时按真实格式解析，
//!    并在记录的 `format.mismatch` 与汇总里标明。

/// Format actually detected from the file header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealFormat {
    Jpeg,
    Png,
    Heic,
    Heif,
    Unknown,
}

impl RealFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::Jpeg => "JPEG",
            Self::Png => "PNG",
            Self::Heic => "HEIC",
            Self::Heif => "HEIF",
            Self::Unknown => "未知",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Heic => "image/heic",
            Self::Heif => "image/heif",
            Self::Unknown => "application/octet-stream",
        }
    }

    pub fn supports_exif(self) -> bool {
        matches!(self, Self::Jpeg | Self::Png)
    }
}

/// Extension group a candidate photo file belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionKind {
    Jpeg,
    Png,
    Heic,
    Heif,
}

impl ExtensionKind {
    pub fn from_name(name: &str) -> Option<Self> {
        let extension = name.rsplit_once('.').map(|(_, extension)| extension)?;
        match extension.to_ascii_lowercase().as_str() {
            "jpg" | "jpeg" => Some(Self::Jpeg),
            "png" => Some(Self::Png),
            "heic" => Some(Self::Heic),
            "heif" => Some(Self::Heif),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Jpeg => "jpg/jpeg",
            Self::Png => "png",
            Self::Heic => "heic",
            Self::Heif => "heif",
        }
    }
}

/// Bytes needed from the head of a file to classify it.
pub const HEADER_PROBE: usize = 32;

/// Detects the real format from the leading bytes.
///
/// - JPEG: `FF D8 FF` (SOI + first marker prefix)
/// - PNG: the 8-byte PNG signature
/// - HEIC/HEIF: ISO-BMFF `ftyp` box whose brand is an `mif1` compatible image
///   brand (`heic`, `heix`, `hevc`, `hevx`, `mif1`, `msf1`, `heim`, `heis`,
///   `avci`, `heif`). `brand == "mif1"` maps to HEIF, `msf1` stays HEIF,
///   other image brands map to HEIC.
pub fn sniff(header: &[u8]) -> RealFormat {
    // Short but unambiguous signatures still identify the real format; the
    // container walker then reports the file as truncated instead of
    // pretending the content is not a photo at all.
    if header.len() >= 2 && header[0] == 0xFF && header[1] == 0xD8 {
        return RealFormat::Jpeg;
    }
    if header.len() >= 4 && header[..4] == [0x89, b'P', b'N', b'G'] {
        return RealFormat::Png;
    }
    if header.len() >= 12 && &header[4..8] == b"ftyp" {
        let major = &header[8..12];
        let minor_bytes = header.get(12..16).unwrap_or(&[]);
        let _ = minor_bytes;
        return match major {
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"avci" => RealFormat::Heic,
            b"mif1" | b"msf1" | b"heif" => RealFormat::Heif,
            _ => {
                // Compatible brands follow; check the first few.
                let mut compatible = RealFormat::Unknown;
                let mut cursor = 16usize;
                while cursor + 4 <= header.len() {
                    match &header[cursor..cursor + 4] {
                        b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"avci" => {
                            compatible = RealFormat::Heic;
                            break;
                        }
                        b"mif1" | b"msf1" | b"heif" => {
                            compatible = RealFormat::Heif;
                            break;
                        }
                        _ => cursor += 4,
                    }
                }
                compatible
            }
        };
    }
    RealFormat::Unknown
}

/// True when the extension and the detected format disagree.
pub fn mismatches(extension: ExtensionKind, format: RealFormat) -> bool {
    !matches!(
        (extension, format),
        (ExtensionKind::Jpeg, RealFormat::Jpeg)
            | (ExtensionKind::Png, RealFormat::Png)
            | (ExtensionKind::Heic, RealFormat::Heic)
            | (ExtensionKind::Heif, RealFormat::Heif)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_real_formats_from_magic_only() {
        assert_eq!(
            sniff(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0]),
            RealFormat::Jpeg,
            "JPEG SOI"
        );
        assert_eq!(
            sniff(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0]),
            RealFormat::Png
        );
        let mut heic = vec![0, 0, 0, 0x18];
        heic.extend_from_slice(b"ftypheic");
        heic.extend_from_slice(&[0, 0, 0, 0]);
        heic.extend_from_slice(b"mif1heic");
        assert_eq!(sniff(&heic), RealFormat::Heic);
        let mut heif = vec![0, 0, 0, 0x18];
        heif.extend_from_slice(b"ftypmif1");
        heif.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(sniff(&heif), RealFormat::Heif);
        let mut mp4 = vec![0, 0, 0, 0x18];
        mp4.extend_from_slice(b"ftypisom");
        mp4.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(sniff(&mp4), RealFormat::Unknown);
        assert_eq!(sniff(b"not an image at all"), RealFormat::Unknown);
        assert_eq!(sniff(&[]), RealFormat::Unknown);
    }

    #[test]
    fn extensions_are_case_insensitive_and_limited_to_photo_types() {
        assert_eq!(ExtensionKind::from_name("IMG_0001.JPG"), Some(ExtensionKind::Jpeg));
        assert_eq!(ExtensionKind::from_name("a.jpeg"), Some(ExtensionKind::Jpeg));
        assert_eq!(ExtensionKind::from_name("a.png"), Some(ExtensionKind::Png));
        assert_eq!(ExtensionKind::from_name("a.HeIc"), Some(ExtensionKind::Heic));
        assert_eq!(ExtensionKind::from_name("a.heif"), Some(ExtensionKind::Heif));
        assert_eq!(ExtensionKind::from_name("notes.txt"), None);
        assert_eq!(ExtensionKind::from_name("noext"), None);
        assert_eq!(ExtensionKind::from_name("dir.jpg/readme"), None);
        assert!(mismatches(ExtensionKind::Jpeg, RealFormat::Png));
        assert!(!mismatches(ExtensionKind::Png, RealFormat::Png));
    }
}
