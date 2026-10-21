//! 合成 EWF 段文件构造器（测试与独立样例验证共用，不依赖历史案件取值）。
//!
//! 布局与解析器一致，均按公开 EWF1 结构：
//! * 文件头 13 字节：8 字节签名 `EVF\x09\x0d\x0a\xff\x00` + fields_start(0x01)
//!   + 段号(u16 LE) + fields_end(2 字节)；
//! * 节段描述符 76 字节：0..16 类型（NUL 结尾 ASCII）、16..24 next 偏移、
//!   24..32 节段长度（含描述符）、32..72 填充、72..76 adler32(0..72)；
//! * volume 节段内容 1052 字节：0 media_type、4..8 number_of_chunks、
//!   8..12 sectors_per_chunk、12..16 bytes_per_sector、16..24 number_of_sectors、
//!   24..36 CHS、36 media_flags、52 compression_level、64..80 集合标识、
//!   1048..1052 adler32(0..1048)。
//!
//! 默认样例按真实 E01 的常见顺序排列：header → volume → table → done。

use crate::ewf::{
    adler32, EWF1_FILE_HEADER_SIZE, EWF2_FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE,
    SECTION_WINDOW_CAP, SIGNATURE,
};

/// EWF1 文件头长度（13 字节）。
pub const HEADER_LEN: usize = EWF1_FILE_HEADER_SIZE as usize;
/// EWF2/Ex01 文件头长度（32 字节）。
pub const EWF2_HEADER_LEN: usize = EWF2_FILE_HEADER_SIZE as usize;
/// EWF1 volume 节段内容长度。
pub const VOLUME_BODY_LEN: usize = 1052;
/// 默认合成 header 节段内容长度（仅占位，不解压）。
pub const DEFAULT_HEADER_SECTION_LEN: usize = 128;

/// volume 节段的合成取值。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeSpec {
    pub media_type: u8,
    pub number_of_chunks: u32,
    pub sectors_per_chunk: u32,
    pub sector_size: u32,
    pub sector_count: u64,
    pub media_flags: u8,
    pub compression_level: u8,
}

impl Default for VolumeSpec {
    fn default() -> Self {
        Self {
            media_type: 0x01,
            number_of_chunks: 32,
            sectors_per_chunk: 64,
            sector_size: 512,
            sector_count: 2048,
            media_flags: 0x01,
            compression_level: 0x01,
        }
    }
}

/// 构造参数。
#[derive(Clone, Debug)]
pub struct SampleSpec {
    /// 文件名（决定扩展名序号）。
    pub name: String,
    /// 格式：`EWF1` / `EWF2` / `Ex01`（EWF2/Ex01 只写 32 字节文件头）。
    pub format: &'static str,
    /// 段号（EWF1 写入 u16，EWF2/Ex01 写入 u32）。
    pub segment_number: u32,
    /// volume 节段取值；None 表示不写 volume 节段。
    pub volume: Option<VolumeSpec>,
    /// 是否在 volume 之前写一枚 header 节段（真实 E01 的常见顺序）。
    pub header_section: bool,
    /// 是否在 volume 之后写一枚 table 节段。
    pub table_section: bool,
    /// 文件末尾追加的 chunk 占位字节数。
    pub padding: usize,
}

impl Default for SampleSpec {
    fn default() -> Self {
        Self {
            name: "sample.E01".to_string(),
            format: "EWF1",
            segment_number: 1,
            volume: Some(VolumeSpec::default()),
            header_section: true,
            table_section: true,
            padding: 64,
        }
    }
}

fn is_ewf1(format: &str) -> bool {
    format.eq_ignore_ascii_case("EWF1")
}

/// 文件头字节：EWF1 13 字节，EWF2/Ex01 32 字节。
pub fn file_header(spec: &SampleSpec) -> Vec<u8> {
    let mut header = Vec::with_capacity(EWF2_HEADER_LEN);
    header.extend_from_slice(SIGNATURE);
    if is_ewf1(spec.format) {
        header.push(0x01); // fields_start
        let segment = u16::try_from(spec.segment_number).unwrap_or(u16::MAX);
        header.extend_from_slice(&segment.to_le_bytes());
        header.extend_from_slice(&[0x01, 0x00]); // fields_end
        assert_eq!(header.len(), HEADER_LEN);
    } else {
        header.push(0x02); // major_version
        header.push(0x01); // minor_version
        header.extend_from_slice(&1u16.to_le_bytes()); // compression method: deflate
        header.extend_from_slice(&spec.segment_number.to_le_bytes()); // u32 段号
        let mut set_identifier = [0u8; 16];
        let text = b"SYNTHETIC-SET";
        set_identifier[..text.len()].copy_from_slice(text);
        header.extend_from_slice(&set_identifier);
        assert_eq!(header.len(), EWF2_HEADER_LEN);
    }
    header
}

/// 76 字节节段描述符。
pub fn section_descriptor(section_type: &str, next_offset: u64, length: u64) -> Vec<u8> {
    let mut descriptor = vec![0u8; SECTION_DESCRIPTOR_SIZE as usize];
    let bytes = section_type.as_bytes();
    let copied = bytes.len().min(16);
    descriptor[..copied].copy_from_slice(&bytes[..copied]);
    descriptor[16..24].copy_from_slice(&next_offset.to_le_bytes());
    descriptor[24..32].copy_from_slice(&length.to_le_bytes());
    if next_offset != 0 {
        descriptor[32..40].copy_from_slice(&1u64.to_le_bytes());
    }
    let checksum = adler32(&descriptor[..72]);
    descriptor[72..76].copy_from_slice(&checksum.to_le_bytes());
    descriptor
}

/// 1052 字节 volume 节段内容（公开 EWF1 volume 结构）。
pub fn volume_body(spec: &VolumeSpec) -> Vec<u8> {
    let mut body = vec![0u8; VOLUME_BODY_LEN];
    body[0] = spec.media_type;
    body[4..8].copy_from_slice(&spec.number_of_chunks.to_le_bytes());
    body[8..12].copy_from_slice(&spec.sectors_per_chunk.to_le_bytes());
    body[12..16].copy_from_slice(&spec.sector_size.to_le_bytes());
    body[16..24].copy_from_slice(&spec.sector_count.to_le_bytes());
    body[36] = spec.media_flags;
    body[52] = spec.compression_level;
    let checksum = adler32(&body[..1048]);
    body[1048..1052].copy_from_slice(&checksum.to_le_bytes());
    body
}

/// header 节段内容占位（开头两字节形似 zlib，但本工程不解压）。
pub fn header_section_body() -> Vec<u8> {
    let mut body = vec![0u8; DEFAULT_HEADER_SECTION_LEN];
    body[0] = 0x78;
    body[1] = 0x9c;
    let text = b"1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\n";
    body[2..2 + text.len()].copy_from_slice(text);
    body
}

/// table 节段内容占位（仅用于类型标记，不解析 chunk 表）。
pub fn table_section_body() -> Vec<u8> {
    let mut body = vec![0u8; 64];
    body[..4].copy_from_slice(&3u32.to_le_bytes());
    body[8..16].copy_from_slice(&0u64.to_le_bytes());
    body
}

/// 按给定节段序列构造 EWF1 段文件：文件头 + 每枚节段（描述符 + 内容）+ 填充。
///
/// 该函数始终写 13 字节 EWF1 文件头；`spec.format` 仅用于段号宽度。
pub fn build_with_sections(spec: &SampleSpec, sections: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = file_header(spec);
    for (index, (section_type, body)) in sections.iter().enumerate() {
        let offset = output.len() as u64;
        let length = SECTION_DESCRIPTOR_SIZE + body.len() as u64;
        let next_offset = if index + 1 < sections.len() {
            offset.saturating_add(length)
        } else {
            0
        };
        output.extend_from_slice(&section_descriptor(section_type, next_offset, length));
        output.extend_from_slice(body);
    }
    output.extend(std::iter::repeat_n(0u8, spec.padding));
    output
}

/// 构造一个完整的合成段文件。
pub fn build(spec: &SampleSpec) -> Vec<u8> {
    if !is_ewf1(spec.format) {
        // v2 节段布局未实现；只提供 32 字节文件头与尾部占位。
        let mut output = file_header(spec);
        output.extend(std::iter::repeat_n(0u8, spec.padding.max(128)));
        return output;
    }
    let header_body = header_section_body();
    let volume_body = spec.volume.as_ref().map(volume_body);
    let table_body = table_section_body();
    let mut sections: Vec<(&str, &[u8])> = Vec::new();
    if spec.header_section {
        sections.push(("header", header_body.as_slice()));
    }
    if let Some(body) = volume_body.as_deref() {
        sections.push(("volume", body));
    }
    if spec.table_section {
        sections.push(("table", table_body.as_slice()));
    }
    sections.push(("done", &[]));
    build_with_sections(spec, &sections)
}

/// 按 `name` 的扩展名选择格式与段号（默认样例）。
pub fn build_named(name: &str) -> Vec<u8> {
    let number = crate::ewf::extension_number(name).unwrap_or(1);
    let format = if crate::ewf::extension_is_ex01(name) {
        "Ex01"
    } else {
        "EWF1"
    };
    let spec = SampleSpec {
        name: name.to_string(),
        format,
        segment_number: u32::try_from(number).unwrap_or(u32::MAX),
        ..SampleSpec::default()
    };
    build(&spec)
}

/// 按解析器的读取方式切分：head（文件起始 512 字节）与 sections（从偏移 13 起
/// 至多 64 KiB 的窗口）。
pub fn split_for_parser(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let head_end = bytes.len().min(512);
    let head = bytes[..head_end].to_vec();
    let start = HEADER_LEN.min(bytes.len());
    let end = start
        .saturating_add(SECTION_WINDOW_CAP as usize)
        .min(bytes.len());
    (head, bytes[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ewf::{
        parse_segment, EwfFormat, EWF1_FILE_HEADER_SIZE, EWF2_FILE_HEADER_SIZE, HEADER_HEX_CAP,
        SECTION_DESCRIPTOR_SIZE,
    };

    #[test]
    fn ewf1_minimal_sample_parses_into_expected_fields() {
        let spec = SampleSpec::default();
        let bytes = build(&spec);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);

        assert!(record.signature_ok);
        assert_eq!(record.signature_len, Some(8));
        assert_eq!(record.format, Some(EwfFormat::Ewf1));
        assert_eq!(record.format_kind, Some("encase-ewf1"));
        assert_eq!(record.format_id, Some(0x01));
        assert_eq!(record.fields_start, Some(0x01));
        assert_eq!(record.fields_end, Some([0x01, 0x00]));
        assert_eq!(record.segment_number, Some(1));
        assert_eq!(record.extension_number, Some(1));
        assert_eq!(record.extension_number_match, Some(true));
        assert_eq!(record.header_offset, 0);
        assert_eq!(record.header_end, EWF1_FILE_HEADER_SIZE);
        assert_eq!(record.section_offset, Some(EWF1_FILE_HEADER_SIZE));
        assert_eq!(record.section_type.as_deref(), Some("header"));
        assert_eq!(
            record.header_length,
            Some(SECTION_DESCRIPTOR_SIZE + DEFAULT_HEADER_SECTION_LEN as u64)
        );
        assert_eq!(record.section_count, 4); // header, volume, table, done
        assert!(record.contains_table_section);
        assert!(record.done_section_present);
        assert!(!record.section_chain_limited);
        assert!(record.errors.is_empty(), "{:?}", record.errors);
        assert_eq!(record.volume.section_type.as_deref(), Some("volume"));
        assert_eq!(record.volume.number_of_chunks, Some(32));
        assert_eq!(record.volume.sectors_per_chunk, Some(64));
        assert_eq!(record.volume.sector_size, Some(512));
        assert_eq!(record.volume.sector_count, Some(2048));
        assert_eq!(record.volume.media_flags, Some(0x01));
        assert_eq!(record.volume.compression_level, Some(0x01));
        assert_eq!(
            record.volume.compression.as_deref(),
            Some("fast/good (0x01)")
        );
        assert_eq!(record.volume.media_size_bytes, Some(2048 * 512));
        assert_eq!(record.volume.checksum_ok, Some(true));
        assert_eq!(record.segment_count_contiguous, None);
        assert!(record.header_hex.len() <= HEADER_HEX_CAP * 2);
    }

    #[test]
    fn ewf1_bare_file_header_without_sections_is_reported() {
        let spec = SampleSpec::default();
        let header = file_header(&spec);
        assert_eq!(header.len(), HEADER_LEN);
        let record = parse_segment(&spec.name, header.len() as u64, &header, &[]);

        assert!(record.signature_ok);
        assert_eq!(record.format, Some(EwfFormat::Ewf1));
        assert_eq!(record.segment_number, Some(1));
        assert_eq!(record.header_end, EWF1_FILE_HEADER_SIZE);
        assert_eq!(record.header_length, None);
        assert!(!record.section_fits);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("节段描述符")));
        assert!(record.header_sha256.is_some());
    }

    #[test]
    fn ewf1_header_sha256_matches_independent_digest() {
        use sha2::{Digest, Sha256};
        let bytes = build(&SampleSpec::default());
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment("sample.E01", bytes.len() as u64, &head, &sections);
        let expected: String = Sha256::digest(&bytes[..HEADER_LEN])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(record.header_sha256.as_deref(), Some(expected.as_str()));
        assert_eq!(record.header_hex.len(), HEADER_LEN * 2);
    }

    #[test]
    fn ewf2_and_ex01_headers_are_recognised_and_sections_are_left_null() {
        for (format, name, expected) in [
            ("EWF2", "disk.E01", EwfFormat::Ewf2),
            ("Ex01", "disk.Ex01", EwfFormat::Ex01),
        ] {
            let spec = SampleSpec {
                name: name.to_string(),
                format,
                ..SampleSpec::default()
            };
            let bytes = build(&spec);
            let (head, sections) = split_for_parser(&bytes);
            let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);

            assert_eq!(record.format, Some(expected));
            assert_eq!(record.header_end, EWF2_FILE_HEADER_SIZE);
            assert_eq!(record.major_version, Some(0x02));
            assert_eq!(record.minor_version, Some(0x01));
            assert_eq!(record.compression_method, Some(1));
            assert_eq!(
                record.set_identifier.as_deref().map(str::len),
                Some(32),
                "16 字节集合标识应转为 32 个 hex 字符"
            );
            assert_eq!(record.section_type, None);
            assert_eq!(record.header_length, None);
            assert_eq!(record.volume.sectors_per_chunk, None);
            assert_eq!(record.volume.sector_size, None);
            assert_eq!(record.volume.sector_count, None);
            assert!(record
                .limitations
                .iter()
                .any(|note| note.contains("v2 布局") && note.contains(expected.as_str())));
            assert!(record.errors.is_empty(), "{:?}", record.errors);
        }
    }

    #[test]
    fn wrong_signature_is_reported_as_not_ewf() {
        let spec = SampleSpec::default();
        let mut bytes = build(&spec);
        bytes[0] = b'X';
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert!(!record.signature_ok);
        assert_eq!(record.format, None);
        assert_eq!(record.header_length, None);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("未找到 EVF 签名")));
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("扩展名像 EWF 段文件")));
    }

    #[test]
    fn incomplete_signature_is_reported_not_silently_zeroed() {
        let full = build(&SampleSpec::default());
        let partial = &full[..7]; // EVF + 09 0d 0a ff，缺最后一个 0x00
        let record = parse_segment("broken.E01", partial.len() as u64, partial, &[]);
        assert!(!record.signature_ok);
        assert_eq!(record.format, None);
        assert_eq!(record.header_length, None);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("签名不完整")));
        assert!(record
            .limitations
            .iter()
            .any(|note| note.contains("部分签名")));
        assert_eq!(record.header_sha256, None);
    }

    #[test]
    fn truncated_file_header_is_reported() {
        let full = build(&SampleSpec::default());
        let truncated = &full[..10];
        let record = parse_segment("sample.E01", truncated.len() as u64, truncated, &[]);
        assert!(record.signature_ok);
        assert_eq!(record.header_end, 10);
        assert!(record.header_truncated);
        assert_eq!(record.segment_number, None);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("文件头被截断")));
        assert_eq!(record.header_sha256, None, "截断文件头不应输出完整摘要");
    }

    #[test]
    fn segment_number_mismatch_with_extension_is_an_error() {
        let spec = SampleSpec {
            name: "disk.E01".to_string(),
            segment_number: 2,
            ..SampleSpec::default()
        };
        let bytes = build(&spec);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert_eq!(record.segment_number, Some(2));
        assert_eq!(record.extension_number, Some(1));
        assert_eq!(record.extension_number_match, Some(false));
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("段号不一致")));

        let spec = SampleSpec {
            name: "disk.E02".to_string(),
            segment_number: 2,
            ..SampleSpec::default()
        };
        let bytes = build(&spec);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert_eq!(record.extension_number_match, Some(true));
    }

    #[test]
    fn ex01_extension_with_ewf1_header_is_flagged() {
        let spec = SampleSpec {
            name: "disk.Ex01".to_string(),
            format: "EWF1",
            segment_number: 1,
            ..SampleSpec::default()
        };
        let bytes = build(&spec);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert_eq!(record.format, Some(EwfFormat::Ewf1));
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("扩展名为 Ex01")));
    }

    #[test]
    fn section_length_beyond_file_is_an_error() {
        let spec = SampleSpec::default();
        let mut bytes = build(&spec);
        let huge = bytes.len() as u64 * 8;
        bytes[HEADER_LEN + 24..HEADER_LEN + 32].copy_from_slice(&huge.to_le_bytes());
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert_eq!(record.header_length, Some(huge));
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("越界") || error.contains("超过文件长度")));
    }

    #[test]
    fn truncated_section_descriptor_is_reported() {
        let full = build(&SampleSpec::default());
        let cut = &full[..HEADER_LEN + 40];
        let (head, sections) = split_for_parser(cut);
        let record = parse_segment("sample.E01", cut.len() as u64, &head, &sections);
        assert!(record.signature_ok);
        assert_eq!(record.header_length, None);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("没有完整的节段描述符")));
    }

    #[test]
    fn zero_and_short_section_lengths_are_errors() {
        let spec = SampleSpec::default();

        let mut zero = build(&spec);
        zero[HEADER_LEN + 24..HEADER_LEN + 32].copy_from_slice(&0u64.to_le_bytes());
        let (head, sections) = split_for_parser(&zero);
        let record = parse_segment(&spec.name, zero.len() as u64, &head, &sections);
        assert_eq!(record.header_length, Some(0));
        assert!(record.errors.iter().any(|error| error.contains("长度为 0")));

        let mut short = build(&spec);
        short[HEADER_LEN + 24..HEADER_LEN + 32].copy_from_slice(&40u64.to_le_bytes());
        let (head, sections) = split_for_parser(&short);
        let record = parse_segment(&spec.name, short.len() as u64, &head, &sections);
        assert_eq!(record.header_length, Some(40));
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("小于描述符长度")));
        assert_eq!(record.volume.sectors_per_chunk, None);
    }

    #[test]
    fn head_section_next_offset_inside_the_body_is_an_error() {
        let spec = SampleSpec::default();
        let mut bytes = build(&spec);
        let body_start = HEADER_LEN + SECTION_DESCRIPTOR_SIZE as usize;
        bytes[HEADER_LEN + 16..HEADER_LEN + 24].copy_from_slice(&(body_start as u64).to_le_bytes());
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("落在本节段内容内")));
        assert_eq!(record.volume.sectors_per_chunk, None);
    }

    #[test]
    fn truncated_ewf2_file_header_is_reported() {
        let bytes = build(&SampleSpec {
            name: "disk.Ex01".to_string(),
            format: "Ex01",
            ..SampleSpec::default()
        });
        let truncated = &bytes[..20];
        let (head, sections) = split_for_parser(truncated);
        let record = parse_segment("disk.Ex01", truncated.len() as u64, &head, &sections);
        assert!(record.signature_ok);
        assert_eq!(record.format, Some(EwfFormat::Ex01));
        assert_eq!(record.header_end, 20);
        assert!(record.header_truncated);
        assert!(record
            .errors
            .iter()
            .any(|error| error.contains("文件头被截断")));
        assert_eq!(record.header_sha256, None);
        assert_eq!(record.set_identifier, None);
    }

    #[test]
    fn volume_candidates_use_the_public_ewf1_offsets() {
        let spec = SampleSpec {
            volume: Some(VolumeSpec {
                media_type: 0x01,
                number_of_chunks: 7,
                sectors_per_chunk: 128,
                sector_size: 4096,
                sector_count: 9999,
                media_flags: 0x03,
                compression_level: 0x02,
            }),
            ..SampleSpec::default()
        };
        let bytes = build(&spec);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);

        let header_section_len = SECTION_DESCRIPTOR_SIZE + DEFAULT_HEADER_SECTION_LEN as u64;
        assert_eq!(
            record.volume.section_offset,
            Some(EWF1_FILE_HEADER_SIZE + header_section_len)
        );
        assert_eq!(record.volume.section_type.as_deref(), Some("volume"));
        assert_eq!(record.volume.media_type, Some(0x01));
        assert_eq!(record.volume.number_of_chunks, Some(7));
        assert_eq!(record.volume.sectors_per_chunk, Some(128));
        assert_eq!(record.volume.sector_size, Some(4096));
        assert_eq!(record.volume.sector_count, Some(9999));
        assert_eq!(record.volume.media_size_bytes, Some(9999 * 4096));
        assert_eq!(record.volume.media_flags, Some(0x03));
        assert_eq!(record.volume.compression_level, Some(0x02));
        assert_eq!(record.volume.compression.as_deref(), Some("best (0x02)"));
        assert_eq!(record.volume.checksum_ok, Some(true));
    }

    #[test]
    fn disk_section_is_not_parsed_as_volume() {
        let spec = SampleSpec {
            volume: None,
            header_section: false,
            table_section: false,
            ..SampleSpec::default()
        };
        let disk_body = volume_body(&VolumeSpec::default());
        let empty: &[u8] = &[];
        let bytes = build_with_sections(&spec, &[("disk", disk_body.as_slice()), ("done", empty)]);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);

        assert_eq!(record.section_type.as_deref(), Some("disk"));
        assert_eq!(record.volume.section_type.as_deref(), Some("disk"));
        assert_eq!(record.volume.sectors_per_chunk, None);
        assert_eq!(record.volume.sector_size, None);
        assert_eq!(record.volume.sector_count, None);
        assert!(record.volume.notes.iter().any(|note| note.contains("disk")));
    }

    #[test]
    fn missing_volume_section_leaves_candidates_null() {
        let spec = SampleSpec {
            volume: None,
            ..SampleSpec::default()
        };
        let bytes = build(&spec);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert_eq!(record.volume.sectors_per_chunk, None);
        assert_eq!(record.volume.sector_size, None);
        assert_eq!(record.volume.sector_count, None);
        assert_eq!(record.volume.media_size_bytes, None);
        assert!(record
            .volume
            .notes
            .iter()
            .any(|note| note.contains("没有找到")));
        assert!(record
            .limitations
            .iter()
            .any(|note| note.contains("未找到 EWF1 volume")));
        assert!(record.contains_table_section);
        assert!(record.done_section_present);
    }

    #[test]
    fn descriptor_checksum_mismatch_is_a_warning_not_a_hard_failure() {
        let spec = SampleSpec::default();
        let mut bytes = build(&spec);
        bytes[HEADER_LEN + 72] ^= 0xff;
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert!(record
            .warnings
            .iter()
            .any(|warning| warning.contains("adler32 不一致")));
        assert_eq!(record.section_type.as_deref(), Some("header"));
        assert_eq!(record.volume.sectors_per_chunk, Some(64));
    }

    #[test]
    fn non_advancing_next_offset_stops_the_chain_with_an_error() {
        let spec = SampleSpec::default();
        let mut bytes = build(&spec);
        bytes[HEADER_LEN + 16..HEADER_LEN + 24].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert!(record.errors.iter().any(|error| error.contains("未前进")));
        assert_eq!(record.section_count, 1);
        assert_eq!(record.volume.sectors_per_chunk, None);
    }

    #[test]
    fn section_chain_beyond_the_read_window_is_limited() {
        let spec = SampleSpec {
            volume: None,
            table_section: false,
            ..SampleSpec::default()
        };
        let big = vec![0u8; SECTION_WINDOW_CAP as usize];
        let empty: &[u8] = &[];
        let bytes = build_with_sections(&spec, &[("header", big.as_slice()), ("done", empty)]);
        let (head, sections) = split_for_parser(&bytes);
        let record = parse_segment(&spec.name, bytes.len() as u64, &head, &sections);
        assert!(record.section_chain_limited);
        assert!(record
            .warnings
            .iter()
            .any(|warning| warning.contains("有界读取窗口")));
        assert_eq!(record.volume.sectors_per_chunk, None);
    }
}
