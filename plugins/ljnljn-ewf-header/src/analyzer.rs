//! `FileAnalyzer` 实现：经 SDK 只读文件句柄读取段文件头与有界节段窗口，
//! 交给 [`crate::ewf::parse_segment`]。
//!
//! 只做两次有界读取（文件头 + 节段窗口），不物化文件、不遍历 chunk 表、不解压数据。

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, File, FileAnalyzer, Finding, Result, ResultColumn,
    ResultNode, Severity, Value,
};

use crate::ewf::{self, EwfFormat, SegmentRecord, FIRST_SECTION_OFFSET, SECTION_WINDOW_CAP};

/// analyzer 名，必须与 plugin.toml 的 `analyzer` 完全一致。
pub const ANALYZER_NAME: &str = "ljnljn.ewf-header";
/// 结果与属性的命名空间。
pub const NS: &str = "ewfhead";
/// 文件头读取上限：足够覆盖 EWF1 的 13 字节与 EWF2/Ex01 的 32 字节文件头。
pub const HEAD_CAP: u64 = 512;
/// 节段窗口读取上限（从偏移 13 开始，覆盖 header/volume 等常见节段）。
pub const BODY_CAP: u64 = SECTION_WINDOW_CAP;

/// EWF/E01 段文件头部元数据分析器。
#[derive(Default)]
pub struct EwfHeaderMetadata;

impl EwfHeaderMetadata {
    pub fn new() -> Self {
        Self
    }
}

impl FileAnalyzer for EwfHeaderMetadata {
    fn analyzer(&self) -> &str {
        ANALYZER_NAME
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let size = file.size();
        let head = file.read(0, HEAD_CAP as usize)?;
        let sections = file.read(FIRST_SECTION_OFFSET, BODY_CAP as usize)?;
        let record = ewf::parse_segment(file.name(), size, &head, &sections);
        Ok(record_to_result(&record, file.name()))
    }
}

/// 把纯解析结果转换为宿主结果：段摘要 artifact、首枚节段 artifact、
/// errors/limitations/warnings/value 文本 artifact，以及字段名 findings。
pub fn record_to_result(record: &SegmentRecord, source_name: &str) -> AnalysisResult {
    let json = serde_json::to_string_pretty(&record_to_json(record, source_name))
        .unwrap_or_else(|error| format!("{{\"serializationError\":\"{error}\"}}"));

    let mut summary = String::new();
    summary.push_str(&format!("段文件 {}", record.path));
    if record.signature_ok {
        summary.push_str(&format!(
            "：EVF 签名通过（{}），格式 {}，段号 {}",
            record
                .signature_len
                .map(|len| format!("{len} 字节签名"))
                .unwrap_or_else(|| "未知长度签名".to_string()),
            record.format.map(EwfFormat::as_str).unwrap_or("未识别"),
            record
                .segment_number
                .map(|number| number.to_string())
                .unwrap_or_else(|| "缺失".to_string())
        ));
    } else {
        summary.push_str("：EVF 签名无效或缺失");
    }
    if record.header_end > 0 {
        summary.push_str(&format!(
            "，文件头[{}, {})",
            record.header_offset, record.header_end
        ));
    }
    if let Some(header_length) = record.header_length {
        summary.push_str(&format!(
            "，首枚节段 {}（偏移 {}）长度 {header_length}",
            record.section_type.as_deref().unwrap_or("?"),
            record.section_offset.unwrap_or(record.header_end)
        ));
    }
    summary.push_str(&format!(
        "；errors {} 条，limitations {} 条、warnings {} 条",
        record.errors.len(),
        record.limitations.len(),
        record.warnings.len()
    ));

    let mut artifacts = Vec::new();
    artifacts.push(record_artifact(record));

    if let (Some(section_type), Some(header_length)) =
        (record.section_type.as_deref(), record.header_length)
    {
        artifacts.push(Artifact {
            artifact_type: format!("{NS}.section"),
            title: format!("首枚节段 {section_type}"),
            value: Some(Value::from(section_type.to_string())),
            attributes: section_attributes(record, source_name, section_type, header_length),
        });
    }

    if !record.errors.is_empty() {
        artifacts.push(text_artifact(
            format!("{NS}.error"),
            "errors",
            record.errors.join("\n"),
            source_name,
        ));
    }
    if !record.limitations.is_empty() {
        artifacts.push(text_artifact(
            format!("{NS}.limitation"),
            "limitations",
            record.limitations.join("\n"),
            source_name,
        ));
    }
    if !record.warnings.is_empty() {
        artifacts.push(text_artifact(
            format!("{NS}.warning"),
            "warnings",
            record.warnings.join("\n"),
            source_name,
        ));
    }
    artifacts.push(text_artifact(
        format!("{NS}.value"),
        "value",
        json,
        source_name,
    ));

    let findings = record
        .errors
        .iter()
        .map(|error| Finding {
            severity: Severity::Medium,
            title: "EWF 段文件结构异常".to_string(),
            description: error.clone(),
            attributes: [("source.path", Value::from(source_name))]
                .into_iter()
                .collect::<Attributes>(),
        })
        .collect();

    AnalysisResult {
        summary: Some(summary),
        nodes: result_nodes(),
        artifacts,
        timeline: Vec::new(),
        findings,
    }
}

/// 结果树：段摘要（每段一行）。
fn result_nodes() -> Vec<ResultNode> {
    let column = |key: &str, label: &str| ResultColumn {
        key: format!("{NS}.{key}"),
        label: label.to_string(),
    };
    vec![
        ResultNode {
            node_type: format!("{NS}.segment"),
            name: "EWF 段文件头部".to_string(),
            columns: vec![
                column("path", "文件"),
                column("file_size", "文件长度"),
                column("signature_ok", "签名"),
                column("format", "格式"),
                column("segment_number", "段号"),
                column("extension_number", "扩展名序号"),
                column("extension_number_match", "段号一致"),
                column("header_length", "首枚节段长度"),
                column("header_offset", "文件头偏移"),
                column("header_end", "文件头结束"),
                column("section_type", "首枚节段"),
                column("sectors_per_chunk", "每 chunk 扇区"),
                column("sector_size", "扇区大小"),
                column("sector_count", "扇区总数"),
                column("compression", "压缩方法"),
            ],
        },
        ResultNode {
            node_type: format!("{NS}.section"),
            name: "EWF 首枚节段".to_string(),
            columns: vec![
                column("section_type", "节段类型"),
                column("header_length", "节段长度"),
                column("section_offset", "节段偏移"),
                column("section_next_offset", "下一节段"),
                column("offset_basis", "偏移依据"),
            ],
        },
        ResultNode {
            node_type: format!("{NS}.error"),
            name: "errors".to_string(),
            columns: vec![column("error_text", "错误")],
        },
        ResultNode {
            node_type: format!("{NS}.limitation"),
            name: "limitations".to_string(),
            columns: vec![column("limitation_text", "限制说明")],
        },
        ResultNode {
            node_type: format!("{NS}.warning"),
            name: "warnings".to_string(),
            columns: vec![column("warning_text", "告警")],
        },
        ResultNode {
            node_type: format!("{NS}.value"),
            name: "value".to_string(),
            columns: vec![column("value_text", "完整 JSON")],
        },
    ]
}

fn record_artifact(record: &SegmentRecord) -> Artifact {
    let mut attributes = Attributes::new();
    let value_key = format!("{NS}.value");
    attributes.insert("source.path", record.path.clone());
    attributes.insert(format!("{NS}.source"), source_key(record));
    attributes.insert(format!("{NS}.path"), record.path.clone());
    attributes.insert(format!("{NS}.file_size"), record.file_size);
    attributes.insert(format!("{NS}.signature_ok"), record.signature_ok);
    attributes.insert_optional(
        format!("{NS}.signature_len"),
        record.signature_len.map(|len| len as u64),
    );
    attributes.insert_optional(format!("{NS}.format"), record.format.map(EwfFormat::as_str));
    attributes.insert_optional(format!("{NS}.format_kind"), record.format_kind);
    attributes.insert_optional(format!("{NS}.format_id"), record.format_id.map(u64::from));
    attributes.insert_optional(
        format!("{NS}.fields_start"),
        record.fields_start.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.fields_end_hex"),
        record.fields_end.map(|bytes| ewf::hex_lower(&bytes)),
    );
    attributes.insert_optional(
        format!("{NS}.major_version"),
        record.major_version.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.minor_version"),
        record.minor_version.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.compression_method"),
        record.compression_method.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.set_identifier"),
        record.set_identifier.clone(),
    );
    attributes.insert_optional(format!("{NS}.segment_number"), record.segment_number);
    attributes.insert_optional(format!("{NS}.extension_number"), record.extension_number);
    attributes.insert_optional(
        format!("{NS}.extension_number_match"),
        record.extension_number_match,
    );
    attributes.insert_optional(format!("{NS}.header_length"), record.header_length);
    attributes.insert(format!("{NS}.header_offset"), record.header_offset);
    attributes.insert(format!("{NS}.header_end"), record.header_end);
    attributes.insert_optional(format!("{NS}.header_sha256"), record.header_sha256.clone());
    attributes.insert(format!("{NS}.header_hex"), record.header_hex.clone());
    attributes.insert(format!("{NS}.header_truncated"), record.header_truncated);
    attributes.insert_optional(format!("{NS}.section_offset"), record.section_offset);
    attributes.insert_optional(format!("{NS}.section_type"), record.section_type.clone());
    attributes.insert_optional(
        format!("{NS}.section_next_offset"),
        record.section_next_offset,
    );
    attributes.insert(format!("{NS}.section_fits"), record.section_fits);
    attributes.insert(format!("{NS}.section_count"), record.section_count as u64);
    attributes.insert(
        format!("{NS}.section_chain_limited"),
        record.section_chain_limited,
    );
    attributes.insert(
        format!("{NS}.contains_table_section"),
        record.contains_table_section,
    );
    attributes.insert(
        format!("{NS}.done_section_present"),
        record.done_section_present,
    );
    attributes.insert_optional(
        format!("{NS}.volume_section_type"),
        record.volume.section_type.clone(),
    );
    attributes.insert_optional(
        format!("{NS}.volume_section_offset"),
        record.volume.section_offset,
    );
    attributes.insert_optional(
        format!("{NS}.media_type"),
        record.volume.media_type.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.number_of_chunks"),
        record.volume.number_of_chunks,
    );
    attributes.insert_optional(
        format!("{NS}.sectors_per_chunk"),
        record.volume.sectors_per_chunk,
    );
    attributes.insert_optional(format!("{NS}.sector_size"), record.volume.sector_size);
    attributes.insert_optional(format!("{NS}.sector_count"), record.volume.sector_count);
    attributes.insert_optional(
        format!("{NS}.media_flags"),
        record.volume.media_flags.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.compression_level"),
        record.volume.compression_level.map(u64::from),
    );
    attributes.insert_optional(
        format!("{NS}.media_size_bytes"),
        record.volume.media_size_bytes,
    );
    attributes.insert_optional(
        format!("{NS}.compression"),
        record.volume.compression.clone(),
    );
    attributes.insert_optional(
        format!("{NS}.volume_checksum_ok"),
        record.volume.checksum_ok,
    );
    attributes.insert(format!("{NS}.segment_count_contiguous"), Value::Nil);
    attributes.insert(format!("{NS}.error_count"), record.errors.len() as u64);
    attributes.insert(
        format!("{NS}.limitation_count"),
        record.limitations.len() as u64,
    );
    attributes.insert(format!("{NS}.warning_count"), record.warnings.len() as u64);

    // 结果表的数据列取属性值；完整 JSON 放在 value 里。
    attributes.insert(value_key.clone(), record.path.clone());
    Artifact {
        artifact_type: format!("{NS}.segment"),
        title: format!(
            "段 {}（{}）",
            record.path,
            record.format.map(EwfFormat::as_str).unwrap_or("未识别格式")
        ),
        value: Some(Value::from(value_key_value(record))),
        attributes,
    }
}

fn value_key_value(record: &SegmentRecord) -> String {
    let signature = if record.signature_ok {
        match record.signature_len {
            Some(len) => format!("签名OK/{len}B"),
            None => "签名OK".to_string(),
        }
    } else {
        "签名无效".to_string()
    };
    format!(
        "{signature} / {} / 段号 {} / 首枚节段长度 {}",
        record.format.map(EwfFormat::as_str).unwrap_or("未识别"),
        record
            .segment_number
            .map(|number| number.to_string())
            .unwrap_or_else(|| "-".to_string()),
        record
            .header_length
            .map(|length| length.to_string())
            .unwrap_or_else(|| "-".to_string())
    )
}

fn source_key(record: &SegmentRecord) -> String {
    format!(
        "{}|sig={}|fmt={}|seg={:?}",
        record.path,
        record.signature_ok,
        record.format.map(EwfFormat::as_str).unwrap_or("-"),
        record.segment_number
    )
}

fn section_attributes(
    record: &SegmentRecord,
    source_name: &str,
    section_type: &str,
    header_length: u64,
) -> Attributes {
    let mut attributes = Attributes::new();
    attributes.insert("source.path", source_name.to_string());
    attributes.insert(format!("{NS}.section_type"), section_type.to_string());
    attributes.insert(format!("{NS}.header_length"), header_length);
    attributes.insert(
        format!("{NS}.section_offset"),
        record.section_offset.unwrap_or(record.header_end),
    );
    attributes.insert(
        format!("{NS}.section_next_offset"),
        record.section_next_offset.unwrap_or(0),
    );
    attributes.insert(
        format!("{NS}.offset_basis"),
        "首枚节段描述符固定在 EWF1 文件头之后（绝对偏移 13）；section_length 取自描述符 \
24..32，next 偏移取自 16..24",
    );
    attributes
}

fn text_artifact(artifact_type: String, label: &str, text: String, source_name: &str) -> Artifact {
    let key = format!("{NS}.{}", text_key(label));
    let mut attributes = Attributes::new();
    attributes.insert("source.path", source_name.to_string());
    attributes.insert(key, text.clone());
    Artifact {
        artifact_type,
        title: label.to_string(),
        value: Some(Value::from(text)),
        attributes,
    }
}

fn text_key(label: &str) -> String {
    match label {
        "errors" => "error_text".to_string(),
        "limitations" => "limitation_text".to_string(),
        "warnings" => "warning_text".to_string(),
        _ => "value_text".to_string(),
    }
}

/// 需求规定的每段输出字段（全部给出，缺失为 null）。
pub fn record_to_json(record: &SegmentRecord, source_name: &str) -> serde_json::Value {
    serde_json::json!({
        "path": record.path,
        "sourceName": source_name,
        "fileSize": record.file_size,
        "signatureOk": record.signature_ok,
        "signatureLength": record.signature_len,
        "format": record.format.map(EwfFormat::as_str),
        "formatKind": record.format_kind,
        "formatId": record.format_id,
        "fieldsStart": record.fields_start,
        "fieldsEndHex": record.fields_end.map(|bytes| ewf::hex_lower(&bytes)),
        "majorVersion": record.major_version,
        "minorVersion": record.minor_version,
        "compressionMethod": record.compression_method,
        "setIdentifier": record.set_identifier,
        "segmentNumber": record.segment_number,
        "extensionNumber": record.extension_number,
        "extensionNumberMatch": record.extension_number_match,
        "headerLength": record.header_length,
        "headerOffset": record.header_offset,
        "headerEnd": record.header_end,
        "headerBytesHex": record.header_hex,
        "headerBytesHexTruncatedAt": ewf::HEADER_HEX_CAP,
        "headerSHA256": record.header_sha256,
        "headerTruncated": record.header_truncated,
        "sectionOffset": record.section_offset,
        "sectionType": record.section_type,
        "sectionNextOffset": record.section_next_offset,
        "sectionFits": record.section_fits,
        "sectionCount": record.section_count,
        "sectionChainLimited": record.section_chain_limited,
        "containsTableSection": record.contains_table_section,
        "doneSectionPresent": record.done_section_present,
        "volume": {
            "sectionType": record.volume.section_type,
            "sectionOffset": record.volume.section_offset,
            "mediaType": record.volume.media_type,
            "numberOfChunks": record.volume.number_of_chunks,
            "sectorsPerChunk": record.volume.sectors_per_chunk,
            "sectorSize": record.volume.sector_size,
            "sectorCount": record.volume.sector_count,
            "mediaFlags": record.volume.media_flags,
            "compressionLevel": record.volume.compression_level,
            "mediaSizeBytes": record.volume.media_size_bytes,
            "compression": record.volume.compression,
            "checksumOk": record.volume.checksum_ok,
            "notes": record.volume.notes,
        },
        "segmentCountContiguous": record.segment_count_contiguous,
        "isLastSegment": serde_json::Value::Null,
        "errors": record.errors,
        "limitations": record.limitations,
        "warnings": record.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ewf::parse_segment;
    use crate::synth::{build, split_for_parser, SampleSpec};

    fn analyze_bytes(name: &str, bytes: &[u8]) -> AnalysisResult {
        let (head, sections) = split_for_parser(bytes);
        let record = parse_segment(name, bytes.len() as u64, &head, &sections);
        record_to_result(&record, name)
    }

    fn attr<'a>(artifact: &'a Artifact, key: &str) -> Option<&'a Value> {
        artifact.attributes.get(key)
    }

    fn segment_artifact(result: &AnalysisResult) -> &Artifact {
        result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == format!("{NS}.segment"))
            .expect("segment artifact")
    }

    #[test]
    fn healthy_sample_produces_segment_artifact_with_source_provenance() {
        let bytes = build(&SampleSpec {
            name: "case.E01".to_string(),
            ..SampleSpec::default()
        });
        let result = analyze_bytes("case.E01", &bytes);
        let artifact = segment_artifact(&result);
        assert_eq!(
            attr(artifact, &format!("{NS}.format")),
            Some(&Value::from("EWF1"))
        );
        assert_eq!(
            attr(artifact, "source.path"),
            Some(&Value::from("case.E01"))
        );
        assert_eq!(
            attr(artifact, &format!("{NS}.segment_number")),
            Some(&Value::from(1u64))
        );
        assert_eq!(
            attr(artifact, &format!("{NS}.header_end")),
            Some(&Value::from(13u64))
        );
        assert_eq!(
            attr(artifact, &format!("{NS}.section_type")),
            Some(&Value::from("header"))
        );
        assert_eq!(
            attr(artifact, &format!("{NS}.sector_size")),
            Some(&Value::from(512u64))
        );
        assert_eq!(
            attr(artifact, &format!("{NS}.media_size_bytes")),
            Some(&Value::from(2048u64 * 512))
        );
        assert_eq!(
            attr(artifact, &format!("{NS}.segment_count_contiguous")),
            Some(&Value::Nil)
        );
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        let summary = result.summary.clone().unwrap_or_default();
        assert!(summary.contains("EWF1"), "{summary}");
        assert!(result
            .artifacts
            .iter()
            .any(|artifact| artifact.artifact_type == format!("{NS}.value")));
    }

    #[test]
    fn broken_sample_reports_errors_and_findings_instead_of_empty_success() {
        let bytes = b"EVF\x09\x0d\x0a\xff".to_vec();
        let result = analyze_bytes("half.E01", &bytes);
        assert!(!result.findings.is_empty(), "异常应进入 findings");
        assert_eq!(result.findings[0].severity, Severity::Medium);
        let error_artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == format!("{NS}.error"))
            .expect("error artifact");
        let text = match error_artifact.value.as_ref().and_then(Value::as_str) {
            Some(text) => text.to_string(),
            None => panic!("error artifact value"),
        };
        assert!(text.contains("签名不完整"), "{text}");
        assert_eq!(
            attr(error_artifact, "source.path"),
            Some(&Value::from("half.E01"))
        );
        let segment = segment_artifact(&result);
        assert_eq!(
            attr(segment, &format!("{NS}.signature_ok")),
            Some(&Value::from(false))
        );
        assert_eq!(attr(segment, &format!("{NS}.format")), Some(&Value::Nil));
    }

    #[test]
    fn ewf2_sample_reports_unsupported_layout_in_limitations() {
        let bytes = build(&SampleSpec {
            name: "disk.Ex01".to_string(),
            format: "Ex01",
            ..SampleSpec::default()
        });
        let result = analyze_bytes("disk.Ex01", &bytes);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        let segment = segment_artifact(&result);
        assert_eq!(
            attr(segment, &format!("{NS}.format")),
            Some(&Value::from("Ex01"))
        );
        assert_eq!(
            attr(segment, &format!("{NS}.sector_size")),
            Some(&Value::Nil)
        );
        let limitation = result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == format!("{NS}.limitation"))
            .expect("limitation artifact");
        let text = limitation
            .value
            .as_ref()
            .and_then(Value::as_str)
            .unwrap_or("");
        assert!(text.contains("v2 布局"), "{text}");
    }

    #[test]
    fn json_value_always_contains_every_required_field() {
        let bytes = b"\x00\x01\x02".to_vec();
        let result = analyze_bytes("odd.bin", &bytes);
        let value_artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == format!("{NS}.value"))
            .expect("value artifact");
        let json_text = value_artifact
            .value
            .as_ref()
            .and_then(Value::as_str)
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(json_text).expect("valid json");
        for key in [
            "path",
            "fileSize",
            "signatureOk",
            "format",
            "segmentNumber",
            "extensionNumberMatch",
            "headerLength",
            "headerOffset",
            "headerEnd",
            "headerBytesHex",
            "headerSHA256",
            "sectionOffset",
            "sectionType",
            "segmentCountContiguous",
            "errors",
            "limitations",
        ] {
            assert!(parsed.get(key).is_some(), "missing field {key}");
        }
        assert_eq!(parsed["volume"]["sectorsPerChunk"], serde_json::Value::Null);
    }

    #[test]
    fn result_nodes_declare_every_artifact_column() {
        let nodes = result_nodes();
        let keys: Vec<&str> = nodes
            .iter()
            .flat_map(|node| node.columns.iter().map(|column| column.key.as_str()))
            .collect();
        for key in [
            "ewfhead.path",
            "ewfhead.file_size",
            "ewfhead.signature_ok",
            "ewfhead.format",
            "ewfhead.segment_number",
            "ewfhead.extension_number_match",
            "ewfhead.header_length",
            "ewfhead.header_offset",
            "ewfhead.sectors_per_chunk",
            "ewfhead.sector_size",
        ] {
            assert!(keys.contains(&key), "missing column {key}");
        }
    }
}
