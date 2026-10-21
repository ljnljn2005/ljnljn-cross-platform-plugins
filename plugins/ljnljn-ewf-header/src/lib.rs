//! EWF/E01 segment header metadata (LPP v2).
//!
//! This is the LPP v2 port of the v1 `ljnljn.ewf-header` file analyzer. The
//! EVF signature check, EWF1 file-header and section-descriptor parser,
//! bounded section-chain walk and EWF1 volume candidates are carried over
//! unchanged (`ewf`); only the result mapping is new:
//!
//! * `ewf.segment` — one record per selected segment file with the format,
//!   segment number, extension match, section-chain flags and EWF1 volume
//!   candidates;
//! * `ewf.header` — the 13-byte EWF1 or 32-byte EWF2/Ex01 file header with
//!   its exact offset/size, signature state and SHA-256;
//! * `ewf.section` — every section descriptor found inside the bounded
//!   window, with descriptor/body sizes and the next-section offset.
//!
//! Ported limitations: header and section metadata only. EWF2/Ex01 only
//! contribute their 32-byte file header (the v2 section/volume layout is
//! not parsed); no chunk-table walk, no decompression, no stream hash and no
//! multi-segment contiguity decision. `segment_count_contiguous` is therefore
//! not claimed, and structural problems are reported as typed errors plus a
//! per-file warning rather than an empty success.

#[allow(dead_code)]
mod ewf;

#[allow(dead_code)]
#[cfg(test)]
mod synth;
#[cfg(test)]
mod tests;

use lovelycarve_plugin::{
    export_plugin, FileRef, Json, Plugin, Record, Result, Run, Severity, SourceRef, Timestamp,
    Value,
};

use crate::ewf::{
    parse_segment, scan_sections, EwfFormat, SegmentRecord, FIRST_SECTION_OFFSET,
    SECTION_WINDOW_CAP,
};

/// Analyzer id; matches the manifest.
pub const ANALYZER: &str = "ewf_header";
/// Plugin id; matches the manifest.
pub const PLUGIN_ID: &str = "org.ljnljn.ewf-header";

/// Bytes read for the file header (covers EWF1 13 B and EWF2/Ex01 32 B).
const HEAD_CAP: u64 = 512;
/// Bounded section window, starting at the first section descriptor.
const BODY_CAP: u64 = SECTION_WINDOW_CAP;

/// One segment file: header outcome, section chain and volume candidates.
#[derive(Record)]
#[record(id = "ewf.segment", label = "EWF 段文件", title = "{file}")]
struct EwfSegment {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "文件大小", kind = "size")]
    file_size: u64,
    #[field(
        label = "格式",
        kind = "enum",
        choices = "ewf1=EWF1,ewf2=EWF2,ex01=Ex01"
    )]
    format: Option<String>,
    #[field(label = "格式类别")]
    format_kind: Option<String>,
    #[field(label = "段号")]
    segment_number: Option<i64>,
    #[field(label = "扩展名序号")]
    extension_number: Option<i64>,
    #[field(label = "扩展名一致")]
    extension_match: Option<bool>,
    #[field(label = "文件头偏移", kind = "size")]
    header_offset: u64,
    #[field(label = "文件头结束", kind = "size")]
    header_end: u64,
    #[field(label = "首枚节段类型")]
    first_section_type: Option<String>,
    #[field(label = "首枚节段长度", kind = "size")]
    first_section_length: Option<u64>,
    #[field(label = "节段数")]
    section_count: i64,
    #[field(label = "节段链受限")]
    chain_limited: bool,
    #[field(label = "含 table 节段")]
    has_table: bool,
    #[field(label = "含 done 节段")]
    has_done: bool,
    #[field(label = "volume 节段偏移", kind = "size")]
    volume_section_offset: Option<u64>,
    #[field(label = "volume：chunk 数")]
    number_of_chunks: Option<u64>,
    #[field(label = "volume：每 chunk 扇区")]
    sectors_per_chunk: Option<u64>,
    #[field(label = "volume：扇区大小", kind = "size")]
    sector_size: Option<u64>,
    #[field(label = "volume：扇区总数")]
    sector_count: Option<u64>,
    #[field(label = "volume：媒体大小", kind = "size")]
    media_size_bytes: Option<u64>,
    #[field(label = "volume：压缩")]
    compression: Option<String>,
    #[field(label = "volume 校验")]
    volume_checksum_ok: Option<bool>,
    #[field(label = "错误数")]
    error_count: i64,
    #[field(label = "告警数")]
    warning_count: i64,
    #[field(label = "错误", kind = "json")]
    errors: Json,
    #[field(label = "告警", kind = "json")]
    warnings: Json,
    #[field(label = "volume 说明", kind = "json")]
    volume_notes: Json,
    #[field(label = "文件修改时间", timeline = "modified")]
    modified: Option<Timestamp>,
}

/// One file header (EWF1 13-byte or EWF2/Ex01 32-byte layout).
#[derive(Record)]
#[record(id = "ewf.header", label = "EWF 文件头", title = "{file} 文件头")]
struct EwfHeader {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "文件头偏移", kind = "size")]
    offset: u64,
    #[field(label = "文件头大小", kind = "size")]
    size: u64,
    #[field(label = "签名有效")]
    signature_ok: bool,
    #[field(label = "签名长度", kind = "size")]
    signature_length: Option<u64>,
    #[field(
        label = "格式",
        kind = "enum",
        choices = "ewf1=EWF1,ewf2=EWF2,ex01=Ex01"
    )]
    format: Option<String>,
    #[field(label = "格式字节 8")]
    format_id: Option<u64>,
    #[field(label = "fields_start")]
    fields_start: Option<u64>,
    #[field(label = "fields_end（hex）")]
    fields_end: Option<String>,
    #[field(label = "主版本")]
    major_version: Option<u64>,
    #[field(label = "次版本")]
    minor_version: Option<u64>,
    #[field(label = "压缩方法")]
    compression_method: Option<u64>,
    #[field(label = "集合标识")]
    set_identifier: Option<String>,
    #[field(label = "段号")]
    segment_number: Option<i64>,
    #[field(label = "文件头 SHA-256", kind = "hash")]
    sha256: Option<String>,
    #[field(label = "文件头被截断")]
    truncated: bool,
    #[field(label = "文件头十六进制")]
    hex: String,
}

/// One EWF1 section descriptor and its body range.
#[derive(Record)]
#[record(
    id = "ewf.section",
    label = "EWF 节段",
    title = "{section_type} @ {offset}"
)]
struct EwfSection {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "节段类型", key)]
    section_type: String,
    #[field(label = "节段偏移", kind = "size", key)]
    offset: u64,
    #[field(label = "节段长度", kind = "size")]
    length: u64,
    #[field(label = "内容偏移", kind = "size")]
    body_offset: u64,
    #[field(label = "内容长度", kind = "size")]
    body_length: u64,
    #[field(label = "下一节段偏移", kind = "size")]
    next_offset: u64,
    #[field(label = "adler32 自检")]
    checksum_ok: Option<bool>,
}

fn ewf_header(run: &Run) -> Result<()> {
    if run.inputs().is_empty() {
        run.warn("INPUT_NOT_FOUND", "未收到待分析的 EWF 段文件")?;
        run.set_summary("未收到 EWF 段文件");
        return Ok(());
    }
    let total = run.inputs().len() as u64;
    let mut segments = 0usize;
    let mut sections = 0usize;
    let mut failures = 0usize;
    for (index, file) in run.inputs().iter().enumerate() {
        run.check_cancelled()?;
        run.progress(index as u64, Some(total), Some(file.name()))?;
        let head = match file.read_at(0, HEAD_CAP as usize) {
            Ok(bytes) => bytes,
            Err(error) => {
                if run.is_cancelled() {
                    return Err(error);
                }
                run.warn_file(file, &error.code.to_ascii_uppercase(), error.message)?;
                failures += 1;
                continue;
            }
        };
        let window = match file.read_at(FIRST_SECTION_OFFSET, BODY_CAP as usize) {
            Ok(bytes) => bytes,
            Err(error) => {
                if run.is_cancelled() {
                    return Err(error);
                }
                run.warn_file(file, &error.code.to_ascii_uppercase(), error.message)?;
                failures += 1;
                continue;
            }
        };
        let record = parse_segment(file.name(), file.size(), &head, &window);
        emit_segment(run, file, &record)?;
        emit_header(run, file, &record, &head)?;
        if record.format == Some(EwfFormat::Ewf1) {
            let scan = scan_sections(&window, file.size());
            for section in &scan.sections {
                run.check_cancelled()?;
                emit_section(run, file, section)?;
                sections += 1;
            }
        }
        if !record.errors.is_empty() {
            let first = record.errors.first().map(String::as_str).unwrap_or("");
            run.warn_file(
                file,
                "EWF_STRUCTURE_ERRORS",
                format!(
                    "{}：{} 处结构异常，首条：{}",
                    file.name(),
                    record.errors.len(),
                    first
                ),
            )?;
            failures += 1;
        }
        segments += 1;
    }
    let mut summary = format!("分析 {segments}/{total} 个 EWF 段文件，{sections} 个节段描述符");
    if failures > 0 {
        summary.push_str("，存在结构异常或读取失败（见告警）");
    }
    run.set_summary(summary);
    Ok(())
}

fn emit_segment(run: &Run, file: &FileRef, record: &SegmentRecord) -> Result<()> {
    let segment = EwfSegment {
        file: record.path.clone(),
        file_size: record.file_size,
        format: record
            .format
            .map(|format| format.as_str().to_ascii_lowercase()),
        format_kind: record.format_kind.map(str::to_owned),
        segment_number: record.segment_number.map(|number| number as i64),
        extension_number: record.extension_number.map(|number| number as i64),
        extension_match: record.extension_number_match,
        header_offset: record.header_offset,
        header_end: record.header_end,
        first_section_type: record.section_type.clone(),
        first_section_length: record.header_length,
        section_count: record.section_count as i64,
        chain_limited: record.section_chain_limited,
        has_table: record.contains_table_section,
        has_done: record.done_section_present,
        volume_section_offset: record.volume.section_offset,
        number_of_chunks: record.volume.number_of_chunks,
        sectors_per_chunk: record.volume.sectors_per_chunk,
        sector_size: record.volume.sector_size,
        sector_count: record.volume.sector_count,
        media_size_bytes: record.volume.media_size_bytes,
        compression: record.volume.compression.clone(),
        volume_checksum_ok: record.volume.checksum_ok,
        error_count: record.errors.len() as i64,
        warning_count: record.warnings.len() as i64,
        errors: Json(string_array(&record.errors)),
        warnings: Json(string_array(&record.warnings)),
        volume_notes: Json(string_array(&record.volume.notes)),
        modified: file
            .info()
            .timestamps
            .modified
            .as_deref()
            .and_then(Timestamp::parse),
    };
    let mut emit = run
        .record(&segment)
        .source(source_of(file, 0, record.file_size, "EWF 段文件"));
    if !record.errors.is_empty() {
        emit = emit.severity(Severity::Medium);
    }
    emit.emit()
}

fn emit_header(run: &Run, file: &FileRef, record: &SegmentRecord, head: &[u8]) -> Result<()> {
    let size = record.header_end.min(head.len() as u64);
    let header = EwfHeader {
        file: record.path.clone(),
        offset: record.header_offset,
        size,
        signature_ok: record.signature_ok,
        signature_length: record.signature_len.map(|length| length as u64),
        format: record
            .format
            .map(|format| format.as_str().to_ascii_lowercase()),
        format_id: record.format_id.map(u64::from),
        fields_start: record.fields_start.map(u64::from),
        fields_end: record.fields_end.map(|bytes| ewf::hex_lower(&bytes)),
        major_version: record.major_version.map(u64::from),
        minor_version: record.minor_version.map(u64::from),
        compression_method: record.compression_method.map(u64::from),
        set_identifier: record.set_identifier.clone(),
        segment_number: record.segment_number.map(|number| number as i64),
        sha256: record.header_sha256.clone(),
        truncated: record.header_truncated,
        hex: record.header_hex.clone(),
    };
    run.record(&header)
        .source(source_of(file, record.header_offset, size, "EVF 文件头"))
        .emit()
}

fn emit_section(run: &Run, file: &FileRef, section: &ewf::SectionDescriptor) -> Result<()> {
    let record = EwfSection {
        file: file.name().to_owned(),
        section_type: section.section_type.clone(),
        offset: section.offset,
        length: section.length,
        body_offset: section.body_offset,
        body_length: section.body_length,
        next_offset: section.next_offset,
        checksum_ok: section.checksum_ok,
    };
    let mut emit = run.record(&record).source(source_of(
        file,
        section.offset,
        section.length,
        "节段描述符与内容",
    ));
    if section.checksum_ok == Some(false) {
        emit = emit.severity(Severity::Low);
    }
    emit.emit()
}

fn string_array(items: &[String]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| Value::from(item.as_str()))
            .collect(),
    )
}

/// Provenance of one byte range. File-scope runs fall back to the host
/// display name when no view path is supplied.
fn source_of(file: &FileRef, offset: u64, length: u64, note: &str) -> SourceRef {
    let mut source = file.source_at(offset, length);
    if source.path.is_none() {
        source.path = Some(file.name().to_owned());
    }
    source.note = Some(note.to_owned());
    source
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID)
        .record::<EwfSegment>()
        .record::<EwfHeader>()
        .record::<EwfSection>()
        .analyzer(ANALYZER, ewf_header)
}

export_plugin!(plugin);
