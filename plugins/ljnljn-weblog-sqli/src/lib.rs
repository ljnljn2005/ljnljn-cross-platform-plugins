//! Web access-log SQL-injection candidates (LPP v2).
//!
//! This is the LPP v2 port of the v1 `ljnljn.weblog-sqli` plugin. The
//! Apache/Nginx line parser, `%XX` decoder, feature families, windowed
//! suspicion rule and per-parameter aggregation are carried over unchanged
//! (`model`, `logline`, `detect`, `aggregate`); only the result mapping is
//! new:
//!
//! * `weblog.document` — one typed record per parsed log file (encoding,
//!   line counts, formats, first/last request time, unparsed reasons);
//! * `weblog.candidate` — one typed record per suspicious `(path, param)`
//!   with the methods seen, the hit feature families, the window statistics,
//!   the verdict, and the exact line/byte evidence range.
//!
//! Two analyzers share the pipeline: `weblog_files` analyzes the selected
//! log files, `weblog_evidence` walks the fixed Web-log roots of every
//! evidence volume (`var/log/nginx`, `var/log/apache2`, …).
//!
//! Ported limitations: pattern-based detection only (no SQL grammar or
//! execution), query parameters only (no POST body), raw log timestamps are
//! never year-completed or timezone-normalised, and no attempt is made to
//! decide whether an injection succeeded. Non-log content is skipped with a
//! warning instead of producing empty successes.

#[allow(dead_code)]
mod aggregate;
#[allow(dead_code)]
mod detect;
mod logline;
#[allow(dead_code)]
mod model;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use lovelycarve_plugin::{
    export_plugin, Error, FileRef, Json, LogLevel, Plugin, Record, Result, Run, Severity,
    SourceRef, Timestamp, Value, View,
};

use crate::aggregate::{decode_log, Finished, ParamAggregate};
use crate::detect::{family_summary, family_totals};
use crate::logline::{parse_timestamp, LineParser};
use crate::model::{Config, TimestampParts};

/// File-scope analyzer id; matches the manifest.
pub const ANALYZER_FILE: &str = "weblog_files";
/// Evidence-scope analyzer id; matches the manifest.
pub const ANALYZER_EVIDENCE: &str = "weblog_evidence";
/// Plugin id; matches the manifest.
pub const PLUGIN_ID: &str = "org.ljnljn.weblog-sqli";

/// Largest single log file read (the part beyond it is reported, not hidden).
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
/// Most log files analyzed per run.
const MAX_FILES: usize = 400;
/// Discovery depth below each fixed log root.
const SCAN_DEPTH: usize = 6;
/// Fixed Web-log roots searched in every evidence volume.
const LOG_ROOTS: &[&str] = &[
    "var/log/nginx",
    "var/log/httpd",
    "var/log/apache2",
    "var/www/logs",
    "var/www/log",
    "logs",
    "log",
];

/// One parsed access-log document.
#[derive(Record)]
#[record(id = "weblog.document", label = "Web 访问日志", title = "{file}")]
struct WebLogDocument {
    #[field(label = "文件", key)]
    file: String,
    #[field(
        label = "编码",
        kind = "enum",
        choices = "utf8=UTF-8,utf16le=UTF-16LE,utf16be=UTF-16BE,gb18030=GB18030"
    )]
    encoding: String,
    #[field(label = "文件大小", kind = "size")]
    file_size: u64,
    #[field(label = "总行数")]
    total_lines: i64,
    #[field(label = "已解析行")]
    parsed_lines: i64,
    #[field(label = "未解析行")]
    unparsed_lines: i64,
    #[field(label = "combined 行")]
    combined_lines: i64,
    #[field(label = "common 行")]
    common_lines: i64,
    #[field(label = "其它格式行")]
    other_lines: i64,
    #[field(label = "首次请求", timeline = "request")]
    first_seen: Option<Timestamp>,
    #[field(label = "末次请求", timeline = "request")]
    last_seen: Option<Timestamp>,
    #[field(label = "涉及年月", kind = "list")]
    year_months: Vec<String>,
    #[field(label = "ident/user", kind = "list")]
    users: Vec<String>,
    #[field(label = "解码替换字符数")]
    replacement_count: i64,
    #[field(label = "内容被截断")]
    truncated: bool,
    #[field(label = "说明")]
    notes: String,
    #[field(label = "未解析原因", kind = "json")]
    unparsed_reasons: Json,
    #[field(label = "可疑候选数")]
    candidate_count: i64,
}

/// One suspicious query parameter of one path.
#[derive(Record)]
#[record(
    id = "weblog.candidate",
    label = "可疑注入参数",
    title = "{method} {path} ? {param}"
)]
struct WebLogCandidate {
    #[field(label = "方法", key)]
    method: String,
    #[field(label = "路径", key)]
    path: String,
    #[field(label = "参数名", key)]
    param: String,
    #[field(label = "位置", kind = "enum", choices = "query=查询参数")]
    location: String,
    #[field(label = "命中特征族")]
    family: String,
    #[field(label = "特征族数")]
    family_count: i64,
    #[field(label = "方法集合", kind = "list")]
    methods: Vec<String>,
    #[field(label = "请求数")]
    request_count: i64,
    #[field(label = "窗口内请求数")]
    window_requests: i64,
    #[field(label = "客户端 IP 数")]
    distinct_ips: i64,
    #[field(label = "窗口内 IP 数")]
    window_ips: i64,
    #[field(label = "首次请求", timeline = "request")]
    first_seen: Option<Timestamp>,
    #[field(label = "末次请求", timeline = "request")]
    last_seen: Option<Timestamp>,
    #[field(label = "窗口起始", timeline = "request")]
    window_first_seen: Option<Timestamp>,
    #[field(label = "窗口结束", timeline = "request")]
    window_last_seen: Option<Timestamp>,
    #[field(label = "置信度（0-1）")]
    confidence: f64,
    #[field(label = "证据起始行")]
    line_start: i64,
    #[field(label = "证据结束行")]
    line_end: i64,
    #[field(label = "解码后文本起始偏移", kind = "size")]
    text_offset_start: u64,
    #[field(label = "解码后文本结束偏移（不含）", kind = "size")]
    text_offset_end: u64,
    #[field(label = "来源偏移精确")]
    source_exact: bool,
    #[field(label = "窗口状态码分布", kind = "json")]
    status_distribution: Json,
    #[field(label = "样例行", kind = "json")]
    samples: Json,
    #[field(label = "解码后样例")]
    sample_value: String,
    #[field(label = "原始编码样例")]
    sample_raw_value: String,
    #[field(label = "判定依据")]
    verdict: String,
}

fn weblog_files(run: &Run) -> Result<()> {
    let config = Config::default();
    let parser = LineParser::new(&config).map_err(Error::invalid_params)?;
    if run.inputs().is_empty() {
        run.warn("INPUT_NOT_FOUND", "未收到待分析的 Web 访问日志文件")?;
        run.set_summary("未收到 Web 访问日志文件");
        return Ok(());
    }
    let mut documents = 0usize;
    let mut parameters = 0usize;
    let mut candidates = 0usize;
    let mut skipped = 0usize;
    let total = run.inputs().len() as u64;
    for (index, file) in run.inputs().iter().enumerate() {
        run.check_cancelled()?;
        run.progress(index as u64, Some(total), Some(file.name()))?;
        if file.size() > MAX_FILE_BYTES {
            run.warn_file(
                file,
                "RESOURCE_LIMIT",
                format!(
                    "{} 有 {} 字节，超过单文件上限 {MAX_FILE_BYTES}",
                    file.name(),
                    file.size()
                ),
            )?;
            skipped += 1;
            continue;
        }
        let bytes = match file.read_all(MAX_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                if run.is_cancelled() {
                    return Err(error);
                }
                run.warn_file(file, &error.code.to_ascii_uppercase(), error.message)?;
                skipped += 1;
                continue;
            }
        };
        match process_document(run, file, &bytes, file.size(), None, &config, &parser)? {
            Some((params, found)) => {
                documents += 1;
                parameters += params;
                candidates += found;
            }
            None => {
                run.warn_file(
                    file,
                    "NOT_ACCESS_LOG",
                    format!(
                        "{} 不符合访问日志特征（缺少 `时间] \"请求行\"` 结构或为空文件），已跳过",
                        file.name()
                    ),
                )?;
                skipped += 1;
            }
        }
    }
    finish(run, documents, parameters, candidates, skipped, 0);
    Ok(())
}

fn weblog_evidence(run: &Run) -> Result<()> {
    let view = run.require_view()?;
    let config = Config::default();
    let parser = LineParser::new(&config).map_err(Error::invalid_params)?;
    let mut notes: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for mount in view.mounts() {
        for root in LOG_ROOTS {
            run.check_cancelled()?;
            let base = join_mount(&mount.path, root);
            if !view.exists(&base)? {
                continue;
            }
            discover(view, &base, &mut paths, &mut seen, &mut notes)?;
            if paths.len() >= MAX_FILES {
                break;
            }
        }
        if paths.len() >= MAX_FILES {
            break;
        }
    }
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_FILES {
        paths.truncate(MAX_FILES);
        notes.push(format!(
            "达到单次运行日志文件上限 {MAX_FILES}，其余文件未分析"
        ));
    }

    let mut documents = 0usize;
    let mut parameters = 0usize;
    let mut candidates = 0usize;
    let mut skipped = 0usize;
    let total = paths.len() as u64;
    for (index, path) in paths.iter().enumerate() {
        run.check_cancelled()?;
        run.progress(index as u64, Some(total), Some(path))?;
        let Some(file) = view.open(path)? else {
            notes.push(format!("{path} 已不存在，已跳过"));
            skipped += 1;
            continue;
        };
        let size = file.size();
        let (bytes, truncated) = if size > MAX_FILE_BYTES {
            let note = format!(
                "{path} 超过 maxFileBytes={MAX_FILE_BYTES}（文件 {size} 字节），只解析前 {MAX_FILE_BYTES} 字节"
            );
            let bytes = file.read_at(0, MAX_FILE_BYTES as usize)?;
            (bytes, Some(note))
        } else {
            match file.read_all(MAX_FILE_BYTES) {
                Ok(bytes) => (bytes, None),
                Err(error) => {
                    if run.is_cancelled() {
                        return Err(error);
                    }
                    run.warn_file(&file, &error.code.to_ascii_uppercase(), error.message)?;
                    skipped += 1;
                    continue;
                }
            }
        };
        match process_document(run, &file, &bytes, size, truncated, &config, &parser)? {
            Some((params, found)) => {
                documents += 1;
                parameters += params;
                candidates += found;
            }
            None => {
                notes.push(format!("{path}：内容不符合访问日志特征，已跳过"));
                skipped += 1;
            }
        }
    }
    if documents == 0 {
        run.warn(
            "NO_LOG_FILES",
            format!(
                "未找到可解析的 Web 访问日志（扫描根：{}）{}",
                LOG_ROOTS.join("、"),
                if notes.is_empty() {
                    String::new()
                } else {
                    format!("；{}", notes.join("；"))
                }
            ),
        )?;
    }
    finish(run, documents, parameters, candidates, skipped, notes.len());
    if !notes.is_empty() {
        run.log(LogLevel::Info, &notes.join("；"));
    }
    Ok(())
}

fn finish(
    run: &Run,
    documents: usize,
    parameters: usize,
    candidates: usize,
    skipped: usize,
    notes: usize,
) {
    let config = Config::default();
    let mut summary = format!(
        "解析 {documents} 个访问日志文件，聚合 {parameters} 个 query 参数，可疑候选 {candidates} 个（{}s 窗口内 ≥{} 次请求、客户端 IP ≤{}、命中 ≥{} 个特征族）",
        config.window_seconds,
        config.min_requests,
        config.max_distinct_ips,
        config.min_families
    );
    if skipped > 0 {
        summary.push_str(&format!("，{skipped} 个文件被跳过（见告警/日志）"));
    }
    if notes > 0 {
        summary.push_str(&format!("，{notes} 条扫描说明"));
    }
    summary.push_str("；结论为线索，未判定攻击是否成功。");
    run.set_summary(summary);
}

/// Decodes one file, aggregates it and emits its document plus candidate
/// records. `None` means the content does not look like an access log.
#[allow(clippy::too_many_arguments)]
fn process_document(
    run: &Run,
    file: &FileRef,
    bytes: &[u8],
    file_size: u64,
    truncated: Option<String>,
    config: &Config,
    parser: &LineParser,
) -> Result<Option<(usize, usize)>> {
    let (text, encoding, replacements) = decode_log(bytes);
    if config.require_log_text && !looks_like_access_log(&text) {
        return Ok(None);
    }
    let finished = aggregate::analyze_text(&text, config, parser, truncated.as_deref());
    let candidates = finished.suspicious();
    let candidate_count = candidates.len();
    let parameters = finished.all_params().count();
    // Byte offsets are only exact when decoding did not change the byte
    // layout: valid UTF-8 (adjusted for a stripped BOM). UTF-16/GB18030
    // re-encode to UTF-8, so the record keeps the line range and the source
    // points at the file without a byte range.
    let bom = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    let source_shift = (encoding == aggregate::Encoding::Utf8
        && replacements == 0
        && bytes.len() == text.len() + bom)
        .then_some(bom as u64);
    let document = document_record(
        file.name(),
        file_size,
        encoding_choice(encoding.as_str()),
        replacements,
        truncated.is_some(),
        &finished,
        candidate_count,
    );
    run.record(&document)
        .source(source_of(file, 0, file_size, "访问日志文件"))
        .emit()?;
    for param in candidates {
        run.check_cancelled()?;
        let record = candidate_record(param, source_shift.is_some());
        let note = match source_shift {
            Some(_) => format!("第 {}..{} 行", param.line_start, param.line_end),
            None => format!(
                "第 {}..{} 行（{} 解码，行号可定位，字节偏移不映射回源文件）",
                param.line_start,
                param.line_end,
                encoding.as_str()
            ),
        };
        let source = match source_shift {
            Some(shift) => source_of(
                file,
                param.byte_start + shift,
                param.byte_end.saturating_sub(param.byte_start),
                &note,
            ),
            None => source_without_range(file, &note),
        };
        let mut emit = run.record(&record).source(source);
        let severity = match param.confidence {
            score if score >= 0.8 => Severity::High,
            score if score >= 0.6 => Severity::Medium,
            _ => Severity::Low,
        };
        emit = emit.severity(severity);
        emit.emit()?;
    }
    Ok(Some((parameters, candidate_count)))
}

fn document_record(
    file: &str,
    file_size: u64,
    encoding: &str,
    replacements: usize,
    truncated: bool,
    finished: &Finished,
    candidate_count: usize,
) -> WebLogDocument {
    let stats = &finished.document;
    WebLogDocument {
        file: file.to_owned(),
        encoding: encoding.to_owned(),
        file_size,
        total_lines: stats.total_lines as i64,
        parsed_lines: stats.parsed_lines as i64,
        unparsed_lines: stats.unparsed_line_count as i64,
        combined_lines: stats.formats.get("combined").copied().unwrap_or(0) as i64,
        common_lines: stats.formats.get("common").copied().unwrap_or(0) as i64,
        other_lines: stats.formats.get("other").copied().unwrap_or(0) as i64,
        first_seen: stats.first_time.as_deref().and_then(timestamp_of),
        last_seen: stats.last_time.as_deref().and_then(timestamp_of),
        year_months: stats
            .spans_years
            .iter()
            .map(|(year, month)| format!("{year:04}-{month:02}"))
            .collect(),
        users: stats.identifiers.iter().cloned().collect(),
        replacement_count: replacements as i64,
        truncated,
        notes: stats.notes.join("；"),
        unparsed_reasons: Json(Value::Map(
            stats
                .unparsed_reasons
                .iter()
                .map(|(reason, count)| (Value::from(*reason), Value::from(*count)))
                .collect(),
        )),
        candidate_count: candidate_count as i64,
    }
}

fn candidate_record(param: &ParamAggregate, source_exact: bool) -> WebLogCandidate {
    let best = &param.window.best;
    let (family_count, _) = family_totals(&param.hit_families);
    let methods: Vec<String> = param.methods.keys().cloned().collect();
    let method = if methods.is_empty() {
        "unknown".to_owned()
    } else {
        methods.join(",")
    };
    WebLogCandidate {
        method,
        path: param.path.clone(),
        param: param.param.clone(),
        location: "query".to_owned(),
        family: family_summary(&param.hit_families),
        family_count: family_count as i64,
        methods,
        request_count: param.request_count as i64,
        window_requests: best.window_requests as i64,
        distinct_ips: param.distinct_client_ips as i64,
        window_ips: best.window_ips as i64,
        first_seen: param.first_seen.as_deref().and_then(timestamp_of),
        last_seen: param.last_seen.as_deref().and_then(timestamp_of),
        window_first_seen: best.window_first_seen.as_deref().and_then(timestamp_of),
        window_last_seen: best.window_last_seen.as_deref().and_then(timestamp_of),
        confidence: param.confidence,
        line_start: param.line_start as i64,
        line_end: param.line_end as i64,
        text_offset_start: param.byte_start,
        text_offset_end: param.byte_end,
        source_exact,
        status_distribution: status_json(&best.window_status),
        samples: samples_json(param),
        sample_value: param
            .decoded_value_samples
            .first()
            .cloned()
            .unwrap_or_default(),
        sample_raw_value: param.raw_value_samples.first().cloned().unwrap_or_default(),
        verdict: param.verdict.clone(),
    }
}

fn status_json(status: &[(Option<u16>, u64)]) -> Json {
    Json(Value::Array(
        status
            .iter()
            .map(|(status, count)| {
                let key = match status {
                    Some(code) => Value::from(u64::from(*code)),
                    None => Value::from("-"),
                };
                Value::Map(vec![
                    (Value::from("status"), key),
                    (Value::from("count"), Value::from(*count)),
                ])
            })
            .collect(),
    ))
}

fn samples_json(param: &ParamAggregate) -> Json {
    Json(Value::Array(
        param
            .sample_lines
            .iter()
            .map(|sample| {
                let status = match sample.status {
                    Some(code) => Value::from(u64::from(code)),
                    None => Value::from("-"),
                };
                Value::Map(vec![
                    (Value::from("line"), Value::from(sample.line_no)),
                    (Value::from("offset"), Value::from(sample.offset)),
                    (Value::from("length"), Value::from(sample.length)),
                    (Value::from("time"), Value::from(sample.raw_time.as_str())),
                    (Value::from("method"), Value::from(sample.method.as_str())),
                    (Value::from("status"), status),
                    (Value::from("client_ip"), Value::from(sample.ip.as_str())),
                    (
                        Value::from("raw_value"),
                        Value::from(sample.raw_value.as_str()),
                    ),
                    (Value::from("line_text"), Value::from(sample.text.as_str())),
                ])
            })
            .collect(),
    ))
}

/// `dd/Mon/yyyy:hh:mm:ss[.frac][ offset]` → RFC 3339 with the offset as
/// written, or a local time when the log carries none.
fn timestamp_of(raw: &str) -> Option<Timestamp> {
    let parts: TimestampParts = parse_timestamp(raw)?;
    let fraction = if parts.nanos == 0 {
        String::new()
    } else {
        let digits = format!("{:09}", parts.nanos);
        format!(".{}", digits.trim_end_matches('0'))
    };
    let offset = match parts.offset {
        Some((hours, minutes)) => {
            let sign = if hours < 0 || minutes < 0 { '-' } else { '+' };
            let hours = hours.abs();
            let minutes = minutes.abs();
            format!("{sign}{hours:02}:{minutes:02}")
        }
        None => String::new(),
    };
    Timestamp::parse(&format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}{offset}",
        parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second
    ))
}

/// Stable enum choice id for an encoding name (choices cannot contain `-`).
fn encoding_choice(encoding: &str) -> &str {
    match encoding {
        "utf-8" => "utf8",
        "utf-16le" => "utf16le",
        "utf-16be" => "utf16be",
        other => other,
    }
}

/// True when the content shows the `[time] "request"` structure on at least
/// half of its first 200 non-blank lines.
fn looks_like_access_log(text: &str) -> bool {
    let mut checked = 0usize;
    let mut hits = 0usize;
    for line in text.lines().take(200) {
        if line.trim().is_empty() {
            continue;
        }
        checked += 1;
        if line.contains("] \"") && (line.contains("HTTP/") || line.contains("] \"-")) {
            hits += 1;
        }
    }
    checked > 0 && hits * 2 >= checked
}

fn skip_directory(name: &str) -> bool {
    name.starts_with('.') || matches!(name, "node_modules" | "proc" | "sys" | "dev")
}

fn is_log_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const NEEDLES: [&str; 6] = ["access", "nginx", "apache", "httpd", "www.log", "web.log"];
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

fn join_mount(mount: &str, root: &str) -> String {
    let mount = mount.trim_matches('/');
    let root = root.trim_matches('/');
    if mount.is_empty() {
        root.to_owned()
    } else {
        format!("{mount}/{root}")
    }
}

fn discover(
    view: &View,
    root: &str,
    found: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let mut queue = vec![(root.to_owned(), 0usize)];
    while let Some((directory, depth)) = queue.pop() {
        if depth > SCAN_DEPTH {
            continue;
        }
        let children = match view.list(&directory) {
            Ok(children) => children,
            Err(error) if error.is_cancelled() => return Err(error),
            Err(error) => {
                notes.push(format!("目录 {directory} 无法列举：{}", error.message));
                continue;
            }
        };
        for child in children.into_iter().rev() {
            let path = if directory.is_empty() {
                child.name.clone()
            } else {
                format!("{directory}/{}", child.name)
            };
            if child.is_dir() {
                if !skip_directory(&child.name) {
                    queue.push((path, depth + 1));
                }
                continue;
            }
            if !child.is_file() || !is_log_name(&child.name) || child.size == 0 {
                continue;
            }
            if seen.insert(path.clone()) {
                found.push(path);
            }
        }
        if found.len() >= MAX_FILES {
            notes.push(format!(
                "达到单次运行日志文件上限 {MAX_FILES}，其余文件未分析"
            ));
            return Ok(());
        }
    }
    Ok(())
}

/// Provenance of one range. Evidence runs carry the volume path; file runs
/// fall back to the host display name when no path is supplied.
fn source_of(file: &FileRef, offset: u64, length: u64, note: &str) -> SourceRef {
    let mut source = file.source_at(offset, length);
    if source.path.is_none() {
        source.path = Some(file.name().to_owned());
    }
    source.note = Some(note.to_owned());
    source
}

/// Provenance without a byte range (the decoded text does not map back to
/// file offsets); the note carries the line range.
fn source_without_range(file: &FileRef, note: &str) -> SourceRef {
    let mut source = file.source();
    if source.path.is_none() {
        source.path = Some(file.name().to_owned());
    }
    source.note = Some(note.to_owned());
    source
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID)
        .record::<WebLogDocument>()
        .record::<WebLogCandidate>()
        .analyzer(ANALYZER_FILE, weblog_files)
        .analyzer(ANALYZER_EVIDENCE, weblog_evidence)
}

export_plugin!(plugin);
