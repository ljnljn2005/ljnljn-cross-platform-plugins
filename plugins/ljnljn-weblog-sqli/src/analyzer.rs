//! LovelyCarve integration: read-only SDK handles in, `AnalysisResult` out.
//!
//! Two capabilities share the same pure parsing core:
//!
//! * `file_analyzer` `ljnljn.weblog-sqli` — one Web access
//!   log file opened from the file list; the file itself is the document.
//! * `evidence_analyzer` (same analyzer name) — the fixed Web-log roots of an
//!   evidence volume (`var/log/nginx`, `var/log/httpd`, `var/log/apache2`,
//!   `var/www/logs`, `var/www/log`, `logs`, `log`), optionally extended by
//!   the operator with `scanPaths`.
//!
//! The SDK exposes no separate option API. Operator parameters are read from
//! the task params the host forwards verbatim (`evidence.params`; file
//! analysis has no params channel in SDK 0.1.0 and therefore always uses the
//! documented defaults):
//!
//! ```json
//! {"minRequests": 5, "windowSeconds": 600, "maxDistinctIps": 3,
//!  "minFamilies": 2, "scanPaths": ["opt/x/logs"], "maxFileBytes": 134217728,
//!  "mapping": {"ip": "...", "request": "...", "status": "..."}}
//! ```
//!
//! Every artifact carries `source.root` / `source.path` and the `weblog.*`
//! evidence fields, so each number can be re-derived from the log.

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, Error, Evidence, EvidenceAnalyzer, EvidenceRoot,
    EvidenceVolume, File, FileAnalyzer, Finding, LogLevel, Plugin, Result, ResultColumn,
    ResultNode, Severity, Value,
};

use crate::aggregate::{
    decode_log, families_as_pairs, analyze_text, Finished, ParamAggregate, SampleLine,
};
use crate::detect::{family_summary, family_totals, WindowScan};
use crate::logline::LineParser;
use crate::model::{Config, Family, Mapping};

/// Base analyzer id; file/evidence capabilities must use distinct names.
pub const ANALYZER: &str = "ljnljn.weblog-sqli";
pub const ANALYZER_FILE: &str = "ljnljn.weblog-sqli.file";
pub const ANALYZER_EVIDENCE: &str = "ljnljn.weblog-sqli.evidence";
/// Plugin id; must match plugin.toml `id`.
pub const PLUGIN_ID: &str = "org.ljnljn.weblog-sqli";
/// Artifact namespace.
pub const NS: &str = "weblog";

/// Directory prefixes searched in an evidence volume, relative to its root.
const LOG_ROOTS: &[&str] = &[
    "var/log/nginx",
    "var/log/httpd",
    "var/log/apache2",
    "var/www/logs",
    "var/www/log",
    "logs",
    "log",
];

/// Directory names never descended into (noise and cycles).
fn skip_directory(name: &str) -> bool {
    name.starts_with('.') || matches!(name, "node_modules" | "proc" | "sys" | "dev")
}

/// True when the file name looks like a Web access log.
fn is_log_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const NEEDLES: [&str; 6] = ["access", "nginx", "apache", "httpd", "www.log", "web.log"];
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

/// Sanity check so that an unrelated `.log` is skipped instead of being
/// reported as 100% unparsed: half of the first 200 lines must show a
/// quoted request line after a bracketed timestamp. An empty or blank-only
/// document carries no line to check and is therefore not an access log.
fn looks_like_access_log(text: &str) -> bool {
    let mut checked = 0_usize;
    let mut hits = 0_usize;
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

// ---------------------------------------------------------------------------
// Operator parameters
// ---------------------------------------------------------------------------

fn param<'a>(params: &'a Value, key: &str) -> Option<&'a Value> {
    params.as_map()?.iter().find_map(|(entry_key, value)| {
        (entry_key.as_str() == Some(key)).then_some(value)
    })
}

fn param_str(params: &Value, key: &str) -> Option<String> {
    param(params, key).and_then(|value| match value {
        Value::String(text) => Some(String::from_utf8_lossy(text.as_bytes()).into_owned()),
        _ => None,
    })
}

/// Builds the effective configuration from task params (unknown keys ignore).
pub fn config_from_params(params: &Value) -> std::result::Result<Config, String> {
    let mut config = Config::default();
    if let Some(value) = param(params, "minRequests").and_then(Value::as_u64) {
        config.min_requests = value;
    }
    if let Some(value) = param(params, "windowSeconds").and_then(Value::as_i64) {
        config.window_seconds = value;
    }
    if let Some(value) = param(params, "maxDistinctIps").and_then(Value::as_u64) {
        config.max_distinct_ips = value;
    }
    if let Some(value) = param(params, "minFamilies").and_then(Value::as_u64) {
        config.min_families = value as usize;
    }
    if let Some(value) = param(params, "samplesPerParam").and_then(Value::as_u64) {
        config.samples_per_param = value as usize;
    }
    if let Some(value) = param(params, "sampleLineChars").and_then(Value::as_u64) {
        config.sample_line_chars = value as usize;
    }
    if let Some(value) = param(params, "maxFileBytes").and_then(Value::as_u64) {
        config.max_file_bytes = value;
    }
    if let Some(value) = param(params, "scanDepth").and_then(Value::as_u64) {
        config.scan_depth = value as usize;
    }
    if let Some(value) = param(params, "maxFiles").and_then(Value::as_u64) {
        config.max_files = value as usize;
    }
    if let Some(value) = param(params, "requireLogText").and_then(Value::as_bool) {
        config.require_log_text = value;
    }
    if let Some(mapping) = param(params, "mapping") {
        let field = |key: &str| param_str(mapping, key);
        config.mapping = Mapping {
            ip: field("ip"),
            time: field("time"),
            request: field("request"),
            status: field("status"),
            bytes: field("bytes"),
            referer: field("referer"),
            user_agent: field("userAgent"),
        };
    }
    config.validate()?;
    Ok(config)
}

/// Absolute-or-relative log paths supplied by the operator.
pub fn scan_paths(params: &Value) -> Vec<String> {
    let clean = |path: &str| path.trim().trim_start_matches('/').to_owned();
    match param(params, "scanPaths") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(clean)
            .filter(|path| !path.is_empty() && !path.contains(".."))
            .collect(),
        Some(value) => {
            let joined = match value {
                Value::String(text) => String::from_utf8_lossy(text.as_bytes()).into_owned(),
                _ => return Vec::new(),
            };
            joined
                .lines()
                .map(clean)
                .filter(|path| !path.is_empty() && !path.contains(".."))
                .collect()
        }
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Document pipeline
// ---------------------------------------------------------------------------

/// Source identity of one analyzed file.
#[derive(Clone, Debug)]
pub struct DocumentSource {
    root: String,
    path: String,
    bytes: u64,
    encoding: String,
    encoding_note: String,
    replacement_count: usize,
    truncated: Option<String>,
}

#[derive(Debug)]
pub struct AnalyzedDocument {
    source: DocumentSource,
    finished: Finished,
    /// First lines of the decoded text, kept as the artifact value.
    head: String,
}

fn head_of(text: &str) -> String {
    text.lines().take(20).collect::<Vec<_>>().join("\n")
}

/// Decodes bytes and runs the aggregation; `None` when the content does not
/// look like an access log at all.
fn analyze_document(
    bytes: &[u8],
    size: u64,
    truncated: Option<String>,
    root: &str,
    path: &str,
    config: &Config,
    parser: &LineParser,
) -> Option<(AnalyzedDocument, bool)> {
    let (text, encoding, replacements) = decode_log(bytes);
    if config.require_log_text && !looks_like_access_log(&text) {
        return None;
    }
    let finished = analyze_text(&text, config, parser, truncated.as_deref());
    let encoding_note = if truncated.is_some() {
        "文件超过 maxFileBytes，只解析了前部分内容".to_owned()
    } else {
        format!("按 {} 解码（严格 UTF-8 优先，失败回退 GB18030）", encoding.as_str())
    };
    let document = AnalyzedDocument {
        source: DocumentSource {
            root: root.to_owned(),
            path: path.to_owned(),
            bytes: size,
            encoding: encoding.as_str().to_owned(),
            encoding_note,
            replacement_count: replacements,
            truncated,
        },
        finished,
        head: head_of(&text),
    };
    let converted = encoding != crate::aggregate::Encoding::Utf8;
    Some((document, converted))
}

/// Bounded read of one volume file; oversized files are truncated and noted.
fn read_volume_file(
    volume: &EvidenceVolume,
    path: &str,
    cap: u64,
) -> Result<Option<(Vec<u8>, u64, Option<String>)>> {
    let Some(node) = volume.stat(path)? else {
        return Ok(None);
    };
    if !node.is_file() {
        return Ok(None);
    }
    let size = node.size;
    if size == 0 {
        return Ok(None);
    }
    if size > cap {
        let bytes = volume.read(path, 0, Some(cap))?;
        let note = format!(
            "{} 超过 maxFileBytes={cap}（文件 {size} 字节），只解析前 {cap} 字节",
            path
        );
        return Ok(Some((bytes, size, Some(note))));
    }
    let bytes = volume.read(path, 0, Some(size))?;
    if bytes.len() as u64 != size {
        return Err(Error::new("SHORT_READ", format!("{path} 读取不完整")));
    }
    Ok(Some((bytes, size, None)))
}

/// Enumerates the candidate log files below `roots`.
fn discover(
    volume: &EvidenceVolume,
    roots: &[String],
    config: &Config,
    notes: &mut Vec<String>,
) -> Result<Vec<String>> {
    let mut found: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for root in roots {
        if volume.stat(root)?.is_none() {
            continue;
        }
        let mut queue = vec![(root.clone(), 0_usize)];
        while let Some((directory, depth)) = queue.pop() {
            if depth > config.scan_depth {
                continue;
            }
            let children = match volume.list(&directory) {
                Ok(children) => children,
                Err(error) if error.is_cancelled() => return Err(error),
                Err(error) => {
                    notes.push(format!("目录 {directory} 无法列举：{}", error.message));
                    continue;
                }
            };
            for child in children.into_iter().rev() {
                let path = format!("{directory}/{}", child.name);
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
            if found.len() >= config.max_files {
                notes.push(format!(
                    "达到单卷日志文件上限 {}，其余文件未分析",
                    config.max_files
                ));
                found.sort();
                return Ok(found);
            }
        }
    }
    found.sort();
    Ok(found)
}

fn roots_for(params: &Value, notes: &mut Vec<String>) -> Vec<String> {
    let mut roots: Vec<String> = LOG_ROOTS.iter().map(|root| (*root).to_string()).collect();
    for extra in scan_paths(params) {
        if !roots.contains(&extra) {
            notes.push(format!("按 scanPaths 追加扫描根：{extra}"));
            roots.push(extra);
        }
    }
    roots
}

// ---------------------------------------------------------------------------
// Result construction
// ---------------------------------------------------------------------------

fn text(value: &Value) -> String {
    match value {
        Value::String(string) => String::from_utf8_lossy(string.as_bytes()).into_owned(),
        Value::Nil => String::new(),
        other => other.to_string(),
    }
}

fn status_value(status: Option<u16>) -> Value {
    match status {
        Some(status) => Value::from(status as u64),
        None => Value::from("-"),
    }
}

fn status_array(status: &[(Option<u16>, u64)]) -> Value {
    Value::Array(
        status
            .iter()
            .map(|(status, count)| {
                Value::Map(vec![
                    (Value::from("status"), status_value(*status)),
                    (Value::from("count"), Value::from(*count)),
                ])
            })
            .collect(),
    )
}

fn families_map(entries: &[(Family, u64)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(family, count)| (Value::from(family.name()), Value::from(*count)))
            .collect(),
    )
}

fn samples_array(samples: &[SampleLine]) -> Value {
    Value::Array(
        samples
            .iter()
            .map(|sample| {
                Value::Map(vec![
                    (Value::from("lineNumber"), Value::from(sample.line_no)),
                    (Value::from("line"), Value::from(sample.text.as_str())),
                    (Value::from("rawTime"), Value::from(sample.raw_time.as_str())),
                    (Value::from("status"), status_value(sample.status)),
                    (Value::from("method"), Value::from(sample.method.as_str())),
                    (Value::from("clientIp"), Value::from(sample.ip.as_str())),
                    (Value::from("rawValue"), Value::from(sample.raw_value.as_str())),
                ])
            })
            .collect(),
    )
}

fn common_attributes(source: &DocumentSource, config: &Config) -> Attributes {
    let mut attributes = Attributes::new();
    attributes.insert("source.root", source.root.as_str());
    attributes.insert("source.path", source.path.as_str());
    attributes.insert(format!("{NS}.source"), source.path.as_str());
    attributes.insert(format!("{NS}.sizeBytes"), source.bytes);
    attributes.insert(format!("{NS}.encoding"), source.encoding.as_str());
    attributes.insert(format!("{NS}.encoding.note"), source.encoding_note.as_str());
    attributes.insert(
        format!("{NS}.encoding.replacementCount"),
        source.replacement_count as u64,
    );
    attributes.insert(
        format!("{NS}.truncated"),
        source.truncated.clone().unwrap_or_default(),
    );
    attributes.insert(format!("{NS}.config.minRequests"), config.min_requests);
    attributes.insert(
        format!("{NS}.config.windowSeconds"),
        config.window_seconds as u64,
    );
    attributes.insert(
        format!("{NS}.config.maxDistinctIps"),
        config.max_distinct_ips,
    );
    attributes.insert(format!("{NS}.config.minFamilies"), config.min_families as u64);
    attributes
}

fn document_artifact(document: &AnalyzedDocument, config: &Config) -> Artifact {
    let source = &document.source;
    let stats = &document.finished.document;
    let mut attributes = common_attributes(source, config);
    attributes.insert(format!("{NS}.totalLines"), stats.total_lines);
    attributes.insert(format!("{NS}.parsedLines"), stats.parsed_lines);
    attributes.insert(
        format!("{NS}.unparsedLineCount"),
        stats.unparsed_line_count,
    );
    attributes.insert(format!("{NS}.formats"), stats.format_label());
    attributes.insert(
        format!("{NS}.unparsed.reasons"),
        Value::Map(
            stats
                .unparsed_reasons
                .iter()
                .map(|(reason, count)| (Value::from(*reason), Value::from(*count)))
                .collect(),
        ),
    );
    attributes.insert(
        format!("{NS}.unparsed.samples"),
        Value::Array(
            stats
                .unparsed_samples
                .iter()
                .map(|sample| {
                    Value::Map(vec![
                        (Value::from("lineNumber"), Value::from(sample.line_no)),
                        (Value::from("reason"), Value::from(sample.reason)),
                        (Value::from("line"), Value::from(sample.text.as_str())),
                    ])
                })
                .collect(),
        ),
    );
    attributes.insert(
        format!("{NS}.spansYears"),
        stats
            .spans_years
            .iter()
            .map(|(year, month)| format!("{year:04}-{month:02}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    attributes.insert(
        format!("{NS}.identifiers"),
        stats.identifiers.iter().cloned().collect::<Vec<_>>().join(","),
    );
    attributes.insert(format!("{NS}.notes"), stats.notes.join("；"));
    Artifact {
        artifact_type: format!("{NS}.document"),
        title: source.path.clone(),
        value: Some(Value::from(document.head.as_str())),
        attributes,
    }
}

fn window_time_sample(param: &ParamAggregate) -> String {
    if let Some(first) = &param.window.best.window_first_seen {
        return first.clone();
    }
    param
        .sample_lines
        .first()
        .map(|sample| sample.raw_time.clone())
        .unwrap_or_default()
}

fn candidate_artifact(
    source: &DocumentSource,
    param: &ParamAggregate,
    rank: usize,
    config: &Config,
) -> Artifact {
    let best: &WindowScan = &param.window.best;
    let families = families_as_pairs(&param.hit_families);
    let (family_count, total_hits) = family_totals(&param.hit_families);
    let mut attributes = common_attributes(source, config);
    attributes.insert(format!("{NS}.rank"), rank as u64);
    attributes.insert(format!("{NS}.path"), param.path.as_str());
    attributes.insert(format!("{NS}.param"), param.param.as_str());
    attributes.insert(format!("{NS}.location"), "query");
    attributes.insert(format!("{NS}.requestCount"), param.request_count);
    attributes.insert(format!("{NS}.requestCount.window"), best.window_requests);
    attributes.insert(
        format!("{NS}.firstSeen"),
        param.first_seen.clone().unwrap_or_default(),
    );
    attributes.insert(
        format!("{NS}.lastSeen"),
        param.last_seen.clone().unwrap_or_default(),
    );
    attributes.insert(
        format!("{NS}.windowFirstSeen"),
        best.window_first_seen.clone().unwrap_or_default(),
    );
    attributes.insert(
        format!("{NS}.windowLastSeen"),
        best.window_last_seen.clone().unwrap_or_default(),
    );
    attributes.insert(format!("{NS}.rawTimeSample"), window_time_sample(param));
    attributes.insert(
        format!("{NS}.distinctClientIps"),
        param.distinct_client_ips,
    );
    attributes.insert(format!("{NS}.distinctClientIps.window"), best.window_ips);
    attributes.insert(
        format!("{NS}.statusDistribution"),
        status_array(&best.window_status),
    );
    attributes.insert(
        format!("{NS}.statusDistribution.file"),
        status_array(&param.status_distribution),
    );
    attributes.insert(format!("{NS}.hitFamilies"), families_map(&families));
    attributes.insert(
        format!("{NS}.hitFamilies.window"),
        families_map(&families_as_pairs(&best.window_families)),
    );
    attributes.insert(
        format!("{NS}.hitFamilies.summary"),
        family_summary(&param.hit_families),
    );
    attributes.insert(
        format!("{NS}.hitFamilies.rawEncoded"),
        family_summary(&param.raw_hit_families),
    );
    attributes.insert(format!("{NS}.hitFamilies.count"), family_count as u64);
    attributes.insert(format!("{NS}.hitFamilies.matches"), total_hits);
    attributes.insert(format!("{NS}.methods"), methods_of(param));
    attributes.insert(
        format!("{NS}.rawValueSamples"),
        param.raw_value_samples.join(" | "),
    );
    attributes.insert(
        format!("{NS}.decodedValueSamples"),
        param.decoded_value_samples.join(" | "),
    );
    attributes.insert(
        format!("{NS}.spansYears"),
        param
            .spans_years
            .iter()
            .map(|(year, month)| format!("{year:04}-{month:02}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    attributes.insert(format!("{NS}.undatedRequests"), param.undated);
    attributes.insert(
        format!("{NS}.payloadRequests"),
        best.payload_requests,
    );
    attributes.insert(format!("{NS}.sampleLines"), samples_array(&param.sample_lines));
    attributes.insert(format!("{NS}.confidence"), param.confidence);
    attributes.insert(format!("{NS}.verdict"), param.verdict.as_str());
    Artifact {
        artifact_type: format!("{NS}.candidate"),
        title: format!("{} ? {}", param.path, param.param),
        value: Some(Value::from(
            param
                .decoded_value_samples
                .first()
                .cloned()
                .unwrap_or_default(),
        )),
        attributes,
    }
}

fn methods_of(param: &ParamAggregate) -> String {
    param
        .methods
        .iter()
        .map(|(method, count)| format!("{method}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn aggregate_artifact(
    source: &DocumentSource,
    param: &ParamAggregate,
    config: &Config,
) -> Artifact {
    let mut attributes = common_attributes(source, config);
    attributes.insert(format!("{NS}.path"), param.path.as_str());
    attributes.insert(format!("{NS}.param"), param.param.as_str());
    attributes.insert(format!("{NS}.location"), "query");
    attributes.insert(format!("{NS}.requestCount"), param.request_count);
    attributes.insert(
        format!("{NS}.firstSeen"),
        param.first_seen.clone().unwrap_or_default(),
    );
    attributes.insert(
        format!("{NS}.lastSeen"),
        param.last_seen.clone().unwrap_or_default(),
    );
    attributes.insert(
        format!("{NS}.distinctClientIps"),
        param.distinct_client_ips,
    );
    attributes.insert(
        format!("{NS}.statusDistribution"),
        status_array(&param.status_distribution),
    );
    attributes.insert(
        format!("{NS}.hitFamilies"),
        families_map(&families_as_pairs(&param.hit_families)),
    );
    attributes.insert(
        format!("{NS}.hitFamilies.summary"),
        family_summary(&param.hit_families),
    );
    attributes.insert(
        format!("{NS}.hitFamilies.count"),
        family_totals(&param.hit_families).0 as u64,
    );
    attributes.insert(format!("{NS}.methods"), methods_of(param));
    attributes.insert(format!("{NS}.suspicious"), param.suspicious);
    attributes.insert(format!("{NS}.confidence"), param.confidence);
    attributes.insert(format!("{NS}.verdict"), param.verdict.as_str());
    attributes.insert(format!("{NS}.sampleLines"), samples_array(&param.sample_lines));
    Artifact {
        artifact_type: format!("{NS}.param"),
        title: format!("{} ? {}", param.path, param.param),
        value: Some(Value::from(param.request_count)),
        attributes,
    }
}

fn limitations_artifact(
    source: Option<&DocumentSource>,
    config: &Config,
    notes: &[String],
) -> Artifact {
    let mut attributes = Attributes::new();
    if let Some(source) = source {
        attributes.insert("source.root", source.root.as_str());
        attributes.insert("source.path", source.path.as_str());
        attributes.insert(format!("{NS}.source"), source.path.as_str());
    }
    let mut items = vec![
        format!(
            "格式未识别/损坏行计入 unparsedLineCount，按 blank/format/request/time 分类，最多保留 {} 条样例",
            config.max_unparsed_samples
        ),
        "body 未解析：只分析 query 参数；POST 表单/JSON 载荷不在覆盖范围".to_owned(),
        "未判定攻击是否成功：状态码分布只是观测值，不能据此证明注入成功或数据外泄".to_owned(),
        "时间原样保留：不做年份补齐、不做时区归一，窗口按日志自身时间轴计算".to_owned(),
        "只读 SDK 句柄分析：不执行检材命令、不进行网络探测或任何利用动作".to_owned(),
        "特征族为可解释正则表达式，属于线索；编码/加密载荷不会被还原".to_owned(),
        "不解析请求头全量、不做 IP 地理归属与账户关联、不做会话 cookie 解析、不做 pcap 还原".to_owned(),
    ];
    items.extend(notes.iter().cloned());
    attributes.insert(
        format!("{NS}.limitations"),
        Value::Array(items.iter().map(|item| Value::from(item.as_str())).collect()),
    );
    Artifact {
        artifact_type: format!("{NS}.limitations"),
        title: format!(
            "{} 限制说明",
            source.map(|source| source.path.as_str()).unwrap_or("全局")
        ),
        value: None,
        attributes,
    }
}

fn result_nodes() -> Vec<ResultNode> {
    let column = |key: &str, label: &str| ResultColumn {
        key: key.to_owned(),
        label: label.to_owned(),
    };
    let k = |key: &str| format!("{NS}.{key}");
    vec![
        ResultNode {
            node_type: format!("{NS}.document"),
            name: "访问日志文件".to_owned(),
            columns: vec![
                column(&k("encoding"), "编码"),
                column(&k("formats"), "日志格式"),
                column(&k("totalLines"), "总行数"),
                column(&k("parsedLines"), "已解析行"),
                column(&k("unparsedLineCount"), "未解析行数"),
                column(&k("sizeBytes"), "文件大小"),
                column(&k("spansYears"), "涉及年月"),
                column(&k("identifiers"), "ident/user"),
                column("source.root", "来源卷"),
            ],
        },
        ResultNode {
            node_type: format!("{NS}.candidate"),
            name: "可疑注入参数".to_owned(),
            columns: vec![
                column(&k("path"), "路径"),
                column(&k("param"), "参数名"),
                column(&k("location"), "位置"),
                column(&k("requestCount"), "请求数"),
                column(&k("requestCount.window"), "窗口内请求数"),
                column(&k("firstSeen"), "首次时间"),
                column(&k("lastSeen"), "末次时间"),
                column(&k("windowFirstSeen"), "窗口首条时间"),
                column(&k("windowLastSeen"), "窗口末条时间"),
                column(&k("distinctClientIps"), "客户端IP数"),
                column(&k("distinctClientIps.window"), "窗口内IP数"),
                column(&k("statusDistribution"), "窗口状态码分布"),
                column(&k("hitFamilies.summary"), "命中特征族"),
                column(&k("hitFamilies.count"), "命中族数"),
                column(&k("hitFamilies.matches"), "命中次数"),
                column(&k("confidence"), "置信度"),
                column(&k("verdict"), "判定依据"),
                column("source.path", "源文件"),
            ],
        },
        ResultNode {
            node_type: format!("{NS}.param"),
            name: "全量参数聚合".to_owned(),
            columns: vec![
                column(&k("path"), "路径"),
                column(&k("param"), "参数名"),
                column(&k("requestCount"), "请求数"),
                column(&k("firstSeen"), "首次时间"),
                column(&k("lastSeen"), "末次时间"),
                column(&k("distinctClientIps"), "客户端IP数"),
                column(&k("statusDistribution"), "状态码分布"),
                column(&k("hitFamilies.summary"), "命中特征族"),
                column(&k("suspicious"), "可疑"),
                column(&k("verdict"), "说明"),
                column("source.path", "源文件"),
            ],
        },
        ResultNode {
            node_type: format!("{NS}.limitations"),
            name: "限制说明".to_owned(),
            columns: vec![
                column(&k("unparsedLineCount"), "未解析行数"),
                column(&k("limitations"), "限制"),
                column("source.path", "源文件"),
            ],
        },
    ]
}

fn findings_for(documents: &[AnalyzedDocument], config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    for document in documents {
        for param in document.finished.suspicious() {
            let best = &param.window.best;
            let families: Vec<&str> = families_as_pairs(&param.hit_families)
                .iter()
                .map(|(family, _)| family.name())
                .collect();
            let severity = match param.confidence {
                score if score >= 0.8 => Severity::High,
                score if score >= 0.6 => Severity::Medium,
                _ => Severity::Low,
            };
            let mut attributes = common_attributes(&document.source, config);
            attributes.insert(format!("{NS}.path"), param.path.as_str());
            attributes.insert(format!("{NS}.param"), param.param.as_str());
            attributes.insert(format!("{NS}.confidence"), param.confidence);
            findings.push(Finding {
                severity,
                title: format!(
                    "可疑查询参数 {} ? {}（{}s 窗口内 {} 次，命中 {}）",
                    param.path,
                    param.param,
                    config.window_seconds,
                    best.window_requests,
                    families.join("+")
                ),
                description: param.verdict.clone(),
                attributes,
            });
        }
    }
    findings
}

/// Assembles the `AnalysisResult` for one or more documents.
pub fn build_result(
    documents: &[AnalyzedDocument],
    config: &Config,
    notes: &[String],
    source_summary: &str,
) -> AnalysisResult {
    let mut artifacts = Vec::new();
    for document in documents {
        artifacts.push(document_artifact(document, config));
        for (rank, param) in document.finished.suspicious().into_iter().enumerate() {
            artifacts.push(candidate_artifact(
                &document.source,
                param,
                rank + 1,
                config,
            ));
        }
        for param in document.finished.sorted_by_requests() {
            artifacts.push(aggregate_artifact(&document.source, param, config));
        }
        artifacts.push(limitations_artifact(
            Some(&document.source),
            config,
            &document.finished.document.notes,
        ));
    }
    if documents.is_empty() {
        artifacts.push(limitations_artifact(None, config, notes));
    }
    let findings = findings_for(documents, config);
    let total_lines: u64 = documents
        .iter()
        .map(|document| document.finished.document.total_lines)
        .sum();
    let parsed: u64 = documents
        .iter()
        .map(|document| document.finished.document.parsed_lines)
        .sum();
    let unparsed: u64 = documents
        .iter()
        .map(|document| document.finished.document.unparsed_line_count)
        .sum();
    let params: usize = documents
        .iter()
        .map(|document| document.finished.all_params().count())
        .sum();
    let mut summary = format!(
        "{source_summary}：解析 {} 个日志文件，{total_lines} 行（已解析 {parsed}，未解析 {unparsed}），聚合 {params} 个 query 参数，可疑候选 {} 个（{}s 窗口内 ≥{} 次请求、客户端 IP ≤{}、命中 ≥{} 个特征族）。",
        documents.len(),
        findings.len(),
        config.window_seconds,
        config.min_requests,
        config.max_distinct_ips,
        config.min_families
    );
    if !notes.is_empty() {
        summary.push_str(&notes.join("；"));
        summary.push('。');
    }
    summary.push_str("结论为线索，未判定攻击是否成功。");
    AnalysisResult {
        summary: Some(summary),
        nodes: result_nodes(),
        artifacts,
        timeline: Vec::new(),
        findings,
    }
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Web 访问日志 → 可疑 SQL 注入查询参数。
pub struct WebLogAnalyzer;

impl WebLogAnalyzer {
    fn prepare(&self, params: &Value) -> Result<(Config, LineParser)> {
        let config = config_from_params(params).map_err(Error::invalid_params)?;
        let parser = LineParser::new(&config).map_err(Error::invalid_params)?;
        Ok((config, parser))
    }
}

impl FileAnalyzer for WebLogAnalyzer {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        // SDK file handles carry no params channel, so the defaults apply.
        let (config, parser) = self.prepare(&Value::Nil)?;
        let size = file.size();
        if size > config.max_file_bytes {
            return Err(Error::new(
                "RESOURCE_LIMIT",
                format!(
                    "{} 有 {size} 字节，超过 maxFileBytes={}；单文件分析不截断，请用检材级分析并调高 maxFileBytes",
                    file.name(),
                    config.max_file_bytes
                ),
            ));
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        let mut offset = 0_u64;
        while offset < size {
            let chunk = file.read(offset, 4 * 1024 * 1024)?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            bytes.extend_from_slice(&chunk);
        }
        let notes = Vec::new();
        match analyze_document(&bytes, size, None, "file", file.name(), &config, &parser) {
            Some((document, converted)) => {
                let mut notes = notes;
                if converted {
                    notes.push(format!("{}：非 UTF-8，按 GB18030 解码", file.name()));
                }
                let documents = vec![document];
                Ok(build_result(
                    &documents,
                    &config,
                    &notes,
                    &format!("单文件分析 {}", file.name()),
                ))
            }
            None => Ok(AnalysisResult {
                summary: Some(format!(
                    "{} 未通过访问日志特征检查（无 `时间] \"请求行\"` 结构或已为空文件），未生成参数聚合",
                    file.name()
                )),
                nodes: result_nodes(),
                artifacts: vec![limitations_artifact(
                    None,
                    &config,
                    &[format!("{}：内容不符合访问日志特征", file.name())],
                )],
                timeline: Vec::new(),
                findings: Vec::new(),
            }),
        }
    }
}

impl EvidenceAnalyzer for WebLogAnalyzer {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let (config, parser) = self.prepare(evidence.params())?;
        let mut notes: Vec<String> = Vec::new();
        let mut log_roots = roots_for(evidence.params(), &mut notes);
        log_roots.retain(|root| !root.is_empty());
        let roots = evidence.roots()?;
        let mut documents: Vec<AnalyzedDocument> = Vec::new();
        let mut scanned_roots: Vec<String> = Vec::new();
        for (index, root) in roots.iter().enumerate() {
            evidence.progress(
                index as u64,
                Some(roots.len() as u64),
                Some(&format!("扫描卷 {}", root.root_id)),
            )?;
            let volume = evidence.volume(&root.root_id);
            let candidates = discover(&volume, &log_roots, &config, &mut notes)?;
            if candidates.is_empty() {
                continue;
            }
            scanned_roots.push(root.root_id.clone());
            for path in candidates {
                evidence.context().check_cancelled()?;
                let Some((bytes, size, truncated)) =
                    read_volume_file(&volume, &path, config.max_file_bytes)?
                else {
                    continue;
                };
                match analyze_document(
                    &bytes,
                    size,
                    truncated,
                    &root.root_id,
                    &path,
                    &config,
                    &parser,
                ) {
                    Some((document, converted)) => {
                        if converted {
                            evidence.context().log(
                                LogLevel::Info,
                                &format!("{path}: 按 GB18030 解码"),
                            );
                        }
                        documents.push(document);
                    }
                    None => notes.push(format!("{path}：内容不符合访问日志特征，已跳过")),
                }
            }
        }
        evidence.progress(
            roots.len() as u64,
            Some(roots.len() as u64),
            Some("汇总结果"),
        )?;
        if documents.is_empty() {
            let mut artifacts = root_artifacts(&roots);
            artifacts.push(limitations_artifact(None, &config, &notes));
            return Ok(AnalysisResult {
                summary: Some(format!(
                    "未找到可解析的 Web 访问日志（扫描根：{}）。{}",
                    LOG_ROOTS.join("、"),
                    notes.join("；")
                )),
                nodes: result_nodes(),
                artifacts,
                timeline: Vec::new(),
                findings: Vec::new(),
            });
        }
        let source_summary = format!("检材卷 {}", scanned_roots.join("、"));
        Ok(build_result(&documents, &config, &notes, &source_summary))
    }
}

fn root_artifacts(roots: &[EvidenceRoot]) -> Vec<Artifact> {
    roots
        .iter()
        .map(|root| {
            let mut attributes = Attributes::new();
            attributes.insert("source.root", root.root_id.as_str());
            attributes.insert(format!("{NS}.root.kind"), root.kind.as_str());
            attributes.insert(format!("{NS}.root.size"), root.size);
            Artifact {
                artifact_type: format!("{NS}.root"),
                title: format!("卷 {}", root.root_id),
                value: None,
                attributes,
            }
        })
        .collect()
}

/// 文件入口与检材入口使用不同 analyzer 名，避免宿主判重复。
pub struct WebLogFile;
pub struct WebLogEvidence;

impl FileAnalyzer for WebLogFile {
    fn analyzer(&self) -> &str { ANALYZER_FILE }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> { WebLogAnalyzer.analyze(file) }
}

impl EvidenceAnalyzer for WebLogEvidence {
    fn analyzer(&self) -> &str { ANALYZER_EVIDENCE }
    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        WebLogAnalyzer.analyze_evidence(evidence)
    }
}

fn plugin() -> Plugin {
    Plugin::new(
        PLUGIN_ID,
        "Web访问日志注入参数检测",
        env!("CARGO_PKG_VERSION"),
    )
    .file_analyzer(WebLogFile)
    .evidence_analyzer(WebLogEvidence)
}

lovelycarve_plugin::export_plugin!(plugin);

/// Convenience for tests and the CLI: analyze raw bytes as one document.
pub fn analyze_bytes_for_test(
    bytes: &[u8],
    config: &Config,
) -> std::result::Result<AnalysisResult, String> {
    let parser = LineParser::new(config)?;
    let size = bytes.len() as u64;
    let Some((document, _)) =
        analyze_document(bytes, size, None, "test", "access.log", config, &parser)
    else {
        return Err("content does not look like an access log".into());
    };
    Ok(build_result(
        &[document],
        config,
        &[],
        "单文件分析 access.log",
    ))
}

/// Used by the CLI to print the text of a `Value`.
pub fn value_text(value: &Value) -> String {
    text(value)
}

/// Re-exported for the CLI report.
pub type Analyzed = Finished;
