//! Aggregation pipeline: parsed lines → per-`(path, param)` statistics →
//! windowed suspicious candidates.
//!
//! Pure Rust, no host access, so the whole pipeline is unit-testable.

use std::collections::{BTreeMap, BTreeSet};

use crate::detect::{
    family_hits, family_summary, family_totals, merge_hits, scan_windows, RequestRecord,
    ScanResult,
};
use crate::logline::{normalize_param_name, parse_query, parse_timestamp, split_target};
use crate::model::{
    truncate_chars, Config, Family, FamilyHits, LogEntry, TimestampParts,
};

/// Encoding chosen for one file after BOM/UTF-8 validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Gb18030,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::Gb18030 => "gb18030",
        }
    }
}

/// Decodes a log file: BOM first, then strict UTF-8, then GB18030 (a strict
/// superset of the GBK log files Chinese web servers emit). `replacement_count`
/// counts U+FFFD left by the decoder so truncated/illegal bytes stay visible.
pub fn decode_log(bytes: &[u8]) -> (String, Encoding, usize) {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        let (text, _) = encoding_rs::UTF_8.decode_without_bom_handling(rest);
        return (text.into_owned(), Encoding::Utf8, 0);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let (text, _) = encoding_rs::UTF_16LE.decode_without_bom_handling(rest);
        return finish_wide(text.into_owned(), Encoding::Utf16Le);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let (text, _) = encoding_rs::UTF_16BE.decode_without_bom_handling(rest);
        return finish_wide(text.into_owned(), Encoding::Utf16Be);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => return (text.to_owned(), Encoding::Utf8, 0),
        Err(error) if error.error_len().is_none() => {
            // Complete but unterminated final sequence: still UTF-8.
            return (String::from_utf8_lossy(bytes).into_owned(), Encoding::Utf8, 1);
        }
        Err(_) => {}
    }
    let (text, _) = encoding_rs::GB18030.decode_without_bom_handling(bytes);
    let text = text.into_owned();
    let replacements = text.matches('\u{FFFD}').count();
    (text, Encoding::Gb18030, replacements)
}

fn finish_wide(text: String, encoding: Encoding) -> (String, Encoding, usize) {
    let replacements = text.matches('\u{FFFD}').count();
    (text, encoding, replacements)
}

/// Line splitter that recognises `\n`, `\r\n` and `\r` and never splits
/// inside a UTF-16 code unit stream (those are decoded before splitting).
pub fn split_log_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        lines.push(line);
    }
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines
}

/// A line that could not be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnparsedSample {
    pub line_no: u64,
    pub reason: &'static str,
    pub text: String,
}

/// Per-`(path, param)` statistics.
#[derive(Clone, Debug)]
pub struct ParamAggregate {
    pub path: String,
    pub param: String,
    pub request_count: u64,
    pub methods: BTreeMap<String, u64>,
    /// Raw `[time]` text of the first / last occurrence (no reformatting).
    pub first_seen: Option<String>,
    /// Raw `[time]` text of the last occurrence.
    pub last_seen: Option<String>,
    /// Offsets of first/last occurrence on the log's own time axis.
    pub first_offset: Option<i64>,
    pub last_offset: Option<i64>,
    /// `(year, month)` pairs, so a year boundary is reported, not hidden.
    pub spans_years: BTreeSet<(i64, u32)>,
    pub distinct_client_ips: u64,
    /// Sorted `(status or None, count)`.
    pub status_distribution: Vec<(Option<u16>, u64)>,
    /// Family hits summed over every value exactly as sent (still `%XX`
    /// encoded) — the literal view of the same requests.
    pub raw_hit_families: FamilyHits,
    /// Family hits of every value of this parameter, whole file.
    pub hit_families: FamilyHits,
    pub sample_lines: Vec<SampleLine>,
    /// Raw (`%XX`) values seen, capped at `distinct_values_per_param`.
    pub raw_value_samples: Vec<String>,
    /// Decoded values paired positionally with `raw_value_samples`.
    pub decoded_value_samples: Vec<String>,
    pub window: ScanResult,
    /// Set when the pair is a candidate.
    pub suspicious: bool,
    /// Why it is (not) a candidate.
    pub verdict: String,
    pub confidence: f64,
    ips: BTreeSet<String>,
    records: Vec<RequestRecord>,
    /// Requests without a parsable timestamp (excluded from windows).
    pub undated: u64,
    window_first_time: Option<String>,
    window_first_nanos: Option<u128>,
    window_last_time: Option<String>,
    window_last_nanos: Option<u128>,
}

/// One sample request line for a parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleLine {
    pub line_no: u64,
    /// Line truncated to `sample_line_chars`.
    pub text: String,
    /// Bound timestamp as written.
    pub raw_time: String,
    pub status: Option<u16>,
    pub method: String,
    pub ip: String,
    /// Raw parameter value (still `%XX`-encoded) as sent.
    pub raw_value: String,
}

impl ParamAggregate {
    fn new(path: &str, param: &str, config: &Config) -> Self {
        Self {
            path: path.to_owned(),
            param: param.to_owned(),
            request_count: 0,
            methods: BTreeMap::new(),
            first_seen: None,
            last_seen: None,
            first_offset: None,
            last_offset: None,
            spans_years: BTreeSet::new(),
            distinct_client_ips: 0,
            status_distribution: Vec::new(),
            raw_hit_families: [0; 8],
            hit_families: [0; 8],
            sample_lines: Vec::with_capacity(config.samples_per_param),
            raw_value_samples: Vec::new(),
            decoded_value_samples: Vec::new(),
            window: ScanResult::default(),
            suspicious: false,
            verdict: String::new(),
            confidence: 0.0,
            ips: BTreeSet::new(),
            records: Vec::new(),
            undated: 0,
            window_first_time: None,
            window_first_nanos: None,
            window_last_time: None,
            window_last_nanos: None,
        }
    }
}

/// Result of one document.
#[derive(Clone, Debug)]
pub struct DocumentStats {
    pub total_lines: u64,
    pub parsed_lines: u64,
    pub unparsed_line_count: u64,
    pub formats: BTreeMap<&'static str, u64>,
    /// Rejected count per reason (`blank`/`format`/`request`/`time`).
    pub unparsed_reasons: BTreeMap<&'static str, u64>,
    pub unparsed_samples: Vec<UnparsedSample>,
    /// Truncation notes (file/line caps hit).
    pub notes: Vec<String>,
    pub first_time: Option<String>,
    pub last_time: Option<String>,
    pub spans_years: BTreeSet<(i64, u32)>,
    pub identifiers: BTreeSet<String>,
}

impl Default for DocumentStats {
    fn default() -> Self {
        Self {
            total_lines: 0,
            parsed_lines: 0,
            unparsed_line_count: 0,
            formats: BTreeMap::new(),
            unparsed_reasons: BTreeMap::new(),
            unparsed_samples: Vec::new(),
            notes: Vec::new(),
            first_time: None,
            last_time: None,
            spans_years: BTreeSet::new(),
            identifiers: BTreeSet::new(),
        }
    }
}

impl DocumentStats {
    pub fn format_label(&self) -> String {
        if self.formats.is_empty() {
            return "unknown".to_owned();
        }
        self.formats
            .iter()
            .map(|(format, count)| format!("{format}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// One aggregation group (all params on the same path).
#[derive(Clone, Debug)]
pub struct Group {
    pub path: String,
    pub params: BTreeMap<String, ParamAggregate>,
}

/// Aggregates every parsed line of one document.
pub struct Aggregator<'a> {
    config: &'a Config,
    pub document: DocumentStats,
    pub notes: Vec<String>,
    groups: BTreeMap<String, BTreeMap<String, ParamAggregate>>,
    first_offset: Option<i64>,
    last_offset: Option<i64>,
    entries: u64,
}

impl<'a> Aggregator<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            document: DocumentStats::default(),
            notes: Vec::new(),
            groups: BTreeMap::new(),
            first_offset: None,
            last_offset: None,
            entries: 0,
        }
    }

    /// Records one recognised line and the sample text it came from.
    pub fn push(&mut self, entry: &LogEntry, sample: &str) {
        self.document.parsed_lines += 1;
        *self
            .document
            .formats
            .entry(entry.format.as_str())
            .or_default() += 1;
        if let Some(user) = &entry.user {
            if self.document.identifiers.len() < 32 {
                self.document.identifiers.insert(user.clone());
            }
        }
        let parts = parse_timestamp(&entry.time);
        if let Some(parts) = &parts {
            let seconds = parts.linear_seconds();
            self.first_offset = Some(self.first_offset.map_or(seconds, |low| low.min(seconds)));
            self.last_offset = Some(self.last_offset.map_or(seconds, |high| high.max(seconds)));
            self.document.spans_years.insert((parts.year, parts.month));
        }
        let (path, query) = split_target(&entry.target);
        if entry.target.is_empty() || path.is_empty() {
            return;
        }
        let path = path.to_owned();
        let pairs = query.map(parse_query).unwrap_or_default();
        // Per-request occurrence index of each key, used to pair every
        // decoded value with its own raw (still encoded) value.
        let mut occurrence: BTreeMap<String, usize> = BTreeMap::new();
        for (name, value) in pairs {
            let name = normalize_param_name(&name);
            if name.is_empty() {
                continue;
            }
            let index = occurrence.entry(name.clone()).or_insert(0);
            let position = *index;
            *index += 1;
            let group = self.groups.entry(path.clone()).or_default();
            if !group.contains_key(&name) {
                group.insert(
                    name.clone(),
                    ParamAggregate::new(&path, &name, self.config),
                );
            }
            let Some(param) = group.get_mut(&name) else {
                continue;
            };
            add_occurrence(
                self.config,
                param,
                entry,
                parts.as_ref(),
                &name,
                &value,
                position,
                sample,
            );
            self.entries += 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_occurrence(
    config: &Config,
    param: &mut ParamAggregate,
    entry: &LogEntry,
    parts: Option<&TimestampParts>,
    name: &str,
    value: &[u8],
    position: usize,
    sample: &str,
) {
    // Every occurrence counts; statistics that must be per-request are taken
    // from the first occurrence only (the IP set and record vector would
    // otherwise double count a repeated key inside one request).
    let first_occurrence = position == 0;
    let raw_value = raw_values_of(entry, name)
        .into_iter()
        .nth(position)
        .unwrap_or_default();
    param.request_count += 1;
    *param.methods.entry(entry.method.clone()).or_default() += 1;
    if first_occurrence {
        param.ips.insert(entry.ip.clone());
        param.distinct_client_ips = param.ips.len() as u64;
        if param.sample_lines.len() < config.samples_per_param {
            param.sample_lines.push(SampleLine {
                line_no: entry.line_no,
                text: truncate_chars(sample, config.sample_line_chars),
                raw_time: entry.time.clone(),
                status: entry.status,
                method: entry.method.clone(),
                ip: entry.ip.clone(),
                raw_value: raw_value.clone(),
            });
        }
        if !param.raw_value_samples.contains(&raw_value)
            && param.raw_value_samples.len() < config.distinct_values_per_param
        {
            param.raw_value_samples.push(raw_value.clone());
            param
                .decoded_value_samples
                .push(truncate_chars(&String::from_utf8_lossy(value), 300));
        }
    }
    let hits = family_hits(value);
    merge_hits(&mut param.hit_families, &hits);
    // The same value exactly as sent, for the "raw encoded" family view.
    merge_hits(
        &mut param.raw_hit_families,
        &family_hits(raw_value.as_bytes()),
    );
    match parts {
        Some(parts) => {
            let seconds = parts.linear_seconds();
            let nanos = seconds as u128 * 1_000_000_000 + parts.nanos as u128;
            let first = param.window_first_nanos.map_or(true, |current| nanos < current);
            if first {
                param.window_first_time = Some(entry.time.clone());
                param.window_first_nanos = Some(nanos);
                param.first_seen = param.window_first_time.clone();
                param.first_offset = Some(seconds);
            }
            if param
                .window_last_nanos
                .map_or(true, |current| nanos > current)
            {
                param.window_last_time = Some(entry.time.clone());
                param.window_last_nanos = Some(nanos);
                param.last_seen = param.window_last_time.clone();
                param.last_offset = Some(seconds);
            }
            param.spans_years.insert((parts.year, parts.month));
            if first_occurrence {
                param.records.push(RequestRecord {
                    time: parts.clone(),
                    ip: entry.ip.clone(),
                    method: entry.method.clone(),
                    status: entry.status,
                    hits,
                });
            }
        }
        None => param.undated += 1,
    }
    match param
        .status_distribution
        .iter_mut()
        .find(|(status, _)| *status == entry.status)
    {
        Some((_, count)) => *count += 1,
        None => param.status_distribution.push((entry.status, 1)),
    }
}

impl<'a> Aggregator<'a> {
    /// Records one rejected line.
    pub fn reject(&mut self, line_no: u64, reason: &'static str, line: &str) {
        self.document.unparsed_line_count += 1;
        *self.document.unparsed_reasons.entry(reason).or_default() += 1;
        if self.document.unparsed_samples.len() < self.config.max_unparsed_samples {
            self.document.unparsed_samples.push(UnparsedSample {
                line_no,
                reason,
                text: truncate_chars(line, self.config.sample_line_chars),
            });
        }
    }

    /// Applies the suspicion rule and returns the groups sorted by path.
    pub fn finish(mut self) -> Finished {
        self.document.notes.append(&mut self.notes);
        let mut suspicion_count = 0;
        for params in self.groups.values_mut() {
            for param in params.values_mut() {
                param.status_distribution.sort_by_key(|(status, _)| *status);
                let scan = scan_windows(&mut param.records, self.config);
                param.window = scan.clone();
                let (families_hit, total_hits) = family_totals(&param.hit_families);
                param.confidence = confidence(self.config, &scan, families_hit, total_hits);
                param.suspicious = scan.best.qualifies(self.config);
                param.verdict = verdict(self.config, param, families_hit, total_hits);
                if param.suspicious {
                    suspicion_count += 1;
                }
            }
        }
        let mut groups: Vec<Group> = self
            .groups
            .into_iter()
            .map(|(path, params)| Group { path, params })
            .collect();
        groups.sort_by(|a, b| a.path.cmp(&b.path));
        Finished {
            document: self.document,
            groups,
            suspicion_count,
            entries: self.entries,
            first_offset: self.first_offset,
            last_offset: self.last_offset,
        }
    }
}

/// Raw (`%XX`-encoded) values of `name` in one request target, in order.
fn raw_values_of(entry: &LogEntry, name: &str) -> Vec<String> {
    let (_, query) = split_target(&entry.target);
    let Some(query) = query else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for segment in query.split('#').next().unwrap_or("").split('&') {
        let Some((key, value)) = segment.split_once('=') else {
            continue;
        };
        let key = String::from_utf8_lossy(&crate::logline::percent_decode(key))
            .trim()
            .to_lowercase();
        if key == name {
            values.push(truncate_chars(value, 300));
        }
    }
    values
}

fn confidence(config: &Config, scan: &ScanResult, families_hit: usize, total_hits: u64) -> f64 {
    let best = &scan.best;
    if !best.qualifies(config) {
        return 0.0;
    }
    let mut score = 0.30;
    score += 0.10 * families_hit as f64;
    score += match best.window_requests {
        0..=4 => 0.0,
        5..=9 => 0.05,
        10..=49 => 0.10,
        50..=199 => 0.18,
        _ => 0.25,
    };
    if best.window_ips <= 1 {
        score += 0.15;
    } else if best.window_ips <= config.max_distinct_ips {
        score += 0.08;
    }
    let window = best.window_requests.max(1) as f64;
    if total_hits as f64 >= window {
        score += 0.10;
    }
    if scan.window_necessary {
        score += 0.05;
    }
    if best.window_first_seen == best.window_last_seen {
        score += 0.05;
    }
    (score.clamp(0.0, 1.0) * 100.0).round() / 100.0
}

fn verdict(config: &Config, param: &ParamAggregate, families_hit: usize, total_hits: u64) -> String {
    let best = &param.window.best;
    let families = family_summary(&best.window_families);
    if param.suspicious {
        let mut reasons = vec![
            format!(
                "窗口 {}s 内该参数 {} 次请求 ≥ 阈值 {}",
                config.window_seconds, best.window_requests, config.min_requests
            ),
            format!(
                "窗口内客户端 IP {} 个 ≤ 上限 {}",
                best.window_ips, config.max_distinct_ips
            ),
            format!(
                "命中 {} 个特征族({}) ≥ 阈值 {}",
                families_hit, families, config.min_families
            ),
        ];
        if param.window.window_necessary {
            reasons.push("整个文件的请求集合不满足同一窗口条件，短时突发是必要条件".into());
        } else {
            reasons.push("整个文件的请求集合本身也满足条件，短时窗口不是必要条件".into());
        }
        if let (Some(first), Some(last)) = (&best.window_first_seen, &best.window_last_seen) {
            reasons.push(format!("窗口时间区间原样保留：[{first}] → [{last}]"));
        }
        if param.undated > 0 {
            reasons.push(format!("{} 条请求时间戳不可解析，未参与窗口判定", param.undated));
        }
        reasons.push(format!(
            "解码后载荷样例：{}；匹配在 %XX 解码后进行，原文另行保留",
            param
                .decoded_value_samples
                .first()
                .cloned()
                .unwrap_or_else(|| "无".into())
        ));
        return reasons.join("；");
    }
    let mut reasons = Vec::new();
    if param.request_count < config.min_requests || best.window_requests < config.min_requests {
        reasons.push(format!(
            "请求数不足：窗口内 {} 次 < 阈值 {}",
            best.window_requests, config.min_requests
        ));
    }
    if best.window_ips > config.max_distinct_ips {
        reasons.push(format!(
            "窗口内客户端 IP {} 个 > 上限 {}",
            best.window_ips, config.max_distinct_ips
        ));
    }
    if families_hit < config.min_families {
        reasons.push(format!(
            "命中特征族 {} 个 ({}) < 阈值 {}，总命中 {} 次",
            families_hit, families, config.min_families, total_hits
        ));
    }
    if param.undated > 0 {
        reasons.push(format!(
            "{} 条请求的时间戳无法解析，未参与窗口判定",
            param.undated
        ));
    }
    if reasons.is_empty() {
        reasons.push("不满足可疑判定条件".into());
    }
    reasons.join("；")
}

/// Aggregation output for one document.
#[derive(Debug)]
pub struct Finished {
    pub document: DocumentStats,
    pub groups: Vec<Group>,
    pub suspicion_count: usize,
    pub entries: u64,
    pub first_offset: Option<i64>,
    pub last_offset: Option<i64>,
}

impl Finished {
    pub fn all_params(&self) -> impl Iterator<Item = &ParamAggregate> {
        self.groups
            .iter()
            .flat_map(|group| group.params.values())
    }

    /// All params with `path`/`param` resolved, sorted by request count.
    pub fn sorted_by_requests(&self) -> Vec<&ParamAggregate> {
        let mut params: Vec<&ParamAggregate> = self.all_params().collect();
        params.sort_by(|a, b| {
            b.suspicious
                .cmp(&a.suspicious)
                .then(b.request_count.cmp(&a.request_count))
                .then(a.path.cmp(&b.path))
                .then(a.param.cmp(&b.param))
        });
        params
    }

    /// Candidates sorted by confidence then request count.
    pub fn suspicious(&self) -> Vec<&ParamAggregate> {
        let mut candidates: Vec<&ParamAggregate> = self
            .all_params()
            .filter(|param| param.suspicious)
            .collect();
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.window.best.window_requests.cmp(&a.window.best.window_requests))
                .then(a.path.cmp(&b.path))
                .then(a.param.cmp(&b.param))
        });
        candidates
    }

    /// Distinct raw time strings of the whole file (from first/last offsets).
    pub fn documents_time_span(&self) -> (Option<i64>, Option<i64>) {
        (self.first_offset, self.last_offset)
    }
}

/// Families with counts, in family order.
pub fn families_as_pairs(hits: &FamilyHits) -> Vec<(Family, u64)> {
    crate::detect::family_entries(hits)
}

/// Convenience: parses and aggregates a whole document.
pub fn analyze_text(
    text: &str,
    config: &Config,
    parser: &crate::logline::LineParser,
    truncation: Option<&str>,
) -> Finished {
    let mut aggregator = Aggregator::new(config);
    if let Some(note) = truncation {
        aggregator.notes.push(note.to_owned());
    }
    let lines = split_log_lines(text);
    aggregator.document.total_lines = lines.len() as u64;
    for (index, line) in lines.iter().enumerate() {
        let line_no = index as u64 + 1;
        match parser.parse(line_no, line) {
            Ok(entry) => aggregator.push(&entry, line),
            Err((reason, _)) => aggregator.reject(line_no, reason.as_str(), line),
        }
    }
    aggregator.finish()
}
