//! Shared data types of the web-access-log analyzer.
//!
//! Everything here is produced by the pure parsing layer
//! ([`crate::logline`], [`crate::aggregate`], [`crate::detect`]) and only
//! afterwards projected onto LovelyCarve artifacts by [`crate::analyzer`],
//! so the whole detection pipeline is unit-testable without a host.

use std::fmt;

/// Detection parameters. Every value is either a documented default or
/// supplied by the operator; nothing is tied to a specific case.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Minimum number of requests inside the window for a candidate.
    pub min_requests: u64,
    /// Window length in seconds as written in the log (timezone-independent).
    pub window_seconds: i64,
    /// Upper bound of distinct client IPs inside the window.
    pub max_distinct_ips: u64,
    /// Minimum number of distinct feature families.
    pub min_families: usize,
    /// Optional field-mapping overrides for non-standard line layouts.
    pub mapping: Mapping,
    /// Bytes kept per sample line.
    pub sample_line_chars: usize,
    /// Sample lines kept per candidate / aggregate record.
    pub samples_per_param: usize,
    /// Distinct raw parameter values remembered per (path, param).
    pub distinct_values_per_param: usize,
    /// Aggregation records kept in the result (lowest requests dropped first).
    pub max_aggregate_records: usize,
    /// Unparsed line samples kept.
    pub max_unparsed_samples: usize,
    /// Discovery hops below the fixed log roots.
    pub scan_depth: usize,
    /// Files per evidence volume.
    pub max_files: usize,
    /// Bytes per log file.
    pub max_file_bytes: u64,
    /// Files skipped when they do not look like access logs.
    pub require_log_text: bool,
}

pub const DEFAULT_SAMPLE_LINE_CHARS: usize = 300;

impl Default for Config {
    fn default() -> Self {
        Self {
            min_requests: 5,
            window_seconds: 600,
            max_distinct_ips: 3,
            min_families: 2,
            mapping: Mapping::default(),
            sample_line_chars: DEFAULT_SAMPLE_LINE_CHARS,
            samples_per_param: 3,
            distinct_values_per_param: 8,
            max_aggregate_records: 500,
            max_unparsed_samples: 20,
            scan_depth: 6,
            max_files: 400,
            max_file_bytes: 128 * 1024 * 1024,
            require_log_text: true,
        }
    }
}

impl Config {
    /// Rejects values that would make the detection meaningless.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_requests == 0 {
            return Err("min_requests 必须 ≥ 1".into());
        }
        if self.window_seconds <= 0 {
            return Err("window_seconds 必须 > 0".into());
        }
        if self.min_families == 0 || self.min_families > Family::ALL.len() {
            return Err(format!(
                "min_families 必须在 1..={} 之间",
                Family::ALL.len()
            ));
        }
        if !(16..=4096).contains(&self.sample_line_chars) {
            return Err("sample_line_chars 必须在 16..=4096 之间".into());
        }
        if self.samples_per_param == 0 || self.samples_per_param > 20 {
            return Err("samples_per_param 必须在 1..=20 之间".into());
        }
        if self.distinct_values_per_param == 0 || self.distinct_values_per_param > 1000 {
            return Err("distinct_values_per_param 必须在 1..=1000 之间".into());
        }
        if self.max_aggregate_records == 0 || self.max_aggregate_records > 10_000 {
            return Err("max_aggregate_records 必须在 1..=10000 之间".into());
        }
        if self.max_unparsed_samples == 0 || self.max_unparsed_samples > 500 {
            return Err("max_unparsed_samples 必须在 1..=500 之间".into());
        }
        if self.scan_depth > 16 {
            return Err("scan_depth 必须 ≤ 16".into());
        }
        if self.max_files == 0 || self.max_files > 4096 {
            return Err("max_files 必须在 1..=4096 之间".into());
        }
        if self.max_file_bytes < 1024 || self.max_file_bytes > 1024 * 1024 * 1024 {
            return Err("max_file_bytes 必须在 1024..=1GiB 之间".into());
        }
        self.mapping.validate()
    }
}

/// Optional override of the line layout for logs that do not follow the
/// standard prefix. Any override replaces the built-in rule for that field;
/// `None` means "built-in rule".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mapping {
    /// Match the client address (first capture group).
    pub ip: Option<String>,
    /// Match the bracketed timestamp without the brackets.
    pub time: Option<String>,
    /// Match the quoted request line (`METHOD TARGET PROTOCOL`).
    pub request: Option<String>,
    /// Match the status code.
    pub status: Option<String>,
    /// Match the response size; `-` becomes 0.
    pub bytes: Option<String>,
    /// Match the quoted Referer.
    pub referer: Option<String>,
    /// Match the quoted User-Agent.
    pub user_agent: Option<String>,
}

impl Mapping {
    /// (field name, regular expression, capture group) of every override.
    /// Empty strings mean "no override".
    pub fn rules(&self) -> Vec<(&'static str, &str, usize)> {
        let mut rules = Vec::new();
        for (name, pattern) in [
            ("ip", self.ip.as_deref()),
            ("time", self.time.as_deref()),
            ("request", self.request.as_deref()),
            ("status", self.status.as_deref()),
            ("bytes", self.bytes.as_deref()),
            ("referer", self.referer.as_deref()),
            ("user_agent", self.user_agent.as_deref()),
        ] {
            if let Some(pattern) = pattern.filter(|pattern| !pattern.is_empty()) {
                rules.push((name, pattern, 1));
            }
        }
        rules
    }

    pub fn is_custom(&self) -> bool {
        !self.rules().is_empty()
    }

    fn validate(&self) -> Result<(), String> {
        let checks: [(&str, Option<&str>); 7] = [
            ("ip", self.ip.as_deref()),
            ("time", self.time.as_deref()),
            ("request", self.request.as_deref()),
            ("status", self.status.as_deref()),
            ("bytes", self.bytes.as_deref()),
            ("referer", self.referer.as_deref()),
            ("user_agent", self.user_agent.as_deref()),
        ];
        for (field, pattern) in checks {
            // An empty string means "no override"; only non-empty values are
            // compiled and validated.
            let Some(pattern) = pattern.filter(|pattern| !pattern.is_empty()) else {
                continue;
            };
            if pattern.len() > 512 {
                return Err(format!(
                    "字段映射 {field} 的正则长度超过 512 字符：覆盖正则应保持简洁"
                ));
            }
            let compiled = regex::Regex::new(pattern)
                .map_err(|error| format!("字段映射 {field} 的正则无效：{error}"))?;
            if compiled.captures_len() < 2 {
                return Err(format!(
                    "字段映射 {field} 的正则必须包含至少 1 个捕获组，用于取值"
                ));
            }
            if field == "request" && !compiled.capture_names().any(|name| name.is_some()) {
                return Err(
                    "字段映射 request 必须使用命名捕获组（如 (?P<req>…)）或单捕获组整体匹配请求行"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

/// Log formats the tokenizer recognises.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Format {
    /// `ip - - [time] "req" status bytes "referer" "ua"` (+ optional `"xff"`/other tail).
    Combined,
    /// `ip - - [time] "req" status bytes`.
    Common,
    /// Anything else that still yields a request line in the standard prefix.
    Other,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Combined => "combined",
            Self::Common => "common",
            Self::Other => "other",
        }
    }
}

/// One recognised line.
#[derive(Clone, Debug, PartialEq)]
pub struct LogEntry {
    /// 1-based line number in the decoded text.
    pub line_no: u64,
    pub format: Format,
    pub ip: String,
    pub ident: Option<String>,
    pub user: Option<String>,
    /// Timestamp exactly as written between the brackets.
    pub time: String,
    pub method: String,
    /// Request target exactly as written (`path?rawQuery`).
    pub target: String,
    pub protocol: Option<String>,
    pub status: Option<u16>,
    pub bytes: Option<u64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

/// One decoded query parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Param {
    /// Normalised (trimmed, lower-cased) parameter name.
    pub name: String,
    /// Value after `%XX` decoding, raw bytes as they were sent.
    pub value: Vec<u8>,
}

/// Time precision of a raw log timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TimePrecision {
    Seconds,
    Millis,
    Micros,
}

impl TimePrecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seconds => "second",
            Self::Millis => "millisecond",
            Self::Micros => "microsecond",
        }
    }
}

/// A log timestamp split into fields; the original text is kept by the
/// caller and is the only value ever compared or displayed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampParts {
    /// `day/Mon/year:hh:mm:ss` and fraction without brackets.
    pub without_offset: String,
    pub year: i64,
    pub month: u32,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    pub nanos: u64,
    pub precision: TimePrecision,
    /// `Some` when the log carries an explicit offset (`+0800`, `+08:00`, `Z`).
    pub offset: Option<(i64, i64)>,
}

impl TimestampParts {
    /// Seconds on a timezone-free axis (the log's own local time). The
    /// declared offset is deliberately *not* applied: a window is measured
    /// inside one log scale, and no year completion is attempted either.
    pub fn linear_seconds(&self) -> i64 {
        let days = days_from_civil(self.year, self.month, self.day);
        days * 86_400 + self.hour * 3600 + self.minute * 60 + self.second
    }

    pub fn linear_nanos(&self) -> u64 {
        (self.linear_seconds() as u128 * 1_000_000_000 + self.nanos as u128) as u64
    }
}

impl fmt::Display for TimestampParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.without_offset)
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`; the year is not clamped, so 4-digit log years still
/// round-trip).
pub fn days_from_civil(year: i64, month: u32, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// SQL-injection feature families. Names and patterns are the documented,
/// explainable set from the requirement; they are user-visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Family {
    /// `waitfor delay`, `pg_sleep`, `sleep(`, `benchmark(`
    TimeFunc,
    /// `order\s+by\s+\d+`
    OrderBy,
    /// `union\s+(all\s+)?select`
    UnionSelect,
    /// `information_schema`, `sysobjects`, `xp_cmdshell`
    Metadata,
    /// `extractvalue(`, `updatexml(`, `load_file(`
    Extract,
    /// `--\s`, `#`, `/*`
    CommentTrunc,
    /// `;\s*(select|insert|update|delete|drop)`
    Stacked,
    /// `'.*or\s+1=1`
    QuoteEscape,
}

impl Family {
    pub const ALL: [Self; 8] = [
        Self::TimeFunc,
        Self::OrderBy,
        Self::UnionSelect,
        Self::Metadata,
        Self::Extract,
        Self::CommentTrunc,
        Self::Stacked,
        Self::QuoteEscape,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::TimeFunc => "time-func",
            Self::OrderBy => "order-by",
            Self::UnionSelect => "union-select",
            Self::Metadata => "metadata",
            Self::Extract => "extract",
            Self::CommentTrunc => "comment-trunc",
            Self::Stacked => "stacked",
            Self::QuoteEscape => "quote-escape",
        }
    }

    /// The explainable regular expression of the family.
    pub fn pattern(self) -> &'static str {
        match self {
            Self::TimeFunc => r"waitfor\s+delay|pg_sleep|sleep\s*\(|benchmark\s*\(",
            Self::OrderBy => r"order\s+by\s+\d+",
            Self::UnionSelect => r"union\s+(all\s+)?select",
            Self::Metadata => r"information_schema|sysobjects|xp_cmdshell",
            Self::Extract => r"extractvalue\s*\(|updatexml\s*\(|load_file\s*\(",
            Self::CommentTrunc => r"--\s|#|/\*",
            Self::Stacked => r";\s*(select|insert|update|delete|drop)",
            Self::QuoteEscape => r"'.*or\s+1=1",
        }
    }

    #[allow(dead_code)]
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Family hits of one parameter value, in [`Family::ALL`] order.
pub type FamilyHits = [u64; 8];

/// Truncate a sample to `limit` characters on a character boundary.
pub fn truncate_chars(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((index, _)) => format!("{}…", &text[..index]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation_rejects_degenerate_parameters() {
        assert!(Config::default().validate().is_ok());
        let mut config = Config::default();
        config.min_requests = 0;
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.window_seconds = -5;
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.min_families = 9;
        assert!(config.validate().is_err());
        // `status` is read with its first capture group, so a pattern without
        // one is rejected.
        let mut config = Config::default();
        config.mapping.status = Some(r"no-group-at-all".into());
        assert!(config.validate().is_err());
        // Invalid regex syntax is rejected too.
        let mut config = Config::default();
        config.mapping.request = Some("(".into());
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.mapping.status = Some("".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn family_patterns_are_valid_and_have_stable_names() {
        for family in Family::ALL {
            regex::Regex::new(family.pattern()).expect("family pattern");
        }
        assert_eq!(Family::ALL.len(), 8);
        assert_eq!(Family::CommentTrunc.name(), "comment-trunc");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate_chars("abcdef", 3), "abc…");
        assert_eq!(truncate_chars("中文字符", 2), "中文…");
        assert_eq!(truncate_chars("abc", 10), "abc");
    }

    #[test]
    fn civil_day_arithmetic_is_exact_across_years() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(
            days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 29),
            1
        );
        assert_eq!(
            days_from_civil(2020, 1, 1) - days_from_civil(2019, 1, 1),
            365
        );
        assert_eq!(
            days_from_civil(2021, 1, 1) - days_from_civil(2020, 1, 1),
            366
        );
        assert_eq!(
            days_from_civil(2025, 1, 1) - days_from_civil(2024, 12, 31),
            1
        );
    }
}
