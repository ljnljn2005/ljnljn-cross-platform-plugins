//! Line-level parsing: the access-log layout, timestamps, and URL decoding.
//!
//! The layout follows the Apache/Nginx conventions the requirement names:
//!
//! ```text
//! 203.0.113.7 - - [12/Jan/2024:03:04:05 +0800] "GET /a?b=1 HTTP/1.1" 200 512 "-" "UA"
//! ```
//!
//! `common` stops after the status and byte count, `combined` appends the
//! quoted Referer and User-Agent; trailing extras (`"X-Forwarded-For"`) are
//! tolerated in `combined`. Timestamps are kept verbatim: no year
//! completion, no timezone normalisation.

use regex::Regex;
use std::sync::OnceLock;

use crate::model::{Config, Format, LogEntry, Mapping, TimePrecision, TimestampParts};

/// Why a line could not be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// Empty or whitespace-only.
    Blank,
    /// The standard prefix did not reach a quoted request line.
    Format,
    /// Prefix matched but the request line is unusable.
    Request,
    /// The timestamp between the brackets is not `dd/Mon/yyyy:hh:mm:ss`.
    Time,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blank => "blank",
            Self::Format => "format",
            Self::Request => "request",
            Self::Time => "time",
        }
    }
}

/// Parsed line or the failure reason.
pub type Parsed = Result<LogEntry, (Reject, String)>;

fn standard_prefix() -> &'static Regex {
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    PREFIX.get_or_init(|| {
        Regex::new(
            r#"^(?P<ip>\S+)[ \t]+(?P<ident>\S+)[ \t]+(?P<user>\S+)[ \t]+\[(?P<time>[^\]]*)\][ \t]+"(?P<req>(?:[^"\\]|\\.)*)""#,
        )
        .expect("standard prefix pattern")
    })
}

fn status_bytes_tail() -> &'static Regex {
    static TAIL: OnceLock<Regex> = OnceLock::new();
    TAIL.get_or_init(|| {
        Regex::new(r"^[ \t]+(?P<status>\d{3})[ \t]+(?P<bytes>\S+)").expect("status/bytes pattern")
    })
}

fn quoted_field_tail() -> &'static Regex {
    static TAIL: OnceLock<Regex> = OnceLock::new();
    TAIL.get_or_init(|| {
        Regex::new(r#"^[ \t]+"(?P<value>(?:[^"\\]|\\.)*)""#).expect("quoted field pattern")
    })
}

fn timestamp_pattern() -> &'static Regex {
    static STAMP: OnceLock<Regex> = OnceLock::new();
    STAMP.get_or_init(|| {
        Regex::new(
            r"^(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:[.,](?P<frac>\d{1,9}))?(?: *\[?(?P<tz>[+-]\d{2}:?\d{2}|[Zz])\]?)?$",
        )
        .expect("timestamp pattern")
    })
}

/// Compiled field-mapping overrides.
pub struct FieldMap {
    rules: Vec<(Field, Regex)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Field {
    Ip,
    Time,
    Request,
    Status,
    Bytes,
    Referer,
    UserAgent,
}

impl Field {
    #[allow(dead_code)]
    fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Time => "time",
            Self::Request => "request",
            Self::Status => "status",
            Self::Bytes => "bytes",
            Self::Referer => "referer",
            Self::UserAgent => "user_agent",
        }
    }

    fn of(name: &str) -> Option<Self> {
        Some(match name {
            "ip" => Self::Ip,
            "time" => Self::Time,
            "request" => Self::Request,
            "status" => Self::Status,
            "bytes" => Self::Bytes,
            "referer" => Self::Referer,
            "user_agent" => Self::UserAgent,
            _ => return None,
        })
    }
}

impl FieldMap {
    pub fn new(mapping: &Mapping) -> Result<Self, String> {
        let mut rules = Vec::new();
        for (name, pattern, _) in mapping.rules() {
            let field = Field::of(name).ok_or_else(|| format!("未知字段映射 {name}"))?;
            let regex = Regex::new(pattern).map_err(|error| format!("{name}: {error}"))?;
            rules.push((field, regex));
        }
        Ok(Self { rules })
    }

    pub fn is_custom(&self) -> bool {
        !self.rules.is_empty()
    }

    /// First capture group of the override (the convention validated by
    /// `Mapping::validate`); `-` and empty values mean "absent".
    fn get(&self, field: Field, line: &str) -> Option<String> {
        let (_, regex) = self.rules.iter().find(|(known, _)| *known == field)?;
        let captures = regex.captures(line)?;
        let match_ = captures
            .get(1)
            .or_else(|| captures.get(0))
            .map(|found| found.as_str())?
            .trim();
        if match_.is_empty() || match_ == "-" {
            None
        } else {
            Some(match_.to_owned())
        }
    }
}

/// Parses one line; `line_no` is 1-based.
pub fn parse_line(line_no: u64, line: &str, fields: &FieldMap) -> Parsed {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return Err((Reject::Blank, String::new()));
    }
    if fields.is_custom() {
        return parse_custom(line_no, line, fields);
    }
    parse_standard(line_no, line)
}

fn parse_standard(line_no: u64, line: &str) -> Parsed {
    let captures = standard_prefix()
        .captures(line)
        .ok_or_else(|| (Reject::Format, String::new()))?;
    let ip = captures.name("ip").map(|m| m.as_str()).unwrap_or("");
    if ip.is_empty() {
        return Err((Reject::Format, String::new()));
    }
    let time = captures.name("time").map(|m| m.as_str()).unwrap_or("");
    let request = captures.name("req").map(|m| m.as_str()).unwrap_or("");
    let rest = &line[captures.get(0).map(|m| m.end()).unwrap_or(line.len())..];
    let parsed = parse_request(request)?;
    if parse_timestamp(time).is_none() {
        return Err((Reject::Time, String::new()));
    }
    let tail = status_bytes_tail().captures(rest);
    let has_status = tail.is_some();
    let status = tail
        .as_ref()
        .and_then(|c| c.name("status"))
        .and_then(|m| m.as_str().parse::<u16>().ok());
    let bytes = tail
        .as_ref()
        .and_then(|c| c.name("bytes"))
        .map(|m| m.as_str())
        .and_then(parse_size);

    let remaining = match &tail {
        Some(captures) => &rest[captures.get(0).map(|m| m.end()).unwrap_or(rest.len())..],
        None => rest,
    };
    let (quoted_fields, trailing_text, referer, user_agent) = quoted_sequence(remaining);
    // `common` ends right after the byte count; `combined` carries the quoted
    // Referer/User-Agent pair (`-` still counts as the field being present);
    // an extra quoted tail such as X-Forwarded-For is tolerated. Anything else
    // is a layout the requirement does not name and is reported as `other`.
    let format = if !has_status {
        if quoted_fields > 0 {
            Format::Other
        } else {
            return Err((Reject::Format, String::new()));
        }
    } else if trailing_text || quoted_fields == 1 {
        Format::Other
    } else if quoted_fields == 0 {
        Format::Common
    } else {
        Format::Combined
    };
    Ok(build_entry(
        line_no,
        format,
        ip,
        captures.name("ident"),
        captures.name("user"),
        time,
        parsed,
        status,
        bytes,
        referer,
        user_agent,
    ))
}

/// Quoted fields after the status/byte pair: `"referer" "ua" [extras]`.
/// Returns `(quoted field count, unused trailing text, referer, user_agent)`.
/// The count is positional, so a `-` referer still marks a `combined` layout;
/// `-` only turns the reported value into `None`.
fn quoted_sequence(rest: &str) -> (usize, bool, Option<String>, Option<String>) {
    let mut values = Vec::new();
    let mut cursor = rest;
    loop {
        let Some(captures) = quoted_field_tail().captures(cursor) else {
            break;
        };
        let whole = captures.get(0).map(|m| m.end()).unwrap_or(cursor.len());
        let value = captures.name("value").map(|m| m.as_str()).unwrap_or("");
        values.push(value.to_owned());
        cursor = &cursor[whole.min(cursor.len())..];
    }
    let referer = values.first().filter(|value| !is_dash(value)).cloned();
    let user_agent = values.get(1).filter(|value| !is_dash(value)).cloned();
    (
        values.len(),
        !cursor.trim().is_empty(),
        referer,
        user_agent,
    )
}

fn is_dash(value: &str) -> bool {
    let value = value.trim();
    value.is_empty() || value == "-"
}

fn parse_size(text: &str) -> Option<u64> {
    match text.trim() {
        "-" => Some(0),
        digits if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) => {
            digits.parse().ok()
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_entry(
    line_no: u64,
    format: Format,
    ip: &str,
    ident: Option<regex::Match<'_>>,
    user: Option<regex::Match<'_>>,
    time: &str,
    (method, target, protocol): (String, String, Option<String>),
    status: Option<u16>,
    bytes: Option<u64>,
    referer: Option<String>,
    user_agent: Option<String>,
) -> LogEntry {
    LogEntry {
        line_no,
        format,
        ip: ip.to_owned(),
        ident: ident.map(|m| m.as_str().to_owned()).filter(|v| !is_dash(v)),
        user: user.map(|m| m.as_str().to_owned()).filter(|v| !is_dash(v)),
        time: time.to_owned(),
        method,
        target,
        protocol,
        status,
        bytes,
        referer,
        user_agent,
    }
}

/// `METHOD TARGET [PROTOCOL]` → parts. A request line without a method
/// (only a target) is accepted when it starts with `/`.
fn parse_request(request: &str) -> Result<(String, String, Option<String>), (Reject, String)> {
    let mut parts = request.split_whitespace();
    let first = parts.next().unwrap_or("");
    if first.starts_with('/') {
        return Ok((String::new(), first.to_owned(), None));
    }
    if first.is_empty() {
        return Err((Reject::Request, String::new()));
    }
    let target = parts
        .next()
        .ok_or_else(|| (Reject::Request, String::new()))?
        .to_owned();
    let protocol = parts
        .next()
        .filter(|value| value.starts_with("HTTP/"))
        .map(str::to_owned);
    Ok((first.to_ascii_uppercase(), target, protocol))
}

/// Field-mapping mode: every overridden field is taken from its pattern,
/// fields without an override keep the standard rule.
fn parse_custom(line_no: u64, line: &str, fields: &FieldMap) -> Parsed {
    let ip = fields
        .get(Field::Ip, line)
        .ok_or_else(|| (Reject::Format, String::new()))?;
    let time = fields.get(Field::Time, line).unwrap_or_default();
    if !time.is_empty() && parse_timestamp(&time).is_none() {
        return Err((Reject::Time, String::new()));
    }
    let (method, target, protocol) = match fields.get(Field::Request, line) {
        Some(request) => parse_request(&request)?,
        None => {
            let captures = standard_prefix()
                .captures(line)
                .ok_or_else(|| (Reject::Request, String::new()))?;
            parse_request(captures.name("req").map(|m| m.as_str()).unwrap_or(""))?
        }
    };
    let status = fields
        .get(Field::Status, line)
        .and_then(|value| value.parse::<u16>().ok());
    let bytes = fields
        .get(Field::Bytes, line)
        .and_then(|value| parse_size(&value));
    Ok(LogEntry {
        line_no,
        format: Format::Other,
        ip,
        ident: None,
        user: None,
        time,
        method,
        target,
        protocol,
        status,
        bytes,
        referer: fields.get(Field::Referer, line),
        user_agent: fields.get(Field::UserAgent, line),
    })
}

/// URL decoding: `%XX` → byte, `+` → space. Invalid escapes are kept
/// literally so a truncated payload is still searchable.
pub fn percent_decode(raw: &str) -> Vec<u8> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Splits a request target into `(path, rawQuery)` at the first `?`.
pub fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// Parses `a=1&b=2&a=3` into decoded `(name, value)` pairs in order.
/// Fragments after `#` are dropped; empty segments and valueless flags are
/// skipped. Every duplicate is kept.
pub fn parse_query(raw: &str) -> Vec<(String, Vec<u8>)> {
    let raw = raw.split('#').next().unwrap_or("");
    let mut pairs = Vec::new();
    for segment in raw.split('&') {
        if segment.is_empty() {
            continue;
        }
        let Some((name, value)) = segment.split_once('=') else {
            continue;
        };
        let name = String::from_utf8_lossy(&percent_decode(name))
            .trim()
            .to_owned();
        if name.is_empty() {
            continue;
        }
        pairs.push((name, percent_decode(value)));
    }
    pairs
}

/// Normalised parameter name: trimmed and lower-cased.
pub fn normalize_param_name(name: &str) -> String {
    name.trim().to_lowercase()
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Parses a bracketed time value as written by Apache/Nginx. Returns `None`
/// for anything that is not `dd/Mon/yyyy:hh:mm:ss[.frac][ offset]`.
pub fn parse_timestamp(raw: &str) -> Option<TimestampParts> {
    let captures = timestamp_pattern().captures(raw.trim())?;
    let month_text = captures.name("mon")?.as_str().to_ascii_lowercase();
    let month = MONTHS.iter().position(|name| *name == month_text)? as u32 + 1;
    let year = captures.name("year")?.as_str().parse::<i64>().ok()?;
    let day = captures.name("day")?.as_str().parse::<i64>().ok()?;
    let hour = captures.name("h")?.as_str().parse::<i64>().ok()?;
    let minute = captures.name("mi")?.as_str().parse::<i64>().ok()?;
    let second = captures.name("s")?.as_str().parse::<i64>().ok()?;
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let fraction = captures.name("frac").map(|m| m.as_str()).unwrap_or("");
    let precision = match fraction.len() {
        0 => TimePrecision::Seconds,
        1..=3 => TimePrecision::Millis,
        _ => TimePrecision::Micros,
    };
    let digits = fraction.get(..fraction.len().min(6)).unwrap_or(fraction);
    let mut nanos_text = digits.to_owned();
    while nanos_text.len() < 6 {
        nanos_text.push('0');
    }
    let nanos = nanos_text.parse::<u64>().ok()? * 1000;
    let offset = captures.name("tz").and_then(|m| parse_offset(m.as_str()));
    Some(TimestampParts {
        without_offset: raw.trim().to_owned(),
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos,
        precision,
        offset,
    })
}

fn parse_offset(raw: &str) -> Option<(i64, i64)> {
    if raw.eq_ignore_ascii_case("z") {
        return Some((0, 0));
    }
    let sign = match raw.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 4 {
        return None;
    }
    let hours = digits.get(..2)?.parse::<i64>().ok()?;
    let minutes = digits.get(2..4)?.parse::<i64>().ok()?;
    Some((sign * hours, sign * minutes))
}

/// Pre-computed parser for one analysis run: owns the compiled field map.
pub struct LineParser {
    fields: FieldMap,
}

impl LineParser {
    pub fn new(config: &Config) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            fields: FieldMap::new(&config.mapping)?,
        })
    }

    pub fn parse(&self, line_no: u64, line: &str) -> Parsed {
        parse_line(line_no, line, &self.fields)
    }
}
