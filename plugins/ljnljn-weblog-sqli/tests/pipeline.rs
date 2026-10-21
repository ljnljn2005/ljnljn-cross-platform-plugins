//! Pure-parser and pipeline tests over synthetic data only.
//!
//! Covers: `combined`/`common` layouts, unrelated illegal lines, missing
//! query, repeated keys, `%XX` payloads (decoded match + raw retention),
//! a year boundary kept verbatim, GBK decoding, business-parameter
//! negatives (`spm`, `page`, prose "order by"), the window thresholds, the
//! provenance attributes, and the plugin identity.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use ljnljn_kb_weblog_sqli_param_detect_30a22be5::aggregate::Finished;
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::aggregate::{
    analyze_text, decode_log, split_log_lines, Encoding,
};
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::analyzer::{
    analyze_bytes_for_test, build_result, config_from_params, WebLogAnalyzer, ANALYZER, PLUGIN_ID,
};
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::detect::{family_hits, family_summary};
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::logline::{
    parse_query, parse_timestamp, percent_decode, split_target, LineParser,
};
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::model::{Config, Family, Mapping};

use lovelycarve_plugin::Value;

/// Operator params exactly as a host would forward them (`evidence.params`).
fn test_params() -> Value {
    Value::Map(vec![
        (Value::from("minRequests"), Value::from(9_u64)),
        (Value::from("windowSeconds"), Value::from(30_i64)),
        (Value::from("maxDistinctIps"), Value::from(2_u64)),
        (Value::from("minFamilies"), Value::from(3_u64)),
        (Value::from("samplesPerParam"), Value::from(2_u64)),
        (Value::from("unknownKey"), Value::from("ignored")),
    ])
}

/// Out-of-range params must be rejected with the exact reason, not clamped.
fn test_params_bad() -> Value {
    Value::Map(vec![(Value::from("minRequests"), Value::from(0_u64))])
}

fn test_params_mapping() -> Value {
    Value::Map(vec![(
        Value::from("mapping"),
        Value::Map(vec![
            (Value::from("ip"), Value::from(r"^(\S+)")),
            (Value::from("status"), Value::from(r"\s(\d{3})\s")),
        ]),
    )])
}

fn default_parser() -> LineParser {
    LineParser::new(&Config::default()).unwrap()
}

/// 1-based line number of the first line containing `needle`. Expectations
/// over the generated document are derived instead of hard-coded, so the
/// fixture can grow without invalidating the provenance assertions.
fn line_number_of(text: &str, needle: &str) -> u64 {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|index| index as u64 + 1)
        .unwrap_or_else(|| panic!("no line contains {needle:?}"))
}

fn run(text: &str, config: &Config) -> Finished {
    let parser = LineParser::new(config).unwrap();
    analyze_text(text, config, &parser, None)
}

fn find<'a>(
    finished: &'a Finished,
    path: &str,
    param: &str,
) -> &'a ljnljn_kb_weblog_sqli_param_detect_30a22be5::aggregate::ParamAggregate {
    finished
        .all_params()
        .find(|candidate| candidate.path == path && candidate.param == param)
        .unwrap_or_else(|| panic!("missing {path}?{param}"))
}

const COMBINED_HEAD: &str = r#"203.0.113.9 - - [12/Jan/2024:03:04:05 +0800] "GET /admin/item/list?id=1&sort=1%20ORDER%20BY%201%20--%20x HTTP/1.1" 500 312 "http://example.test/" "sqlmap/1.8.1#stable""#;

/// A compact synthetic document: business traffic plus one burst.
fn synthetic() -> String {
    let mut lines: Vec<String> = Vec::new();
    // Business traffic on several paths, two client IPs, several minutes.
    for minute in 0..6 {
        lines.push(format!(
            "198.51.100.10 - - [01/Jan/2024:00:0{minute}:00 +0800] \"GET /shop/list?page=2&spm=m-95-96-97 HTTP/1.1\" 200 4210 \"-\" \"Mozilla/5.0 Chrome/120.0\""
        ));
        lines.push(format!(
            "198.51.100.11 - - [01/Jan/2024:00:0{minute}:10 +0800] \"GET /shop/help?q=order+by+title HTTP/1.1\" 200 880 \"-\" \"Mozilla/5.0 Chrome/120.0\""
        ));
    }
    // Repeated key inside one request.
    lines.push(
        "198.51.100.12 - - [01/Jan/2024:00:02:00 +0800] \"GET /shop/detail?page=2&page=3 HTTP/1.1\" 200 5200 \"-\" \"Mozilla/5.0\"".into(),
    );
    // Year boundary: same parameter, next year, only raw text kept.
    lines.push(
        "198.51.100.10 - - [31/Dec/2023:23:59:50 +0800] \"GET /shop/list?page=2 HTTP/1.1\" 200 4100 \"-\" \"Mozilla/5.0\"".into(),
    );
    // Missing query.
    lines.push(
        "203.0.113.0 - - [01/Jan/2024:00:01:30 +0800] \"GET /favicon.ico HTTP/1.1\" 404 153 \"-\" \"Mozilla/5.0\"".into(),
    );
    // Injection burst: one IP, five seconds, multiple families.
    let payloads = [
        ("1%20ORDER%20BY%201%20--%20x", "500"),
        ("1%20ORDER%20BY%205%20--%20x", "500"),
        (
            "-1%27%20UNION%20ALL%20SELECT%20NULL%2Cname%20FROM%20information_schema.tables--%20x",
            "500",
        ),
        ("1'%3BWAITFOR%20DELAY%20'0%3A0%3A5'--%20x", "500"),
        ("1%3BEXEC%20xp_cmdshell%20'whoami'--%20x", "200"),
        (
            "1%29%20AND%20EXTRACTVALUE%281%2CCONCAT%280x7e%29%29--%20x",
            "500",
        ),
    ];
    for (index, (payload, status)) in payloads.iter().enumerate() {
        lines.push(format!(
            "203.0.113.9 - - [01/Jan/2024:00:02:0{index} +0800] \"GET /admin/item/list?page=1&sort={payload} HTTP/1.1\" {status} 300 \"-\" \"sqlmap/1.8.1\""
        ));
    }
    // A suspicious-looking single request with a different IP: must not lift
    // the burst above the distinct-IP limit.
    lines.push(
        "198.51.100.12 - - [01/Jan/2024:00:02:09 +0800] \"GET /shop/search?q=extractvalue%281%2C1%29 HTTP/1.1\" 500 120 \"-\" \"Mozilla/5.0\"".into(),
    );
    // Unrelated non-log lines.
    lines.push("May 12 03:04:05 web01 kernel: usb 1-1: new high-speed USB device".into());
    lines.push("garbage line without any access-log structure".into());
    lines.push("203.0.113 badly-truncated [12/Jan/2024".into());
    // Common format (no referer/UA).
    lines.push(
        "198.51.100.13 - - [02/Jan/2024:09:00:00 +0000] \"POST /api/login HTTP/1.1\" 302 0".into(),
    );
    lines.join("\n")
}

// -------------------------------------------------------------------------
// Normal input
// -------------------------------------------------------------------------

#[test]
fn combined_and_common_lines_are_recognised_and_counted() {
    let text = format!(
        "{COMBINED_HEAD}\n198.51.100.13 - - [02/Jan/2024:09:00:00 +0000] \"POST /api/login HTTP/1.1\" 302 0"
    );
    let finished = run(&text, &Config::default());
    assert_eq!(finished.document.total_lines, 2);
    assert_eq!(finished.document.parsed_lines, 2);
    assert_eq!(finished.document.unparsed_line_count, 0);
    let formats = finished.document.format_label();
    assert!(formats.contains("combined:1"), "{formats}");
    assert!(formats.contains("common:1"), "{formats}");
    // A `-` referer is still the referer field, so the layout stays `combined`.
    let dashed = "198.51.100.14 - - [02/Jan/2024:09:00:01 +0000] \"GET /api/list HTTP/1.1\" 200 7 \"-\" \"Mozilla/5.0\"";
    assert_eq!(
        run(dashed, &Config::default()).document.format_label(),
        "combined:1"
    );
}

#[test]
fn burst_is_flagged_with_families_and_verbatim_times() {
    let document = synthetic();
    let finished = run(&document, &Config::default());
    let sort = find(&finished, "/admin/item/list", "sort");
    assert!(sort.suspicious, "{}", sort.verdict);
    assert_eq!(sort.request_count, 6);
    assert_eq!(sort.window.best.window_requests, 6);
    assert_eq!(sort.window.best.window_ips, 1);
    assert_eq!(
        sort.window.best.window_first_seen.as_deref(),
        Some("01/Jan/2024:00:02:00 +0800")
    );
    assert_eq!(
        sort.window.best.window_last_seen.as_deref(),
        Some("01/Jan/2024:00:02:05 +0800")
    );
    for family in [
        Family::OrderBy,
        Family::UnionSelect,
        Family::TimeFunc,
        Family::Metadata,
        Family::Extract,
    ] {
        assert!(sort.hit_families[family.index()] > 0, "{family:?}");
    }
    assert!(sort.confidence >= 0.5, "{}", sort.confidence);
    assert!(sort.verdict.contains("特征族"), "{}", sort.verdict);
    assert_eq!(sort.window.best.window_status.len(), 2);
    assert_eq!(sort.sample_lines.len(), 3);
    let first_payload_line = line_number_of(&document, "sort=1%20ORDER%20BY%201%20--%20x");
    assert_eq!(sort.sample_lines[0].line_no, first_payload_line);
    // The sample is the original line, not a re-serialised record.
    assert!(sort
        .sample_lines[0]
        .text
        .starts_with("203.0.113.9 - - [01/Jan/2024:00:02:00 +0800] \"GET /admin/item/list?"));
    assert!(sort.sample_lines[0].text.contains("sort=1%20ORDER%20BY%201"));
    assert_eq!(sort.sample_lines[0].raw_value, "1%20ORDER%20BY%201%20--%20x");
}

#[test]
fn business_parameters_are_not_flagged() {
    let finished = run(&synthetic(), &Config::default());
    let spm = find(&finished, "/shop/list", "spm");
    assert!(!spm.suspicious, "{}", spm.verdict);
    assert_eq!(spm.request_count, 6);
    let page_list = find(&finished, "/shop/list", "page");
    assert!(!page_list.suspicious, "{}", page_list.verdict);
    // "order by title" is prose: contains "order by" but no digit.
    let help = find(&finished, "/shop/help", "q");
    assert!(!help.suspicious);
    assert_eq!(help.hit_families[Family::OrderBy.index()], 0);
    let detail = find(&finished, "/shop/detail", "page");
    assert!(!detail.suspicious);
    // Repeated key in one request counts twice but from one IP.
    assert_eq!(detail.request_count, 2);
    assert_eq!(detail.distinct_client_ips, 1);
    // The single search payload has one IP but too few requests.
    let search = find(&finished, "/shop/search", "q");
    assert!(!search.suspicious);
    assert!(search.verdict.contains("请求数不足"), "{}", search.verdict);
    assert_eq!(finished.suspicion_count, 1);
}

#[test]
fn unparsed_lines_are_counted_with_reasons_and_line_numbers() {
    let document = synthetic();
    let finished = run(&document, &Config::default());
    assert!(finished.document.unparsed_line_count >= 3);
    assert!(
        finished
            .document
            .unparsed_reasons
            .get("format")
            .copied()
            .unwrap_or(0)
            >= 2
    );
    let first = &finished.document.unparsed_samples[0];
    assert_eq!(first.line_no, line_number_of(&document, "May 12 03:04:05"));
    assert!(first.text.starts_with("May 12 03:04:05"));
    assert!(finished.document.total_lines >= finished.document.parsed_lines);
}

#[test]
fn malformed_lines_are_skipped_with_specific_reasons() {
    let parser = default_parser();
    let reason = |line: &str| parser.parse(1, line).unwrap_err().0.as_str();
    assert_eq!(reason("not a log line"), "format");
    assert_eq!(
        reason("203.0.113.9 - - [not-a-time] \"GET /a?x=1 HTTP/1.1\" 200 1"),
        "time"
    );
    assert_eq!(
        reason("203.0.113.9 - - [12/Jan/2024:03:04:05 +0800] \"\" 200 1"),
        "request"
    );
    assert_eq!(reason(" \t "), "blank");
}

#[test]
fn several_query_parameters_can_be_flagged_independently() {
    let payloads = [
        "1%20UNION%20SELECT%201%20--%20x",
        "2%20UNION%20ALL%20SELECT%20NULL%20--%20x",
        "3%20UNION%20SELECT%20%40%40version%20--%20x",
    ];
    let lines: Vec<String> = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            format!(
                "203.0.113.50 - - [01/Jan/2024:00:00:0{index} +0800] \"GET /api/report?id={payload}&name=1%20AND%20SLEEP%285%29%20--%20x HTTP/1.1\" 500 10 \"-\" \"sqlmap\""
            )
        })
        .collect();
    let config = Config {
        min_requests: 3,
        min_families: 1,
        max_distinct_ips: 1,
        ..Config::default()
    };
    let finished = run(&lines.join("\n"), &config);
    for (param, family) in [("id", Family::UnionSelect), ("name", Family::TimeFunc)] {
        let found = find(&finished, "/api/report", param);
        assert!(found.suspicious, "{param}: {}", found.verdict);
        assert!(found.hit_families[family.index()] > 0, "{param}");
    }
    assert_eq!(finished.suspicion_count, 2);
}

#[test]
fn missing_query_creates_no_parameter_rows() {
    let finished = run(&synthetic(), &Config::default());
    assert!(finished
        .all_params()
        .all(|param| !param.path.ends_with("favicon.ico")));
    let text = "203.0.113.0 - - [01/Jan/2024:00:01:30 +0800] \"GET /healthz HTTP/1.1\" 200 3 \"-\" \"UA\"\n";
    let finished = run(text, &Config::default());
    assert_eq!(finished.document.parsed_lines, 1);
    assert_eq!(finished.all_params().count(), 0);
}

#[test]
fn year_boundary_stays_verbatim_and_is_reported() {
    let finished = run(&synthetic(), &Config::default());
    let page = find(&finished, "/shop/list", "page");
    assert_eq!(
        page.first_seen.as_deref(),
        Some("31/Dec/2023:23:59:50 +0800")
    );
    assert_eq!(
        page.last_seen.as_deref(),
        Some("01/Jan/2024:00:05:00 +0800")
    );
    let years: Vec<String> = page
        .spans_years
        .iter()
        .map(|(year, month)| format!("{year}-{month:02}"))
        .collect();
    assert_eq!(years, vec!["2023-12".to_owned(), "2024-01".to_owned()]);
    // The window never merges across years unless they are really close.
    assert!(!page.suspicious);
}

#[test]
fn window_thresholds_are_parameterised() {
    let document = synthetic();
    let strict = Config {
        min_requests: 7,
        ..Config::default()
    };
    assert!(!find(&run(&document, &strict), "/admin/item/list", "sort").suspicious);

    let sort_families = find(&run(&document, &Config::default()), "/admin/item/list", "sort")
        .window
        .best
        .family_count();
    assert!(sort_families >= 2);
    let stricter_families = Config {
        min_families: sort_families + 1,
        ..Config::default()
    };
    assert!(!find(&run(&document, &stricter_families), "/admin/item/list", "sort").suspicious);

    let narrow_window = Config {
        window_seconds: 2,
        ..Config::default()
    };
    assert!(!find(&run(&document, &narrow_window), "/admin/item/list", "sort").suspicious);

    let no_ip_limit = Config {
        max_distinct_ips: 0,
        ..Config::default()
    };
    assert!(!find(&run(&document, &no_ip_limit), "/admin/item/list", "sort").suspicious);

    let loose = Config {
        min_requests: 1,
        window_seconds: 86_400,
        max_distinct_ips: 9,
        min_families: 1,
        ..Config::default()
    };
    assert!(find(&run(&document, &loose), "/shop/search", "q").suspicious);
}

// -------------------------------------------------------------------------
// Payload decoding
// -------------------------------------------------------------------------

#[test]
fn percent_encoded_payload_matches_after_decoding_and_raw_is_kept() {
    let text = format!("{COMBINED_HEAD}\n");
    let finished = run(&text, &Config::default());
    let sort = find(&finished, "/admin/item/list", "sort");
    assert_eq!(sort.hit_families[Family::OrderBy.index()], 1);
    assert!(sort.raw_value_samples[0].starts_with("1%20ORDER%20BY%201"));
    assert_eq!(sort.decoded_value_samples[0], "1 ORDER BY 1 -- x");
    // Matched on raw text, no ORDER BY number before decoding: nothing.
    assert_eq!(sort.raw_hit_families[Family::OrderBy.index()], 0);
}

#[test]
fn url_decoding_handles_plus_and_broken_escapes() {
    assert_eq!(percent_decode("a+b%41"), b"a bA");
    assert_eq!(percent_decode("%ZZ%4"), b"%ZZ%4");
    assert_eq!(percent_decode("%E4%B8%AD"), "中".as_bytes());
    let pairs = parse_query("a=1&a=2&A=3");
    assert_eq!(pairs.len(), 3);
    assert_eq!(pairs[2].0, "A");
    assert_eq!(split_target("/x?a=1?b=2").1, Some("a=1?b=2"));
}

#[test]
fn family_patterns_match_the_documented_forms() {
    let cases: &[(&str, Family)] = &[
        ("1;WAITFOR DELAY '0:0:5'", Family::TimeFunc),
        ("1 AND PG_SLEEP(5)", Family::TimeFunc),
        ("1 OR benchmark(1000000,md5(1))", Family::TimeFunc),
        ("1 ORDER BY 1150--", Family::OrderBy),
        ("-1 UNION SELECT name", Family::UnionSelect),
        ("-1 UNION ALL SELECT name", Family::UnionSelect),
        ("1 FROM information_schema.tables", Family::Metadata),
        ("1;EXEC xp_cmdshell 'id'", Family::Metadata),
        ("extractvalue(1,concat(0x7e))", Family::Extract),
        ("updatexml(1,1,1)", Family::Extract),
        ("load_file('/etc/passwd')", Family::Extract),
        ("1'-- comment", Family::CommentTrunc),
        ("1#hash", Family::CommentTrunc),
        ("1/*join*/", Family::CommentTrunc),
        ("1;DROP TABLE users", Family::Stacked),
        ("1' OR 1=1--", Family::QuoteEscape),
    ];
    for (value, family) in cases {
        let hits = family_hits(value.as_bytes());
        assert!(hits[family.index()] > 0, "{value:?} should hit {family:?}");
    }
    let benign = [
        "m-95-96-97",
        "2",
        "order by title",
        "ORDER BY popularity",
        "pull-down menu",
        "chinese",
        "hello world",
        "1",
    ];
    for value in benign {
        let hits = family_hits(value.as_bytes());
        assert_eq!(family_summary(&hits), "none", "{value:?} produced {hits:?}");
    }
}

// -------------------------------------------------------------------------
// Encoding
// -------------------------------------------------------------------------

#[test]
fn utf8_preferred_and_gb18030_fallback_decode_chinese_text() {
    let gbk: &[u8] = &[
        0x31, 0x39, 0x32, 0x2E, 0x30, 0x2E, 0x32, 0x2E, 0x31, 0x20, 0x2D, 0x20, 0x2D, 0x20, 0xB1,
        0xA8, 0xB1, 0xED, // "报表" in GBK
    ];
    let (text, encoding, replacements) = decode_log(gbk);
    assert_eq!(encoding, Encoding::Gb18030);
    assert!(text.contains("报表"), "{text}");
    assert_eq!(replacements, 0);

    let (text, encoding, _) = decode_log("报表 报表".as_bytes());
    assert_eq!(encoding, Encoding::Utf8);
    assert!(text.contains("报表"));

    let (text, encoding, _) = decode_log(b"\xEF\xBB\xBFreport");
    assert_eq!(encoding, Encoding::Utf8);
    assert_eq!(text, "report");

    let (_, encoding, _) = decode_log(&[0xFF, 0xFE, b'a', 0x00]);
    assert_eq!(encoding, Encoding::Utf16Le);
}

#[test]
fn gbk_log_keeps_utf8_payload_semantics() {
    // A GBK file whose Referer holds GBK bytes and whose query holds %XX.
    let line = "192.0.2.44 - - [03/Mar/2024:10:00:05 +0800] \"GET /news/search?kw=%E6%8A%A5%E8%A1%A8 HTTP/1.1\" 200 2100 \"-\" \"Mozilla/5.0\"";
    let mut bytes = b"[note] ".to_vec();
    bytes.extend_from_slice(&[0xB1, 0xA8, 0xB8]); // deliberately invalid UTF-8
    bytes.push(b'\n');
    bytes.extend_from_slice(line.as_bytes());
    let (text, encoding, _) = decode_log(&bytes);
    assert_eq!(encoding, Encoding::Gb18030);
    let finished = run(&text, &Config::default());
    assert_eq!(finished.document.parsed_lines, 1);
    let kw = find(&finished, "/news/search", "kw");
    assert_eq!(kw.decoded_value_samples[0], "报表");
}

// -------------------------------------------------------------------------
// Timestamps
// -------------------------------------------------------------------------

#[test]
fn timestamps_parse_and_compare_within_a_year_without_normalising() {
    let a = parse_timestamp("31/Dec/2023:23:59:59.900 +0800").unwrap();
    let b = parse_timestamp("01/Jan/2024:00:00:00.100 +0800").unwrap();
    assert_eq!(b.linear_seconds() - a.linear_seconds(), 1);
    assert_eq!(a.precision.as_str(), "millisecond");
    assert_eq!(a.offset, Some((8, 0)));
    // An offset is recorded but never applied to the linear axis.
    let utc = parse_timestamp("01/Jan/2024:00:00:00 +0000").unwrap();
    let plus8 = parse_timestamp("01/Jan/2024:00:00:00 +0800").unwrap();
    assert_eq!(utc.linear_seconds(), plus8.linear_seconds());
    assert!(parse_timestamp("1/Feb/2024:00:00:00 Z").is_some());
    assert!(parse_timestamp("01/Xyz/2024:00:00:00").is_none());
    assert!(parse_timestamp("01/Jan/2024:24:00:00").is_none());
    assert!(parse_timestamp("").is_none());
}

#[test]
fn line_numbers_survive_crlf_and_blank_lines() {
    let text =
        "\r\n\r\n203.0.113.9 - - [12/Jan/2024:03:04:05 +0800] \"GET /a?x=1 HTTP/1.1\" 200 1\r\n";
    assert_eq!(split_log_lines(text).len(), 3);
    let finished = run(text, &Config::default());
    assert_eq!(finished.document.total_lines, 3);
    assert_eq!(find(&finished, "/a", "x").sample_lines[0].line_no, 3);
    assert_eq!(finished.document.unparsed_reasons.get("blank"), Some(&2));
}

// -------------------------------------------------------------------------
// Damage / boundaries
// -------------------------------------------------------------------------

#[test]
fn empty_and_binary_documents_degrade_gracefully() {
    let finished = run("", &Config::default());
    assert_eq!(finished.document.total_lines, 0);
    assert_eq!(finished.document.parsed_lines, 0);
    assert_eq!(finished.all_params().count(), 0);

    let binary: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let (text, _, _) = decode_log(&binary);
    let finished = run(&text, &Config::default());
    assert_eq!(
        finished.document.parsed_lines + finished.document.unparsed_line_count,
        finished.document.total_lines
    );
    assert_eq!(finished.all_params().count(), 0);
}

#[test]
fn very_long_lines_are_truncated_in_samples_only() {
    let long_payload = format!("1%20ORDER%20BY%201%20--%20{}", "A".repeat(900));
    let text = format!(
        "203.0.113.9 - - [12/Jan/2024:03:04:05 +0800] \"GET /a?sort={long_payload} HTTP/1.1\" 500 1 \"-\" \"UA\"\n"
    );
    let config = Config::default();
    let finished = run(&text, &config);
    let sort = find(&finished, "/a", "sort");
    assert!(sort.sample_lines[0].text.chars().count() <= config.sample_line_chars + 1);
    // The sample keeps the line as written (`%XX`), while the decoded value
    // samples show the payload the matcher worked on.
    assert!(sort.sample_lines[0].text.contains("sort=1%20ORDER%20BY%201%20--%20A"));
    assert!(sort.decoded_value_samples[0].contains("ORDER BY 1"));
}

#[test]
fn field_mapping_override_accepts_custom_layouts() {
    let config = Config {
        mapping: Mapping {
            ip: Some(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)".into()),
            time: Some(r"\| (\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})".into()),
            request: Some(r#""(?P<req>[A-Z]+ [^"]+)""#.into()),
            status: Some(r"\| (\d{3})$".into()),
            ..Mapping::default()
        },
        ..Config::default()
    };
    let text = "9.9.9.9 | 12/Jan/2024:03:04:05 | \"GET /x?id=1%20ORDER%20BY%202\" | 500\n";
    let finished = run(text, &config);
    assert_eq!(finished.document.parsed_lines, 1);
    let id = find(&finished, "/x", "id");
    assert_eq!(id.hit_families[Family::OrderBy.index()], 1);
    assert_eq!(id.sample_lines[0].status, Some(500));
}

#[test]
fn invalid_parameters_are_rejected_explicitly() {
    assert!(Config {
        min_requests: 0,
        ..Config::default()
    }
    .validate()
    .is_err());
    assert!(Config {
        mapping: Mapping {
            request: Some("no-group".into()),
            ..Mapping::default()
        },
        ..Config::default()
    }
    .validate()
    .is_err());
    assert!(LineParser::new(&Config {
        mapping: Mapping {
            ip: Some("(".into()),
            ..Mapping::default()
        },
        ..Config::default()
    })
    .is_err());
}

// -------------------------------------------------------------------------
// Source identity and SDK projection
// -------------------------------------------------------------------------

#[test]
fn every_artifact_carries_source_identity() {
    let document = synthetic();
    let result = analyze_bytes_for_test(document.as_bytes(), &Config::default()).unwrap();
    assert!(!result.artifacts.is_empty());
    use lovelycarve_plugin::Value;
    for artifact in &result.artifacts {
        let has_path = artifact.attributes.contains_key("source.path");
        if artifact.artifact_type.ends_with(".limitations") && !has_path {
            continue;
        }
        assert_eq!(
            artifact.attributes.get("source.path"),
            Some(&Value::from("access.log"))
        );
        assert_eq!(
            artifact.attributes.get("source.root"),
            Some(&Value::from("test"))
        );
        assert_eq!(
            artifact.attributes.get("weblog.source"),
            Some(&Value::from("access.log"))
        );
    }
    let candidate = result
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_type == "weblog.candidate")
        .expect("candidate artifact");
    assert_eq!(
        candidate.attributes.get("weblog.path"),
        Some(&Value::from("/admin/item/list"))
    );
    assert_eq!(
        candidate.attributes.get("weblog.param"),
        Some(&Value::from("sort"))
    );
    let samples = candidate
        .attributes
        .get("weblog.sampleLines")
        .and_then(Value::as_array)
        .expect("sample lines");
    assert_eq!(samples.len(), 3);
    let first = &samples[0];
    let line_number = first
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some("lineNumber"))
        })
        .and_then(|(_, value)| value.as_u64());
    assert_eq!(
        line_number,
        Some(line_number_of(&document, "sort=1%20ORDER%20BY%201%20--%20x"))
    );
}

#[test]
fn result_summary_nodes_and_limitations_are_complete() {
    let result = analyze_bytes_for_test(synthetic().as_bytes(), &Config::default()).unwrap();
    let summary = result.summary.unwrap();
    assert!(summary.contains("未判定攻击是否成功"), "{summary}");
    let node_types: Vec<&str> = result
        .nodes
        .iter()
        .map(|node| node.node_type.as_str())
        .collect();
    assert_eq!(
        node_types,
        vec![
            "weblog.document",
            "weblog.candidate",
            "weblog.param",
            "weblog.limitations"
        ]
    );
    let limitations = result
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_type == "weblog.limitations")
        .unwrap();
    let items = limitations.attributes.get("weblog.limitations").unwrap();
    assert!(items.as_array().unwrap().len() >= 6);
    assert_eq!(result.findings.len(), 1);
}

#[test]
fn non_log_content_is_rejected_by_the_pipeline() {
    assert!(analyze_bytes_for_test(b"\x00\x01binary", &Config::default()).is_err());
    assert!(analyze_bytes_for_test(b"", &Config::default()).is_err());
}

#[test]
fn identity_and_param_parsing_are_stable() {
    use lovelycarve_plugin::EvidenceAnalyzer;
    let analyzer = WebLogAnalyzer;
    assert_eq!(analyzer.analyzer(), ANALYZER);
    assert_eq!(ANALYZER, "ljnljn.weblog-sqli");
    assert_eq!(
        PLUGIN_ID,
        "org.ljnljn.weblog-sqli"
    );
    let value = test_params();
    let config = config_from_params(&value).unwrap();
    assert_eq!(config.min_requests, 9);
    assert_eq!(config.window_seconds, 30);
    assert_eq!(config.max_distinct_ips, 2);
    assert_eq!(config.min_families, 3);
    assert_eq!(config.samples_per_param, 2);
    assert!(config_from_params(&test_params_bad()).is_err());
    // Unknown keys and a nil handle fall back to the documented defaults.
    let defaults = config_from_params(&Value::Nil).unwrap();
    assert_eq!(defaults, Config::default());
    assert_eq!(
        config_from_params(&test_params_mapping())
            .unwrap()
            .mapping
            .ip
            .as_deref(),
        Some(r"^(\S+)")
    );
}

#[test]
fn aggregate_table_lists_every_parameter_sorted() {
    let finished = run(&synthetic(), &Config::default());
    let sorted = finished.sorted_by_requests();
    assert!(sorted.first().unwrap().suspicious);
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for param in &sorted {
        *counts.entry(param.path.as_str()).or_default() += 1;
    }
    assert!(counts.contains_key("/shop/list"));
    let result = build_result(&[], &Config::default(), &["没有文件".into()], "空");
    assert!(result.summary.unwrap().contains("0 个日志文件"));
}

