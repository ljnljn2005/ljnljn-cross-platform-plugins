use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};
use lovelycarve_plugin::{Severity, Value};

use crate::aggregate::{analyze_text, decode_log, Encoding, Finished, ParamAggregate};
use crate::detect::{family_hits, family_summary};
use crate::logline::{parse_query, parse_timestamp, percent_decode, split_target, LineParser};
use crate::model::{Config, Family, Mapping};

use super::{timestamp_of, ANALYZER_EVIDENCE, ANALYZER_FILE};

const DOCUMENT: &str = "weblog.document";
const CANDIDATE: &str = "weblog.candidate";

fn default_parser() -> LineParser {
    LineParser::new(&Config::default()).unwrap()
}

fn run(text: &str, config: &Config) -> Finished {
    let parser = LineParser::new(config).unwrap();
    analyze_text(text, config, &parser, None)
}

fn find<'a>(finished: &'a Finished, path: &str, param: &str) -> &'a ParamAggregate {
    finished
        .all_params()
        .find(|candidate| candidate.path == path && candidate.param == param)
        .unwrap_or_else(|| panic!("missing {path}?{param}"))
}

fn line_number_of(text: &str, needle: &str) -> u64 {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|index| index as u64 + 1)
        .unwrap_or_else(|| panic!("no line contains {needle:?}"))
}

fn line_offset(text: &str, line_no: u64) -> u64 {
    let mut offset = 0u64;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        if index as u64 + 1 == line_no {
            return offset;
        }
        offset += line.len() as u64;
    }
    panic!("line {line_no} out of range");
}

fn line_end_offset(text: &str, line_no: u64) -> u64 {
    let mut offset = 0u64;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        offset += line.len() as u64;
        if index as u64 + 1 == line_no {
            return offset;
        }
    }
    panic!("line {line_no} out of range");
}

const COMBINED_HEAD: &str = r#"203.0.113.9 - - [12/Jan/2024:03:04:05 +0800] "GET /admin/item/list?id=1&sort=1%20ORDER%20BY%201%20--%20x HTTP/1.1" 500 312 "http://example.test/" "sqlmap/1.8.1#stable""#;

/// A compact synthetic document: business traffic plus one burst.
fn synthetic() -> String {
    let mut lines: Vec<String> = Vec::new();
    for minute in 0..6 {
        lines.push(format!(
            "198.51.100.10 - - [01/Jan/2024:00:0{minute}:00 +0800] \"GET /shop/list?page=2&spm=m-95-96-97 HTTP/1.1\" 200 4210 \"-\" \"Mozilla/5.0 Chrome/120.0\""
        ));
        lines.push(format!(
            "198.51.100.11 - - [01/Jan/2024:00:0{minute}:10 +0800] \"GET /shop/help?q=order+by+title HTTP/1.1\" 200 880 \"-\" \"Mozilla/5.0 Chrome/120.0\""
        ));
    }
    lines.push(
        "198.51.100.12 - - [01/Jan/2024:00:02:00 +0800] \"GET /shop/detail?page=2&page=3 HTTP/1.1\" 200 5200 \"-\" \"Mozilla/5.0\"".into(),
    );
    lines.push(
        "198.51.100.10 - - [31/Dec/2023:23:59:50 +0800] \"GET /shop/list?page=2 HTTP/1.1\" 200 4100 \"-\" \"Mozilla/5.0\"".into(),
    );
    lines.push(
        "203.0.113.0 - - [01/Jan/2024:00:01:30 +0800] \"GET /favicon.ico HTTP/1.1\" 404 153 \"-\" \"Mozilla/5.0\"".into(),
    );
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
    lines.push(
        "198.51.100.12 - - [01/Jan/2024:00:02:09 +0800] \"GET /shop/search?q=extractvalue%281%2C1%29 HTTP/1.1\" 500 120 \"-\" \"Mozilla/5.0\"".into(),
    );
    lines.push("May 12 03:04:05 web01 kernel: usb 1-1: new high-speed USB device".into());
    lines.push("garbage line without any access-log structure".into());
    lines.push("203.0.113 badly-truncated [12/Jan/2024".into());
    lines.push(
        "198.51.100.13 - - [02/Jan/2024:09:00:00 +0000] \"POST /api/login HTTP/1.1\" 302 0".into(),
    );
    lines.join("\n")
}

// -------------------------------------------------------------------------
// Parser / aggregation behaviour carried over from the v1 package
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
    assert_eq!(sort.window.best.window_status.len(), 2);
    assert_eq!(sort.sample_lines.len(), 3);
    let first_payload_line = line_number_of(&document, "sort=1%20ORDER%20BY%201%20--%20x");
    assert_eq!(sort.sample_lines[0].line_no, first_payload_line);
    assert_eq!(
        sort.sample_lines[0].offset,
        line_offset(&document, first_payload_line)
    );
    assert!(sort.sample_lines[0]
        .text
        .starts_with("203.0.113.9 - - [01/Jan/2024:00:02:00 +0800] \"GET /admin/item/list?"));
    assert_eq!(
        sort.sample_lines[0].raw_value,
        "1%20ORDER%20BY%201%20--%20x"
    );
    // Evidence range covers every request that carried the parameter.
    assert_eq!(
        sort.line_start,
        line_number_of(&document, "sort=1%20ORDER%20BY%201%20--%20x")
    );
    assert_eq!(sort.line_end, line_number_of(&document, "EXTRACTVALUE%281"));
    assert_eq!(sort.byte_start, line_offset(&document, sort.line_start));
    assert!(sort.byte_end > sort.byte_start);
}

#[test]
fn business_parameters_are_not_flagged() {
    let finished = run(&synthetic(), &Config::default());
    let spm = find(&finished, "/shop/list", "spm");
    assert!(!spm.suspicious, "{}", spm.verdict);
    assert_eq!(spm.request_count, 6);
    let page_list = find(&finished, "/shop/list", "page");
    assert!(!page_list.suspicious, "{}", page_list.verdict);
    let help = find(&finished, "/shop/help", "q");
    assert!(!help.suspicious);
    assert_eq!(help.hit_families[Family::OrderBy.index()], 0);
    let detail = find(&finished, "/shop/detail", "page");
    assert!(!detail.suspicious);
    assert_eq!(detail.request_count, 2);
    assert_eq!(detail.distinct_client_ips, 1);
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

    let sort_families = find(
        &run(&document, &Config::default()),
        "/admin/item/list",
        "sort",
    )
    .window
    .best
    .family_count();
    assert!(sort_families >= 2);
    let stricter_families = Config {
        min_families: sort_families + 1,
        ..Config::default()
    };
    assert!(
        !find(
            &run(&document, &stricter_families),
            "/admin/item/list",
            "sort"
        )
        .suspicious
    );

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

#[test]
fn percent_encoded_payload_matches_after_decoding_and_raw_is_kept() {
    let text = format!("{COMBINED_HEAD}\n");
    let finished = run(&text, &Config::default());
    let sort = find(&finished, "/admin/item/list", "sort");
    assert_eq!(sort.hit_families[Family::OrderBy.index()], 1);
    assert!(sort.raw_value_samples[0].starts_with("1%20ORDER%20BY%201"));
    assert_eq!(sort.decoded_value_samples[0], "1 ORDER BY 1 -- x");
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

#[test]
fn utf8_preferred_and_gb18030_fallback_decode_chinese_text() {
    let gbk: &[u8] = &[
        0x31, 0x39, 0x32, 0x2E, 0x30, 0x2E, 0x32, 0x2E, 0x31, 0x20, 0x2D, 0x20, 0x2D, 0x20, 0xB1,
        0xA8, 0xB1, 0xED,
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
fn timestamps_parse_and_compare_within_a_year_without_normalising() {
    let a = parse_timestamp("31/Dec/2023:23:59:59.900 +0800").unwrap();
    let b = parse_timestamp("01/Jan/2024:00:00:00.100 +0800").unwrap();
    assert_eq!(b.linear_seconds() - a.linear_seconds(), 1);
    assert_eq!(a.precision.as_str(), "millisecond");
    assert_eq!(a.offset, Some((8, 0)));
    let utc = parse_timestamp("01/Jan/2024:00:00:00 +0000").unwrap();
    let plus8 = parse_timestamp("01/Jan/2024:00:00:00 +0800").unwrap();
    assert_eq!(utc.linear_seconds(), plus8.linear_seconds());
    assert!(parse_timestamp("1/Feb/2024:00:00:00 Z").is_some());
    assert!(parse_timestamp("01/Xyz/2024:00:00:00").is_none());
    assert!(parse_timestamp("01/Jan/2024:24:00:00").is_none());
    assert!(parse_timestamp("").is_none());
}

#[test]
fn timestamps_become_rfc3339_with_the_offset_as_written() {
    let with_offset = timestamp_of("01/Jan/2024:00:02:00 +0800").expect("offset timestamp");
    assert_eq!(with_offset.as_str(), "2024-01-01T00:02:00+08:00");
    assert!(with_offset.has_offset());
    let millis = timestamp_of("31/Dec/2023:23:59:59.900 +0800").expect("millis");
    assert_eq!(millis.as_str(), "2023-12-31T23:59:59.9+08:00");
    let local = timestamp_of("02/Jan/2024:03:04:05").expect("local time");
    assert_eq!(local.as_str(), "2024-01-02T03:04:05");
    assert!(!local.has_offset());
    assert!(timestamp_of("not a time").is_none());
}

#[test]
fn line_numbers_survive_crlf_and_blank_lines() {
    let text =
        "\r\n\r\n203.0.113.9 - - [12/Jan/2024:03:04:05 +0800] \"GET /a?x=1 HTTP/1.1\" 200 1\r\n";
    let finished = run(text, &Config::default());
    assert_eq!(finished.document.total_lines, 3);
    let found = find(&finished, "/a", "x");
    assert_eq!(found.sample_lines[0].line_no, 3);
    assert_eq!(found.sample_lines[0].offset, 4);
    assert_eq!(found.sample_lines[0].length, text.len() as u64 - 4);
    assert_eq!(finished.document.unparsed_reasons.get("blank"), Some(&2));
}

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
    assert!(sort.sample_lines[0]
        .text
        .contains("sort=1%20ORDER%20BY%201%20--%20A"));
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

#[test]
fn aggregate_sorting_and_suspicion_count_are_stable() {
    let finished = run(&synthetic(), &Config::default());
    let sorted = finished.sorted_by_requests();
    assert!(sorted.first().unwrap().suspicious);
    assert_eq!(finished.suspicion_count, 1);
}

// -------------------------------------------------------------------------
// LPP v2 records and analyzers
// -------------------------------------------------------------------------

struct FixtureDir {
    path: PathBuf,
}

impl FixtureDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-weblog-v2-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let file = self.path.join(relative);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&file, bytes).unwrap();
        file
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_files(paths: &[&Path]) -> TestRun {
    Harness::new(super::plugin)
        .run(ANALYZER_FILE, Fixture::files(paths))
        .expect("run")
}

fn run_evidence(root: &Path) -> TestRun {
    Harness::new(super::plugin)
        .run(ANALYZER_EVIDENCE, Fixture::evidence(&[("part:1", root)]))
        .expect("run")
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(key))
        .map(|(_, value)| value)
}

#[test]
fn files_scope_emits_document_and_candidate_records_with_evidence_ranges() {
    let fixture = FixtureDir::new("files");
    let document = synthetic();
    let path = fixture.write("access.log", document.as_bytes());
    let run = run_files(&[&path]);

    assert_eq!(run.count(DOCUMENT), 1);
    assert_eq!(run.count(CANDIDATE), 1);
    let document_record = run.of_type(DOCUMENT)[0];
    assert_eq!(document_record.text("file"), Some("access.log"));
    assert_eq!(document_record.text("encoding"), Some("utf8"));
    assert_eq!(
        document_record.int("file_size"),
        Some(document.len() as i64)
    );
    assert_eq!(
        document_record.int("total_lines"),
        Some(document.lines().count() as i64)
    );
    assert_eq!(document_record.int("candidate_count"), Some(1));
    assert_eq!(
        document_record.text("first_seen"),
        Some("2023-12-31T23:59:50+08:00")
    );
    assert_eq!(
        document_record.text("last_seen"),
        Some("2024-01-02T09:00:00+00:00")
    );
    let years = document_record
        .get("year_months")
        .and_then(Value::as_array)
        .expect("year months");
    assert_eq!(years.len(), 2);
    let reasons = document_record
        .get("unparsed_reasons")
        .and_then(Value::as_map)
        .expect("unparsed reasons");
    assert!(reasons.iter().any(|(key, count)| {
        key.as_str() == Some("format") && count.as_u64().unwrap_or(0) >= 2
    }));

    let candidate = run.of_type(CANDIDATE)[0];
    assert_eq!(candidate.text("method"), Some("GET"));
    assert_eq!(candidate.text("path"), Some("/admin/item/list"));
    assert_eq!(candidate.text("param"), Some("sort"));
    assert_eq!(candidate.text("location"), Some("query"));
    assert_eq!(
        candidate.text("family"),
        Some("time-func:1,order-by:2,union-select:1,metadata:2,extract:1,comment-trunc:6")
    );
    assert_eq!(candidate.int("family_count"), Some(6));
    assert_eq!(candidate.int("request_count"), Some(6));
    assert_eq!(candidate.int("window_requests"), Some(6));
    assert_eq!(candidate.int("window_ips"), Some(1));
    assert_eq!(
        candidate.text("window_first_seen"),
        Some("2024-01-01T00:02:00+08:00")
    );
    assert_eq!(
        candidate.text("window_last_seen"),
        Some("2024-01-01T00:02:05+08:00")
    );
    assert_eq!(candidate.severity, Some(Severity::High));
    assert!(candidate.title.starts_with("GET /admin/item/list ? sort"));

    // Evidence range: the exact byte span of the burst lines.
    let start_line = line_number_of(&document, "sort=1%20ORDER%20BY%201%20--%20x");
    let end_line = line_number_of(&document, "EXTRACTVALUE%281");
    assert_eq!(candidate.int("line_start"), Some(start_line as i64));
    assert_eq!(candidate.int("line_end"), Some(end_line as i64));
    let start = line_offset(&document, start_line);
    let end = line_end_offset(&document, end_line);
    assert_eq!(candidate.int("text_offset_start"), Some(start as i64));
    assert_eq!(candidate.int("text_offset_end"), Some(end as i64));
    assert_eq!(candidate.get("source_exact"), Some(&Value::Boolean(true)));
    assert_eq!(candidate.sources.len(), 1);
    let source = &candidate.sources[0];
    assert_eq!(source.root.as_deref(), Some("files"));
    assert_eq!(source.path.as_deref(), Some("access.log"));
    assert_eq!(source.offset, Some(start));
    assert_eq!(source.length, Some(end - start));
    let expected_note = format!("第 {start_line}..{end_line} 行");
    assert_eq!(source.note.as_deref(), Some(expected_note.as_str()));

    let statuses = candidate
        .get("status_distribution")
        .and_then(Value::as_array)
        .expect("status distribution");
    assert_eq!(statuses.len(), 2);
    let samples = candidate
        .get("samples")
        .and_then(Value::as_array)
        .expect("samples");
    assert_eq!(samples.len(), 3);
    assert_eq!(
        map_get(&samples[0], "line").and_then(Value::as_u64),
        Some(start_line)
    );
    assert_eq!(
        map_get(&samples[0], "raw_value").and_then(Value::as_str),
        Some("1%20ORDER%20BY%201%20--%20x")
    );
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("未判定攻击是否成功"));
}

#[test]
fn evidence_scope_walks_fixed_web_log_roots() {
    let fixture = FixtureDir::new("evidence");
    let document = synthetic();
    fixture.write("var/log/nginx/access.log", document.as_bytes());
    // A non-log file and an unrelated log file are ignored.
    fixture.write("var/log/nginx/error.log.metrics", b"not a log");
    fixture.write("var/log/nginx/notes.txt", b"hello\nworld\n");
    let run = run_evidence(&fixture.path);

    assert_eq!(run.count(DOCUMENT), 1);
    assert_eq!(run.count(CANDIDATE), 1);
    let document_record = run.of_type(DOCUMENT)[0];
    assert_eq!(document_record.text("file"), Some("access.log"));
    let candidate = run.of_type(CANDIDATE)[0];
    assert_eq!(
        candidate.sources[0].path.as_deref(),
        Some("var/log/nginx/access.log")
    );
    assert_eq!(candidate.sources[0].root.as_deref(), Some("part:1"));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("1 个访问日志文件"));
}

#[test]
fn gb18030_log_files_are_decoded_and_reported() {
    let fixture = FixtureDir::new("gbk");
    let line = "192.0.2.44 - - [03/Mar/2024:10:00:05 +0800] \"GET /news/search?kw=%E6%8A%A5%E8%A1%A8 HTTP/1.1\" 200 2100 \"-\" \"Mozilla/5.0\"";
    let mut bytes = b"[note] ".to_vec();
    bytes.extend_from_slice(&[0xB1, 0xA8, 0xB8]);
    bytes.push(b'\n');
    for _ in 0..5 {
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    let path = fixture.write("access.log", &bytes);
    let test_run = run_files(&[&path]);

    assert_eq!(test_run.count(DOCUMENT), 1);
    let document_record = test_run.of_type(DOCUMENT)[0];
    assert_eq!(document_record.text("encoding"), Some("gb18030"));
    assert_eq!(document_record.int("parsed_lines"), Some(5));
    assert_eq!(document_record.int("unparsed_lines"), Some(1));

    // The same bytes through the pure pipeline keep the decoded payload.
    let (text, encoding, _) = decode_log(&bytes);
    assert_eq!(encoding, Encoding::Gb18030);
    let finished = run(&text, &Config::default());
    let kw = find(&finished, "/news/search", "kw");
    assert_eq!(kw.decoded_value_samples[0], "报表");
}

#[test]
fn gb18030_candidates_keep_line_ranges_without_claiming_byte_offsets() {
    let fixture = FixtureDir::new("gbk-candidate");
    let mut bytes = b"[note] ".to_vec();
    bytes.extend_from_slice(&[0xB1, 0xA8, 0xB8]); // invalid UTF-8 forces GB18030
    bytes.push(b'\n');
    for index in 0..5 {
        let payload = if index % 2 == 0 {
            "1%20UNION%20SELECT%201--%20x"
        } else {
            "1%27%20OR%201%3D1--%20x"
        };
        let line = format!(
            "203.0.113.70 - - [01/Jan/2024:00:00:0{index} +0800] \"GET /api/item?sort={payload} HTTP/1.1\" 500 10 \"-\" \"sqlmap\"\n"
        );
        bytes.extend_from_slice(line.as_bytes());
    }
    let path = fixture.write("access.log", &bytes);
    let test_run = run_files(&[&path]);

    assert_eq!(test_run.count(CANDIDATE), 1);
    let candidate = test_run.of_type(CANDIDATE)[0];
    assert_eq!(candidate.text("param"), Some("sort"));
    assert_eq!(candidate.get("source_exact"), Some(&Value::Boolean(false)));
    assert!(candidate.int("line_start").unwrap_or(0) >= 2);
    assert!(candidate.int("line_end").unwrap_or(0) > candidate.int("line_start").unwrap_or(0));
    let source = &candidate.sources[0];
    assert_eq!(source.offset, None);
    assert_eq!(source.length, None);
    assert!(source.note.as_deref().unwrap_or("").contains("gb18030"));
    assert!(source.note.as_deref().unwrap_or("").contains("行"));
}

#[test]
fn utf8_bom_is_accounted_for_in_the_source_offset() {
    let fixture = FixtureDir::new("bom");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    for index in 0..5 {
        let payload = if index % 2 == 0 {
            "1%20UNION%20SELECT%201--%20x"
        } else {
            "1%27%20OR%201%3D1--%20x"
        };
        let line = format!(
            "203.0.113.71 - - [01/Jan/2024:00:00:0{index} +0800] \"GET /api/item?sort={payload} HTTP/1.1\" 500 10 \"-\" \"sqlmap\"\n"
        );
        bytes.extend_from_slice(line.as_bytes());
    }
    let path = fixture.write("access.log", &bytes);
    let test_run = run_files(&[&path]);

    let candidate = test_run.of_type(CANDIDATE)[0];
    assert_eq!(candidate.get("source_exact"), Some(&Value::Boolean(true)));
    let text_start = candidate.int("text_offset_start").unwrap_or(0) as u64;
    assert_eq!(candidate.sources[0].offset, Some(text_start + 3));
}

#[test]
fn non_log_content_is_skipped_with_a_warning() {
    let fixture = FixtureDir::new("notlog");
    let path = fixture.write("notes.log", b"hello\nworld\n");
    let run = run_files(&[&path]);

    assert_eq!(run.count(DOCUMENT), 0);
    assert_eq!(run.count(CANDIDATE), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "NOT_ACCESS_LOG"));
}

#[test]
fn an_empty_file_selection_is_an_explicit_warning() {
    let run = Harness::new(super::plugin)
        .run(ANALYZER_FILE, Fixture::Files(Vec::new()))
        .expect("run");
    assert_eq!(run.count(DOCUMENT), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn evidence_without_logs_reports_no_log_files() {
    let fixture = FixtureDir::new("empty-evidence");
    let run = run_evidence(&fixture.path);
    assert_eq!(run.count(DOCUMENT), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "NO_LOG_FILES"));
}

#[test]
fn non_suspicious_parameters_do_not_emit_records() {
    let fixture = FixtureDir::new("benign");
    let document = "198.51.100.10 - - [01/Jan/2024:00:00:00 +0800] \"GET /shop/list?page=2&spm=m-95-96-97 HTTP/1.1\" 200 4210 \"-\" \"Mozilla/5.0\"\n";
    let path = fixture.write("access.log", document.as_bytes());
    let run = run_files(&[&path]);

    assert_eq!(run.count(DOCUMENT), 1);
    assert_eq!(run.count(CANDIDATE), 0);
    assert_eq!(run.of_type(DOCUMENT)[0].int("candidate_count"), Some(0));
}

#[test]
fn plugin_identity_matches_the_manifest() {
    let harness = Harness::new(super::plugin);
    let hello = harness.hello();
    assert_eq!(hello.protocol, 2);
    assert_eq!(hello.plugin, "org.ljnljn.weblog-sqli");
    assert_eq!(hello.analyzers, vec!["weblog_files", "weblog_evidence"]);
    let manifest = include_str!("../plugin.toml");
    assert!(manifest.contains("id = \"org.ljnljn.weblog-sqli\""));
    assert!(manifest.contains("library = \"ljnljn_weblog_sqli\""));
    assert!(manifest.contains("id = \"weblog_files\""));
    assert!(manifest.contains("id = \"weblog_evidence\""));
    assert!(manifest.contains("scope = \"files\""));
    assert!(manifest.contains("scope = \"evidence\""));
}
