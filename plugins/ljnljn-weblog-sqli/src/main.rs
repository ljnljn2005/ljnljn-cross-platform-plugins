//! Offline self-check CLI (development aid, **not** a host interface).
//!
//! The plugin itself only reads evidence through SDK handles; this binary
//! exists so the same pure pipeline can be exercised on a plain local file
//! during development and in the independent sample verification, without a
//! host, network access or any evidence modification.
//!
//! ```text
//! weblog-sqli-param-detect <file> [--min-requests N] [--window SECONDS]
//!                          [--max-ips N] [--min-families N] [--json]
//! ```

use std::process::ExitCode;

use ljnljn_kb_weblog_sqli_param_detect_30a22be5::aggregate::{
    analyze_text, decode_log, families_as_pairs,
};
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::detect::family_summary;
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::logline::LineParser;
use ljnljn_kb_weblog_sqli_param_detect_30a22be5::model::Config;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        return usage();
    };
    let mut config = Config::default();
    let mut json = false;
    while let Some(flag) = args.next() {
        let mut take = || args.next();
        match flag.as_str() {
            "--json" => json = true,
            "--min-requests" => match take().and_then(|v| v.parse().ok()) {
                Some(v) => config.min_requests = v,
                None => return usage(),
            },
            "--window" => match take().and_then(|v| v.parse().ok()) {
                Some(v) => config.window_seconds = v,
                None => return usage(),
            },
            "--max-ips" => match take().and_then(|v| v.parse().ok()) {
                Some(v) => config.max_distinct_ips = v,
                None => return usage(),
            },
            "--min-families" => match take().and_then(|v| v.parse().ok()) {
                Some(v) => config.min_families = v,
                None => return usage(),
            },
            other => {
                eprintln!("unknown option {other}");
                return usage();
            }
        }
    }
    if let Err(error) = config.validate() {
        eprintln!("invalid parameters: {error}");
        return ExitCode::from(2);
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let parser = match LineParser::new(&config) {
        Ok(parser) => parser,
        Err(error) => {
            eprintln!("invalid mapping: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (text, encoding, replacements) = decode_log(&bytes);
    let finished = analyze_text(&text, &config, &parser, None);
    let document = &finished.document;
    if json {
        let mut params = Vec::new();
        for param in finished.sorted_by_requests() {
            params.push(serde_like_param(param));
        }
        println!(
            "{{\"file\":{:?},\"size\":{},\"encoding\":{:?},\"replacementCount\":{},\"totalLines\":{},\"parsedLines\":{},\"unparsedLineCount\":{},\"formats\":{:?},\"unparsedReasons\":{{{}}},\"params\":[{}]}}",
            path,
            bytes.len(),
            encoding.as_str(),
            replacements,
            document.total_lines,
            document.parsed_lines,
            document.unparsed_line_count,
            document.format_label(),
            document
                .unparsed_reasons
                .iter()
                .map(|(reason, count)| format!("\"{reason}\":{count}"))
                .collect::<Vec<_>>()
                .join(","),
            params.join(",")
        );
        return ExitCode::SUCCESS;
    }
    println!("file            {path}");
    println!("size            {} bytes", bytes.len());
    println!(
        "encoding        {} (U+FFFD {})",
        encoding.as_str(),
        replacements
    );
    println!(
        "lines           total {} / parsed {} / unparsed {}",
        document.total_lines, document.parsed_lines, document.unparsed_line_count
    );
    println!("formats         {}", document.format_label());
    println!(
        "unparsed        {}",
        document
            .unparsed_reasons
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("params          {}", finished.all_params().count());
    println!("suspicious      {}", finished.suspicion_count);
    for param in finished.sorted_by_requests() {
        println!(
            "  [{}] {} ? {} requests={} window={} ips={} families={} confidence={} {}",
            if param.suspicious {
                "SUSPICIOUS"
            } else {
                "normal"
            },
            param.path,
            param.param,
            param.request_count,
            param.window.best.window_requests,
            param.window.best.window_ips,
            family_summary(&param.hit_families),
            param.confidence,
            param.verdict
        );
        for (family, count) in families_as_pairs(&param.window.best.window_families) {
            println!("      window-family {}={count}", family.name());
        }
        for sample in &param.sample_lines {
            println!("      line {}: {}", sample.line_no, sample.text);
        }
    }
    ExitCode::SUCCESS
}

fn serde_like_param(
    param: &ljnljn_kb_weblog_sqli_param_detect_30a22be5::aggregate::ParamAggregate,
) -> String {
    let families = families_as_pairs(&param.hit_families)
        .iter()
        .map(|(family, count)| format!("\"{}\":{count}", family.name()))
        .collect::<Vec<_>>()
        .join(",");
    let statuses = param
        .status_distribution
        .iter()
        .map(|(status, count)| {
            format!(
                "\"{}\":{count}",
                status.map_or("-".to_owned(), |code| code.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let samples = param
        .sample_lines
        .iter()
        .map(|sample| {
            format!(
                "{{\"lineNumber\":{},\"rawTime\":{:?},\"line\":{:?}}}",
                sample.line_no, sample.raw_time, sample.text
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"path\":{:?},\"param\":{:?},\"requestCount\":{},\"firstSeen\":{:?},\"lastSeen\":{:?},\"distinctClientIps\":{},\"statusDistribution\":{{{statuses}}},\"hitFamilies\":{{{families}}},\"suspicious\":{},\"confidence\":{},\"verdict\":{:?},\"sampleLines\":[{samples}]}}",
        param.path,
        param.param,
        param.request_count,
        param.first_seen.clone().unwrap_or_default(),
        param.last_seen.clone().unwrap_or_default(),
        param.distinct_client_ips,
        param.suspicious,
        param.confidence,
        param.verdict
    )
}

fn usage() -> ExitCode {
    eprintln!("usage: weblog-sqli-param-detect <file> [--min-requests N] [--window SECONDS] [--max-ips N] [--min-families N] [--json]");
    ExitCode::from(2)
}
