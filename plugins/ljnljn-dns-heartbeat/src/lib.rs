//! DNS query heartbeat periodicity (LPP v2).
//!
//! This is the LPP v2 port of the v1 `ljnljn.dns-heartbeat` file analyzer.
//! The classic-pcap reader, DNS question parser, transport extraction and
//! interval statistics are carried over unchanged (`capture`, `packet`,
//! `dns`, `interval`, `options`, `engine`); only the result mapping is new:
//!
//! * `dns.capture.summary` — one typed record per capture file with the pcap
//!   metadata, DNS query counts, every skip counter and the verdict
//!   thresholds;
//! * `dns.heartbeat.domain` — one typed record per `(qname, qtype)` group with
//!   first/last query timestamps, interval statistics (seconds), the
//!   stability and candidate scores, and the periodic verdict.
//!
//! Each domain record points at the exact byte range of the first and last
//! packet record that carried the query, so the interval math can be re-derived
//! from the capture.
//!
//! Ported limitations: classic pcap only (pcapng is rejected explicitly),
//! IPv4/Ethernet or DLT_RAW only, UDP port 53 only, no IP fragment reassembly,
//! no TCP DNS, no IDNA decoding, no client-address grouping and no file hash.
//! A malformed or unsupported capture is reported as a per-file warning; it
//! never turns into a silent empty success.

#[allow(dead_code)]
#[cfg(test)]
mod synth;
#[cfg(test)]
mod tests;

#[allow(dead_code)]
mod capture;
mod dns;
#[allow(dead_code)]
mod engine;
#[allow(dead_code)]
mod error;
mod interval;
#[allow(dead_code)]
mod options;
mod packet;

use lovelycarve_plugin::{
    export_plugin, FileRef, Json, Plugin, Record, Result, Run, Severity, SourceRef, Timestamp,
    Value,
};

use crate::capture::FileSource;
use crate::engine::Report;
use crate::interval::GroupStats;

/// Analyzer id; matches the manifest.
pub const ANALYZER: &str = "dns_heartbeat";
/// Plugin id; matches the manifest.
pub const PLUGIN_ID: &str = "org.ljnljn.dns-heartbeat";

/// Largest capture accepted by the reader (the parser itself is bounded and
/// reads on demand; this only rejects absurd single files early).
const CAPTURE_CAP: u64 = 4 * 1024 * 1024 * 1024;

/// One DNS query group: interval statistics and the periodicity verdict.
#[derive(Record)]
#[record(
    id = "dns.heartbeat.domain",
    label = "DNS 查询心跳域名",
    title = "{qname} ({qtype_name})"
)]
struct DomainHeartbeat {
    #[field(label = "位次")]
    rank: i64,
    #[field(label = "域名", key)]
    qname: String,
    #[field(label = "问题类型", key)]
    qtype: i64,
    #[field(label = "类型名")]
    qtype_name: String,
    #[field(label = "查询数")]
    query_count: i64,
    #[field(label = "首次查询", timeline = "dns")]
    first_seen: Option<Timestamp>,
    #[field(label = "末次查询", timeline = "dns")]
    last_seen: Option<Timestamp>,
    #[field(label = "间隔样本数")]
    interval_count: i64,
    #[field(label = "间隔中位数（秒）", kind = "duration")]
    interval_median: Option<f64>,
    #[field(label = "间隔均值（秒）", kind = "duration")]
    interval_mean: Option<f64>,
    #[field(label = "间隔标准差（秒）", kind = "duration")]
    interval_stdev: Option<f64>,
    #[field(label = "最小间隔（秒）", kind = "duration")]
    interval_min: Option<f64>,
    #[field(label = "最大间隔（秒）", kind = "duration")]
    interval_max: Option<f64>,
    #[field(label = "稳定性（%）")]
    stability_pct: f64,
    #[field(label = "候选分（0-1）")]
    candidate_score: f64,
    #[field(
        label = "判定",
        kind = "enum",
        choices = "periodic=疑似周期心跳,irregular=间隔不规则,insufficient=样本不足,no_intervals=无相邻间隔"
    )]
    verdict: String,
    #[field(label = "疑似周期心跳")]
    periodic: bool,
    #[field(label = "样本不足")]
    insufficient_samples: bool,
    #[field(label = "乱序条数")]
    out_of_order: i64,
    #[field(label = "超限未采样条数")]
    truncated_samples: i64,
    #[field(label = "首条包记录槽位")]
    first_slot: i64,
    #[field(label = "末条包记录槽位")]
    last_slot: i64,
    #[field(label = "间隔样本（秒）", kind = "json")]
    interval_samples: Json,
}

/// One capture file: pcap metadata, DNS counts, skip counters and thresholds.
#[derive(Record)]
#[record(id = "dns.capture.summary", label = "DNS 抓包摘要", title = "{file}")]
struct CaptureSummary {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "文件大小", kind = "size")]
    file_size: u64,
    #[field(label = "抓包格式", kind = "enum", choices = "pcap=classic pcap")]
    format: String,
    #[field(label = "链路类型")]
    linktype: u64,
    #[field(label = "snaplen", kind = "size")]
    snaplen: u64,
    #[field(label = "保留字段（原值，不参与换算）")]
    reserved_field: u64,
    #[field(label = "纳秒时间戳")]
    nanoseconds: bool,
    #[field(label = "时间基准")]
    time_basis: String,
    #[field(label = "包记录数")]
    record_count: i64,
    #[field(label = "帧数")]
    frame_count: i64,
    #[field(label = "DNS 查询报文数")]
    dns_query_messages: i64,
    #[field(label = "计入统计的查询数")]
    queries_counted: i64,
    #[field(label = "域名·类型分组数")]
    group_count: i64,
    #[field(label = "疑似周期分组数")]
    periodic_groups: i64,
    #[field(label = "跳过：非 UDP")]
    skipped_not_udp: i64,
    #[field(label = "跳过：非 53 端口 UDP")]
    skipped_not_dns_port: i64,
    #[field(label = "跳过：IPv6")]
    skipped_ipv6: i64,
    #[field(label = "跳过：IP 分片")]
    skipped_fragmented: i64,
    #[field(label = "跳过：TCP-DNS")]
    skipped_tcp: i64,
    #[field(label = "跳过：链路类型")]
    skipped_linktype: i64,
    #[field(label = "跳过：截断")]
    skipped_truncated: i64,
    #[field(label = "跳过：头部畸形")]
    skipped_malformed: i64,
    #[field(label = "跳过：非 DNS")]
    skipped_not_dns: i64,
    #[field(label = "跳过：DNS 响应")]
    skipped_dns_response: i64,
    #[field(label = "跳过：畸形 DNS")]
    skipped_dns_malformed: i64,
    #[field(label = "跳过：后缀过滤")]
    skipped_suffix_filtered: i64,
    #[field(label = "判定：最小样本数 N")]
    min_samples: i64,
    #[field(label = "判定：抖动容差")]
    tolerance: f64,
    #[field(label = "判定：稳定性阈值")]
    stability_threshold: f64,
    #[field(label = "判定：间隔明细上限")]
    detail_limit: i64,
}

fn dns_heartbeat(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut parsed = 0usize;
    let mut groups = 0usize;
    let mut periodic = 0usize;
    let mut failures = 0usize;

    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        run.progress(
            files as u64,
            Some(run.inputs().len() as u64),
            Some(file.name()),
        )?;
        if file.size() > CAPTURE_CAP {
            run.warn_file(
                file,
                "RESOURCE_LIMIT",
                format!(
                    "{} 有 {} 字节，超过单文件上限 {CAPTURE_CAP}",
                    file.name(),
                    file.size()
                ),
            )?;
            failures += 1;
            continue;
        }
        let read = |offset: u64, length: usize| {
            file.read_at(offset, length)
                .map_err(|error| format!("{}: {}", error.code, error.message))
        };
        let source = FileSource::new(file.size(), &read);
        let report = match engine::analyze_source(&source, options::AnalysisOptions::default()) {
            Ok(report) => report,
            Err(error) => {
                if run.is_cancelled() {
                    return Err(error.into_plugin());
                }
                let code = error.code.to_ascii_uppercase();
                run.warn_file(file, &code, format!("{}: {}", file.name(), error))?;
                failures += 1;
                continue;
            }
        };
        parsed += 1;
        groups += report.groups.len();
        periodic += report.groups.iter().filter(|group| group.periodic).count();
        emit_report(run, file, &report)?;
    }

    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未收到待分析的抓包文件")?;
    }
    let mut summary = format!(
        "解析 {parsed}/{files} 个抓包文件，{groups} 个域名·类型分组，其中疑似周期心跳 {periodic} 个"
    );
    if failures > 0 {
        summary.push_str(&format!("，{failures} 个文件无法解析（见告警）"));
    }
    run.set_summary(summary);
    Ok(())
}

fn emit_report(run: &Run, file: &FileRef, report: &Report) -> Result<()> {
    for group in &report.groups {
        run.check_cancelled()?;
        let record = domain_record(group);
        let end = group.last_end.max(group.first_offset);
        let length = end.saturating_sub(group.first_offset);
        let mut emit = run
            .record(&record)
            .source(source_of(
                file,
                group.first_offset,
                length,
                &format!(
                    "#{}..#{} 包记录，文件偏移 {}..{}",
                    group.first_slot, group.last_slot, group.first_offset, end
                ),
            ))
            .title(if group.periodic {
                format!(
                    "疑似周期心跳：{} ({})",
                    group.qname,
                    dns::qtype_name(group.qtype)
                )
            } else {
                format!(
                    "DNS 查询：{} ({})",
                    group.qname,
                    dns::qtype_name(group.qtype)
                )
            });
        if group.periodic {
            emit = emit.severity(Severity::Low);
        }
        emit.emit()?;
    }
    let summary = summary_record(file.name(), file.size(), report);
    run.record(&summary)
        .source(source_of(file, 0, file.size(), "classic pcap 抓包"))
        .emit()?;
    Ok(())
}

/// Provenance of one range in `file`. A file-scope run may not know a view
/// path, so the host display name is used when no path is supplied.
fn source_of(file: &FileRef, offset: u64, length: u64, note: &str) -> SourceRef {
    let mut source = file.source_at(offset, length);
    if source.path.is_none() {
        source.path = Some(file.name().to_owned());
    }
    source.note = Some(note.to_owned());
    source
}

fn domain_record(group: &GroupStats) -> DomainHeartbeat {
    let has_intervals = group.interval_count > 0;
    let verdict = if group.insufficient_samples {
        "insufficient"
    } else if !has_intervals {
        "no_intervals"
    } else if group.periodic {
        "periodic"
    } else {
        "irregular"
    };
    DomainHeartbeat {
        rank: group.rank as i64,
        qname: group.qname.clone(),
        qtype: i64::from(group.qtype),
        qtype_name: dns::qtype_name(group.qtype),
        query_count: group.query_count as i64,
        first_seen: epoch_timestamp(group.first_epoch),
        last_seen: epoch_timestamp(group.last_epoch),
        interval_count: group.interval_count as i64,
        interval_median: has_intervals.then_some(round3(group.interval_median)),
        interval_mean: has_intervals.then_some(round6(group.interval_mean)),
        interval_stdev: has_intervals.then_some(round6(group.interval_stdev)),
        interval_min: has_intervals.then_some(round6(group.interval_min)),
        interval_max: has_intervals.then_some(round6(group.interval_max)),
        stability_pct: round2(group.stability * 100.0),
        candidate_score: round3(group.candidate_score),
        verdict: verdict.to_owned(),
        periodic: group.periodic,
        insufficient_samples: group.insufficient_samples,
        out_of_order: group.out_of_order as i64,
        truncated_samples: group.truncated as i64,
        first_slot: group.first_slot as i64,
        last_slot: group.last_slot as i64,
        interval_samples: Json(Value::Array(
            group
                .detail
                .iter()
                .map(|seconds| Value::F64(round6(*seconds)))
                .collect(),
        )),
    }
}

fn summary_record(file: &str, file_size: u64, report: &Report) -> CaptureSummary {
    let skipped = &report.skipped;
    CaptureSummary {
        file: file.to_owned(),
        file_size,
        format: report.info.format.to_owned(),
        linktype: u64::from(report.info.linktype),
        snaplen: u64::from(report.info.snaplen),
        reserved_field: u64::from(report.info.reserved_field),
        nanoseconds: report.info.nanoseconds,
        time_basis: report.info.timebase.clone(),
        record_count: report.scan.records as i64,
        frame_count: report.scan.frames as i64,
        dns_query_messages: report.dns_query_messages as i64,
        queries_counted: report.queries_counted as i64,
        group_count: report.groups.len() as i64,
        periodic_groups: report.groups.iter().filter(|group| group.periodic).count() as i64,
        skipped_not_udp: skipped.not_udp as i64,
        skipped_not_dns_port: skipped.not_dns_port as i64,
        skipped_ipv6: skipped.ipv6 as i64,
        skipped_fragmented: skipped.fragmented as i64,
        skipped_tcp: skipped.tcp as i64,
        skipped_linktype: skipped.linktype as i64,
        skipped_truncated: skipped.truncated as i64,
        skipped_malformed: skipped.malformed as i64,
        skipped_not_dns: skipped.not_dns as i64,
        skipped_dns_response: skipped.dns_response as i64,
        skipped_dns_malformed: skipped.dns_malformed as i64,
        skipped_suffix_filtered: skipped.suffix_filtered as i64,
        min_samples: report.options.min_samples as i64,
        tolerance: report.options.tolerance,
        stability_threshold: report.options.stability_threshold,
        detail_limit: report.options.detail_limit as i64,
    }
}

/// `epoch = ts_sec + ts_frac / resolution` → RFC 3339 UTC.
fn epoch_timestamp(epoch: f64) -> Option<Timestamp> {
    if !epoch.is_finite() || epoch < 0.0 {
        return None;
    }
    let seconds = epoch.floor();
    if seconds > i64::MAX as f64 {
        return None;
    }
    let nanos = ((epoch - seconds) * 1_000_000_000.0)
        .round()
        .clamp(0.0, 999_999_999.0) as u32;
    Some(Timestamp::from_unix_nanos(seconds as i64, nanos))
}

fn round2(value: f64) -> f64 {
    if value.is_finite() {
        (value * 100.0).round() / 100.0
    } else {
        0.0
    }
}

fn round3(value: f64) -> f64 {
    if value.is_finite() {
        (value * 1_000.0).round() / 1_000.0
    } else {
        0.0
    }
}

fn round6(value: f64) -> f64 {
    if value.is_finite() {
        (value * 1_000_000.0).round() / 1_000_000.0
    } else {
        0.0
    }
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID)
        .record::<DomainHeartbeat>()
        .record::<CaptureSummary>()
        .analyzer(ANALYZER, dns_heartbeat)
}

export_plugin!(plugin);
