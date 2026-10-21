//! DNS 查询心跳周期（首版）— LovelyCarve `file_analyzer`。
//!
//! 输入：宿主传进来的单个抓包文件句柄（逻辑 `File`，只读、有界读取）。
//! 能力范围（严格按首版）：classic pcap → Ethernet（含 1–2 层 VLAN）/ `DLT_RAW`
//! → IPv4 → UDP → 源或目的端口 53 → DNS **查询**（QR=0）问题名；按
//! (qname, qtype) 分组、按时间排序、统计相邻间隔，输出周期心跳候选。
//!
//! 输出（每个域名·类型一个数据项，另加一个汇总数据项）：
//! qname、qtype、queryCount、firstTs/lastTs（ISO8601 与原始 epoch 秒）、
//! intervalMedianMs、intervalMeanMs、intervalStdevMs、intervalMinMs、
//! intervalMaxMs（**整数毫秒**，键名以 `_ms` 结尾，列标签写 (ms)，避免把
//! "秒"标签套在毫秒值上）、stabilityPct / candidateScorePct（**0–100 的
//! 百分比整数**，键名以 `_pct` 结尾）、periodic（布尔）、间隔明细（前 K 条，
//! 秒、3 位小数）、源文件句柄、显示名、长度、抓包时间基准与记录级溯源
//! （源文件槽位区间、抓包文件偏移区间）。
//!
//! **未计算源文件哈希**：解析器按需随机/重复读取文件，读回调的字节序列不等于
//! 源文件字节序，因此不能把读回调摘要称为 SHA-256；首版不输出该字段。
//!
//! **未覆盖（不是"已支持"）**：pcapng、IPv6、IP 分片重组、TCP 承载 DNS、
//! IDNA 解码、多域名同步轮询标记、跨客户端区分、命令行/宿主自定义参数、
//! 域名信誉查询、任何网络访问。
//!
//! 判定阈值默认值来自需求文本（N=5、tolerance=0.1、stability≥0.8），见
//! [`options`]；宿主没有给 `file_analyzer` 传参的通道，所以这些值只能在本
//! crate 内覆盖（单元测试与 `AnalysisOptions`），不新增宿主参数 API。

pub mod capture;
pub mod dns;
pub mod engine;
pub mod error;
pub mod interval;
pub mod options;
pub mod packet;
pub mod synth;

use lovelycarve_plugin::{
    export_plugin, AnalysisResult, Artifact, Attributes, File, FileAnalyzer, Finding, Plugin,
    Result, ResultColumn, ResultNode, Value,
};

use crate::capture::FileSource;

/// Analyzer id；与 plugin.toml `[[capabilities]] analyzer` 一致。
pub const ANALYZER: &str = "ljnljn.dns-heartbeat";
/// 插件 id；与 plugin.toml `id` 一致。
pub const PLUGIN_ID: &str = "org.ljnljn.dns-heartbeat";
/// 插件显示名；与 plugin.toml `name` 一致。
pub const PLUGIN_NAME: &str = "DNS 查询心跳周期分析";
/// 插件版本；与 plugin.toml `version` 一致。
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
/// 数据项类型命名空间。
pub const ARTIFACT_DOMAIN: &str = "ljnljn.dns_heartbeat.domain";
/// 汇总数据项类型。
pub const ARTIFACT_SUMMARY: &str = "ljnljn.dns_heartbeat.summary";

/// 溯源键前缀。
const KEY_SOURCE_FILE: &str = "dns_heartbeat.source_file";
const KEY_SOURCE_FILE_ID: &str = "dns_heartbeat.source_file_id";
const KEY_SOURCE_FILE_SIZE: &str = "dns_heartbeat.source_file_size";
const KEY_SOURCE_FORMAT: &str = "dns_heartbeat.source_format";
const KEY_TIME_BASIS: &str = "dns_heartbeat.time_basis";
const KEY_RESERVED: &str = "dns_heartbeat.reserved_field";
const KEY_SNAPLEN: &str = "dns_heartbeat.snaplen";
const KEY_LINKTYPE: &str = "dns_heartbeat.linktype";
const KEY_PARAMS: &str = "dns_heartbeat.params";

/// 记录级键。
const KEY_RANK: &str = "dns_heartbeat.rank";
const KEY_QNAME: &str = "dns_heartbeat.qname";
const KEY_QTYPE: &str = "dns_heartbeat.qtype";
const KEY_QTYPE_NAME: &str = "dns_heartbeat.qtype_name";
const KEY_QUERY_COUNT: &str = "dns_heartbeat.query_count";
const KEY_FIRST_TS: &str = "dns_heartbeat.first_ts";
const KEY_FIRST_EPOCH: &str = "dns_heartbeat.first_epoch_sec";
const KEY_LAST_TS: &str = "dns_heartbeat.last_ts";
const KEY_LAST_EPOCH: &str = "dns_heartbeat.last_epoch_sec";
const KEY_MEDIAN_MS: &str = "dns_heartbeat.interval_median_ms";
const KEY_MEAN_MS: &str = "dns_heartbeat.interval_mean_ms";
const KEY_STDEV_MS: &str = "dns_heartbeat.interval_stdev_ms";
const KEY_MIN_MS: &str = "dns_heartbeat.interval_min_ms";
const KEY_MAX_MS: &str = "dns_heartbeat.interval_max_ms";
const KEY_STABILITY_PCT: &str = "dns_heartbeat.stability_pct";
const KEY_PERIODIC: &str = "dns_heartbeat.periodic";
const KEY_SCORE_PCT: &str = "dns_heartbeat.candidate_score_pct";
const KEY_INSUFFICIENT: &str = "dns_heartbeat.insufficient_samples";
const KEY_OUT_OF_ORDER: &str = "dns_heartbeat.out_of_order";
const KEY_TRUNCATED: &str = "dns_heartbeat.truncated_samples";
const KEY_DETAIL: &str = "dns_heartbeat.interval_details";
const KEY_DETAIL_OMITTED: &str = "dns_heartbeat.interval_details_omitted";
const KEY_SLOT_RANGE: &str = "dns_heartbeat.source_record_slots";
const KEY_OFFSET_RANGE: &str = "dns_heartbeat.source_byte_offsets";
const KEY_EVIDENCE: &str = "dns_heartbeat.evidence";

/// 分析器：只通过 SDK 文件句柄读取，不接触真实路径、不联网。
pub struct DnsHeartbeatAnalyzer;

impl FileAnalyzer for DnsHeartbeatAnalyzer {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let size = file.size();
        // 只读句柄；解析器会按需随机/重复读取，因此这里**不**对读回调做哈希：
        // 读回调的顺序与重复次数都不等于源文件字节序，得到的摘要不能称为源文件
        // SHA-256。首版不计算文件哈希，只保留 SDK 文件 id / 显示名 / 长度。
        let read = |offset: u64, len: usize| -> std::result::Result<Vec<u8>, String> {
            file.read(offset, len)
                .map_err(|error| format!("{}: {}", error.code, error.message))
        };
        let source = FileSource::new(size, &read);
        let report = engine::analyze_source(&source, options::AnalysisOptions::default())
            .map_err(error::AnalyzeError::into_plugin)?;
        Ok(build_result(&report, file.name(), file.id(), size))
    }
}

/// 结果节点：每个数据项一组列。
pub fn result_nodes() -> Vec<ResultNode> {
    let columns = |pairs: &[(&str, &str)]| {
        pairs
            .iter()
            .map(|(key, label)| ResultColumn {
                key: (*key).to_string(),
                label: (*label).to_string(),
            })
            .collect()
    };
    vec![
        ResultNode {
            node_type: ARTIFACT_DOMAIN.to_string(),
            name: "DNS 查询心跳候选域名".to_string(),
            columns: columns(&[
                (KEY_RANK, "#"),
                (KEY_QNAME, "域名"),
                (KEY_QTYPE, "qtype"),
                (KEY_QTYPE_NAME, "类型名"),
                (KEY_QUERY_COUNT, "查询数"),
                (KEY_MEDIAN_MS, "间隔中位数(ms)"),
                (KEY_MEAN_MS, "间隔均值(ms)"),
                (KEY_STDEV_MS, "间隔标准差(ms)"),
                (KEY_MIN_MS, "最小间隔(ms)"),
                (KEY_MAX_MS, "最大间隔(ms)"),
                (KEY_STABILITY_PCT, "稳定性(%)"),
                (KEY_PERIODIC, "疑似周期"),
                (KEY_SCORE_PCT, "候选分(0-100)"),
                (KEY_FIRST_TS, "首次查询(ISO8601)"),
                (KEY_FIRST_EPOCH, "首次 epoch"),
                (KEY_LAST_TS, "末次查询(ISO8601)"),
                (KEY_LAST_EPOCH, "末次 epoch"),
                (KEY_DETAIL, "间隔明细"),
                (KEY_DETAIL_OMITTED, "被截断明细数"),
                (KEY_OUT_OF_ORDER, "乱序条数"),
                (KEY_TRUNCATED, "超限未采样条数"),
                (KEY_INSUFFICIENT, "样本不足"),
                (KEY_SLOT_RANGE, "源记录槽位"),
                (KEY_OFFSET_RANGE, "源文件字节偏移"),
                (KEY_SOURCE_FILE, "源文件"),
                (KEY_SOURCE_FILE_ID, "源文件句柄"),
            ]),
        },
        ResultNode {
            node_type: ARTIFACT_SUMMARY.to_string(),
            name: "分析汇总与溯源".to_string(),
            columns: columns(&[
                (KEY_SOURCE_FILE, "源文件"),
                (KEY_SOURCE_FILE_SIZE, "文件大小"),
                (KEY_SOURCE_FORMAT, "抓包格式"),
                (KEY_TIME_BASIS, "时间基准"),
                (KEY_RESERVED, "保留字段（仅记录，不参与换算）"),
                (KEY_SNAPLEN, "snaplen"),
                (KEY_LINKTYPE, "链路类型"),
                (KEY_PARAMS, "判定阈值"),
                (KEY_EVIDENCE, "统计明细"),
            ]),
        },
    ]
}

/// 把分析结果映射成 LPP 产物（数据项 + 时间线 + finding）。
pub fn build_result(
    report: &engine::Report,
    file_name: &str,
    file_id: &str,
    file_size: u64,
) -> AnalysisResult {
    let mut artifacts = Vec::new();
    let mut timeline = Vec::new();
    let mut findings = Vec::new();

    let provenance: [(&str, Value); 3] = [
        (KEY_SOURCE_FILE, Value::from(file_name)),
        (KEY_SOURCE_FILE_ID, Value::from(file_id)),
        (KEY_SOURCE_FILE_SIZE, Value::from(file_size)),
    ];

    for group in &report.groups {
        let mut attributes = Attributes::new();
        attributes.insert(KEY_RANK, Value::from(group.rank as u64));
        attributes.insert(KEY_QNAME, Value::from(group.qname.as_str()));
        attributes.insert(KEY_QTYPE, Value::from(u64::from(group.qtype)));
        attributes.insert(KEY_QTYPE_NAME, Value::from(dns::qtype_name(group.qtype)));
        attributes.insert(KEY_QUERY_COUNT, Value::from(group.query_count));
        attributes.insert(KEY_FIRST_TS, Value::from(iso8601(group.first_epoch)));
        attributes.insert(KEY_FIRST_EPOCH, Value::from(format!("{:.6}", group.first_epoch)));
        attributes.insert(KEY_LAST_TS, Value::from(iso8601(group.last_epoch)));
        attributes.insert(KEY_LAST_EPOCH, Value::from(format!("{:.6}", group.last_epoch)));
        attributes.insert(KEY_MEDIAN_MS, Value::from(millis(group.interval_median)));
        attributes.insert(KEY_MEAN_MS, Value::from(millis(group.interval_mean)));
        attributes.insert(KEY_STDEV_MS, Value::from(millis(group.interval_stdev)));
        attributes.insert(KEY_MIN_MS, Value::from(millis(group.interval_min)));
        attributes.insert(KEY_MAX_MS, Value::from(millis(group.interval_max)));
        attributes.insert(KEY_STABILITY_PCT, Value::from(percent(group.stability)));
        attributes.insert(KEY_PERIODIC, Value::from(group.periodic));
        attributes.insert(KEY_SCORE_PCT, Value::from(percent(group.candidate_score)));
        attributes.insert(KEY_INSUFFICIENT, Value::from(group.insufficient_samples));
        attributes.insert(KEY_OUT_OF_ORDER, Value::from(group.out_of_order));
        attributes.insert(KEY_TRUNCATED, Value::from(group.truncated));
        attributes.insert(
            KEY_DETAIL,
            Value::from(detail_text(&report.options, &group.detail)),
        );
        attributes.insert(KEY_DETAIL_OMITTED, Value::from(group.detail_omitted));
        attributes.insert(
            KEY_SLOT_RANGE,
            Value::from(format!(
                "#{}..#{}",
                group.first_slot, group.last_slot
            )),
        );
        attributes.insert(
            KEY_OFFSET_RANGE,
            Value::from(format!(
                "{}..{}",
                group.first_offset, group.last_offset
            )),
        );
        for (key, value) in &provenance {
            attributes.insert(*key, value.clone());
        }
        let title = if group.periodic {
            format!("疑似周期心跳：{} ({})", group.qname, dns::qtype_name(group.qtype))
        } else {
            format!("DNS 查询域名：{} ({})", group.qname, dns::qtype_name(group.qtype))
        };
        artifacts.push(Artifact {
            artifact_type: ARTIFACT_DOMAIN.to_string(),
            title,
            value: Some(Value::from(format!(
                "{} {}：查询 {} 次，间隔中位数 {:.3}s，稳定性 {:.0}%",
                group.qname,
                dns::qtype_name(group.qtype),
                group.query_count,
                group.interval_median,
                group.stability * 100.0
            ))),
            attributes,
        });

        if group.periodic {
            findings.push(Finding {
                severity: lovelycarve_plugin::Severity::Low,
                title: format!("疑似周期心跳域名 {} ({})", group.qname, dns::qtype_name(group.qtype)),
                description: format!(
                    "该域名·类型共 {} 条 DNS 查询，相邻间隔中位数 {:.3}s，{:.0}% 的间隔落在 ±{:.0}% 容差窗口内（阈值 N={}、stability≥{:.2}）。仅为时序特征，未做信誉判定。",
                    group.query_count,
                    group.interval_median,
                    group.stability * 100.0,
                    report.options.tolerance * 100.0,
                    report.options.min_samples,
                    report.options.stability_threshold
                ),
                attributes: [
                    (KEY_QNAME.to_string(), Value::from(group.qname.as_str())),
                    (KEY_QTYPE.to_string(), Value::from(u64::from(group.qtype))),
                    (KEY_MEDIAN_MS.to_string(), Value::from(millis(group.interval_median))),
                    (KEY_STABILITY_PCT.to_string(), Value::from(percent(group.stability))),
                    (KEY_SOURCE_FILE.to_string(), Value::from(file_name)),
                    (KEY_SOURCE_FILE_ID.to_string(), Value::from(file_id)),
                ]
                .into_iter()
                .collect(),
            });
            for epoch in [group.first_epoch, group.last_epoch] {
                timeline.push(lovelycarve_plugin::TimelineEvent {
                    timestamp: iso8601(epoch),
                    event_type: "dns_heartbeat.candidate".to_string(),
                    description: format!(
                        "周期心跳候选 {} ({})",
                        group.qname,
                        dns::qtype_name(group.qtype)
                    ),
                    attributes: [
                        (KEY_QNAME.to_string(), Value::from(group.qname.as_str())),
                        (KEY_QTYPE.to_string(), Value::from(u64::from(group.qtype))),
                        (KEY_SOURCE_FILE.to_string(), Value::from(file_name)),
                        (KEY_SOURCE_FILE_ID.to_string(), Value::from(file_id)),
                    ]
                    .into_iter()
                    .collect(),
                });
            }
        }
    }

    // 汇总数据项：抓包元数据 + 阈值 + 跳过计数 + 溯源。
    let mut summary_attributes = Attributes::new();
    summary_attributes.insert(KEY_SOURCE_FILE, Value::from(file_name));
    summary_attributes.insert(KEY_SOURCE_FILE_ID, Value::from(file_id));
    summary_attributes.insert(KEY_SOURCE_FILE_SIZE, Value::from(file_size));
    summary_attributes.insert(KEY_SOURCE_FORMAT, Value::from(report.info.format));
    summary_attributes.insert(KEY_TIME_BASIS, Value::from(report.info.timebase.as_str()));
    summary_attributes.insert(KEY_RESERVED, Value::from(u64::from(report.info.reserved_field)));
    summary_attributes.insert(KEY_SNAPLEN, Value::from(u64::from(report.info.snaplen)));
    summary_attributes.insert(KEY_LINKTYPE, Value::from(u64::from(report.info.linktype)));
    summary_attributes.insert(
        KEY_PARAMS,
        Value::from(format!(
            "N={} tolerance={} stability>={} detailK={}",
            report.options.min_samples,
            report.options.tolerance,
            report.options.stability_threshold,
            report.options.detail_limit
        )),
    );
    summary_attributes.insert(KEY_EVIDENCE, Value::from(report.summary_line()));
    artifacts.push(Artifact {
        artifact_type: ARTIFACT_SUMMARY.to_string(),
        title: "DNS 查询心跳分析汇总".to_string(),
        value: Some(Value::from(report.summary_line())),
        attributes: summary_attributes,
    });

    AnalysisResult {
        summary: Some(report.summary_line()),
        nodes: result_nodes(),
        artifacts,
        timeline,
        findings,
    }
}

/// 间隔明细文本：`2.999,3.001,…`，并注明截断条数。
fn detail_text(_options: &options::AnalysisOptions, detail: &[f64]) -> String {
    detail
        .iter()
        .map(|value| format!("{value:.3}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// 秒 → 毫秒整数（输出字段 `*_ms`；不做"秒标签 + 毫秒值"的混用）。
/// `interval::GroupStats` 内部仍以秒为浮点，避免累积舍入误差。
fn millis(seconds: f64) -> u64 {
    if !seconds.is_finite() || seconds <= 0.0 {
        return 0;
    }
    (seconds * 1000.0).round() as u64
}

/// 0..=1 比例 → 0–100 的百分比整数（输出字段 `*_pct`）。
fn percent(ratio: f64) -> u64 {
    if !ratio.is_finite() {
        return 0;
    }
    (ratio * 100.0).round().clamp(0.0, 100.0) as u64
}

/// epoch 秒 → `yyyy-MM-ddTHH:MM:SSZ`（按 Unix 时间计算，不依赖本机时钟）。
pub fn iso8601(epoch: f64) -> String {
    if !epoch.is_finite() {
        return "invalid".to_string();
    }
    let total = epoch.floor();
    if total < 0.0 {
        return "invalid".to_string();
    }
    let seconds = total as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant 的 civil_from_days 算法（1970-01-01 为第 0 天）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, PLUGIN_VERSION).file_analyzer(DnsHeartbeatAnalyzer)
}

export_plugin!(plugin);

// ---------------------------------------------------------------------------
// 端到端测试：合成 pcap → 完整分析 → LPP 产物属性
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Report;
    use crate::interval::GroupStats;
    use crate::synth::{self, PcapEntry, UdpPacket};

    fn entries(queries: &[(f64, &str, u16)]) -> Vec<PcapEntry> {
        queries
            .iter()
            .map(|(epoch, name, qtype)| {
                PcapEntry::Udp(UdpPacket::to_dns(
                    synth::epoch_sec(*epoch),
                    synth::frac_of(*epoch),
                    synth::dns_query_name(name, *qtype),
                ))
            })
            .collect()
    }

    fn analyze(entries: &[PcapEntry]) -> Report {
        let bytes = synth::build_pcap(entries);
        engine::analyze_bytes(&bytes, options::AnalysisOptions::default()).expect("合成 pcap 应可解析")
    }

    fn group<'a>(report: &'a Report, name: &str, qtype: u16) -> &'a GroupStats {
        report
            .groups
            .iter()
            .find(|group| group.qname == name && group.qtype == qtype)
            .unwrap_or_else(|| panic!("缺少分组 {name}/{qtype}"))
    }

    #[test]
    fn fixed_three_second_domain_is_periodic() {
        let base = 1_700_000_000.0;
        let queries: Vec<(f64, &str, u16)> = (0..8)
            .map(|index| (base + index as f64 * 3.0, "heartbeat-a.example", 1))
            .collect();
        let report = analyze(&entries(&queries));
        let stats = group(&report, "heartbeat-a.example", 1);
        assert_eq!(stats.query_count, 8);
        assert_eq!(stats.interval_count, 7);
        assert!(stats.periodic);
        assert!((stats.interval_median - 3.0).abs() < 1e-6, "median={}", stats.interval_median);
        assert!((stats.stability - 1.0).abs() < 1e-9);
        assert_eq!(report.info.format, "pcap");
    }

    #[test]
    fn random_interval_domain_is_not_periodic() {
        let base = 1_700_000_000.0;
        let offsets = [0.0, 4.0, 21.0, 22.5, 60.0, 61.5, 200.0, 201.0];
        let queries: Vec<(f64, &str, u16)> = offsets
            .iter()
            .map(|offset| (base + offset, "random-b.example", 1))
            .collect();
        let report = analyze(&entries(&queries));
        let stats = group(&report, "random-b.example", 1);
        assert_eq!(stats.query_count, 8);
        assert!(!stats.periodic);
        assert!(stats.stability < 0.8, "stability={}", stats.stability);
    }

    #[test]
    fn single_missing_query_lowers_stability_but_is_tolerated_with_wider_tolerance() {
        let base = 1_700_000_000.0;
        // 每 3s 一条，第 5 条缺失 → 出现一个 6s 间隔。
        let offsets = [0.0, 3.0, 6.0, 9.0, 15.0, 18.0, 21.0, 24.0];
        let queries: Vec<(f64, &str, u16)> = offsets
            .iter()
            .map(|offset| (base + offset, "gappy-c.example", 1))
            .collect();
        let entries = entries(&queries);
        let report = analyze(&entries);
        let stats = group(&report, "gappy-c.example", 1);
        assert!((stats.interval_median - 3.0).abs() < 1e-6);
        assert!((stats.stability - 6.0 / 7.0).abs() < 1e-9, "stability={}", stats.stability);
        // 6/7 ≈ 0.857 ≥ 0.8：默认阈值下仍判周期（可容忍一次缺失），
        // 但稳定性明显低于无缺失的规律心跳。
        assert!(stats.periodic);

        let bytes = synth::build_pcap(&entries);
        let tolerant = engine::analyze_bytes(
            &bytes,
            options::AnalysisOptions {
                tolerance: 1.0,
                ..options::AnalysisOptions::default()
            },
        )
        .expect("合成 pcap 应可解析");
        assert!(group(&tolerant, "gappy-c.example", 1).periodic);
    }

    #[test]
    fn out_of_order_packets_are_sorted_before_interval_math() {
        let base = 1_700_000_000.0;
        // 乱序写入：0,9,3,6,12 秒。
        let offsets = [0.0, 9.0, 3.0, 6.0, 12.0];
        let queries: Vec<(f64, &str, u16)> = offsets
            .iter()
            .map(|offset| (base + offset, "shuffled-d.example", 1))
            .collect();
        let report = analyze(&entries(&queries));
        let stats = group(&report, "shuffled-d.example", 1);
        assert_eq!(report.scan.out_of_order, 2);
        assert_eq!(stats.out_of_order, 2);
        assert_eq!(stats.first_epoch, base);
        assert_eq!(stats.last_epoch, base + 12.0);
        // 排序后间隔为 3,3,3,3 → 中位数 3s，无负间隔。
        assert!((stats.interval_median - 3.0).abs() < 1e-6);
        assert!(stats.detail.iter().all(|interval| *interval > 0.0));
    }

    #[test]
    fn capture_without_dns_yields_no_groups_but_keeps_a_summary() {
        let entries = vec![
            // UDP 载荷不足 12 字节 → 不是 DNS，计入 not_dns。
            PcapEntry::Udp(UdpPacket::to_dns(1_700_000_000, 0, synth::non_dns_payload_of(8))),
            // 非 UDP：TCP 协议号 6（以太网帧内 20 字节 IPv4 + 20 字节 TCP）。
            PcapEntry::RawFrame {
                ts_sec: 1_700_000_001,
                ts_frac: 0,
                frame: {
                    let mut frame = vec![
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst mac
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
                        0x08, 0x00, // IPv4
                    ];
                    frame.extend_from_slice(&[
                        0x45, 0x00, 0x00, 0x28, // ver/ihl, tos, total_len=40
                        0x00, 0x00, 0x40, 0x00, // id, flags
                        64, 6, 0x00, 0x00, // ttl, proto=TCP, checksum
                        10, 0, 0, 1, 10, 0, 0, 2,
                    ]);
                    frame.extend_from_slice(&[0u8; 20]);
                    frame
                },
            },
        ];
        let report = analyze(&entries);
        assert!(report.groups.is_empty());
        assert_eq!(report.dns_query_messages, 0);
        assert_eq!(report.skipped.not_dns, 1);
        // 该 TCP 帧两端 53 端口不参与：TCP 直接按"不支持"跳过。
        assert_eq!(report.skipped.tcp, 1);
        let result = build_result(&report, "empty.pcap", "file-1", 1234);
        // 只有汇总数据项，没有域名数据项。
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(result.artifacts[0].artifact_type, ARTIFACT_SUMMARY);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn responses_fragments_and_ipv6_are_skipped_with_counters() {
        let base = 1_700_000_000.0;
        let mut entries = entries(&[(base, "counted.example", 1)]);
        entries.push(PcapEntry::Udp(UdpPacket::to_dns(
            synth::epoch_sec(base + 1.0),
            synth::frac_of(base + 1.0),
            synth::dns_response("counted.example", 1),
        )));
        // IPv6（ethertype 换成 0x86DD）。
        entries.push(PcapEntry::RawFrame {
            ts_sec: synth::epoch_sec(base + 2.0),
            ts_frac: 0,
            frame: {
                let mut frame = vec![0u8; 12];
                frame.extend_from_slice(&[0x86, 0xDD]);
                frame.extend_from_slice(&[0u8; 40]);
                frame
            },
        });
        let report = analyze(&entries);
        assert_eq!(report.dns_query_messages, 1);
        assert_eq!(report.skipped.dns_response, 1);
        assert_eq!(report.skipped.ipv6, 1);
        assert_eq!(group(&report, "counted.example", 1).query_count, 1);
        assert!(group(&report, "counted.example", 1).insufficient_samples);
        assert!(!group(&report, "counted.example", 1).periodic);
    }

    #[test]
    fn non_dns_port_udp_is_not_parsed_as_dns() {
        // 44818 端口的 UDP 载荷恰好以 DNS 头结构开头（qdcount=1）：
        // 若不按端口过滤，会被错误计入统计。
        let mut payload = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        payload.extend_from_slice(&[1, b'x', 0, 0x00, 0x01, 0x00, 0x01]);
        let mut packet = synth::UdpPacket::to_dns(1_700_000_000, 0, payload.clone());
        packet.dst_port = 44818;
        packet.src_port = 44818;
        let entries = vec![PcapEntry::Udp(packet)];
        let report = analyze(&entries);
        assert!(report.groups.is_empty());
        assert_eq!(report.dns_query_messages, 0);
        assert_eq!(report.skipped.not_dns_port, 1);

        // 换成目的端口 53 则正常统计（证明过滤条件只是端口）。
        let mut packet = synth::UdpPacket::to_dns(1_700_000_000, 0, payload);
        packet.dst_port = 53;
        let report = analyze(&[PcapEntry::Udp(packet)]);
        assert_eq!(report.dns_query_messages, 1);
        assert_eq!(report.skipped.not_dns_port, 0);
        assert_eq!(group(&report, "x", 1).query_count, 1);
    }

    #[test]
    fn source_identity_and_thresholds_are_recorded_on_every_artifact() {
        let base = 1_700_000_000.0;
        let queries: Vec<(f64, &str, u16)> = (0..6)
            .map(|index| (base + index as f64 * 2.0, "track.example", 1))
            .collect();
        let report = analyze(&entries(&queries));
        let result = build_result(&report, "capture.pcap", "file-abc", 4096);

        assert_eq!(result.artifacts.len(), 2);
        for artifact in &result.artifacts {
            assert_eq!(
                artifact.attributes.get(KEY_SOURCE_FILE),
                Some(&Value::from("capture.pcap"))
            );
            assert_eq!(
                artifact.attributes.get(KEY_SOURCE_FILE_ID),
                Some(&Value::from("file-abc"))
            );
            // 首版不计算源文件哈希：任何哈希键都不得出现，避免把
            // 解析器随机读取的摘要冒充成源文件摘要。
            for (key, _) in artifact.attributes.iter() {
                assert!(
                    !key.contains("sha") && !key.contains("hash") && !key.contains("md5"),
                    "不应输出哈希字段 {key}"
                );
            }
        }
        let domain = &result.artifacts[0];
        assert_eq!(domain.artifact_type, ARTIFACT_DOMAIN);
        assert_eq!(domain.attributes.get(KEY_QNAME), Some(&Value::from("track.example")));
        assert_eq!(domain.attributes.get(KEY_PERIODIC), Some(&Value::from(true)));
        assert_eq!(domain.attributes.get(KEY_MEDIAN_MS), Some(&Value::from(2000_u64)));
        assert_eq!(domain.attributes.get(KEY_STABILITY_PCT), Some(&Value::from(100_u64)));
        assert_eq!(
            domain.attributes.get(KEY_DETAIL),
            Some(&Value::from("2.000,2.000,2.000,2.000,2.000"))
        );
        // 记录级溯源：源记录槽位与文件字节偏移区间（由合成 pcap 的实际布局推出）。
        let dns_len = synth::dns_query_name("track.example", 1).len();
        let frame_len = 14 + 20 + 8 + dns_len;
        assert_eq!(domain.attributes.get(KEY_SLOT_RANGE), Some(&Value::from("#0..#5")));
        assert_eq!(
            domain.attributes.get(KEY_OFFSET_RANGE),
            Some(&Value::from(format!("24..{}", 24 + 5 * (16 + frame_len))))
        );
        // 不得把逻辑文件名伪装成检材相对路径。
        assert!(!domain.attributes.contains_key("source.path"));
        assert!(!domain.attributes.contains_key("source.root"));
        let summary = &result.artifacts[1];
        assert_eq!(summary.artifact_type, ARTIFACT_SUMMARY);
        assert_eq!(
            summary.attributes.get(KEY_PARAMS),
            Some(&Value::from("N=5 tolerance=0.1 stability>=0.8 detailK=16"))
        );
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.nodes.len(), 2);
        assert!(result.summary.as_deref().unwrap_or_default().contains("疑似周期心跳 1 个"));
    }

    #[test]
    fn iso8601_matches_known_epochs() {
        assert_eq!(iso8601(0.0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000.0), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601(1_709_164_800.5), "2024-02-29T00:00:00Z");
        assert_eq!(iso8601(-1.0), "invalid");
        assert_eq!(iso8601(f64::NAN), "invalid");
    }

    #[test]
    fn reserved_thiszone_field_is_kept_as_metadata_not_compensated() {
        // pcap 文件头保留字段（旧 thiszone）非零时**不得**加到 Unix epoch 上：
        // 记录时间戳本身通常已是 epoch，规范亦未定义该字段的校正含义。
        let base = 1_700_000_000.0;
        let entries: Vec<PcapEntry> = (0..6)
            .map(|index| (base + index as f64 * 4.0, "thiszone.example", 1))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(epoch, name, qtype)| {
                PcapEntry::Udp(UdpPacket::to_dns(
                    synth::epoch_sec(epoch),
                    synth::frac_of(epoch),
                    synth::dns_query_name(name, qtype),
                ))
            })
            .collect();
        let mut bytes = synth::build_pcap(&entries);
        // 写入保留字段 = 28800（+8h），构造"非零保留字段"样例。
        bytes[8..12].copy_from_slice(&28_800i32.to_le_bytes());
        let report = engine::analyze_bytes(&bytes, options::AnalysisOptions::default())
            .expect("非零保留字段的 pcap 应可解析");

        assert_eq!(report.info.reserved_field, 28_800);
        let stats = group(&report, "thiszone.example", 1);
        // 若错误地累加，first_epoch 会是 base+28800（2023-11-15T06:13:20Z）。
        assert_eq!(stats.first_epoch, base);
        assert_eq!(iso8601(stats.first_epoch), "2023-11-14T22:13:20Z");
        assert!((stats.interval_median - 4.0).abs() < 1e-6);
        assert!(stats.periodic);

        // 汇总数据项仍记录原始保留字段值，便于复核。
        let result = build_result(&report, "tz.pcap", "f", bytes.len() as u64);
        let summary = result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == ARTIFACT_SUMMARY)
            .expect("应有汇总项");
        assert_eq!(
            summary.attributes.get(KEY_RESERVED),
            Some(&Value::from(28_800_i64))
        );
        assert!(summary
            .attributes
            .get(KEY_TIME_BASIS)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("reserved_field_ignored"));
    }

    #[test]
    fn plugin_identity_matches_manifest_constants() {
        assert_eq!(ANALYZER, "ljnljn.dns-heartbeat");
        assert_eq!(PLUGIN_ID, "org.ljnljn.dns-heartbeat");
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains(&format!("id = \"{PLUGIN_ID}\"")));
        assert!(manifest.contains(&format!("name = \"{PLUGIN_NAME}\"")));
        assert!(manifest.contains(&format!("version = \"{PLUGIN_VERSION}\"")));
        assert!(manifest.contains(&format!("analyzer = \"{ANALYZER}\"")));
        assert!(manifest.contains("path = \"ljnljn_kb_dns_heartbeat_periodicity_64075a55\""));
        assert!(manifest.contains("isolation = \"process\""));
        assert!(manifest.contains("emit_artifacts"));
        assert_eq!(DnsHeartbeatAnalyzer.analyzer(), ANALYZER);
    }

    #[test]
    fn unsupported_and_broken_inputs_return_errors_not_empty_success() {
        let our_unused = analyze(&entries(&[(1.0, "x.example", 1)]));
        let _ = our_unused;
        let pcapng = {
            let mut bytes = vec![0x0A, 0x0D, 0x0D, 0x0A];
            bytes.extend_from_slice(&[0x1C, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A]);
            bytes.extend_from_slice(&[0u8; 32]);
            bytes
        };
        let error = engine::analyze_bytes(&pcapng, options::AnalysisOptions::default())
            .expect_err("pcapng 应报不支持");
        assert_eq!(error.code, "unsupported_capture_format");

        let mut truncated = synth::build_pcap(&entries(&[(1.0, "x.example", 1)]));
        truncated.truncate(truncated.len() - 3);
        let error = engine::analyze_bytes(&truncated, options::AnalysisOptions::default())
            .expect_err("截断应报错");
        assert_eq!(error.code, "truncated_capture");

        let header_only = synth::build_pcap(&[]);
        let error = engine::analyze_bytes(&header_only, options::AnalysisOptions::default())
            .expect_err("只有文件头应报错");
        assert_eq!(error.code, "no_valid_timestamp");
    }
}
