//! 分析编排：抓包 → 帧 → UDP → DNS 查询 → 分组统计。
//!
//! 这里是**唯一**把解析层串起来的地方，FileAnalyzer 与单元测试共用同一条
//! 路径（差别只在 `ByteSource` 实现：SDK `File::read` 或内存切片）。

use crate::capture::{scan, ByteSource, CaptureInfo, Frame, FrameVisitor, ScanStats};
use crate::dns::{parse_dns, DnsParse};
use crate::error::{AnalyzeError, AnalyzeResult, E_IO};
use crate::interval::{self, GroupStats, Groups, QueryHit};
use crate::options::AnalysisOptions;
use crate::packet::{extract_udp, Transport};

/// DNS 默认端口。
pub const DNS_PORT: u16 = 53;

/// 被跳过的帧计数（用于输出"为什么没算"，可审计）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SkipCounters {
    /// 非 UDP / 非 IPv4 / 不支持的链路类型等。
    pub not_udp: u64,
    /// IPv6。
    pub ipv6: u64,
    /// IP 分片（首版不重组）。
    pub fragmented: u64,
    /// 抓包/网络层截断。
    pub truncated: u64,
    /// 头部畸形。
    pub malformed: u64,
    /// 不支持的链路类型。
    pub linktype: u64,
    /// TCP 承载的 DNS（首版不做 TCP 重组）。
    pub tcp: u64,
    /// 不是 DNS（UDP 载荷不足 12 字节）。
    pub not_dns: u64,
    /// 源与目的端口都不是 53 的 UDP 报文（不当 DNS 解读）。
    pub not_dns_port: u64,
    /// DNS 响应（QR=1）。
    pub dns_response: u64,
    /// 畸形/截断的 DNS。
    pub dns_malformed: u64,
    /// 域名后缀过滤掉的查询。
    pub suffix_filtered: u64,
}

/// 一次分析的完整结果。
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub info: CaptureInfo,
    pub scan: ScanStats,
    pub skipped: SkipCounters,
    pub groups: Vec<GroupStats>,
    pub options: AnalysisOptions,
    /// DNS 查询报文数（含被后缀过滤掉的）。
    pub dns_query_messages: u64,
    /// 计入统计的查询条数。
    pub queries_counted: u64,
}

impl Report {
    /// 汇总一行。
    pub fn summary_line(&self) -> String {
        let periodic = self.groups.iter().filter(|group| group.periodic).count();
        let mut line = format!(
            "{} 抓包：{} 条记录/{} 帧；DNS 查询报文 {} 条，计入统计 {} 条；{} 个域名·类型分组，其中疑似周期心跳 {} 个。",
            self.info.format,
            self.scan.records,
            self.scan.frames,
            self.dns_query_messages,
            self.queries_counted,
            self.groups.len(),
            periodic
        );
        line.push_str(&format!(
            "\n判定阈值：N={}、tolerance={}、stability≥{}（来源：需求文本默认值）。",
            self.options.min_samples, self.options.tolerance, self.options.stability_threshold
        ));
        line.push_str(&format!(
            "\n跳过：非UDP {}、非53端口UDP {}、IPv6 {}、IP分片 {}、TCP-DNS {}、链路类型 {}、截断 {}、畸形 {}、非DNS {}、DNS响应 {}、畸形DNS {}、后缀过滤 {}。",
            self.skipped.not_udp,
            self.skipped.not_dns_port,
            self.skipped.ipv6,
            self.skipped.fragmented,
            self.skipped.tcp,
            self.skipped.linktype,
            self.skipped.truncated,
            self.skipped.malformed,
            self.skipped.not_dns,
            self.skipped.dns_response,
            self.skipped.dns_malformed,
            self.skipped.suffix_filtered
        ));
        line.push_str(&format!(
            "\n时间基准：{}；保留字段原始值 {}（仅记录，不参与 epoch 换算）；乱序记录 {} 条（已排序、原值保留）。",
            self.info.timebase, self.info.reserved_field, self.scan.out_of_order
        ));
        line
    }
}

struct Collector {
    groups: Groups,
    skipped: SkipCounters,
    options: AnalysisOptions,
    dns_query_messages: u64,
    queries_counted: u64,
}

impl FrameVisitor for Collector {
    fn on_frame(&mut self, frame: &Frame) -> AnalyzeResult<()> {
        collect_frame(
            frame,
            &self.options,
            &mut self.groups,
            &mut self.skipped,
            &mut self.dns_query_messages,
            &mut self.queries_counted,
        );
        Ok(())
    }
}

fn collect_frame(
    frame: &Frame,
    options: &AnalysisOptions,
    groups: &mut Groups,
    skipped: &mut SkipCounters,
    dns_query_messages: &mut u64,
    queries_counted: &mut u64,
) {
    let transport = extract_udp(frame.linktype, &frame.payload);
    let payload = match transport {
        Transport::Udp {
            payload,
            src_port,
            dst_port,
        } => {
            // DNS 端口过滤：只有源或目的端口为 53 的 UDP 报文才按 DNS 解读。
            // 否则普通 UDP 载荷（NTP/QUIC/…）会因头部巧合被误判成畸形 DNS，
            // 甚至被当成查询计入统计。
            if src_port != DNS_PORT && dst_port != DNS_PORT {
                skipped.not_dns_port += 1;
                return;
            }
            payload
        }
        Transport::Unsupported { reason } => {
            record_skip(skipped, reason);
            return;
        }
    };
    match parse_dns(&payload) {
        DnsParse::Query { questions } => {
            *dns_query_messages += 1;
            for question in questions {
                if !options.suffix_matches(&question.qname) {
                    skipped.suffix_filtered += 1;
                    continue;
                }
                interval::record(
                    groups,
                    &question.qname,
                    question.qtype,
                    QueryHit {
                        epoch: frame.epoch,
                        out_of_order: frame.out_of_order,
                        slot: frame.slot,
                        offset: frame.offset,
                        end: frame.offset + 16 + frame.payload.len() as u64,
                    },
                );
                *queries_counted += 1;
            }
        }
        DnsParse::Response { .. } => skipped.dns_response += 1,
        DnsParse::NotDns => skipped.not_dns += 1,
        DnsParse::Malformed { .. } => skipped.dns_malformed += 1,
    }
}

fn record_skip(skipped: &mut SkipCounters, reason: &'static str) {
    match reason {
        crate::packet::SKIP_NOT_IPV4 | crate::packet::SKIP_NOT_UDP => skipped.not_udp += 1,
        crate::packet::SKIP_IPV6 => skipped.ipv6 += 1,
        crate::packet::SKIP_FRAGMENTED => skipped.fragmented += 1,
        crate::packet::SKIP_TRUNCATED => skipped.truncated += 1,
        crate::packet::SKIP_MALFORMED => skipped.malformed += 1,
        crate::packet::SKIP_LINKTYPE => skipped.linktype += 1,
        crate::packet::SKIP_TCP => skipped.tcp += 1,
        _ => skipped.malformed += 1,
    }
}

/// 对任意字节来源执行完整分析。
pub fn analyze_source(source: &dyn ByteSource, options: AnalysisOptions) -> AnalyzeResult<Report> {
    let mut collector = Collector {
        groups: Groups::new(),
        skipped: SkipCounters::default(),
        options,
        dns_query_messages: 0,
        queries_counted: 0,
    };
    let (info, scan_stats) = scan(source, &mut collector)?;
    let groups = interval::analyze(collector.groups, &collector.options);
    Ok(Report {
        info,
        scan: scan_stats,
        skipped: collector.skipped,
        groups,
        options: collector.options,
        dns_query_messages: collector.dns_query_messages,
        queries_counted: collector.queries_counted,
    })
}

/// 便捷入口：对内存字节执行分析（单元测试与合成样例使用）。
pub fn analyze_bytes(bytes: &[u8], options: AnalysisOptions) -> AnalyzeResult<Report> {
    let source = crate::capture::MemorySource::new(bytes);
    analyze_source(&source, options)
}

/// 读取错误包装（宿主错误统一成 `read_error`，保留原文）。
pub fn read_error(message: String) -> crate::error::AnalyzeError {
    AnalyzeError::new(E_IO, message)
}
