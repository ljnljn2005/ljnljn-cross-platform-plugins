//! 合成 pcap 构造器（测试样例，不读取任何真实检材）。
//!
//! 只生成 Ethernet / IPv4 / UDP / DNS 查询报文，用于单元测试与
//! `cargo run --example synth` 的本地快速验证。所有时间戳与域名都由调用方
//! 给出，本模块**不含**任何固定案件参数。

/// 一条待写入的 UDP 报文。
#[derive(Clone, Debug)]
pub struct UdpPacket {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    /// 构造一条发往 53 端口的报文。
    pub fn to_dns(ts_sec: u32, ts_frac: u32, payload: Vec<u8>) -> Self {
        Self {
            ts_sec,
            ts_frac,
            src_port: 40_000,
            dst_port: 53,
            payload,
        }
    }
}

/// DNS 查询报文（QDCOUNT=1，QR=0，RD=1），问题名按标签写入。
pub fn dns_query(labels: &[&str], qtype: u16) -> Vec<u8> {
    let mut message = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: QR=0, RD=1
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
    ];
    for label in labels {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message
}

/// DNS 查询报文，域名按点号切分。
pub fn dns_query_name(name: &str, qtype: u16) -> Vec<u8> {
    let labels: Vec<&str> = name.split('.').filter(|label| !label.is_empty()).collect();
    dns_query(&labels, qtype)
}

/// DNS 响应报文（QR=1），用于验证"响应不统计"。
pub fn dns_response(name: &str, qtype: u16) -> Vec<u8> {
    let mut message = dns_query_name(name, qtype);
    message[2] |= 0x80;
    message
}

/// 非 DNS 的 UDP 载荷（NTP 风格 48 字节）。
pub fn non_dns_payload() -> Vec<u8> {
    non_dns_payload_of(48)
}

/// 指定长度的非 DNS UDP 载荷：不足 12 字节会被回报为"非 DNS"，
/// ≥12 字节则按 DNS 解析并多半被判为畸形查询。
pub fn non_dns_payload_of(len: usize) -> Vec<u8> {
    let mut payload = vec![0u8; len];
    if len > 0 {
        payload[0] = 0x1B;
    }
    if len > 1 {
        payload[1] = 0x01;
    }
    // qdcount（偏移 4..6）留 0：若长度 ≥12 会得到确定的 "畸形查询"
    // （qdcount_zero），不会落入"非 DNS"分支。
    payload
}

fn ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01]); // id
    ip.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment=0
    ip.push(64);
    ip.push(17);
    ip.extend_from_slice(&[0x00, 0x00]); // checksum 留空
    ip.extend_from_slice(&[192, 0, 2, 10]);
    ip.extend_from_slice(&[192, 0, 2, 53]);
    ip.extend_from_slice(&src_port.to_be_bytes());
    ip.extend_from_slice(&dst_port.to_be_bytes());
    ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00]); // UDP checksum 留空
    ip.extend_from_slice(payload);
    ip
}

fn ethernet(ip: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src
        0x08, 0x00, // IPv4
    ];
    frame.extend_from_slice(ip);
    frame
}

/// 一条带时间戳的原始包记录。
#[derive(Clone, Debug)]
pub enum PcapEntry {
    Udp(UdpPacket),
    /// 直接给定链路层帧（用于注入损坏/非 IP 数据）。
    RawFrame {
        ts_sec: u32,
        ts_frac: u32,
        frame: Vec<u8>,
    },
}

impl PcapEntry {
    fn timestamp(&self) -> (u32, u32) {
        match self {
            Self::Udp(packet) => (packet.ts_sec, packet.ts_frac),
            Self::RawFrame {
                ts_sec, ts_frac, ..
            } => (*ts_sec, *ts_frac),
        }
    }

    fn frame(&self) -> Vec<u8> {
        match self {
            Self::Udp(packet) => {
                ethernet(&ipv4_udp(packet.src_port, packet.dst_port, &packet.payload))
            }
            Self::RawFrame { frame, .. } => frame.clone(),
        }
    }
}

/// 生成 classic pcap（小端、以太网、微秒）。
pub fn build_pcap(entries: &[PcapEntry]) -> Vec<u8> {
    build_pcap_with_network(entries, 1)
}

/// 指定 `network`（linktype）字段生成 pcap。
pub fn build_pcap_with_network(entries: &[PcapEntry], network: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    bytes.extend_from_slice(&network.to_le_bytes());
    for entry in entries {
        let frame = entry.frame();
        let (sec, frac) = entry.timestamp();
        bytes.extend_from_slice(&sec.to_le_bytes());
        bytes.extend_from_slice(&frac.to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    bytes
}

/// 便捷：把 (timestamp, 域名, qtype) 列表变成 pcap 字节。
pub fn pcap_with_queries(queries: &[(f64, &str, u16)]) -> Vec<u8> {
    let entries: Vec<PcapEntry> = queries
        .iter()
        .map(|(epoch, name, qtype)| {
            PcapEntry::Udp(UdpPacket::to_dns(
                epoch_sec(*epoch),
                frac_of(*epoch),
                dns_query_name(name, *qtype),
            ))
        })
        .collect();
    build_pcap(&entries)
}

/// epoch → 秒（截断）。
pub fn epoch_sec(epoch: f64) -> u32 {
    epoch.floor().max(0.0) as u32
}

/// epoch → 微秒小数部分。
pub fn frac_of(epoch: f64) -> u32 {
    let frac = epoch - epoch.floor();
    (frac * 1_000_000.0).round().clamp(0.0, 999_999.0) as u32
}
