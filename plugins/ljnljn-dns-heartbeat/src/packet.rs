//! 链路层 → IPv4 → UDP 的提取（首版范围）。
//!
//! 支持：Ethernet（含 802.1Q/QinQ VLAN 标签，最多 2 层）与 DLT_RAW（直接 IPv4）。
//! 未覆盖（遇到即返回明确原因，不猜）：
//! * IPv6（含扩展头）；
//! * IP 分片（`MF` 或 `fragment offset != 0`，即首版不做重组）；
//! * TCP 承载的 DNS（不实现 TCP 流重组）；
//! * Linux cooked（SLL/SLL2）、loopback 等其它链路类型；
//! * UDP 之外的传输层协议。

/// 支持的链路类型（与 pcap 文件头的 network 字段一致）。
pub const DLT_EN10MB: u32 = 1;
/// Raw IP（IPv4/IPv6 裸包）。
pub const DLT_RAW: u32 = 101;
/// Ethernet 协议类型 IPv4。
const ETHERTYPE_IPV4: u16 = 0x0800;
/// VLAN 标签协议类型。
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERTYPE_QINQ_OLD: u16 = 0x9100;
/// 最多穿透的 VLAN 标签层数。
const MAX_VLAN_TAGS: usize = 2;

/// 提取结果。
#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    /// UDP 载荷（已剥离 8 字节 UDP 头）。
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    },
    /// 该帧不是 UDP / 不是本版支持的协议；`reason` 为稳定原因码。
    Unsupported { reason: &'static str },
}

/// 稳定原因码。
pub const SKIP_NOT_IPV4: &str = "not_ipv4";
pub const SKIP_IPV6: &str = "ipv6_not_supported";
pub const SKIP_FRAGMENTED: &str = "ip_fragment_not_reassembled";
pub const SKIP_LINKTYPE: &str = "linktype_not_supported";
pub const SKIP_NOT_UDP: &str = "transport_not_udp";
pub const SKIP_TRUNCATED: &str = "truncated_frame";
pub const SKIP_MALFORMED: &str = "malformed_header";
/// TCP 承载的 DNS：首版不做 TCP 流重组。
pub const SKIP_TCP: &str = "tcp_dns_not_supported";

/// 从一帧链路层数据里提取 UDP 载荷。
pub fn extract_udp(linktype: u32, frame: &[u8]) -> Transport {
    let ip = match linktype {
        DLT_EN10MB => match strip_ethernet(frame) {
            Ok(rest) => rest,
            Err(reason) => return Transport::Unsupported { reason },
        },
        DLT_RAW => frame,
        _ => {
            return Transport::Unsupported {
                reason: SKIP_LINKTYPE,
            }
        }
    };
    extract_udp_from_ip(ip)
}

fn strip_ethernet(frame: &[u8]) -> Result<&[u8], &'static str> {
    if frame.len() < 14 {
        return Err(SKIP_TRUNCATED);
    }
    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    offset += 2;
    let mut tags = 0;
    while matches!(
        ethertype,
        ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_OLD
    ) {
        if tags >= MAX_VLAN_TAGS {
            return Err(SKIP_MALFORMED);
        }
        if frame.len() < offset + 4 {
            return Err(SKIP_TRUNCATED);
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
        tags += 1;
    }
    match ethertype {
        ETHERTYPE_IPV4 => Ok(&frame[offset..]),
        // 802.3 长度字段 + LLC：不是 IPv4。
        0x0000..=0x05DC => Err(SKIP_NOT_IPV4),
        0x86DD => Err(SKIP_IPV6),
        _ => Err(SKIP_NOT_IPV4),
    }
}

fn extract_udp_from_ip(ip: &[u8]) -> Transport {
    if ip.is_empty() {
        return Transport::Unsupported {
            reason: SKIP_TRUNCATED,
        };
    }
    match ip[0] >> 4 {
        4 => {}
        6 => return Transport::Unsupported { reason: SKIP_IPV6 },
        _ => {
            return Transport::Unsupported {
                reason: SKIP_NOT_IPV4,
            }
        }
    }
    if ip.len() < 20 {
        return Transport::Unsupported {
            reason: SKIP_TRUNCATED,
        };
    }
    let ihl = usize::from(ip[0] & 0x0F) * 4;
    if ihl < 20 || ihl > ip.len() {
        return Transport::Unsupported {
            reason: SKIP_MALFORMED,
        };
    }
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if total_len < ihl {
        return Transport::Unsupported {
            reason: SKIP_MALFORMED,
        };
    }
    let flags_fragment = u16::from_be_bytes([ip[6], ip[7]]);
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = flags_fragment & 0x1FFF;
    if more_fragments || fragment_offset != 0 {
        // 首片以外的分片没有传输层头；首片也不做重组，避免产出半截 DNS。
        return Transport::Unsupported {
            reason: SKIP_FRAGMENTED,
        };
    }
    // 以 IP 头声明的长度为准；抓包截断（total_len 大于实际）时用实际长度。
    let end = total_len.min(ip.len());
    let protocol = ip[9];
    match protocol {
        17 => {}
        6 => return Transport::Unsupported { reason: SKIP_TCP },
        _ => {
            return Transport::Unsupported {
                reason: SKIP_NOT_UDP,
            }
        }
    }
    if end < ihl + 8 {
        return Transport::Unsupported {
            reason: SKIP_TRUNCATED,
        };
    }
    let udp = &ip[ihl..end];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let payload_end = if udp_len >= 8 && udp_len <= udp.len() {
        udp_len
    } else {
        udp.len()
    };
    Transport::Udp {
        src_port,
        dst_port,
        payload: udp[8..payload_end].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 IPv4 + UDP 帧体。
    pub(crate) fn ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // id
        ip.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment
        ip.push(64); // ttl
        ip.push(17); // protocol UDP
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum
        ip.extend_from_slice(&[10, 0, 0, 1]); // src
        ip.extend_from_slice(&[10, 0, 0, 2]); // dst
        ip.extend_from_slice(&src_port.to_be_bytes());
        ip.extend_from_slice(&dst_port.to_be_bytes());
        ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // udp checksum
        ip.extend_from_slice(payload);
        ip
    }

    pub(crate) fn ethernet(ip: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(ip);
        frame
    }

    fn payload_of(transport: Transport) -> Option<Vec<u8>> {
        match transport {
            Transport::Udp { payload, .. } => Some(payload),
            _ => None,
        }
    }

    #[test]
    fn extracts_udp_payload_from_ethernet() {
        let ip = ipv4_udp(54321, 53, b"\x12\x34dns");
        let frame = ethernet(&ip);
        match extract_udp(DLT_EN10MB, &frame) {
            Transport::Udp {
                src_port,
                dst_port,
                payload,
            } => {
                assert_eq!(src_port, 54321);
                assert_eq!(dst_port, 53);
                assert_eq!(payload, b"\x12\x34dns");
            }
            other => panic!("应提取到 UDP: {other:?}"),
        }
        assert_eq!(
            payload_of(extract_udp(DLT_RAW, &ip)),
            Some(b"\x12\x34dns".to_vec())
        );
    }

    #[test]
    fn vlan_tags_are_skipped_once_or_twice() {
        let ip = ipv4_udp(1, 53, b"x");
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x64]);
        frame.extend_from_slice(&ETHERTYPE_QINQ.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x65]);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        assert_eq!(
            payload_of(extract_udp(DLT_EN10MB, &frame)),
            Some(b"x".to_vec())
        );
    }

    #[test]
    fn ipv6_and_fragments_and_tcp_are_skipped_with_reasons() {
        let mut frame = ethernet(&ipv4_udp(1, 53, b"x"));
        // 改成 IPv6 ethertype。
        frame[12] = 0x86;
        frame[13] = 0xDD;
        assert_eq!(
            extract_udp(DLT_EN10MB, &frame),
            Transport::Unsupported { reason: SKIP_IPV6 }
        );

        // 非首片分片。
        let mut ip = ipv4_udp(1, 53, b"x");
        ip[6] = 0x00;
        ip[7] = 0x01;
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported {
                reason: SKIP_FRAGMENTED
            }
        );

        // MF 位置 1 的首片也不处理（不做重组）。
        let mut ip = ipv4_udp(1, 53, b"x");
        ip[6] = 0x20;
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported {
                reason: SKIP_FRAGMENTED
            }
        );

        // TCP。
        let mut ip = ipv4_udp(1, 53, b"x");
        ip[9] = 6;
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported { reason: SKIP_TCP }
        );

        // ICMP。
        let mut ip = ipv4_udp(1, 53, b"x");
        ip[9] = 1;
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported {
                reason: SKIP_NOT_UDP
            }
        );
    }

    #[test]
    fn unsupported_linktypes_and_truncated_frames_report_reasons() {
        assert_eq!(
            extract_udp(113, b"whatever"),
            Transport::Unsupported {
                reason: SKIP_LINKTYPE
            }
        );
        assert_eq!(
            extract_udp(DLT_EN10MB, &[0u8; 10]),
            Transport::Unsupported {
                reason: SKIP_TRUNCATED
            }
        );
        // IPv4 头声明 60 字节但帧里只有 28 字节（UDP 头只剩 4 字节）→ 截断。
        let mut ip = ipv4_udp(1, 53, b"x");
        ip.truncate(24);
        ip[2] = 0x00;
        ip[3] = 0x3C;
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported {
                reason: SKIP_TRUNCATED
            }
        );
    }

    #[test]
    fn bad_ipv4_ihl_and_length_are_malformed() {
        let mut ip = ipv4_udp(1, 53, b"x");
        ip[0] = 0x44; // IHL=4 (<5)
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported {
                reason: SKIP_MALFORMED
            }
        );
        let mut ip = ipv4_udp(1, 53, b"x");
        ip[2] = 0x00;
        ip[3] = 0x0A; // total_len=10 < ihl
        assert_eq!(
            extract_udp(DLT_RAW, &ip),
            Transport::Unsupported {
                reason: SKIP_MALFORMED
            }
        );
    }

    #[test]
    fn ip_options_are_respected_via_ihl() {
        let mut ip = ipv4_udp(1, 53, b"abc");
        // 把 IHL 扩到 6（24 字节）并在选项区插入 4 字节，同时修正长度。
        let options = [0x01u8, 0x01, 0x01, 0x01];
        let mut extended = ip[..20].to_vec();
        extended.extend_from_slice(&options);
        extended.extend_from_slice(&ip[20..]);
        extended[0] = 0x46;
        let total = (extended.len() - 0) as u16;
        extended[2] = (total >> 8) as u8;
        extended[3] = (total & 0xFF) as u8;
        ip = extended;
        assert_eq!(payload_of(extract_udp(DLT_RAW, &ip)), Some(b"abc".to_vec()));
    }
}
