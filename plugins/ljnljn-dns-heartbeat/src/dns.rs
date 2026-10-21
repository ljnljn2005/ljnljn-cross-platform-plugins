//! DNS 报文解析：只提取"问题段"（question section）与题目要求的边界处理。
//!
//! 覆盖：
//! * 只取 QR=0 的查询报文；响应（QR=1）忽略，不计入统计；
//! * QDCOUNT=0 视为畸形；
//! * EDNS 多个问题名（QDCOUNT>1）：全部问题名都返回，各自成为独立记录，
//!   用 `question_index` 区分（首版不额外合并）。
//!
//! 边界与失败场景（每条都有单元测试）：
//! * 标签压缩指针不允许出现在问题名中（RFC 1035 只规定在消息别处压缩），
//!   出现指针判为畸形；
//! * 长度越界、标签超长（>63）、名字超长（>255）、报文截断都判为畸形并给出原因码；
//! * 名字按标签拼回并小写、去掉末尾点（根标签本身不产生空标签）。
//!
//! 未覆盖：IDNA（`xn--` A-label 解码）。含非 ASCII 字节的标签按 ISO-8859-1
//! 一一映射为 Unicode 标量，`xn--` 标签保持 ASCII 原文。

/// 畸形 DNS 的原因码（稳定字符串，测试逐字断言）。
pub const MALFORMED_TRUNCATED: &str = "truncated";
pub const MALFORMED_POINTER_IN_QNAME: &str = "compression_pointer_in_qname";
pub const MALFORMED_BAD_LABEL: &str = "bad_label";
pub const MALFORMED_NAME_TOO_LONG: &str = "name_too_long";
pub const MALFORMED_LABEL_TOO_LONG: &str = "label_too_long";
pub const MALFORMED_EMPTY_QNAME: &str = "empty_qname";
pub const MALFORMED_QDCOUNT_ZERO: &str = "qdcount_zero";

/// DNS 头固定长度。
pub const DNS_HEADER_LEN: usize = 12;
/// 域名全名（含标签长度字节与根）的最大长度。
pub const MAX_NAME_LEN: usize = 255;
/// 单个标签最大长度。
pub const MAX_LABEL_LEN: usize = 63;

/// 一个 DNS 问题名。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    /// 规范化后的名字：小写、去末尾点。
    pub qname: String,
    /// 问题类型 qtype。
    pub qtype: u16,
    /// 问题在报文 question 段中的序号（0 起）。
    pub question_index: u16,
}

/// 一条报文解析结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsParse {
    /// QR=0 的查询报文，正常解析出的问题名。
    Query { questions: Vec<Question> },
    /// QR=1 的响应，按需求不统计。
    Response { questions: usize },
    /// 不是 DNS 报文（长度不足 12 字节）。
    NotDns,
    /// 是 DNS 查询但畸形/截断。
    Malformed { reason: &'static str, qdcount: u16 },
}

/// 解析 DNS 载荷。
pub fn parse_dns(payload: &[u8]) -> DnsParse {
    if payload.len() < DNS_HEADER_LEN {
        return DnsParse::NotDns;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if flags & 0x8000 != 0 {
        return DnsParse::Response {
            questions: usized(qdcount),
        };
    }
    if qdcount == 0 {
        return DnsParse::Malformed {
            reason: MALFORMED_QDCOUNT_ZERO,
            qdcount,
        };
    }
    let mut questions = Vec::with_capacity(usized(qdcount).min(8));
    let mut offset = DNS_HEADER_LEN;
    for index in 0..qdcount {
        let (name, next) = match read_question_name(payload, offset) {
            Ok(parsed) => parsed,
            Err(reason) => return DnsParse::Malformed { reason, qdcount },
        };
        if next + 4 > payload.len() {
            return DnsParse::Malformed {
                reason: MALFORMED_TRUNCATED,
                qdcount,
            };
        }
        let qtype = u16::from_be_bytes([payload[next], payload[next + 1]]);
        offset = next + 4;
        if name.is_empty() {
            return DnsParse::Malformed {
                reason: MALFORMED_EMPTY_QNAME,
                qdcount,
            };
        }
        questions.push(Question {
            qname: name,
            qtype,
            question_index: index,
        });
    }
    DnsParse::Query { questions }
}

fn usized(value: u16) -> usize {
    usize::from(value)
}

/// 读问题名：返回 (规范化名字, 名字之后 qtype 的偏移)。
fn read_question_name(payload: &[u8], mut offset: usize) -> Result<(String, usize), &'static str> {
    let mut labels: Vec<String> = Vec::new();
    let mut name_len = 0usize;
    loop {
        if offset >= payload.len() {
            return Err(MALFORMED_TRUNCATED);
        }
        let length = payload[offset];
        // 压缩指针（11xxxxxx）：问题段不允许。
        if length & 0xC0 == 0xC0 {
            return Err(MALFORMED_POINTER_IN_QNAME);
        }
        if length & 0xC0 != 0 {
            return Err(MALFORMED_BAD_LABEL);
        }
        if length == 0 {
            // 根标签：结束；不产生空标签，因此 "a.com." 与 "a.com" 等价。
            offset += 1;
            break;
        }
        let length = usize::from(length);
        if length > MAX_LABEL_LEN {
            return Err(MALFORMED_LABEL_TOO_LONG);
        }
        name_len += length + 1;
        if name_len + 1 > MAX_NAME_LEN {
            return Err(MALFORMED_NAME_TOO_LONG);
        }
        let start = offset + 1;
        let end = start + length;
        if end > payload.len() {
            return Err(MALFORMED_TRUNCATED);
        }
        labels.push(normalize_label(&payload[start..end]));
        offset = end;
    }
    Ok((labels.join("."), offset))
}

/// 标签规范化为小写；非 ASCII 字节按 ISO-8859-1 一一映射为 Unicode 标量，
/// 保证结果仍是合法 UTF-8 且可逆（不做 IDNA 解码）。
fn normalize_label(bytes: &[u8]) -> String {
    let mut label = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii() {
            label.push(char::from(byte.to_ascii_lowercase()));
        } else {
            label.push(char::from(byte));
        }
    }
    label
}

/// qtype 的人类可读名；未知类型返回 `TYPE<number>`。
pub fn qtype_name(qtype: u16) -> String {
    let name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        other => return format!("TYPE{other}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条查询报文（单个问题）。
    pub(crate) fn query_message(name_labels: &[&str], qtype: u16) -> Vec<u8> {
        let mut message = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: QR=0, RD=1
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name_labels {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message
    }

    #[test]
    fn parses_a_normal_query_and_normalizes_the_name() {
        let message = query_message(&["ExAmPle", "COM"], 1);
        match parse_dns(&message) {
            DnsParse::Query { questions } => {
                assert_eq!(questions.len(), 1);
                assert_eq!(questions[0].qname, "example.com");
                assert_eq!(questions[0].qtype, 1);
                assert_eq!(questions[0].question_index, 0);
            }
            other => panic!("应解析为查询: {other:?}"),
        }
    }

    #[test]
    fn trailing_root_label_is_not_kept() {
        // 根标签由一个 0 字节表示，拼回名字后不带末尾点。
        let message = query_message(&["a", "b"], 16);
        match parse_dns(&message) {
            DnsParse::Query { questions } => assert_eq!(questions[0].qname, "a.b"),
            other => panic!("应解析为查询: {other:?}"),
        }
    }

    #[test]
    fn responses_are_not_counted() {
        let mut message = query_message(&["example", "com"], 1);
        message[2] |= 0x80; // QR=1
        assert_eq!(parse_dns(&message), DnsParse::Response { questions: 1 });
    }

    #[test]
    fn non_dns_payloads_are_reported_separately() {
        assert_eq!(parse_dns(&[]), DnsParse::NotDns);
        assert_eq!(parse_dns(&[0u8; 11]), DnsParse::NotDns);
        let header_only = [0u8, 1, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_dns(&header_only),
            DnsParse::Malformed {
                reason: MALFORMED_QDCOUNT_ZERO,
                qdcount: 0
            }
        );
    }

    #[test]
    fn truncated_names_are_malformed() {
        let message = query_message(&["example", "com"], 1);
        let truncated = &message[..message.len() - 10];
        assert_eq!(
            parse_dns(truncated),
            DnsParse::Malformed {
                reason: MALFORMED_TRUNCATED,
                qdcount: 1
            }
        );
        // 标签长度声明超出报文：0x7F 有保留位但小于 128，判为非法标签。
        let mut lying = message.clone();
        lying[DNS_HEADER_LEN] = 0x7F;
        assert_eq!(
            parse_dns(&lying),
            DnsParse::Malformed {
                reason: MALFORMED_BAD_LABEL,
                qdcount: 1
            }
        );
        // 声明长度合法（≤63）但报文里没有那么多字节 → 截断。
        let mut short = message.clone();
        short[DNS_HEADER_LEN] = 63;
        assert_eq!(
            parse_dns(&short),
            DnsParse::Malformed {
                reason: MALFORMED_TRUNCATED,
                qdcount: 1
            }
        );
        // 只提供 qtype 的前两个字节。
        let cut_qtype = &message[..message.len() - 3];
        assert_eq!(
            parse_dns(cut_qtype),
            DnsParse::Malformed {
                reason: MALFORMED_TRUNCATED,
                qdcount: 1
            }
        );
    }

    #[test]
    fn compression_pointer_in_question_is_malformed() {
        let mut message = query_message(&["example", "com"], 1);
        message[DNS_HEADER_LEN] = 0xC0;
        assert_eq!(
            parse_dns(&message),
            DnsParse::Malformed {
                reason: MALFORMED_POINTER_IN_QNAME,
                qdcount: 1
            }
        );
    }

    #[test]
    fn empty_qname_and_overlong_names_are_malformed() {
        let root_query = query_message(&[], 1);
        assert_eq!(
            parse_dns(&root_query),
            DnsParse::Malformed {
                reason: MALFORMED_EMPTY_QNAME,
                qdcount: 1
            }
        );
        let labels: Vec<String> = (0..5).map(|_| "a".repeat(63)).collect();
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let long = query_message(&refs, 1);
        assert_eq!(
            parse_dns(&long),
            DnsParse::Malformed {
                reason: MALFORMED_NAME_TOO_LONG,
                qdcount: 1
            }
        );
    }

    #[test]
    fn multiple_questions_are_all_returned() {
        let mut message = query_message(&["a", "example"], 1);
        message[5] = 2; // qdcount = 2
        message.extend_from_slice(&[1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        message.extend_from_slice(&28u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        match parse_dns(&message) {
            DnsParse::Query { questions } => {
                assert_eq!(questions.len(), 2);
                assert_eq!(questions[0].qname, "a.example");
                assert_eq!(questions[0].question_index, 0);
                assert_eq!(questions[1].qname, "b.example");
                assert_eq!(questions[1].qtype, 28);
                assert_eq!(questions[1].question_index, 1);
            }
            other => panic!("应解析为两条问题: {other:?}"),
        }
    }

    #[test]
    fn non_ascii_labels_are_preserved_reversibly_and_punycode_kept_as_is() {
        let mut message = query_message(&["example"], 1);
        // 在问题名前插入一个含 0xC3 0xA9 (é in Latin-1) 的标签。
        let mut custom = message[..DNS_HEADER_LEN].to_vec();
        custom.extend_from_slice(&[2, 0xC3, 0xA9]);
        custom.extend_from_slice(&message[DNS_HEADER_LEN..]);
        message = custom;
        match parse_dns(&message) {
            DnsParse::Query { questions } => assert_eq!(questions[0].qname, "Ã©.example"),
            other => panic!("应解析为查询: {other:?}"),
        }
        // `xn--` 标签保持 ASCII 原文（首版不做 IDNA 解码）。
        let puny = query_message(&["xn--bcher-kva", "example"], 1);
        match parse_dns(&puny) {
            DnsParse::Query { questions } => {
                assert_eq!(questions[0].qname, "xn--bcher-kva.example")
            }
            other => panic!("应解析为查询: {other:?}"),
        }
    }

    #[test]
    fn qtypes_have_names() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(999), "TYPE999");
    }
}
