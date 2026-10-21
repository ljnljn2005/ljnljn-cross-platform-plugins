//! 小工具：hex 编解码（salt / HMAC / 主密钥都按小写 hex 输出与输入）。

/// 小写 hex，无分隔符。
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// 解析 hex：允许空白与 `0x` 前缀，必须成对且全为 hex 字符。
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut cleaned = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_whitespace() || ch == ':' || ch == '-' || ch == '_' {
            continue;
        }
        cleaned.push(ch);
    }
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned)
        .to_owned();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    let digits = cleaned.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(out)
}

/// 前若干个字节的 hex 片段，用于 evidence 属性里的"读取到的原始字节"。
pub fn prefix(bytes: &[u8], count: usize) -> String {
    encode(&bytes[..bytes.len().min(count)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tolerant_input() {
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(decode("00abff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode("0x00 AB-ff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode("00:ab:ff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode("abc"), None); // 奇数长度
        assert_eq!(decode("zz"), None); // 非 hex
        assert_eq!(decode(""), None);
    }

    #[test]
    fn prefix_clamps_to_length() {
        assert_eq!(prefix(&[1, 2], 16), "0102");
    }
}
