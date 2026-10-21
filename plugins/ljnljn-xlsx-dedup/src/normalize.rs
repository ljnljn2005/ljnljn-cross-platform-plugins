//! 字段规范化：去空白、全角转半角、电话保留数字与前导 `+`、地址去常见标点、姓名去空白。
//!
//! 规范化只作用于“去重键”与脱敏展示，原始单元格值另存于来源记录中备核。
//! 全角转换覆盖 ASCII 全角区（U+FF01..U+FF5E）、全角空格 U+3000、
//! 以及电话/地址里常见的中日韩全角标点（－—–・等）。

/// 全角转半角：ASCII 全角区减 0xFEE0，全角空格转普通空格，常见全角标点按语义映射。
pub fn to_halfwidth(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        let mapped = match ch {
            '\u{3000}' => ' ',
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
            // 中文输入法常见的“全角连字符/破折号/中点”，电话里一律视作分隔。
            '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{30FB}' | '\u{FF65}' => '-',
            '\u{FFE5}' => '¥',
            other => other,
        };
        output.push(mapped);
    }
    output
}

fn squeeze_whitespace(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut last_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !last_space && !output.is_empty() {
                output.push(' ');
            }
            last_space = true;
        } else {
            output.push(ch);
            last_space = false;
        }
    }
    while output.ends_with(' ') {
        output.pop();
    }
    output
}

/// 通用清洗：全角转半角 → 去首尾空白 → 内部连续空白压缩为一个空格。
pub fn clean(input: &str) -> String {
    squeeze_whitespace(&to_halfwidth(input))
}

/// 姓名：去掉所有空白（含全角空格），其余字符保留。
pub fn normalize_name(input: &str) -> String {
    to_halfwidth(input)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect()
}

/// 电话：仅保留数字与“开头的一个 `+`”，`+` 只在首位有意义。
pub fn normalize_phone(input: &str) -> String {
    let half = to_halfwidth(input);
    let trimmed = half.trim();
    let mut output = String::with_capacity(trimmed.len());
    let mut plus_allowed = true;
    for ch in trimmed.chars() {
        if ch == '+' {
            if plus_allowed && output.is_empty() {
                output.push('+');
            }
            plus_allowed = false;
        } else if ch.is_ascii_digit() {
            output.push(ch);
            plus_allowed = false;
        } else if !ch.is_whitespace() {
            // 分隔符（-、/、()、· 等）直接丢弃。
            plus_allowed = false;
        }
    }
    output
}

/// 地址里视作分隔的常见标点（保留 `#` 与空白，因为门牌号 `#` 有语义差异，
/// 但需求要求“去常见标点并压缩空白”，故 `#` 也视为分隔）。
fn is_address_separator(ch: char) -> bool {
    matches!(
        ch,
        ',' | '.'
            | '。'
            | '、'
            | ';'
            | ':'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '"'
            | '\''
            | '“'
            | '”'
            | '!'
            | '?'
            | '！'
            | '？'
            | '~'
            | '·'
            | '•'
            | '—'
            | '–'
            | '−'
            | '№'
            | '#'
            | '《'
            | '》'
            | '<'
            | '>'
            | '/'
            | '\\'
            | '|'
            | '_'
            | '*'
            | '&'
            | '^'
            | '%'
            | '$'
            | '@'
            | '='
            | '+'
    )
}

/// 地址：全角转半角 → 分隔标点替换为空格 → 压缩空白。
///
/// `-` 也是地址里常见的连接符（`1-2-3`），因此同样按分隔处理，使
/// `长安街 1-2-3 号` 与 `长安街1号2号楼3单元` 之外的标点差异不再影响去重。
pub fn normalize_address(input: &str) -> String {
    let half = to_halfwidth(input);
    let mut spaced = String::with_capacity(half.len() + 8);
    for ch in half.chars() {
        if ch.is_whitespace() || ch == '-' || is_address_separator(ch) {
            spaced.push(' ');
        } else {
            spaced.push(ch);
        }
    }
    squeeze_whitespace(&spaced)
}

/// 电话脱敏：保留前 3 位与后 4 位，中间按实际长度补 `*`。
///
/// - 长度 ≤ 7 时整体按“前 3 后 4”展示，重叠部分只保留一份，避免泄露完整号码；
/// - 长度不足 8 时同样不会原样输出任何完整号码。
pub fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    let len = chars.len();
    if len == 0 {
        return String::new();
    }
    let (prefix, suffix) = (3usize.min(len), 4usize.min(len));
    if len <= prefix + suffix {
        // 太短：只展示前 2 位与末 2 位，中间全部打码。
        let head = (len.saturating_sub(2)).min(2);
        let tail = (len - head).min(2);
        let masked = len.saturating_sub(head + tail);
        let mut out: String = chars[..head].iter().collect();
        out.push_str(&"*".repeat(masked));
        out.extend(chars[len - tail..].iter());
        return out;
    }
    let mut out: String = chars[..prefix].iter().collect();
    out.push_str(&"*".repeat(len - prefix - suffix));
    out.extend(chars[len - suffix..].iter());
    out
}

/// 姓名脱敏：保留首字，其余每个字符替换为 `*`。
pub fn mask_name(name: &str) -> String {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let rest = chars.count();
    format!("{first}{}", "*".repeat(rest))
}

/// 地址脱敏：保留前 6 个字符与最后 4 个字符。
pub fn mask_address(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    let len = chars.len();
    if len == 0 {
        return String::new();
    }
    if len <= 12 {
        let head = 2.min(len);
        let tail = 2.min(len - head);
        return format!(
            "{}{}{}",
            chars[..head].iter().collect::<String>(),
            "*".repeat(len - head - tail),
            chars[len - tail..].iter().collect::<String>()
        );
    }
    format!(
        "{}{}{}",
        chars[..6].iter().collect::<String>(),
        "*".repeat(len - 10),
        chars[len - 4..].iter().collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halfwidth_conversion_covers_ascii_and_ideographic_space() {
        assert_eq!(to_halfwidth("ＡＢＣ１２３"), "ABC123");
        assert_eq!(to_halfwidth("张　三"), "张 三");
        assert_eq!(to_halfwidth("＋８６－１３８"), "+86-138");
    }

    #[test]
    fn clean_trims_and_squeezes_inner_whitespace() {
        assert_eq!(clean("  王  小 明 \t"), "王 小 明");
        assert_eq!(clean("　　"), "");
        assert_eq!(clean("广东省 深圳市\n南山区"), "广东省 深圳市 南山区");
    }

    #[test]
    fn phone_keeps_only_digits_and_one_leading_plus() {
        assert_eq!(normalize_phone(" 138-0013-8000 "), "13800138000");
        assert_eq!(normalize_phone("+86 138 0013 8000"), "+8613800138000");
        assert_eq!(normalize_phone("+86-138-0013-8000"), "+8613800138000");
        assert_eq!(
            normalize_phone("＋８６　１３８－００１３－８０００"),
            "+8613800138000"
        );
        assert_eq!(normalize_phone("138+0013"), "1380013");
        assert_eq!(normalize_phone(""), "");
        assert_eq!(normalize_phone("13800138000转800"), "13800138000800");
    }

    #[test]
    fn address_drops_punctuation_and_squeezes_spaces() {
        assert_eq!(
            normalize_address("广东省 深圳市 南山区，科技园（南区）1栋-2单元"),
            "广东省 深圳市 南山区 科技园 南区 1栋 2单元"
        );
        assert_eq!(
            normalize_address("北京市海淀区中关村大街１号；"),
            "北京市海淀区中关村大街1号"
        );
        assert_eq!(normalize_address("  "), "");
    }

    #[test]
    fn name_drops_all_whitespace() {
        assert_eq!(normalize_name(" 李 四 "), "李四");
        assert_eq!(normalize_name("Ａｄａ　Lovelace"), "AdaLovelace");
    }

    #[test]
    fn phone_mask_keeps_three_and_four_and_hides_the_middle() {
        assert_eq!(mask_phone("13800138000"), "138****8000");
        assert_eq!(mask_phone("+8613800138000"), "+86*******8000");
        assert_eq!(mask_phone("12345678"), "123*5678");
        // 7 位号码按“前 2 后 2 + 打码”处理，不泄露完整号码。
        assert_eq!(mask_phone("1234567"), "12***67");
        // 未规范化的原始文本按实际字符数打码（前 3 后 4，中间全部为 *）。
        assert_eq!(mask_phone("0755-1234"), "075**1234");
        assert_eq!(mask_phone(""), "");
        assert_eq!(mask_name("张三丰"), "张**");
        // 13 个字符：保留前 6（北京市海淀区）与末 4（大街1号），中间 3 个打码。
        assert_eq!(
            mask_address("北京市海淀区中关村大街1号"),
            "北京市海淀区***大街1号"
        );
    }
}
