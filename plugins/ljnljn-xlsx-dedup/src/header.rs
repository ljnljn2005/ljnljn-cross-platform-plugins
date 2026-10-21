//! 表头识别：按首行（必要时前若干行）匹配姓名/电话/地址列别名，
//! 无表头时按已知列序回退并标记 `headerSource = positional`。

use crate::normalize::clean;

/// 字段类型。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Field {
    Name,
    Phone,
    Address,
}

impl Field {
    pub const ALL: [Field; 3] = [Field::Name, Field::Phone, Field::Address];

    pub fn key(self) -> &'static str {
        match self {
            Field::Name => "name",
            Field::Phone => "phone",
            Field::Address => "address",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Field::Name => "姓名",
            Field::Phone => "电话",
            Field::Address => "地址",
        }
    }
}

/// 表头来源。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSource {
    /// 首行（或探测到的第 N 行）命中别名。
    Header,
    /// 前三行都没有命中，按已知列序回退。
    Positional,
}

impl HeaderSource {
    pub fn as_str(self) -> &'static str {
        match self {
            HeaderSource::Header => "header",
            HeaderSource::Positional => "positional",
        }
    }
}

/// 无表头回退列序：
/// 1. `ID, 姓名, 电话, 地址, 省, 市, 10`（历史口径的顺丰导出表）；
/// 2. `姓名, 电话, 地址`（恰好三列的数据表）；
/// 3. `姓名, 电话, 地址` 出现在列 0/1/2 的通用三列布局（与 2 相同，保留以记录来源）。
pub const POSITIONAL_LAYOUTS: &[(&str, [Option<usize>; 3])] = &[
    ("ID,姓名,电话,地址,省,市,10", [Some(1), Some(2), Some(3)]),
    ("姓名,电话,地址", [Some(0), Some(1), Some(2)]),
];

/// 表头探测最多向下看多少行（首个非空行起算）。
pub const HEADER_SCAN_ROWS: usize = 3;

/// 列名别名（已规范化：全角转半角、去空白、小写）。
pub const NAME_ALIASES: &[&str] = &[
    "姓名",
    "收件人",
    "收件人姓名",
    "收件人姓名(name)",
    "名字",
    "联系人",
    "联系人姓名",
    "客户姓名",
    "收货人",
    "收货人姓名",
    "顾客姓名",
    "name",
    "recipient",
    "recipientname",
    "receivername",
    "contact",
    "contactname",
    "customername",
    "consignee",
    "收件方",
    "致件人",
];

pub const PHONE_ALIASES: &[&str] = &[
    "电话",
    "电话号码",
    "手机",
    "手机号",
    "手机号码",
    "联系电话",
    "收件电话",
    "收件人电话",
    "收件人手机",
    "电话号",
    "移动电话",
    "联系方式",
    "tel",
    "telephone",
    "phone",
    "phoneno",
    "phonenumber",
    "mobile",
    "mobileno",
    "mobilenumber",
    "cellphone",
    "cell",
    "msisdn",
    "contact",
    "contactphone",
    "recipientphone",
    "收件手机",
];

pub const ADDRESS_ALIASES: &[&str] = &[
    "地址",
    "详细地址",
    "收件地址",
    "收件人地址",
    "收货地址",
    "住址",
    "家庭地址",
    "联系地址",
    "邮寄地址",
    "收件详细地址",
    "address",
    "addresseeaddress",
    "detailaddress",
    "detailedaddress",
    "streetaddress",
    "addr",
    "addressdetail",
    "recipientaddress",
    "联系人地址",
    "所在地址",
];

fn aliases_for(field: Field) -> &'static [&'static str] {
    debug_assert!(!NAME_ALIASES.is_empty());
    match field {
        Field::Name => NAME_ALIASES,
        Field::Phone => PHONE_ALIASES,
        Field::Address => ADDRESS_ALIASES,
    }
}

/// 某字段的别名表（供 README/结果说明引用）。
pub fn aliases(field: Field) -> &'static [&'static str] {
    aliases_for(field)
}

/// 表头单元格规范化：全角转半角、去所有空白、去 `*`/`:`、小写。
pub fn normalize_header_label(raw: &str) -> String {
    clean(raw)
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ':' && *ch != '*' && *ch != '、')
        .flat_map(char::to_lowercase)
        .collect()
}

/// 精确别名匹配（先精确，后前缀/包含，避免“收件人电话”被误判成姓名）。
pub fn match_header(label: &str) -> Option<Field> {
    let label = normalize_header_label(label);
    if label.is_empty() {
        return None;
    }
    // 电话优先：含“电话/手机/tel/phone/mobile”的列一律当电话。
    for alias in PHONE_ALIASES {
        if label == *alias {
            return Some(Field::Phone);
        }
    }
    for alias in ADDRESS_ALIASES {
        if label == *alias {
            return Some(Field::Address);
        }
    }
    for alias in NAME_ALIASES {
        if label == *alias {
            return Some(Field::Name);
        }
    }
    // 包含匹配，按“信息量更大”的顺序判定。
    let phone_markers = ["电话", "手机", "tel", "phone", "mobile", "msisdn"];
    if phone_markers.iter().any(|marker| label.contains(marker)) {
        return Some(Field::Phone);
    }
    let address_markers = ["地址", "address", "住址"];
    if address_markers.iter().any(|marker| label.contains(marker)) {
        return Some(Field::Address);
    }
    let name_markers = [
        "姓名",
        "收件人",
        "收货人",
        "联系人",
        "name",
        "recipient",
        "consignee",
    ];
    if name_markers.iter().any(|marker| label.contains(marker)) {
        return Some(Field::Name);
    }
    None
}

/// 一次表头探测结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderMatch {
    pub source: HeaderSource,
    /// 行号（1 起，按 XML 物理行 `r` 属性；缺省时按出现次序推得）。
    pub header_row: u32,
    /// 每个字段的 0 基列号。
    pub columns: [Option<usize>; 3],
    /// 命中的表头文本，用于结果溯源。
    pub labels: [Option<String>; 3],
    /// positional 回退时使用的布局描述。
    pub layout: Option<&'static str>,
}

impl HeaderMatch {
    pub fn column(&self, field: Field) -> Option<usize> {
        self.columns[field as usize]
    }

    pub fn has_any(&self) -> bool {
        self.columns.iter().any(Option::is_some)
    }
}

fn column_of(field: Field, cells: &[(usize, String)]) -> Option<(usize, String)> {
    for (column, text) in cells {
        if matches!(match_header(text), Some(found) if found == field) {
            return Some((*column, text.clone()));
        }
    }
    None
}

/// 由一行（行号 + 非空单元格）判定表头。
pub fn detect_header_row(row_number: u32, cells: &[(usize, String)]) -> Option<HeaderMatch> {
    let mut columns = [None, None, None];
    let mut labels: [Option<String>; 3] = [None, None, None];
    for field in Field::ALL {
        if let Some((column, text)) = column_of(field, cells) {
            if columns.iter().filter(|slot| **slot == Some(column)).count() == 0 {
                columns[field as usize] = Some(column);
                labels[field as usize] = Some(clean(&text));
            }
        }
    }
    let found = columns.iter().filter(|slot| slot.is_some()).count();
    if found == 0 {
        return None;
    }
    Some(HeaderMatch {
        source: HeaderSource::Header,
        header_row: row_number,
        columns,
        labels,
        layout: None,
    })
}

/// 无表头回退：按“最大列号 + 1”选择布局。
pub fn positional_layout(max_column: Option<usize>) -> Option<(usize, HeaderMatch)> {
    let width = max_column.map(|column| column + 1).unwrap_or(0);
    for (label, columns) in POSITIONAL_LAYOUTS {
        let needed = columns
            .iter()
            .flatten()
            .copied()
            .max()
            .map(|column| column + 1)
            .unwrap_or(0);
        if width >= needed {
            return Some((
                0,
                HeaderMatch {
                    source: HeaderSource::Positional,
                    header_row: 0,
                    columns: *columns,
                    labels: [None, None, None],
                    layout: Some(label),
                },
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(items: &[(usize, &str)]) -> Vec<(usize, String)> {
        items.iter().map(|(c, t)| (*c, (*t).to_string())).collect()
    }

    #[test]
    fn chinese_headers_match_aliases() {
        let header = detect_header_row(
            1,
            &cells(&[
                (0, "ID"),
                (1, " 姓名 "),
                (2, "收件人电话"),
                (3, "详细地址"),
                (4, "省"),
            ]),
        )
        .expect("header");
        assert_eq!(header.source, HeaderSource::Header);
        assert_eq!(header.columns, [Some(1), Some(2), Some(3)]);
        assert_eq!(header.labels[0].as_deref(), Some("姓名"));
        assert_eq!(header.labels[2].as_deref(), Some("详细地址"));
    }

    #[test]
    fn english_headers_case_and_space_insensitive() {
        let header = detect_header_row(
            2,
            &cells(&[(0, "Name"), (2, " Phone Number "), (5, "ADDRESS")]),
        )
        .expect("header");
        assert_eq!(header.columns, [Some(0), Some(2), Some(5)]);
        assert_eq!(header.header_row, 2);
    }

    #[test]
    fn recipient_and_mobile_aliases() {
        let header = detect_header_row(1, &cells(&[(0, "收件人"), (1, "手机号"), (2, "收件地址")]))
            .expect("header");
        assert_eq!(header.columns, [Some(0), Some(1), Some(2)]);
    }

    #[test]
    fn phone_wins_over_name_markers() {
        assert_eq!(match_header("收件人电话"), Some(Field::Phone));
        assert_eq!(match_header("电话(姓名)"), Some(Field::Phone));
        assert_eq!(match_header("联系人手机号"), Some(Field::Phone));
        assert_eq!(match_header("收件人姓名"), Some(Field::Name));
        assert_eq!(match_header("unknown-column"), None);
        assert_eq!(match_header(""), None);
    }

    #[test]
    fn positional_layout_uses_known_column_order() {
        let (offset, fallback) = positional_layout(Some(6)).expect("layout");
        assert_eq!(offset, 0);
        assert_eq!(fallback.source, HeaderSource::Positional);
        assert_eq!(fallback.columns, [Some(1), Some(2), Some(3)]);
        assert_eq!(fallback.header_row, 0);
        // 只有三列时退回 姓名,电话,地址。
        let (_, three) = positional_layout(Some(2)).expect("three column layout");
        assert_eq!(three.columns, [Some(0), Some(1), Some(2)]);
        // 不足三列无法回退。
        assert!(positional_layout(Some(1)).is_none());
        assert!(positional_layout(None).is_none());
    }

    #[test]
    fn partial_header_is_still_a_header() {
        let header = detect_header_row(
            1,
            &cells(&[(0, "单号"), (1, "姓名"), (2, "电话"), (3, "备注")]),
        )
        .expect("header");
        assert_eq!(header.columns, [Some(1), Some(2), None]);
        assert_eq!(header.source, HeaderSource::Header);
    }
}
