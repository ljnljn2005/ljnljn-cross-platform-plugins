//! 流式 xlsx/xlsm 读取：工作表枚举、共享字符串、合并单元格、单元格值。
//!
//! 不执行宏、不解析外部链接：`xl/workbook.xml` 只取 `<sheet>` 的
//! name / sheetId / r:id；关系文件只用于把 r:id 映射到 `xl/worksheets/*.xml`
//! 与合并单元格；工作表按 `<row>` 事件流式处理，遇到目标行即回调，不保留整表。
//!
//! 单元格取值规则（需求 ①）：
//! - `t="s"` 共享字符串；`t="inlineStr"` 取 `<is>` 内全部 `<t>`；`t="str"` 取公式缓存文本；
//! - `t="b"` 转 `TRUE`/`FALSE`；错误值（`t="e"`）保留错误码文本；
//! - 数值单元格统一转字符串：语言无关的最短表示（`1` 而不是 `1.0`，
//!   `13800138000` 不写成 `1.38e10`）；
//! - 日期/时间类样式（内置 14–22、27–36、45–47、50–58 与自定义格式里的
//!   `y/m/d/h/s`，且不在引号或 `[]` 内）保留单元格原值文本，不做时区换算。

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::error::DedupError;
use crate::limits::{MAX_AUX_XML_BYTES, MAX_CELL_TEXT, MAX_SHEET_XML_BYTES};
use crate::zipread::{read_entries_from, read_entry, Blob, ZipEntry};

/// 一个工作表在包内的位置。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SheetRef {
    pub name: String,
    pub path: String,
    pub sheet_id: Option<u32>,
    /// 对应的工作表关系文件（若存在，用于合并单元格）。
    pub rels_path: Option<String>,
}

/// 解析出的工作簿结构。
#[derive(Clone, Debug, Default)]
pub struct Workbook {
    pub sheets: Vec<SheetRef>,
    pub shared_strings: Vec<String>,
    pub date_styles: Vec<bool>,
    /// 包内成员清单（诊断“是不是 xlsx”与枚举来源）。
    pub parts: Vec<String>,
}

impl Workbook {
    pub fn has_sheet_part(&self) -> bool {
        self.parts.iter().any(|part| part.starts_with("xl/worksheets/"))
    }
}

fn entry_named<'a>(entries: &'a [ZipEntry], name: &str) -> Option<&'a ZipEntry> {
    entries.iter().find(|entry| entry.name == name)
}

fn read_part<B: Blob + ?Sized>(
    blob: &B,
    entries: &[ZipEntry],
    name: &str,
    cap: u64,
) -> Result<Option<Vec<u8>>, DedupError> {
    match entry_named(entries, name) {
        Some(entry) => Ok(Some(read_entry(blob, entry, cap)?)),
        None => Ok(None),
    }
}

fn reader_for(bytes: &[u8]) -> Reader<&[u8]> {
    let mut reader = Reader::from_reader(bytes);
    // 电子表格里常见裸 `&`；宽松处理避免整表解析失败。
    let config = reader.config_mut();
    config.check_end_names = false;
    reader
}

fn attr_value(element: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    for attribute in element.attributes().flatten() {
        let key = attribute.key.as_ref();
        let local = key.rsplit(|byte| *byte == b':').next().unwrap_or(key);
        if key == name || local == name {
            if let Ok(text) = attribute.normalized_value(XmlVersion::Explicit1_0) {
                return Some(text.into_owned());
            }
            return Some(String::from_utf8_lossy(attribute.value.as_ref()).into_owned());
        }
    }
    None
}

fn text_piece(text: &quick_xml::events::BytesText<'_>) -> String {
    let decoded = match text.xml_content(XmlVersion::Explicit1_0) {
        Ok(text) => text,
        Err(_) => return String::from_utf8_lossy(text.as_ref()).into_owned(),
    };
    quick_xml::escape::unescape(&decoded)
        .map(|text| text.into_owned())
        .unwrap_or_else(|_| decoded.into_owned())
}

/// 读取 `xl/workbook.xml` + 关系 + 共享字符串 + 单元格样式。
pub fn read_workbook<B: Blob + ?Sized>(blob: &B) -> Result<Workbook, DedupError> {
    let entries = read_entries_from(blob)?;
    let parts: Vec<String> = entries.iter().map(|entry| entry.name.clone()).collect();
    let mut workbook = Workbook {
        parts,
        ..Workbook::default()
    };

    let Some(workbook_xml) = read_part(blob, &entries, "xl/workbook.xml", MAX_AUX_XML_BYTES)?
    else {
        return Err(DedupError::new(
            "xlsx.not_xlsx",
            "缺少 xl/workbook.xml，不是 Excel 工作簿（.xlsx/.xlsm）",
        ));
    };

    // r:id → 关系目标
    let mut rel_targets: HashMap<String, String> = HashMap::new();
    if let Some(rels) = read_part(blob, &entries, "xl/_rels/workbook.xml.rels", MAX_AUX_XML_BYTES)?
    {
        let mut reader = reader_for(&rels);
        let mut buffer = Vec::new();
        loop {
            match reader.read_event_into(&mut buffer) {
                Ok(Event::Start(element)) | Ok(Event::Empty(element))
                    if element.local_name().as_ref() == b"Relationship" =>
                {
                    if let (Some(id), Some(target)) =
                        (attr_value(&element, b"Id"), attr_value(&element, b"Target"))
                    {
                        rel_targets.insert(id, normalize_target(&target));
                    }
                }
                Ok(Event::Eof) => break,
                Err(error) => {
                    return Err(DedupError::new(
                        "xlsx.rels",
                        format!("xl/_rels/workbook.xml.rels 解析失败：{error}"),
                    ))
                }
                _ => {}
            }
            buffer.clear();
        }
    }

    let mut reader = reader_for(&workbook_xml);
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) | Ok(Event::Empty(element))
                if element.local_name().as_ref() == b"sheet" =>
            {
                let name = attr_value(&element, b"name").unwrap_or_default();
                let path = attr_value(&element, b"id")
                    .as_deref()
                    .and_then(|id| rel_targets.get(id).cloned())
                    .unwrap_or_else(|| {
                        format!("xl/worksheets/sheet{}.xml", workbook.sheets.len() + 1)
                    });
                let rels_path = path
                    .rsplit_once('/')
                    .map(|(dir, file)| format!("{dir}/_rels/{file}.rels"));
                workbook.sheets.push(SheetRef {
                    name,
                    path,
                    sheet_id: attr_value(&element, b"sheetId").and_then(|id| id.parse().ok()),
                    rels_path,
                });
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(DedupError::new(
                    "xlsx.workbook",
                    format!("xl/workbook.xml 解析失败：{error}"),
                ))
            }
            _ => {}
        }
        buffer.clear();
    }

    if let Some(shared) = read_part(blob, &entries, "xl/sharedStrings.xml", MAX_AUX_XML_BYTES)? {
        workbook.shared_strings = parse_shared_strings(&shared)?;
    }
    if let Some(styles) = read_part(blob, &entries, "xl/styles.xml", MAX_AUX_XML_BYTES)? {
        workbook.date_styles = parse_date_styles(&styles);
    }
    Ok(workbook)
}

/// 关系目标规范化：`/xl/worksheets/sheet1.xml` → `xl/worksheets/sheet1.xml`；
/// `worksheets/sheet1.xml` 相对 `xl/`。
fn normalize_target(target: &str) -> String {
    let target = target.replace('\\', "/");
    if let Some(stripped) = target.strip_prefix('/') {
        return stripped.to_owned();
    }
    if target.starts_with("xl/") {
        return target;
    }
    format!("xl/{target}")
}

/// 共享字符串表；`<si>` 内所有 `<t>` 直接拼接（富文本分片属于同一字符串）。
pub fn parse_shared_strings(xml: &[u8]) -> Result<Vec<String>, DedupError> {
    let mut reader = reader_for(xml);
    let mut buffer = Vec::new();
    let mut strings = Vec::new();
    let mut current: Option<String> = None;
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                b"si" => current = Some(String::new()),
                b"t" if current.is_some() => in_text = true,
                _ => {}
            },
            Ok(Event::Empty(element)) if element.local_name().as_ref() == b"si" => {
                strings.push(String::new())
            }
            Ok(Event::End(element)) => match element.local_name().as_ref() {
                b"si" => {
                    if let Some(text) = current.take() {
                        strings.push(text);
                    }
                    in_text = false;
                }
                b"t" => in_text = false,
                _ => {}
            },
            Ok(Event::Text(text)) if in_text => {
                if let Some(current) = current.as_mut() {
                    if current.len() < MAX_CELL_TEXT {
                        current.push_str(&text_piece(&text));
                    }
                }
            }
            Ok(Event::CData(text)) if in_text => {
                if let Some(current) = current.as_mut() {
                    current.push_str(&String::from_utf8_lossy(text.as_ref()));
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(DedupError::new(
                    "xlsx.shared_strings",
                    format!("xl/sharedStrings.xml 解析失败：{error}"),
                ))
            }
            _ => {}
        }
        buffer.clear();
    }
    Ok(strings)
}

/// 单元格样式：`cellXfs[i]` 的 `numFmtId` 属于日期类，或自定义格式含日期时间占位符。
pub fn parse_date_styles(xml: &[u8]) -> Vec<bool> {
    let mut reader = reader_for(xml);
    let mut buffer = Vec::new();
    let mut custom: HashMap<u32, String> = HashMap::new();
    let mut xf_formats: Vec<Option<u32>> = Vec::new();
    let mut in_cell_xfs = false;
    loop {
        let parsed = reader.read_event_into(&mut buffer);
        match &parsed {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                b"numFmt" => record_num_fmt(element, &mut custom),
                b"cellXfs" => in_cell_xfs = true,
                b"xf" if in_cell_xfs => {
                    xf_formats
                        .push(attr_value(element, b"numFmtId").and_then(|id| id.parse().ok()));
                }
                _ => {}
            },
            Ok(Event::Empty(element)) => match element.local_name().as_ref() {
                b"numFmt" => record_num_fmt(element, &mut custom),
                b"xf" if in_cell_xfs => {
                    xf_formats
                        .push(attr_value(element, b"numFmtId").and_then(|id| id.parse().ok()));
                }
                _ => {}
            },
            Ok(Event::End(element)) if element.local_name().as_ref() == b"cellXfs" => {
                in_cell_xfs = false
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buffer.clear();
    }
    xf_formats
        .into_iter()
        .map(|num_fmt| {
            let Some(num_fmt) = num_fmt else {
                return false;
            };
            is_builtin_date_format(num_fmt)
                || custom
                    .get(&num_fmt)
                    .map(|code| format_is_date_like(code))
                    .unwrap_or(false)
        })
        .collect()
}

fn record_num_fmt(element: &quick_xml::events::BytesStart<'_>, custom: &mut HashMap<u32, String>) {
    if let (Some(id), Some(code)) = (
        attr_value(element, b"numFmtId"),
        attr_value(element, b"formatCode"),
    ) {
        if let Ok(id) = id.parse::<u32>() {
            custom.insert(id, code);
        }
    }
}

fn is_builtin_date_format(id: u32) -> bool {
    matches!(id, 14..=22 | 27..=36 | 45..=47 | 50..=58)
}

/// 自定义格式是否日期/时间：忽略引号内文本与 `[]`（颜色/条件/区域）内的字符。
pub fn format_is_date_like(code: &str) -> bool {
    let mut in_quote = false;
    let mut in_bracket = false;
    let mut escaped = false;
    for ch in code.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => in_quote = !in_quote,
            '[' if !in_quote => in_bracket = true,
            ']' if !in_quote => in_bracket = false,
            'y' | 'Y' | 'm' | 'M' | 'd' | 'D' | 'h' | 'H' | 's' | 'S' if !in_quote && !in_bracket => {
                return true
            }
            _ => {}
        }
    }
    false
}

/// 数值单元格的字符串化：语言无关的最短表示，去掉浮点噪声尾巴，不用科学计数法。
pub fn number_to_text(raw: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }
    let negative = text.starts_with('-');
    let body = text.trim_start_matches(['-', '+']);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(index) => (&body[..index], body[index + 1..].parse::<i32>().ok()),
        None => (body, None),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((int_part, frac_part)) => (int_part, frac_part),
        None => (mantissa, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return text.to_owned();
    }
    if !int_part.chars().all(|ch| ch.is_ascii_digit())
        || !frac_part.chars().all(|ch| ch.is_ascii_digit())
    {
        return text.to_owned();
    }
    let mut digits: String = format!("{int_part}{frac_part}");
    let mut point = int_part.len() as i32 + exponent.unwrap_or(0);
    while digits.len() > 1 && digits.starts_with('0') {
        digits.remove(0);
        point -= 1;
    }
    if digits.chars().all(|ch| ch == '0') {
        return "0".to_owned();
    }
    while digits.len() > 1 && digits.ends_with('0') && point < digits.len() as i32 {
        digits.pop();
    }
    let mut output = String::with_capacity(digits.len() + 4);
    if negative {
        output.push('-');
    }
    if point <= 0 {
        output.push_str("0.");
        output.push_str(&"0".repeat((-point) as usize));
        output.push_str(&digits);
    } else if point as usize >= digits.len() {
        output.push_str(&digits);
        output.push_str(&"0".repeat(point as usize - digits.len()));
    } else {
        let (head, tail) = digits.split_at(point as usize);
        output.push_str(head);
        output.push('.');
        output.push_str(tail);
    }
    output
}

/// 列字母 → 0 基列号（`A`→0，`AB`→27）。
pub fn column_index(reference: &str) -> Option<usize> {
    let mut value: usize = 0;
    let mut seen = false;
    for ch in reference.chars() {
        if ch.is_ascii_alphabetic() {
            let digit = (ch.to_ascii_uppercase() as u8 - b'A') as usize + 1;
            value = value.checked_mul(26)?.checked_add(digit)?;
            seen = true;
        } else {
            break;
        }
    }
    seen.then(|| value - 1)
}

/// 工作表内的一行：行号 + 升序排列的 (列号, 文本) 非空格。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SheetRow {
    pub number: u32,
    pub cells: Vec<(usize, String)>,
}

impl SheetRow {
    pub fn is_blank(&self) -> bool {
        self.cells.is_empty()
    }
}

/// 行处理的返回值：`Ok(false)` 表示提前结束（行数超限等）。
pub type RowAction = Result<bool, DedupError>;

/// 合并单元格：(起始行, 起始列, 结束行, 结束列)，行 1 基、列 0 基。
pub type Merge = (u32, usize, u32, usize);

struct RowState {
    row: SheetRow,
    column_cursor: usize,
}

/// 流式解析一个工作表，把每一行交给 `sink`。
pub fn stream_rows<B: Blob + ?Sized>(
    blob: &B,
    entries: &[ZipEntry],
    sheet: &SheetRef,
    workbook: &Workbook,
    mut sink: impl FnMut(SheetRow) -> RowAction,
) -> Result<u64, DedupError> {
    let Some(entry) = entries.iter().find(|entry| entry.name == sheet.path) else {
        return Err(DedupError::new(
            "xlsx.sheet_missing",
            format!("工作表 {} 对应的 {} 不存在", sheet.name, sheet.path),
        ));
    };
    let sheet_bytes = read_entry(blob, entry, MAX_SHEET_XML_BYTES)?;

    // 合并单元格：只有左上角存值，其余格按合并区继承。
    let merges: Vec<Merge> = match sheet.rels_path.as_deref() {
        Some(rels_path) => match read_part(blob, entries, rels_path, MAX_AUX_XML_BYTES)? {
            Some(rels) => parse_merge_cells(&rels),
            None => Vec::new(),
        },
        None => Vec::new(),
    };

    let mut reader = reader_for(&sheet_bytes);
    let mut buffer = Vec::new();
    let mut rows = 0u64;
    let mut last_row: u32 = 0;
    let mut state: Option<RowState> = None;
    let mut cell: Option<(usize, String, Option<usize>)> = None;
    let mut text_buffer: Option<String> = None;
    let mut in_value = false;
    let mut in_inline = false;
    let mut stop = false;

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                b"row" => {
                    let number = attr_value(&element, b"r")
                        .and_then(|r| r.trim().parse::<u32>().ok())
                        .unwrap_or(last_row.saturating_add(1));
                    last_row = number;
                    state = Some(RowState {
                        row: SheetRow {
                            number,
                            cells: Vec::new(),
                        },
                        column_cursor: 0,
                    });
                }
                b"c" => {
                    let reference = attr_value(&element, b"r").unwrap_or_default();
                    let cursor = state.as_ref().map(|s| s.column_cursor).unwrap_or(0);
                    let column = column_index(&reference).unwrap_or(cursor);
                    if let Some(state) = state.as_mut() {
                        state.column_cursor = column + 1;
                    }
                    cell = Some((
                        column,
                        attr_value(&element, b"t").unwrap_or_default(),
                        attr_value(&element, b"s").and_then(|s| s.parse::<usize>().ok()),
                    ));
                    text_buffer = None;
                    in_value = false;
                    in_inline = false;
                }
                b"is" => in_inline = true,
                b"v" => {
                    in_value = true;
                    text_buffer.get_or_insert_with(String::new);
                }
                b"t" if in_inline => {
                    in_value = true;
                    text_buffer.get_or_insert_with(String::new);
                }
                _ => {}
            },
            Ok(Event::Empty(element)) => {
                if element.local_name().as_ref() == b"c" {
                    if let Some(state) = state.as_mut() {
                        state.column_cursor += 1;
                    }
                }
            }
            Ok(Event::Text(text)) if in_value => {
                if let Some(buffer_text) = text_buffer.as_mut() {
                    if buffer_text.chars().count() < MAX_CELL_TEXT {
                        buffer_text.push_str(&text_piece(&text));
                    }
                }
            }
            Ok(Event::CData(text)) if in_value => {
                if let Some(buffer_text) = text_buffer.as_mut() {
                    buffer_text.push_str(&String::from_utf8_lossy(text.as_ref()));
                }
            }
            Ok(Event::End(element)) => match element.local_name().as_ref() {
                b"v" | b"t" => in_value = false,
                b"is" => in_inline = false,
                b"c" => {
                    if let Some((column, data_type, style)) = cell.take() {
                        let raw = text_buffer.take().unwrap_or_default();
                        let value = cell_text(&raw, &data_type, style, workbook);
                        if let Some(state) = state.as_mut() {
                            push_cell(&mut state.row, column, value);
                        }
                    }
                    in_value = false;
                }
                b"row" => {
                    if let Some(RowState { mut row, .. }) = state.take() {
                        apply_merges(&mut row, &merges);
                        row.cells.sort_by_key(|(column, _)| *column);
                        rows += 1;
                        if !sink(row)? {
                            stop = true;
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(DedupError::new(
                    "xlsx.sheet",
                    format!("工作表 {} 解析失败：{error}", sheet.name),
                ))
            }
            _ => {}
        }
        buffer.clear();
        if stop {
            break;
        }
    }
    Ok(rows)
}

fn push_cell(row: &mut SheetRow, column: usize, value: String) {
    if value.is_empty() {
        return;
    }
    match row.cells.iter_mut().find(|(existing, _)| *existing == column) {
        Some(slot) => slot.1.push_str(&value),
        None => row.cells.push((column, value)),
    }
}

/// 单元格文本 → 字符串（按 `t` 与日期样式）。
pub fn cell_text(raw: &str, data_type: &str, style: Option<usize>, workbook: &Workbook) -> String {
    let text: String = raw.chars().take(MAX_CELL_TEXT).collect();
    match data_type {
        "s" => {
            let index: usize = text.trim().parse().unwrap_or(usize::MAX);
            workbook
                .shared_strings
                .get(index)
                .cloned()
                .unwrap_or(text)
        }
        "b" => match text.trim() {
            "1" => "TRUE".to_owned(),
            "0" => "FALSE".to_owned(),
            other => other.to_owned(),
        },
        "n" | "" => {
            let is_date = style
                .and_then(|style| workbook.date_styles.get(style).copied())
                .unwrap_or(false);
            if is_date {
                // 日期类原始序列值保留为文本，不做时区/纪元换算。
                text
            } else {
                number_to_text(&text)
            }
        }
        _ => text,
    }
}

/// 工作表关系文件里 `<mergeCell ref="A1:C3"/>` 的列表。
pub fn parse_merge_cells(xml: &[u8]) -> Vec<Merge> {
    let mut reader = reader_for(xml);
    let mut buffer = Vec::new();
    let mut merges = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) | Ok(Event::Empty(element))
                if element.local_name().as_ref() == b"mergeCell" =>
            {
                if let Some(reference) = attr_value(&element, b"ref") {
                    if let Some(range) = parse_range(&reference) {
                        merges.push(range);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buffer.clear();
    }
    merges
}

/// `A1:C3` → (1, 0, 3, 2)；`A1` → (1, 0, 1, 0)。
pub fn parse_range(reference: &str) -> Option<Merge> {
    let reference = reference.trim();
    let (start, end) = match reference.split_once(':') {
        Some((start, end)) => (start, Some(end)),
        None => (reference, None),
    };
    let (start_row, start_column) = parse_cell_address(start)?;
    let (end_row, end_column) = match end {
        Some(end) => parse_cell_address(end)?,
        None => (start_row, start_column),
    };
    if end_row < start_row || end_column < start_column {
        return None;
    }
    Some((start_row, start_column, end_row, end_column))
}

/// `A1` → (行 1 基, 列 0 基)。
pub fn parse_cell_address(address: &str) -> Option<(u32, usize)> {
    let column = column_index(address)?;
    let digits: String = address.chars().skip_while(|ch| ch.is_ascii_alphabetic()).collect();
    let row: u32 = digits.trim().parse().ok()?;
    (row >= 1).then_some((row, column))
}

/// 合并区内除左上角之外的格子继承左上角的值（只补“目标列非空、同行非空”的情况）。
fn apply_merges(row: &mut SheetRow, merges: &[Merge]) {
    if merges.is_empty() || row.cells.is_empty() {
        return;
    }
    for &(start_row, start_column, end_row, end_column) in merges {
        if row.number < start_row || row.number > end_row {
            continue;
        }
        let Some(source) = row
            .cells
            .iter()
            .find(|(column, _)| *column == start_column)
            .map(|(_, text)| text.clone())
        else {
            continue;
        };
        for column in start_column..=end_column.min(start_column + 64) {
            if column != start_column
                && !row.cells.iter().any(|(existing, _)| *existing == column)
            {
                row.cells.push((column, source.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_text_uses_shortest_stable_form() {
        assert_eq!(number_to_text("13800138000"), "13800138000");
        assert_eq!(number_to_text("1.0"), "1");
        assert_eq!(number_to_text("3.1400"), "3.14");
        assert_eq!(number_to_text("1.38E+10"), "13800000000");
        assert_eq!(number_to_text("0.000120"), "0.00012");
        assert_eq!(number_to_text("-0.5"), "-0.5");
        assert_eq!(number_to_text("0"), "0");
        assert_eq!(number_to_text("-0.0"), "0");
        assert_eq!(number_to_text("abc"), "abc");
        assert_eq!(number_to_text(""), "");
    }

    #[test]
    fn column_and_address_conversion() {
        assert_eq!(column_index("A1"), Some(0));
        assert_eq!(column_index("Z9"), Some(25));
        assert_eq!(column_index("AA1"), Some(26));
        assert_eq!(column_index("AB"), Some(27));
        assert_eq!(column_index("1"), None);
        assert_eq!(parse_cell_address("B3"), Some((3, 1)));
        assert_eq!(parse_range("A1:C3"), Some((1, 0, 3, 2)));
        assert_eq!(parse_range("D2"), Some((2, 3, 2, 3)));
        assert_eq!(parse_range("C3:A1"), None);
    }

    #[test]
    fn date_format_detection_ignores_quoted_and_bracketed_text() {
        assert!(format_is_date_like("yyyy-mm-dd"));
        assert!(format_is_date_like("h:mm:ss"));
        assert!(!format_is_date_like("#,##0.00"));
        assert!(!format_is_date_like("0\"days\""));
        assert!(!format_is_date_like("[Red]0.0"));
        assert!(is_builtin_date_format(14));
        assert!(is_builtin_date_format(22));
        assert!(!is_builtin_date_format(4));
    }

    #[test]
    fn shared_strings_concatenate_rich_text_runs() {
        let xml = r#"<?xml version="1.0"?><sst><si><t>张</t></si><si><r><t>李</t></r><r><t>四</t></r></si><si/></sst>"#;
        let strings = parse_shared_strings(xml.as_bytes()).expect("shared strings");
        assert_eq!(strings, vec!["张".to_string(), "李四".to_string(), String::new()]);
    }

    #[test]
    fn merges_extend_values_inside_the_region() {
        let mut row = SheetRow {
            number: 2,
            cells: vec![(1, "北京市".to_string())],
        };
        apply_merges(&mut row, &[(2, 1, 2, 3)]);
        row.cells.sort_by_key(|(column, _)| *column);
        assert_eq!(
            row.cells,
            vec![
                (1, "北京市".to_string()),
                (2, "北京市".to_string()),
                (3, "北京市".to_string())
            ]
        );
    }

    #[test]
    fn cell_text_resolves_shared_strings_and_booleans() {
        let workbook = Workbook {
            shared_strings: vec!["张三".to_string()],
            date_styles: vec![false, true],
            ..Workbook::default()
        };
        assert_eq!(cell_text("0", "s", None, &workbook), "张三");
        assert_eq!(cell_text("1", "b", None, &workbook), "TRUE");
        assert_eq!(cell_text("1.0", "n", Some(0), &workbook), "1");
        assert_eq!(cell_text("45000.5", "", Some(1), &workbook), "45000.5");
        assert_eq!(cell_text("内联", "inlineStr", None, &workbook), "内联");
    }
}
