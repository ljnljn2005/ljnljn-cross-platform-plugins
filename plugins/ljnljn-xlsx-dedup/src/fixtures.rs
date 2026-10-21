//! 测试夹具：在内存里合成最小的 xlsx / zip 包（不依赖外部程序）。
//!
//! 只用 STORED（不压缩）与 deflate 两种方式写出合法 ZIP 结构（本地头 +
//! 中央目录 + EOCD），足以覆盖本插件自己的读取路径；另提供一个可选的外部
//! 校验器：用 dev-dependency `quick-xml` 独立读回写出的工作表，确认夹具本身
//! 是格式正确的 XML，避免“夹具错、代码跟着错”。

use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::Compression;

/// 单元格类型。
#[derive(Clone, Debug)]
pub enum Cell {
    /// 共享字符串索引。
    Shared(usize),
    /// 内联字符串。
    Inline(String),
    /// 数值（原样写进 `<v>`）。
    Number(String),
    /// 带样式的数值（日期样式等）。
    StyledNumber(String, usize),
    /// 布尔。
    Bool(bool),
    /// 公式缓存字符串（`t="str"`）。
    FormulaString(String),
    /// 空单元格（写 `<c r=".."/>`）。
    Empty,
}

#[derive(Clone, Debug)]
pub struct RowSpec {
    /// 行号（1 基）；`None` 表示省略 `r` 属性。
    pub number: Option<u32>,
    pub cells: Vec<(usize, Cell)>,
}

impl RowSpec {
    pub fn new(number: u32, cells: Vec<(usize, Cell)>) -> Self {
        Self {
            number: Some(number),
            cells,
        }
    }

    pub fn no_number(cells: Vec<(usize, Cell)>) -> Self {
        Self {
            number: None,
            cells,
        }
    }
}

pub struct SheetSpec {
    pub name: String,
    pub rows: Vec<RowSpec>,
    /// 合并单元格引用（`A1:C1` 等）。
    pub merges: Vec<String>,
}

impl SheetSpec {
    pub fn new(name: &str, rows: Vec<RowSpec>) -> Self {
        Self {
            name: name.to_owned(),
            rows,
            merges: Vec::new(),
        }
    }
}

/// 列号 → 列字母（0 → A）。
pub fn column_letter(mut column: usize) -> String {
    let mut letters = Vec::new();
    loop {
        letters.push((b'A' + (column % 26) as u8) as char);
        if column < 26 {
            break;
        }
        column = column / 26 - 1;
    }
    letters.iter().rev().collect()
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

fn sheet_xml(spec: &SheetSpec) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>",
    );
    for row in &spec.rows {
        match row.number {
            Some(number) => xml.push_str(&format!("<row r=\"{number}\">")),
            None => xml.push_str("<row>"),
        }
        for (column, cell) in &row.cells {
            let reference = format!("{}{}", column_letter(*column), row.number.unwrap_or(1));
            match cell {
                Cell::Empty => xml.push_str(&format!("<c r=\"{reference}\"/>")),
                Cell::Shared(index) => xml.push_str(&format!(
                    "<c r=\"{reference}\" t=\"s\"><v>{index}</v></c>"
                )),
                Cell::Inline(text) => xml.push_str(&format!(
                    "<c r=\"{reference}\" t=\"inlineStr\"><is><t>{}</t></is></c>",
                    escape(text)
                )),
                Cell::Number(value) => xml.push_str(&format!(
                    "<c r=\"{reference}\" t=\"n\"><v>{}</v></c>",
                    escape(value)
                )),
                Cell::StyledNumber(value, style) => xml.push_str(&format!(
                    "<c r=\"{reference}\" s=\"{style}\" t=\"n\"><v>{}</v></c>",
                    escape(value)
                )),
                Cell::Bool(flag) => xml.push_str(&format!(
                    "<c r=\"{reference}\" t=\"b\"><v>{}</v></c>",
                    if *flag { 1 } else { 0 }
                )),
                Cell::FormulaString(text) => xml.push_str(&format!(
                    "<c r=\"{reference}\" t=\"str\"><f>\"x\"</f><v>{}</v></c>",
                    escape(text)
                )),
            }
        }
        xml.push_str("</row>");
    }
    xml.push_str("</sheetData>");
    if !spec.merges.is_empty() {
        xml.push_str("<mergeCells>");
        for reference in &spec.merges {
            xml.push_str(&format!("<mergeCell ref=\"{reference}\"/>"));
        }
        xml.push_str("</mergeCells>");
    }
    xml.push_str("</worksheet>");
    xml
}

/// 一个工作簿的描述。
pub struct WorkbookSpec {
    pub sheets: Vec<SheetSpec>,
    pub shared_strings: Vec<String>,
    /// 自定义日期样式（cellXfs 中 `s="1"` 即日期格式 14）。
    pub date_style: bool,
}

impl WorkbookSpec {
    pub fn new(sheets: Vec<SheetSpec>, shared_strings: Vec<String>) -> Self {
        Self {
            sheets,
            shared_strings,
            date_style: true,
        }
    }
}

/// 生成 xlsx 包内文件列表（路径, 内容）。
pub fn xlsx_parts(spec: &WorkbookSpec) -> Vec<(String, Vec<u8>)> {
    let mut parts: Vec<(String, Vec<u8>)> = Vec::new();
    parts.push((
        "[Content_Types].xml".to_owned(),
        b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/></Types>".to_vec(),
    ));
    let mut workbook = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>",
    );
    let mut rels = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
    );
    for (index, sheet) in spec.sheets.iter().enumerate() {
        let id = index + 1;
        workbook.push_str(&format!(
            "<sheet name=\"{}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
            escape(&sheet.name),
            id,
            id
        ));
        rels.push_str(&format!(
            "<Relationship Id=\"rId{id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{id}.xml\"/>"
        ));
        parts.push((
            format!("xl/worksheets/sheet{id}.xml"),
            sheet_xml(sheet).into_bytes(),
        ));
    }
    workbook.push_str("</sheets></workbook>");
    rels.push_str("</Relationships>");
    parts.push(("xl/workbook.xml".to_owned(), workbook.into_bytes()));
    parts.push((
        "xl/_rels/workbook.xml.rels".to_owned(),
        rels.into_bytes(),
    ));

    let mut sst = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">",
    );
    for text in &spec.shared_strings {
        sst.push_str(&format!("<si><t>{}</t></si>", escape(text)));
    }
    sst.push_str("</sst>");
    parts.push(("xl/sharedStrings.xml".to_owned(), sst.into_bytes()));

    let styles = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
<numFmts count=\"1\"><numFmt numFmtId=\"164\" formatCode=\"yyyy\\-mm\\-dd\"/></numFmts>\
<cellStyleXfs count=\"1\"><xf numFmtId=\"0\"/></cellStyleXfs>\
<cellXfs count=\"2\"><xf numFmtId=\"0\"/><xf numFmtId=\"{}\"/></cellXfs>\
</styleSheet>",
        if spec.date_style { 164 } else { 0 }
    );
    parts.push(("xl/styles.xml".to_owned(), styles.into_bytes()));
    parts
}

/// ZIP 写出选项。
#[derive(Clone, Copy, Debug)]
pub struct ZipOptions {
    pub deflate: bool,
    /// 写一个会破坏 CRC 的条目名（测试损坏检测）。
    pub corrupt_crc_entry: Option<usize>,
}

impl Default for ZipOptions {
    fn default() -> Self {
        Self {
            deflate: false,
            corrupt_crc_entry: None,
        }
    }
}

/// 按给定条目顺序写出合法 ZIP 包。
pub fn zip_bytes(entries: &[(String, Vec<u8>)], options: ZipOptions) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut directory: Vec<u8> = Vec::new();
    for (index, (name, data)) in entries.iter().enumerate() {
        let method: u16 = if options.deflate { 8 } else { 0 };
        let payload = if options.deflate {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(data).expect("deflate");
            encoder.finish().expect("deflate finish")
        } else {
            data.clone()
        };
        let mut crc = crc32fast::hash(data);
        if options.corrupt_crc_entry == Some(index) {
            crc ^= 0xFFFF_FFFF;
        }
        let offset = out.len() as u32;
        let name_bytes = name.as_bytes();
        // 本地头
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0x0080u16.to_le_bytes()); // UTF-8 名称标记
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&payload);
        // 中央目录项
        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes()); // version made by
        directory.extend_from_slice(&20u16.to_le_bytes()); // version needed
        directory.extend_from_slice(&0x0080u16.to_le_bytes());
        directory.extend_from_slice(&method.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes()); // extra
        directory.extend_from_slice(&0u16.to_le_bytes()); // comment
        directory.extend_from_slice(&0u16.to_le_bytes()); // disk
        directory.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        directory.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name_bytes);
    }
    let cd_offset = out.len() as u32;
    let cd_size = directory.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

const EOCD_SIG: u32 = 0x0605_4b50;

/// 合成 xlsx 字节。
pub fn xlsx_bytes(spec: &WorkbookSpec, options: ZipOptions) -> Vec<u8> {
    zip_bytes(&xlsx_parts(spec), options)
}

/// 用 `quick-xml` 独立校验写出的工作表 XML 可被解析（夹具自检）。
pub fn sheet_xml_is_well_formed(spec: &SheetSpec) -> bool {
    let xml = sheet_xml(spec);
    let mut reader = quick_xml::Reader::from_reader(xml.as_bytes());
    let config = reader.config_mut();
    config.check_end_names = true;
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(quick_xml::events::Event::Eof) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_sheet_xml_is_well_formed() {
        let spec = SheetSpec::new(
            "Sheet1",
            vec![
                RowSpec::new(
                    1,
                    vec![(0, Cell::Inline("姓名".to_owned())), (1, Cell::Inline("电话".to_owned()))],
                ),
                RowSpec::new(
                    2,
                    vec![(0, Cell::Shared(0)), (1, Cell::Number("13800138000".to_owned()))],
                ),
            ],
        );
        assert!(sheet_xml_is_well_formed(&spec));
    }

    #[test]
    fn generated_zip_has_a_readable_central_directory() {
        let spec = WorkbookSpec::new(vec![SheetSpec::new("Sheet1", Vec::new())], Vec::new());
        let bytes = xlsx_bytes(&spec, ZipOptions::default());
        let entries = crate::zipread::read_entries(&bytes).expect("central directory");
        assert!(entries.iter().any(|entry| entry.name == "xl/workbook.xml"));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "xl/worksheets/sheet1.xml"));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "xl/sharedStrings.xml"));
    }
}
