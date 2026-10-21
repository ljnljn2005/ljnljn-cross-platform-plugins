//! 去重统计核心：工作表级表头定位 → 行级三元组抽取 → 跨文件/跨表去重。
//!
//! 计数定义（全部来自实际解析，不内置任何名单或数字）：
//! - `total_rows`：所有参与工作表（表头已确定）里非空行的条数，含表头行本身；
//! - `valid_rows`：姓名/电话/地址三项规范化后都非空的行；
//! - `incomplete_rows`：三项中至少一项为空（含整行为空）的行，不参与去重；
//! - `unique_count`：按规范化后 (姓名, 电话, 地址) 去重后的键数量；
//! - `duplicate_count`：有效行中出现过的重复行数（`valid_rows - unique_count`）；
//! - `duplicate_groups`：出现次数 ≥ 2 的键，只展示脱敏键与来源行。
//!
//! 未命中表头/回退布局的工作表不参与任何计数，只计入 `skipped_sheets`。

use std::collections::HashMap;

use crate::header::{detect_header_row, positional_layout, Field, HeaderMatch, HeaderSource};
use crate::limits::{
    MAX_DUPLICATE_GROUPS, MAX_INCOMPLETE_SHOWN, MAX_ROWS_PER_SHEET, MAX_SOURCES_PER_KEY,
    MAX_UNIQUE_KEYS,
};
use crate::normalize::{
    mask_address, mask_name, mask_phone, normalize_address, normalize_name, normalize_phone,
};
use crate::parse::Link;
use crate::xlsx::{stream_rows, SheetRef, SheetRow, Workbook};
use crate::zipread::{read_entries_from, Blob, ZipEntry};

/// 一条去重键的来源行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRow {
    pub link: Link,
    /// 文件显示名（`File::name()` 或 zip 内条目名）。
    pub file: String,
    pub sheet: String,
    pub row: u32,
}

impl SourceRow {
    /// 用于结果列与标题的紧凑定位串：`文件!工作表!行号`。
    pub fn location(&self) -> String {
        format!("{}!{}!{}", self.file, self.sheet, self.row)
    }
}

/// 一行抽取出的三元组（已规范化）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TripleRow {
    pub link: Link,
    pub sheet: String,
    pub row: u32,
    pub name: String,
    pub phone: String,
    pub address: String,
    pub missing: Vec<Field>,
}

impl TripleRow {
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// 规范化后的去重键（不直接进结果，结果里只出现脱敏展示）。
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub name: String,
    pub phone: String,
    pub address: String,
}

impl Key {
    /// 脱敏展示键：姓名首字、电话前 3 后 4、地址首 6 末 4。
    pub fn masked_display(&self) -> String {
        format!(
            "{} | {} | {}",
            mask_name(&self.name),
            mask_phone(&self.phone),
            mask_address(&self.address)
        )
    }

    pub fn masked_name(&self) -> String {
        mask_name(&self.name)
    }

    pub fn masked_phone(&self) -> String {
        mask_phone(&self.phone)
    }

    pub fn masked_address(&self) -> String {
        mask_address(&self.address)
    }
}

/// 一个重复组。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    pub key: Key,
    pub occurrences: usize,
    /// 首次出现的来源行（保留首次出现行）。
    pub first: SourceRow,
    /// 全部来源行（首次在前）；超过上限时只保留前 `MAX_SOURCES_PER_KEY` 条。
    pub sources: Vec<SourceRow>,
    pub truncated: bool,
}

/// 一个工作表的处理结论。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SheetReport {
    /// 该表所属逻辑输入（证据根/路径或宿主文件），用于结果溯源。
    pub link: Option<Link>,
    pub file: String,
    pub sheet: String,
    pub total_rows: usize,
    pub valid_rows: usize,
    pub incomplete_rows: usize,
    pub header: Option<HeaderMatch>,
    /// 跳过的原因（未跳过为 `None`）。
    pub skipped_reason: Option<String>,
}

/// 一个文件的汇总。
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FileReport {
    /// 该文件的逻辑输入（证据根/路径或宿主文件），用于结果溯源。
    pub link: Option<Link>,
    pub file: String,
    /// 包内 `xl/workbook.xml` 声明的工作表数。
    pub sheets: usize,
    /// 实际参与统计的工作表数。
    pub sheets_used: usize,
    pub skipped_sheets: Vec<String>,
    pub total_rows: usize,
    pub valid_rows: usize,
    pub incomplete_rows: usize,
    pub header_source: Option<String>,
}

/// 解析失败/被跳过的输入（来源可追溯）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub link: Link,
    pub display: String,
    pub code: &'static str,
    pub message: String,
}

/// 聚合结果（字段名与需求 ④ 对齐）。
#[derive(Clone, Debug, Default)]
pub struct Aggregation {
    pub total_rows: usize,
    pub valid_rows: usize,
    pub unique_count: usize,
    pub duplicate_count: usize,
    pub incomplete_rows: usize,
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub per_file: Vec<FileReport>,
    pub sheets: Vec<SheetReport>,
    pub skipped_sheets: Vec<String>,
    pub files_parsed: Vec<String>,
    pub duplicate_inputs: Vec<String>,
    pub rejected: Vec<Rejected>,
    pub incomplete_shown: Vec<TripleRow>,
    pub header_source: Option<String>,
    pub key_space_exhausted_at: Option<usize>,
    pub limitations: Vec<String>,
    pub row_limit_reached: Vec<String>,
}

impl Aggregation {
    /// 是否没有任何可统计数据（用于“空文件/无数据行返回 0 并说明”）。
    pub fn is_empty(&self) -> bool {
        self.valid_rows == 0 && self.incomplete_rows == 0
    }
}

/// 累积器：跨文件共享去重状态。
#[derive(Default)]
pub struct Accumulator {
    keys: HashMap<Key, DuplicateGroup>,
    key_order: Vec<Key>,
    total_rows: usize,
    valid_rows: usize,
    incomplete_rows: usize,
    per_file: Vec<FileReport>,
    sheets: Vec<SheetReport>,
    skipped_sheets: Vec<String>,
    files_parsed: Vec<String>,
    duplicate_inputs: Vec<String>,
    rejected: Vec<Rejected>,
    incomplete_shown: Vec<TripleRow>,
    limitations: Vec<String>,
    key_space_exhausted_at: Option<usize>,
    row_limit_reached: Vec<String>,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note(&mut self, message: impl Into<String>) {
        let message = message.into();
        if !self.limitations.contains(&message) {
            self.limitations.push(message);
        }
    }

    /// 记录无法解析的输入（不存在、损坏、格式不支持、超限）。
    pub fn reject(
        &mut self,
        link: Link,
        display: impl Into<String>,
        code: &'static str,
        message: impl Into<String>,
    ) {
        self.rejected.push(Rejected {
            link,
            display: display.into(),
            code,
            message: message.into(),
        });
    }

    pub fn mark_duplicate_input(&mut self, display: impl Into<String>) {
        self.duplicate_inputs.push(display.into());
        self.note("同一文件重复传入只计一次（重复项记录在 duplicateInputs）");
    }

    /// 处理一个已确认是 xlsx/xlsm 的包；`display` 是文件显示名（zip 内条目用条目名）。
    pub fn analyze_workbook<B: Blob + ?Sized>(
        &mut self,
        link: Link,
        display: &str,
        blob: &B,
        workbook: &Workbook,
    ) {
        let entries: Vec<ZipEntry> = match read_entries_from(blob) {
            Ok(entries) => entries,
            Err(error) => {
                self.reject(link, display, error.code, error.message);
                return;
            }
        };
        let mut file_report = FileReport {
            link: Some(link.clone()),
            file: display.to_owned(),
            sheets: workbook.sheets.len(),
            ..FileReport::default()
        };
        if workbook.sheets.is_empty() {
            self.note(format!("{display}: 工作簿内没有工作表声明，按 0 行处理"));
            self.per_file.push(file_report);
            self.files_parsed.push(display.to_owned());
            return;
        }
        for sheet in &workbook.sheets {
            self.analyze_sheet(
                link.clone(),
                display,
                blob,
                &entries,
                sheet,
                workbook,
                &mut file_report,
            );
        }
        file_report.header_source = Some(header_summary_of(&file_report, &self.sheets));
        self.per_file.push(file_report);
        self.files_parsed.push(display.to_owned());
    }

    fn analyze_sheet<B: Blob + ?Sized>(
        &mut self,
        link: Link,
        display: &str,
        blob: &B,
        entries: &[ZipEntry],
        sheet: &SheetRef,
        workbook: &Workbook,
        file_report: &mut FileReport,
    ) {
        let label = format!("{display}!{}", sheet.name);
        let mut header: Option<HeaderMatch> = None;
        let mut scan_rows: Vec<SheetRow> = Vec::new();
        let mut max_column: Option<usize> = None;
        let mut data_rows: Vec<SheetRow> = Vec::new();
        let mut row_limit_hit = false;
        let mut key_space_full = false;

        let outcome = stream_rows(blob, entries, sheet, workbook, |row| {
            if let Some(last) = row.cells.last().map(|(column, _)| *column) {
                max_column = Some(max_column.map_or(last, |current| current.max(last)));
            }
            if header.is_none() && scan_rows.len() < crate::header::HEADER_SCAN_ROWS {
                if !row.is_blank() {
                    if let Some(matched) = detect_header_row(row.number, &row.cells) {
                        header = Some(matched);
                    }
                }
                scan_rows.push(row);
                return Ok(true);
            }
            if data_rows.len() as u64 >= MAX_ROWS_PER_SHEET {
                row_limit_hit = true;
                return Ok(false);
            }
            data_rows.push(row);
            Ok(!key_space_full)
        });

        if let Err(error) = outcome {
            let message = format!("工作表 {label} 读取失败：{}", error.message);
            file_report
                .skipped_sheets
                .push(format!("{}（{}）", sheet.name, error.code));
            self.skipped_sheets
                .push(format!("{label}（{}）", error.code));
            self.note(message);
            self.sheets.push(SheetReport {
                link: Some(link),
                file: display.to_owned(),
                sheet: sheet.name.clone(),
                total_rows: 0,
                valid_rows: 0,
                incomplete_rows: 0,
                header: None,
                skipped_reason: Some(error.code.to_string()),
            });
            return;
        }

        // 没有命中表头：按首个非空行的最大列号做列序回退。
        if header.is_none() {
            let target = scan_rows
                .iter()
                .find(|row| !row.is_blank())
                .and_then(|row| row.cells.last().map(|(column, _)| *column))
                .or(max_column);
            match positional_layout(target) {
                Some((_, fallback)) => header = Some(fallback),
                None => {
                    let reason = if scan_rows.iter().all(SheetRow::is_blank) {
                        "空工作表（没有非空行）"
                    } else {
                        "前 3 行未命中姓名/电话/地址表头，且列数不足以按已知列序回退"
                    };
                    file_report
                        .skipped_sheets
                        .push(format!("{}（{reason}）", sheet.name));
                    self.skipped_sheets.push(format!("{label}（{reason}）"));
                    self.sheets.push(SheetReport {
                        link: Some(link),
                        file: display.to_owned(),
                        sheet: sheet.name.clone(),
                        total_rows: 0,
                        valid_rows: 0,
                        incomplete_rows: 0,
                        header: None,
                        skipped_reason: Some(reason.to_string()),
                    });
                    return;
                }
            }
        }
        let header_ref = header.expect("header resolved");

        let mut sheet_total_len = 0usize;
        let mut sheet_valid = 0usize;
        let mut sheet_incomplete = 0usize;

        // 1) 表头探测阶段扫过的行：表头行计入 totalRows，其后为数据行。
        let header_row = header_ref.header_row;
        let header_is_header = header_ref.source == HeaderSource::Header;
        for row in &scan_rows {
            if header_is_header && row.number <= header_row {
                if row.number == header_row {
                    sheet_total_len += 1;
                }
                continue;
            }
            if row.is_blank() {
                sheet_total_len += 1;
                sheet_incomplete += 1;
                continue;
            }
            sheet_total_len += 1;
            match self.record_row(link.clone(), display, &sheet.name, row, &header_ref) {
                RowOutcome::Complete => sheet_valid += 1,
                RowOutcome::Incomplete => sheet_incomplete += 1,
                RowOutcome::KeySpaceFull => key_space_full = true,
            }
        }

        // 2) 后续数据行。
        for row in &data_rows {
            sheet_total_len += 1;
            if row.is_blank() {
                sheet_incomplete += 1;
                continue;
            }
            if key_space_full {
                continue;
            }
            match self.record_row(link.clone(), display, &sheet.name, row, &header_ref) {
                RowOutcome::Complete => sheet_valid += 1,
                RowOutcome::Incomplete => sheet_incomplete += 1,
                RowOutcome::KeySpaceFull => key_space_full = true,
            }
        }

        if row_limit_hit {
            self.row_limit_reached.push(label.clone());
            self.note(format!(
                "{label} 超过单表 {MAX_ROWS_PER_SHEET} 行上限，其后的行未计入"
            ));
        }
        file_report.sheets_used += 1;
        file_report.total_rows += sheet_total_len;
        file_report.valid_rows += sheet_valid;
        file_report.incomplete_rows += sheet_incomplete;
        self.total_rows += sheet_total_len;
        self.valid_rows += sheet_valid;
        self.incomplete_rows += sheet_incomplete;
        self.sheets.push(SheetReport {
            link: Some(link),
            file: display.to_owned(),
            sheet: sheet.name.clone(),
            total_rows: sheet_total_len,
            valid_rows: sheet_valid,
            incomplete_rows: sheet_incomplete,
            header: Some(header_ref),
            skipped_reason: None,
        });
    }

    /// 记录一行；返回该行的归类。
    fn record_row(
        &mut self,
        link: Link,
        display: &str,
        sheet: &str,
        row: &SheetRow,
        header: &HeaderMatch,
    ) -> RowOutcome {
        let cell = |field: Field| -> String {
            let Some(column) = header.column(field) else {
                return String::new();
            };
            row.cells
                .iter()
                .find(|(existing, _)| *existing == column)
                .map(|(_, text)| text.clone())
                .unwrap_or_default()
        };
        let name = normalize_name(&cell(Field::Name));
        let phone = normalize_phone(&cell(Field::Phone));
        let address = normalize_address(&cell(Field::Address));
        let mut missing = Vec::new();
        if name.is_empty() {
            missing.push(Field::Name);
        }
        if phone.is_empty() {
            missing.push(Field::Phone);
        }
        if address.is_empty() {
            missing.push(Field::Address);
        }
        if !missing.is_empty() {
            if self.incomplete_shown.len() < MAX_INCOMPLETE_SHOWN {
                self.incomplete_shown.push(TripleRow {
                    link,
                    sheet: sheet.to_owned(),
                    row: row.number,
                    name,
                    phone,
                    address,
                    missing,
                });
            }
            return RowOutcome::Incomplete;
        }
        let key = Key {
            name,
            phone,
            address,
        };
        if let Some(group) = self.keys.get_mut(&key) {
            group.occurrences += 1;
            if group.sources.len() < MAX_SOURCES_PER_KEY {
                group.sources.push(SourceRow {
                    link,
                    file: display.to_owned(),
                    sheet: sheet.to_owned(),
                    row: row.number,
                });
            } else {
                group.truncated = true;
            }
            return RowOutcome::Complete;
        }
        if self.keys.len() >= MAX_UNIQUE_KEYS {
            if self.key_space_exhausted_at.is_none() {
                self.key_space_exhausted_at = Some(self.total_rows);
            }
            self.note(format!(
                "去重键数量超过 {MAX_UNIQUE_KEYS} 上限，其后的新键不再计入（已出现键的重复仍会累计）"
            ));
            return RowOutcome::KeySpaceFull;
        }
        let first = SourceRow {
            link,
            file: display.to_owned(),
            sheet: sheet.to_owned(),
            row: row.number,
        };
        self.keys.insert(
            key.clone(),
            DuplicateGroup {
                key: key.clone(),
                occurrences: 1,
                first: first.clone(),
                sources: vec![first],
                truncated: false,
            },
        );
        self.key_order.push(key);
        RowOutcome::Complete
    }

    /// 完成统计并产出结果。
    pub fn finish(mut self) -> Aggregation {
        let mut groups: Vec<DuplicateGroup> = Vec::new();
        for key in &self.key_order {
            if let Some(group) = self.keys.remove(key) {
                if group.occurrences > 1 {
                    groups.push(group);
                }
            }
        }
        groups.sort_by(|left, right| {
            right
                .occurrences
                .cmp(&left.occurrences)
                .then_with(|| left.first.location().cmp(&right.first.location()))
                .then_with(|| left.key.cmp(&right.key))
        });
        let duplicate_count: usize = groups.iter().map(|group| group.occurrences - 1).sum();
        let unique_count = self.key_order.len();
        if groups.len() > MAX_DUPLICATE_GROUPS {
            self.note(format!(
                "重复组共 {} 组，结果只返回前 {MAX_DUPLICATE_GROUPS} 组（按出现次数降序）",
                groups.len()
            ));
            groups.truncate(MAX_DUPLICATE_GROUPS);
        }
        if self.incomplete_shown.len() >= MAX_INCOMPLETE_SHOWN {
            self.note(format!("缺失项行明细只返回前 {MAX_INCOMPLETE_SHOWN} 行"));
        }
        let header_source = header_summary(&self.sheets);
        let mut limitations = std::mem::take(&mut self.limitations);
        for line in default_limitations() {
            if !limitations.contains(&line) {
                limitations.push(line);
            }
        }
        Aggregation {
            total_rows: self.total_rows,
            valid_rows: self.valid_rows,
            unique_count,
            duplicate_count,
            incomplete_rows: self.incomplete_rows,
            duplicate_groups: groups,
            per_file: self.per_file,
            sheets: self.sheets,
            skipped_sheets: self.skipped_sheets,
            files_parsed: self.files_parsed,
            duplicate_inputs: self.duplicate_inputs,
            rejected: self.rejected,
            incomplete_shown: self.incomplete_shown,
            header_source,
            key_space_exhausted_at: self.key_space_exhausted_at,
            limitations,
            row_limit_reached: self.row_limit_reached,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowOutcome {
    Complete,
    Incomplete,
    KeySpaceFull,
}

fn header_summary_of(report: &FileReport, sheets: &[SheetReport]) -> String {
    let file_sheets: Vec<&SheetReport> = sheets
        .iter()
        .filter(|sheet| sheet.file == report.file && sheet.header.is_some())
        .collect();
    summary_string(&file_sheets).unwrap_or_else(|| "none".to_owned())
}

/// 汇总 headerSource：全是表头命中 → `header`；全是列序回退 → `positional`；
/// 两者都有 → `mixed`；没有参与统计的表 → `None`。
pub fn header_summary(sheets: &[SheetReport]) -> Option<String> {
    let participated: Vec<&SheetReport> = sheets.iter().filter(|s| s.header.is_some()).collect();
    summary_string(&participated)
}

fn summary_string(participated: &[&SheetReport]) -> Option<String> {
    if participated.is_empty() {
        return None;
    }
    let headers = participated
        .iter()
        .filter(|s| {
            s.header
                .as_ref()
                .is_some_and(|h| h.source == HeaderSource::Header)
        })
        .count();
    let positional = participated.len() - headers;
    Some(if positional == 0 {
        "header".to_owned()
    } else if headers == 0 {
        "positional".to_owned()
    } else {
        "mixed".to_owned()
    })
}

pub fn default_limitations() -> Vec<String> {
    vec![
        "同名不同电话按不同人处理（不做模糊合并）；同电话不同名同样视为不同人".to_owned(),
        "不做拼音/地址分词/编辑距离等模糊相似去重".to_owned(),
        "不解析 .xls/.docx/.pdf 版式，不递归解析 zip 内的非 xlsx 资源".to_owned(),
        "日期类单元格保留原始序列值文本，不做时区或纪元换算".to_owned(),
        "xlsx 宏（vbaProject.bin）与外部链接从不执行或解析".to_owned(),
        "地址规范化会把 - 与常见中英文标点视为分隔，可能把个别有语义的门牌号写法合并".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        xlsx_bytes, xlsx_parts, zip_bytes, Cell, RowSpec, SheetSpec, WorkbookSpec, ZipOptions,
    };

    /// 在内存里跑完整链路：zip 容器 → 工作簿 → 工作表 → 去重聚合。
    fn parse(display: &str, bytes: &[u8]) -> Aggregation {
        let mut accumulator = Accumulator::new();
        crate::analyzer::parse_input(
            &mut accumulator,
            Link::Evidence {
                root: "part:0".to_owned(),
                path: display.to_owned(),
            },
            display,
            bytes,
        );
        accumulator.finish()
    }

    fn inline(text: &str) -> Cell {
        Cell::Inline(text.to_owned())
    }

    fn header_row() -> RowSpec {
        RowSpec::new(
            1,
            vec![
                (0, inline("ID")),
                (1, inline("姓名")),
                (2, inline("电话")),
                (3, inline("地址")),
            ],
        )
    }

    fn person_row(number: u32, id: &str, name: &str, phone: &str, address: &str) -> RowSpec {
        RowSpec::new(
            number,
            vec![
                (0, inline(id)),
                (1, inline(name)),
                (2, inline(phone)),
                (3, inline(address)),
            ],
        )
    }

    fn sample_sheet() -> SheetSpec {
        SheetSpec::new(
            "Sheet1",
            vec![
                header_row(),
                person_row(2, "1", "张三", "13800138000", "北京市海淀区中关村大街1号"),
                person_row(3, "2", "李四", "13900139000", "上海市浦东新区世纪大道100号"),
                // 与第 2 行同一人：电话分隔符、地址全角数字都应被规范化后合并。
                person_row(
                    4,
                    "3",
                    "张三",
                    "138-0013-8000",
                    "北京市海淀区中关村大街１号",
                ),
                person_row(5, "4", "王五", "13700137000", "广州市天河区体育西路1号"),
            ],
        )
    }

    #[test]
    fn normal_rows_and_exact_duplicates_are_counted() {
        let spec = WorkbookSpec::new(vec![sample_sheet()], Vec::new());
        let aggregation = parse("收件人.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));

        assert!(
            aggregation.rejected.is_empty(),
            "{:?}",
            aggregation.rejected
        );
        assert_eq!(aggregation.total_rows, 5, "表头行 + 4 个数据行");
        assert_eq!(aggregation.valid_rows, 4);
        assert_eq!(aggregation.unique_count, 3);
        assert_eq!(aggregation.duplicate_count, 1);
        assert_eq!(aggregation.incomplete_rows, 0);
        assert_eq!(aggregation.header_source.as_deref(), Some("header"));
        assert_eq!(aggregation.skipped_sheets, Vec::<String>::new());

        // 真实 xlsx 大多用 DEFLATE：同一份内容压缩后必须得到相同计数。
        let deflated = parse(
            "收件人-deflate.xlsx",
            &xlsx_bytes(
                &spec,
                ZipOptions {
                    deflate: true,
                    corrupt_crc_entry: None,
                },
            ),
        );
        assert!(deflated.rejected.is_empty(), "{:?}", deflated.rejected);
        assert_eq!(deflated.valid_rows, aggregation.valid_rows);
        assert_eq!(deflated.unique_count, aggregation.unique_count);
        assert_eq!(deflated.duplicate_count, aggregation.duplicate_count);

        let group = aggregation
            .duplicate_groups
            .first()
            .expect("one duplicate group");
        assert_eq!(group.occurrences, 2);
        assert_eq!(group.first.row, 2);
        assert_eq!(
            group
                .sources
                .iter()
                .map(|source| source.row)
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
        assert_eq!(group.key.name, "张三");
        assert_eq!(group.key.phone, "13800138000");
        assert_eq!(group.key.address, "北京市海淀区中关村大街1号");
        assert!(group.key.masked_display().contains("138****8000"));

        let sheet = aggregation.sheets.first().expect("sheet report");
        assert_eq!(sheet.sheet, "Sheet1");
        assert_eq!(sheet.total_rows, 5);
        assert_eq!(sheet.valid_rows, 4);
        let report = aggregation.per_file.first().expect("file report");
        assert_eq!(report.file, "收件人.xlsx");
        assert_eq!(report.sheets, 1);
        assert_eq!(report.sheets_used, 1);
        assert_eq!(report.header_source.as_deref(), Some("header"));
    }

    #[test]
    fn empty_sheets_and_missing_columns_are_reported() {
        let spec = WorkbookSpec::new(
            vec![
                // 只有表头、没有数据行。
                SheetSpec::new(
                    "只有表头",
                    vec![RowSpec::new(
                        1,
                        vec![
                            (0, inline("姓名")),
                            (1, inline("电话")),
                            (2, inline("地址")),
                        ],
                    )],
                ),
                // 完全没有行的工作表不参与统计。
                SheetSpec::new("空白表", Vec::new()),
                // 缺少地址列：数据行全部计为缺项。
                SheetSpec::new(
                    "缺地址列",
                    vec![
                        RowSpec::new(1, vec![(0, inline("姓名")), (1, inline("电话"))]),
                        RowSpec::new(2, vec![(0, inline("张三")), (1, inline("13800138000"))]),
                        RowSpec::new(3, vec![(0, inline("李四")), (1, inline("13900139000"))]),
                    ],
                ),
            ],
            Vec::new(),
        );
        let aggregation = parse("空表.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));

        assert!(
            aggregation.rejected.is_empty(),
            "{:?}",
            aggregation.rejected
        );
        // 只有表头行的表：总行数 1，没有有效/缺项行。
        assert_eq!(aggregation.total_rows, 4, "1 + 0 + 3");
        assert_eq!(aggregation.valid_rows, 0);
        assert_eq!(aggregation.incomplete_rows, 2);
        assert_eq!(aggregation.unique_count, 0);
        assert_eq!(aggregation.duplicate_count, 0);
        // 只有空白表被跳过，其余两张表参与统计（表头来源均为 header）。
        assert_eq!(aggregation.skipped_sheets.len(), 1);
        assert!(aggregation.skipped_sheets[0].contains("空白表"));
        assert!(aggregation.skipped_sheets[0].contains("空工作表"));
        assert_eq!(aggregation.header_source.as_deref(), Some("header"));
        assert_eq!(aggregation.per_file[0].sheets, 3);
        assert_eq!(aggregation.per_file[0].sheets_used, 2);

        let missing = aggregation
            .sheets
            .iter()
            .find(|sheet| sheet.sheet == "缺地址列")
            .expect("missing-column sheet");
        let header = missing.header.as_ref().expect("header still detected");
        assert_eq!(header.columns, [Some(0), Some(1), None]);
        assert_eq!(
            aggregation
                .incomplete_shown
                .iter()
                .filter(|row| row.missing.contains(&Field::Address))
                .count(),
            2
        );
        assert_eq!(
            aggregation.incomplete_shown[0].missing,
            vec![Field::Address]
        );
    }

    #[test]
    fn workbook_without_sheets_reports_zero() {
        let spec = WorkbookSpec::new(Vec::new(), Vec::new());
        let aggregation = parse("空工作簿.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));

        assert!(
            aggregation.rejected.is_empty(),
            "{:?}",
            aggregation.rejected
        );
        assert!(aggregation.is_empty());
        assert_eq!(aggregation.total_rows, 0);
        assert_eq!(aggregation.valid_rows, 0);
        assert_eq!(aggregation.unique_count, 0);
        assert_eq!(aggregation.per_file.len(), 1);
        assert_eq!(aggregation.per_file[0].sheets, 0);
        assert_eq!(aggregation.header_source, None);
        assert!(aggregation
            .limitations
            .iter()
            .any(|line| line.contains("没有工作表声明")));
    }

    #[test]
    fn shared_strings_and_numeric_phones_are_resolved() {
        let spec = WorkbookSpec::new(
            vec![SheetSpec::new(
                "Sheet1",
                vec![
                    RowSpec::new(
                        1,
                        vec![
                            (0, Cell::Shared(0)),
                            (1, Cell::Shared(1)),
                            (2, Cell::Shared(2)),
                        ],
                    ),
                    RowSpec::new(
                        2,
                        vec![
                            (0, Cell::Shared(3)),
                            (1, Cell::Number("13800138000".to_owned())),
                            (2, Cell::Shared(4)),
                        ],
                    ),
                ],
            )],
            vec![
                "姓名".to_owned(),
                "电话".to_owned(),
                "地址".to_owned(),
                "张三".to_owned(),
                "北京市海淀区中关村大街1号".to_owned(),
            ],
        );
        let aggregation = parse("共享字符串.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));

        assert!(
            aggregation.rejected.is_empty(),
            "{:?}",
            aggregation.rejected
        );
        assert_eq!(aggregation.header_source.as_deref(), Some("header"));
        assert_eq!(aggregation.total_rows, 2);
        assert_eq!(aggregation.valid_rows, 1);
        assert_eq!(aggregation.unique_count, 1);
        assert!(aggregation.duplicate_groups.is_empty());
    }

    #[test]
    fn headerless_sheet_falls_back_to_known_column_order() {
        let spec = WorkbookSpec::new(
            vec![SheetSpec::new(
                "无表头",
                vec![
                    RowSpec::new(
                        1,
                        vec![
                            (0, inline("1")),
                            (1, inline("张三")),
                            (2, inline("13800138000")),
                            (3, inline("北京市海淀区中关村大街1号")),
                            (4, inline("北京")),
                            (5, inline("北京")),
                        ],
                    ),
                    RowSpec::new(
                        2,
                        vec![
                            (0, inline("2")),
                            (1, inline("李四")),
                            (2, inline("13900139000")),
                            (3, inline("上海市浦东新区世纪大道100号")),
                            (4, inline("上海")),
                            (5, inline("上海")),
                        ],
                    ),
                ],
            )],
            Vec::new(),
        );
        let aggregation = parse("无表头.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));

        assert_eq!(aggregation.total_rows, 2);
        assert_eq!(aggregation.valid_rows, 2);
        assert_eq!(aggregation.unique_count, 2);
        assert_eq!(aggregation.header_source.as_deref(), Some("positional"));
        let header = aggregation.sheets[0].header.as_ref().expect("fallback");
        assert_eq!(header.source, HeaderSource::Positional);
        assert_eq!(header.columns, [Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn corrupt_zip_and_corrupt_xml_are_rejected_with_codes() {
        let spec = WorkbookSpec::new(vec![sample_sheet()], Vec::new());
        let valid = xlsx_bytes(&spec, ZipOptions::default());

        // 1) CRC 损坏：xl/workbook.xml 的目录 CRC 与数据不符。
        let parts = xlsx_parts(&spec);
        let workbook_index = parts
            .iter()
            .position(|(name, _)| name == "xl/workbook.xml")
            .expect("workbook part");
        let bad_crc = zip_bytes(
            &parts,
            ZipOptions {
                deflate: false,
                corrupt_crc_entry: Some(workbook_index),
            },
        );
        let aggregation = parse("坏CRC.xlsx", &bad_crc);
        assert_eq!(aggregation.rejected.len(), 1);
        assert_eq!(aggregation.rejected[0].code, "zip.crc");
        assert_eq!(aggregation.rejected[0].display, "坏CRC.xlsx");
        assert!(aggregation.files_parsed.is_empty());

        // 2) 截断的 zip：找不到中央目录结束记录。
        let aggregation = parse("截断.xlsx", &valid[..valid.len() / 2]);
        assert_eq!(aggregation.rejected.len(), 1);
        assert_eq!(aggregation.rejected[0].code, "zip.not_zip");

        // 3) 损坏的 xl/workbook.xml：整包拒绝。
        let mut broken_parts = xlsx_parts(&spec);
        for (name, data) in broken_parts.iter_mut() {
            if name == "xl/workbook.xml" {
                *data = b"<<not-xml".to_vec();
            }
        }
        let aggregation = parse(
            "坏工作簿XML.xlsx",
            &zip_bytes(&broken_parts, ZipOptions::default()),
        );
        assert_eq!(aggregation.rejected.len(), 1);
        assert_eq!(aggregation.rejected[0].code, "xlsx.workbook");

        // 4) 工作表 XML 损坏：只跳过该表，并在 skipped_sheets 记录。
        let mut broken_sheet_parts = xlsx_parts(&spec);
        for (name, data) in broken_sheet_parts.iter_mut() {
            if name == "xl/worksheets/sheet1.xml" {
                *data = b"<<not-xml".to_vec();
            }
        }
        let aggregation = parse(
            "坏表XML.xlsx",
            &zip_bytes(&broken_sheet_parts, ZipOptions::default()),
        );
        assert!(
            aggregation.rejected.is_empty(),
            "{:?}",
            aggregation.rejected
        );
        assert_eq!(aggregation.skipped_sheets.len(), 1);
        assert!(aggregation.skipped_sheets[0].contains("xlsx.sheet"));
        assert_eq!(aggregation.total_rows, 0);
        assert_eq!(aggregation.valid_rows, 0);
        assert_eq!(aggregation.per_file[0].sheets, 1);
        assert_eq!(aggregation.per_file[0].sheets_used, 0);
    }

    #[test]
    fn cross_file_sources_are_traceable_in_results() {
        let spec = WorkbookSpec::new(vec![sample_sheet()], Vec::new());
        let inner = xlsx_bytes(&spec, ZipOptions::default());
        let outer = zip_bytes(
            &[
                ("导出/顺丰1k.xlsx".to_owned(), inner.clone()),
                ("说明.txt".to_owned(), b"ignored".to_vec()),
            ],
            ZipOptions::default(),
        );
        let aggregation = parse("收件人.zip", &outer);

        assert!(
            aggregation.rejected.is_empty(),
            "{:?}",
            aggregation.rejected
        );
        assert_eq!(
            aggregation.files_parsed,
            vec!["收件人.zip::导出/顺丰1k.xlsx".to_owned()]
        );
        assert_eq!(aggregation.valid_rows, 4);
        assert_eq!(aggregation.duplicate_count, 1);
        let group = &aggregation.duplicate_groups[0];
        assert_eq!(group.first.file, "收件人.zip::导出/顺丰1k.xlsx");
        assert_eq!(
            group.first.location(),
            "收件人.zip::导出/顺丰1k.xlsx!Sheet1!2"
        );
        assert_eq!(
            group.first.link,
            Link::Evidence {
                root: "part:0".to_owned(),
                path: "收件人.zip".to_owned(),
            }
        );
    }
}
