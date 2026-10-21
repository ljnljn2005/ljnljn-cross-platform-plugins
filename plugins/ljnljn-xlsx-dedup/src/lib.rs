//! Recipient-table de-duplication (LPP v2).
//!
//! Port of the v1 `ljnljn.xlsx-dedup` analyzer. The container, workbook,
//! header-detection, normalization and de-duplication layers are carried over
//! (`zipread`, `xlsx`, `header`, `normalize`, `dedup`, `parse`); this crate
//! adds typed LPP v2 records and two analyzers:
//!
//! - `dedup_files` (scope `files`): the selected `.xlsx` / `.xlsm` / `.zip`
//!   files, cross-file de-duplicated in one run;
//! - `dedup_evidence` (scope `evidence`): a bounded recursive walk of every
//!   volume in the evidence view, skipping system directories, capped at
//!   [`MAX_INPUT_FILES`] spreadsheet/zip inputs.
//!
//! The counts keep the v1 definitions: `total_rows` includes the header row,
//! `valid_rows` have all three normalized values, `unique_count` counts
//! distinct `(name, phone, address)` keys, `duplicate_count` is
//! `valid_rows - unique_count`, and `incomplete_rows` never participate in
//! de-duplication. Only masked names/phones/addresses appear in duplicate
//! records; the normalized full values are never emitted.

pub mod analyzer;
pub mod blob;
pub mod dedup;
pub mod error;
pub mod header;
pub mod limits;
pub mod normalize;
pub mod parse;
pub mod value;
pub mod xlsx;
pub mod zipread;

#[cfg(test)]
pub mod fixtures;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use lovelycarve_plugin::{export_plugin, FileRef, Plugin, Record, Result, Run, View};

use crate::analyzer::parse_input;
use crate::blob::FileBlob;
use crate::dedup::{Aggregation, DuplicateGroup, FileReport, SheetReport, TripleRow};
use crate::header::Field;
use crate::limits::MAX_INPUT_FILES;
use crate::parse::{is_spreadsheet_name, is_zip_name, Link};

/// File-scope analyzer id (must match `plugin.toml`).
pub const ANALYZER_FILES: &str = "dedup_files";
/// Evidence-scope analyzer id (must match `plugin.toml`).
pub const ANALYZER_EVIDENCE: &str = "dedup_evidence";
/// Maximum directory depth of the evidence walk.
pub const MAX_WALK_DEPTH: usize = 10;

/// One aggregate record per run.
#[derive(Record)]
#[record(
    id = "xlsx.dedup.summary",
    label = "收件人表去重汇总",
    title = "{analyzer}"
)]
struct SummaryRecord {
    #[field(label = "分析器", key)]
    analyzer: String,
    #[field(label = "总行数（含表头）")]
    total_rows: i64,
    #[field(label = "有效行数")]
    valid_rows: i64,
    #[field(label = "唯一三元组数")]
    unique_count: i64,
    #[field(label = "重复行数")]
    duplicate_count: i64,
    #[field(label = "缺项行数")]
    incomplete_rows: i64,
    #[field(label = "参与统计的文件数")]
    files_parsed: i64,
    #[field(label = "参与统计的工作表数")]
    sheets_used: i64,
    #[field(label = "跳过的工作表数")]
    skipped_sheets: i64,
    #[field(label = "重复组数（已输出）")]
    duplicate_groups: i64,
    #[field(label = "重复输入数")]
    duplicate_inputs: i64,
    #[field(label = "表头来源")]
    header_source: Option<String>,
    #[field(label = "去重键空间耗尽于第几行")]
    key_space_exhausted_at: Option<i64>,
    #[field(label = "解析文件", kind = "list")]
    files: Vec<String>,
    #[field(label = "限制与覆盖说明", kind = "list")]
    limitations: Vec<String>,
    #[field(label = "达到行数上限的文件", kind = "list")]
    row_limit_reached: Vec<String>,
}

/// One source file/archive-member summary.
#[derive(Record)]
#[record(id = "xlsx.dedup.file", label = "表格文件汇总", title = "{file}")]
struct FileSummaryRecord {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "工作表数")]
    sheets: i64,
    #[field(label = "参与统计的工作表数")]
    sheets_used: i64,
    #[field(label = "总行数")]
    row_count: i64,
    #[field(label = "有效行数")]
    valid_rows: i64,
    #[field(label = "缺项行数")]
    incomplete_rows: i64,
    #[field(label = "表头来源")]
    header_source: Option<String>,
    #[field(label = "跳过的工作表", kind = "list")]
    skipped_sheets: Vec<String>,
}

/// One worksheet's header detection and row counts.
#[derive(Record)]
#[record(
    id = "xlsx.dedup.sheet",
    label = "工作表处理结果",
    title = "{file} · {sheet}"
)]
struct SheetRecord {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "工作表", key)]
    sheet: String,
    #[field(
        label = "表头来源",
        kind = "enum",
        choices = "header=表头别名,positional=列序回退,skipped=跳过"
    )]
    header_source: String,
    #[field(label = "表头行号")]
    header_row: i64,
    #[field(label = "姓名列号（1 起）")]
    name_column: Option<i64>,
    #[field(label = "电话列号（1 起）")]
    phone_column: Option<i64>,
    #[field(label = "地址列号（1 起）")]
    address_column: Option<i64>,
    #[field(label = "总行数")]
    row_count: i64,
    #[field(label = "有效行数")]
    valid_rows: i64,
    #[field(label = "缺项行数")]
    incomplete_rows: i64,
    #[field(label = "跳过原因")]
    skipped_reason: Option<String>,
}

/// One `(name, phone, address)` group that occurs at least twice.
#[derive(Record)]
#[record(
    id = "xlsx.dedup.duplicate",
    label = "重复收件人",
    title = "{name} | {phone} | {address} × {occurrences}"
)]
struct DuplicateRecord {
    #[field(label = "首次出现")]
    first_source: String,
    #[field(label = "姓名（脱敏）")]
    name: String,
    #[field(label = "电话（前 3 后 4）")]
    phone: String,
    #[field(label = "地址（脱敏）")]
    address: String,
    #[field(label = "出现次数")]
    occurrences: i64,
    #[field(label = "文件")]
    first_file: String,
    #[field(label = "工作表")]
    first_sheet: String,
    #[field(label = "行号")]
    first_row: i64,
    #[field(label = "全部来源行", kind = "list")]
    sources: Vec<String>,
    #[field(label = "来源行被截断")]
    sources_truncated: bool,
}

/// One row with at least one missing normalized field.
#[derive(Record)]
#[record(
    id = "xlsx.dedup.incomplete",
    label = "缺项收件人行",
    title = "{file} · {sheet} · 第 {row} 行"
)]
struct IncompleteRecord {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "工作表", key)]
    sheet: String,
    #[field(label = "行号", key)]
    row: i64,
    #[field(label = "缺失字段", kind = "list")]
    missing: Vec<String>,
    #[field(label = "姓名（脱敏）")]
    name: String,
    #[field(label = "电话（脱敏）")]
    phone: String,
    #[field(label = "地址（脱敏）")]
    address: String,
}

/// An input that could not be parsed.
#[derive(Record)]
#[record(
    id = "xlsx.dedup.rejected",
    label = "跳过的输入",
    title = "{file} [{code}]"
)]
struct RejectedRecord {
    #[field(label = "文件", key)]
    file: String,
    #[field(label = "错误代码", key)]
    code: String,
    #[field(label = "说明")]
    message: String,
}

/// Cross-input de-duplication state plus the handles of the inputs, used to
/// attach source references to the records after aggregation.
struct Context {
    accumulator: Option<dedup::Accumulator>,
    files: HashMap<Link, FileRef>,
}

impl Context {
    fn new() -> Self {
        Self {
            accumulator: Some(dedup::Accumulator::new()),
            files: HashMap::new(),
        }
    }

    fn analyze(&mut self, file: &FileRef, link: Link, display: &str) {
        let blob = FileBlob::new(file);
        if let Some(accumulator) = self.accumulator.as_mut() {
            parse_input(accumulator, link.clone(), display, &blob);
        }
        self.files.insert(link, file.clone());
    }

    fn finish(&mut self) -> Aggregation {
        self.accumulator.take().unwrap_or_default().finish()
    }

    fn source(&self, link: &Link) -> Option<&FileRef> {
        self.files.get(link)
    }
}

fn dedup_files(run: &Run) -> Result<()> {
    if run.inputs().is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "没有选中任何 xlsx/xlsm/zip（分析器声明扩展名 xlsx、xlsm、zip）",
        )?;
        run.set_summary("未找到可分析的表格");
        return Ok(());
    }
    let mut context = Context::new();
    for file in run.inputs() {
        run.check_cancelled()?;
        let display = display_name(file);
        let link = Link::File {
            file_id: file.id().to_owned(),
        };
        context.analyze(file, link, &display);
    }
    let aggregation = context.finish();
    emit_aggregation(run, ANALYZER_FILES, &aggregation, &context)?;
    Ok(())
}

fn dedup_evidence(run: &Run) -> Result<()> {
    let view = run.require_view()?;
    let mut context = Context::new();
    let collected = collect_evidence(run, view)?;
    for (path, message) in &collected.errors {
        if let Some(accumulator) = context.accumulator.as_mut() {
            accumulator.reject(
                Link::Evidence {
                    root: "view".to_owned(),
                    path: path.clone(),
                },
                path,
                "evidence.walk",
                message.clone(),
            );
        }
    }
    if collected.truncated {
        if let Some(accumulator) = context.accumulator.as_mut() {
            accumulator.note(format!("输入文件超过 {MAX_INPUT_FILES} 上限，其余未分析"));
        }
    }
    if collected.paths.is_empty() {
        if let Some(accumulator) = context.accumulator.as_mut() {
            accumulator.note(format!(
                "未找到目标 xlsx/xlsm 或包含 xlsx 的 zip（递归深度 ≤ {MAX_WALK_DEPTH}）"
            ));
        }
    }
    let total = collected.paths.len();
    for (index, path) in collected.paths.iter().enumerate() {
        run.check_cancelled()?;
        run.progress(index as u64 + 1, Some(total as u64), Some(path))?;
        let Some(file) = view.open(path)? else {
            if let Some(accumulator) = context.accumulator.as_mut() {
                accumulator.reject(
                    Link::Evidence {
                        root: "view".to_owned(),
                        path: path.clone(),
                    },
                    path,
                    "not_found",
                    "枚举后文件不再存在或不是普通文件",
                );
            }
            continue;
        };
        let link = evidence_link(&file, path);
        context.analyze(&file, link, path);
    }
    let aggregation = context.finish();
    emit_aggregation(run, ANALYZER_EVIDENCE, &aggregation, &context)?;
    Ok(())
}

struct Collected {
    paths: Vec<String>,
    errors: Vec<(String, String)>,
    truncated: bool,
}

/// Bounded depth-first walk of the evidence view. System directories are
/// skipped; only spreadsheet and zip names are collected (regular files).
fn collect_evidence(run: &Run, view: &View) -> Result<Collected> {
    let mut paths = Vec::new();
    let mut errors = Vec::new();
    let mut truncated = false;
    let mut stack = vec![(String::new(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        run.check_cancelled()?;
        let nodes = match view.list(&directory) {
            Ok(nodes) => nodes,
            Err(error) if error.is_cancelled() => return Err(error),
            Err(error) => {
                if errors.len() < 200 {
                    errors.push((
                        directory.clone(),
                        format!("{}: {}", error.code, error.message),
                    ));
                }
                continue;
            }
        };
        for node in nodes {
            if node.deleted || node.link_target.is_some() {
                continue;
            }
            let child = if directory.is_empty() {
                node.name.clone()
            } else {
                format!("{directory}/{}", node.name)
            };
            if node.is_dir() {
                if depth < MAX_WALK_DEPTH && !is_skipped_directory(&node.name) {
                    stack.push((child, depth + 1));
                }
                continue;
            }
            if !node.is_file() || node.size == 0 {
                continue;
            }
            if !(is_spreadsheet_name(&node.name) || is_zip_name(&node.name)) {
                continue;
            }
            if paths.len() >= MAX_INPUT_FILES {
                truncated = true;
                continue;
            }
            paths.push(child);
        }
    }
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_INPUT_FILES {
        paths.truncate(MAX_INPUT_FILES);
        truncated = true;
    }
    Ok(Collected {
        paths,
        errors,
        truncated,
    })
}

fn is_skipped_directory(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "windows" | "winnt" | "$recycle.bin" | "system volume information" | "proc" | "sys" | "dev"
    )
}

fn evidence_link(file: &FileRef, view_path: &str) -> Link {
    Link::Evidence {
        root: file.root().unwrap_or("view").to_owned(),
        path: file
            .root_path()
            .map(str::to_owned)
            .unwrap_or_else(|| view_path.to_owned()),
    }
}

fn emit_aggregation(
    run: &Run,
    analyzer: &str,
    aggregation: &Aggregation,
    context: &Context,
) -> Result<()> {
    let summary = SummaryRecord {
        analyzer: analyzer.to_owned(),
        total_rows: aggregation.total_rows as i64,
        valid_rows: aggregation.valid_rows as i64,
        unique_count: aggregation.unique_count as i64,
        duplicate_count: aggregation.duplicate_count as i64,
        incomplete_rows: aggregation.incomplete_rows as i64,
        files_parsed: aggregation.files_parsed.len() as i64,
        sheets_used: aggregation
            .sheets
            .iter()
            .filter(|sheet| sheet.header.is_some())
            .count() as i64,
        skipped_sheets: aggregation.skipped_sheets.len() as i64,
        duplicate_groups: aggregation.duplicate_groups.len() as i64,
        duplicate_inputs: aggregation.duplicate_inputs.len() as i64,
        header_source: aggregation.header_source.clone(),
        key_space_exhausted_at: aggregation.key_space_exhausted_at.map(|value| value as i64),
        files: aggregation.files_parsed.clone(),
        limitations: aggregation.limitations.clone(),
        row_limit_reached: aggregation.row_limit_reached.clone(),
    };
    run.record(&summary).emit()?;

    for report in &aggregation.per_file {
        emit_file(run, report, context)?;
    }
    for sheet in &aggregation.sheets {
        emit_sheet(run, sheet, context)?;
    }
    for group in &aggregation.duplicate_groups {
        emit_duplicate(run, group, context)?;
    }
    for row in &aggregation.incomplete_shown {
        emit_incomplete_row(run, row, context)?;
    }
    for rejected in &aggregation.rejected {
        emit_rejected(run, rejected, context)?;
    }

    if aggregation.rejected.len() > 3 {
        run.warn(
            "INPUTS_REJECTED",
            format!(
                "{} 个输入无法解析，详见 xlsx.dedup.rejected 记录",
                aggregation.rejected.len()
            ),
        )?;
    }
    if aggregation.total_rows == 0 && aggregation.rejected.is_empty() {
        run.warn(
            "NO_DATA_ROWS",
            "没有可统计的数据行（文件为空、表头未识别或全部跳过）",
        )?;
    }
    run.set_summary(format!(
        "总行 {}（有效 {}，缺项 {}，唯一 {}，重复 {}）；文件 {} 个，工作表 {} 张，重复组 {}",
        aggregation.total_rows,
        aggregation.valid_rows,
        aggregation.incomplete_rows,
        aggregation.unique_count,
        aggregation.duplicate_count,
        aggregation.files_parsed.len(),
        aggregation
            .sheets
            .iter()
            .filter(|sheet| sheet.header.is_some())
            .count(),
        aggregation.duplicate_groups.len()
    ));
    Ok(())
}

fn emit_file(run: &Run, report: &FileReport, context: &Context) -> Result<()> {
    let record = FileSummaryRecord {
        file: report.file.clone(),
        sheets: report.sheets as i64,
        sheets_used: report.sheets_used as i64,
        row_count: report.total_rows as i64,
        valid_rows: report.valid_rows as i64,
        incomplete_rows: report.incomplete_rows as i64,
        header_source: report.header_source.clone(),
        skipped_sheets: report.skipped_sheets.clone(),
    };
    let mut emit = run.record(&record);
    if let Some(link) = &report.link {
        if let Some(file) = context.source(link) {
            emit = emit.from(file);
        }
        emit = emit.note(link.describe());
    }
    emit.emit()
}

fn emit_sheet(run: &Run, sheet: &SheetReport, context: &Context) -> Result<()> {
    let header = sheet.header.as_ref();
    let record = SheetRecord {
        file: sheet.file.clone(),
        sheet: sheet.sheet.clone(),
        header_source: header
            .map(|header| header.source.as_str().to_owned())
            .unwrap_or_else(|| "skipped".to_owned()),
        header_row: header
            .map(|header| i64::from(header.header_row))
            .unwrap_or(0),
        name_column: header
            .and_then(|header| header.column(Field::Name))
            .map(|column| column as i64 + 1),
        phone_column: header
            .and_then(|header| header.column(Field::Phone))
            .map(|column| column as i64 + 1),
        address_column: header
            .and_then(|header| header.column(Field::Address))
            .map(|column| column as i64 + 1),
        row_count: sheet.total_rows as i64,
        valid_rows: sheet.valid_rows as i64,
        incomplete_rows: sheet.incomplete_rows as i64,
        skipped_reason: sheet.skipped_reason.clone(),
    };
    let note = match header {
        Some(header) => format!(
            "{}!{} 表头来源 {}，第 {} 行",
            sheet.file,
            sheet.sheet,
            header.source.as_str(),
            header.header_row
        ),
        None => format!(
            "{}!{} 跳过：{}",
            sheet.file,
            sheet.sheet,
            sheet.skipped_reason.as_deref().unwrap_or("未知原因")
        ),
    };
    let mut emit = run.record(&record);
    if let Some(link) = &sheet.link {
        if let Some(file) = context.source(link) {
            emit = emit.from(file);
        }
    }
    emit.note(note).emit()
}

fn emit_duplicate(run: &Run, group: &DuplicateGroup, context: &Context) -> Result<()> {
    let sources: Vec<String> = group
        .sources
        .iter()
        .map(|source| source.location())
        .collect();
    let record = DuplicateRecord {
        first_source: group.first.location(),
        name: group.key.masked_name(),
        phone: group.key.masked_phone(),
        address: group.key.masked_address(),
        occurrences: group.occurrences as i64,
        first_file: group.first.file.clone(),
        first_sheet: group.first.sheet.clone(),
        first_row: i64::from(group.first.row),
        sources,
        sources_truncated: group.truncated,
    };
    let mut emit = run.record(&record);
    if let Some(file) = context.source(&group.first.link) {
        emit = emit.from(file);
    }
    emit.note(format!(
        "首次 {}，共出现 {} 次",
        group.first.location(),
        group.occurrences
    ))
    .emit()
}

fn emit_incomplete_row(run: &Run, row: &TripleRow, context: &Context) -> Result<()> {
    let record = IncompleteRecord {
        file: row.link.describe(),
        sheet: row.sheet.clone(),
        row: i64::from(row.row),
        missing: row
            .missing
            .iter()
            .map(|field| field.label().to_owned())
            .collect(),
        name: crate::normalize::mask_name(&row.name),
        phone: crate::normalize::mask_phone(&row.phone),
        address: crate::normalize::mask_address(&row.address),
    };
    let mut emit = run.record(&record);
    if let Some(file) = context.source(&row.link) {
        emit = emit.from(file);
    }
    emit.note(format!("{}!{}!{}", row.link.describe(), row.sheet, row.row))
        .emit()
}

fn emit_rejected(run: &Run, rejected: &crate::dedup::Rejected, context: &Context) -> Result<()> {
    let record = RejectedRecord {
        file: rejected.display.clone(),
        code: rejected.code.to_owned(),
        message: rejected.message.clone(),
    };
    let mut emit = run.record(&record);
    if let Some(file) = context.source(&rejected.link) {
        emit = emit.from(file);
    }
    emit.note(rejected.link.describe()).emit()
}

fn display_name(file: &FileRef) -> String {
    let name = file.name().trim();
    if !name.is_empty() {
        return name.replace('\\', "/");
    }
    file.view_path()
        .or_else(|| file.root_path())
        .map(|path| path.replace('\\', "/"))
        .unwrap_or_else(|| file.id().to_owned())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.xlsx-dedup")
        .record::<SummaryRecord>()
        .record::<FileSummaryRecord>()
        .record::<SheetRecord>()
        .record::<DuplicateRecord>()
        .record::<IncompleteRecord>()
        .record::<RejectedRecord>()
        .analyzer(ANALYZER_FILES, dedup_files)
        .analyzer(ANALYZER_EVIDENCE, dedup_evidence)
}

export_plugin!(plugin);
