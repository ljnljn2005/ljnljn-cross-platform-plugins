//! Import iLEAPP / ALEAPP TSV exports into LovelyCarve records.
//!
//! iLEAPP and ALEAPP are external Python tools. Their process isolation and
//! full-extraction input path do not fit the LPP v2 plugin process model, so
//! this plugin imports their `_TSV Exports/*.tsv` reports instead of trying to
//! execute the tools inside the plugin host. Run the parser externally, then
//! point this analyzer at the report folder or a selected TSV file.

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, Json, Plugin, Record, Result, Run, Value};

const TEXT_CAP: u64 = 128 * 1024 * 1024;
const MAX_ROWS: usize = 100_000;

#[derive(Record)]
#[record(
    id = "mobile.report.file",
    label = "移动终端报告文件",
    title = "{tool} / {module}"
)]
struct ReportFile {
    #[field(label = "路径", key)]
    path: String,
    #[field(label = "工具")]
    tool: String,
    #[field(label = "模块")]
    module: String,
    #[field(label = "大小", kind = "size")]
    size: u64,
    #[field(label = "数据行数")]
    row_count: u64,
    #[field(label = "列数")]
    column_count: u64,
    #[field(label = "状态")]
    status: String,
}

#[derive(Record)]
#[record(
    id = "mobile.report.row",
    label = "移动终端报告行",
    title = "{module} #{row_index}"
)]
struct ReportRow {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    row_index: i64,
    #[field(label = "工具")]
    tool: String,
    #[field(label = "模块")]
    module: String,
    #[field(label = "列名")]
    columns: Vec<String>,
    #[field(label = "值")]
    values: Json,
}

fn report_files(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut rows = 0usize;
    for file in run.inputs() {
        run.check_cancelled()?;
        let (r, _) = analyze_file(run, file)?;
        rows += r;
        files += 1;
    }
    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未选择 iLEAPP/ALEAPP TSV 报告")?;
    }
    run.set_summary(format!(
        "iLEAPP/ALEAPP 报告：{files} 个文件，{rows} 行记录"
    ));
    Ok(())
}

fn report_system(run: &Run) -> Result<()> {
    analyze_view(run, "系统")
}

fn report_evidence(run: &Run) -> Result<()> {
    analyze_view(run, "检材")
}

fn analyze_view(run: &Run, label: &str) -> Result<()> {
    let view = run.require_view()?;
    let mut patterns = Vec::new();
    for mount in view.mounts() {
        let prefix = mount.path.trim_matches('/');
        for pattern in ["**/_TSV Exports/*.tsv", "_TSV Exports/*.tsv"] {
            patterns.push(if prefix.is_empty() {
                pattern.to_owned()
            } else {
                format!("{prefix}/{pattern}")
            });
        }
    }
    patterns.sort();
    patterns.dedup();
    let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let paths = match view.find(&refs) {
        Ok(paths) => paths,
        Err(error) => {
            run.warn(&error.code, error.message.clone())?;
            return Ok(());
        }
    };
    let mut files = 0usize;
    let mut rows = 0usize;
    for path in paths {
        run.check_cancelled()?;
        let Some(file) = view.open(&path)? else {
            continue;
        };
        let (r, _) = analyze_file(run, &file)?;
        rows += r;
        files += 1;
    }
    if files == 0 {
        run.warn(
            "REPORT_NOT_FOUND",
            format!("未找到 {label} 中的 _TSV Exports/*.tsv"),
        )?;
    }
    run.set_summary(format!(
        "iLEAPP/ALEAPP 报告（{label}）：{files} 个文件，{rows} 行记录"
    ));
    Ok(())
}

fn analyze_file(run: &Run, file: &lovelycarve_plugin::FileRef) -> Result<(usize, usize)> {
    let source = source_path(file);
    let text = match file.read_text(TEXT_CAP) {
        Ok(text) => text,
        Err(error) => {
            run.warn_file(file, &error.code, error.message.clone())?;
            return Ok((0, 0));
        }
    };
    let (columns, rows, status) = parse_tsv(&text);
    let module = module_name(&source);
    let tool = tool_from_path(&source);
    let mut emitted = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let values: Vec<Value> = row.iter().map(|value| Value::from(value.as_str())).collect();
        run.record(&ReportRow {
            source: source.clone(),
            row_index: index as i64 + 2,
            tool: tool.clone(),
            module: module.clone(),
            columns: columns.clone(),
            values: Json(Value::Array(values)),
        })
        .from(file)
        .note(format!("数据行 {}", index + 1))
        .emit()?;
        emitted += 1;
    }
    run.record(&ReportFile {
        path: source.clone(),
        tool,
        module,
        size: file.size(),
        row_count: emitted as u64,
        column_count: columns.len() as u64,
        status: status.to_owned(),
    })
    .from(file)
    .emit()?;
    if status != "ok" && status != "empty" {
        run.warn_file(file, "REPORT_STATUS", format!("{source}: {status}"))?;
    }
    Ok((emitted, columns.len()))
}

/// Parses the TSV emitted by iLEAPP/ALEAPP (`csv.writer` with tab delimiter).
///
/// Python's csv module quotes a field when it contains a tab, quote or line
/// break, so this is a real TSV reader rather than a line split: quoted line
/// breaks stay inside the field. A BOM and CRLF are accepted.
fn parse_tsv(text: &str) -> (Vec<String>, Vec<Vec<String>>, &'static str) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            '\t' if !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted && chars.peek() == Some(&'\n') => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                // CSV 空行（只有一个空字段）不算记录。
                if !(row.len() == 1 && row[0].is_empty()) {
                    records.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
                // 表头 + MAX_ROWS 数据行是允许的；再多读一行只为判定截断。
                if records.len() > MAX_ROWS + 1 {
                    break;
                }
            }
            _ => field.push(character),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        if !(row.len() == 1 && row[0].is_empty()) {
            records.push(row);
        }
    }
    let mut records = records.into_iter();
    let Some(columns) = records.next() else {
        return (Vec::new(), Vec::new(), "empty");
    };
    if columns.is_empty() {
        return (Vec::new(), Vec::new(), "no_header");
    }
    let mut rows: Vec<Vec<String>> = records.by_ref().take(MAX_ROWS).collect();
    let truncated = records.next().is_some();
    if rows.is_empty() {
        return (columns, rows, "empty");
    }
    // 数据行补齐/截断到表头宽度，保证每行与列名一一对应。
    for row in &mut rows {
        row.resize(columns.len(), String::new());
    }
    let status = if truncated { "truncated" } else { "ok" };
    (columns, rows, status)
}

fn source_path(file: &lovelycarve_plugin::FileRef) -> String {
    file.view_path().unwrap_or_else(|| file.name()).to_owned()
}

fn module_name(path: &str) -> String {
    path.rsplit('/')
        .next()
        .unwrap_or(path)
        .strip_suffix(".tsv")
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path))
        .to_owned()
}

fn tool_from_path(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.contains("ileapp") {
        "ileapp".to_owned()
    } else if lower.contains("aleapp") {
        "aleapp".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.ileapp-aleapp-report")
        .record::<ReportFile>()
        .record::<ReportRow>()
        .analyzer("report_files", report_files)
        .analyzer("report_system", report_system)
        .analyzer("report_evidence", report_evidence)
}

export_plugin!(plugin);
