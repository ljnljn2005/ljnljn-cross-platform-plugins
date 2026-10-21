//! 纯函数：把 [`Aggregation`] 转换成 LPP v1 结果（summary / nodes / artifacts / findings）。
//!
//! 不依赖宿主，可在单元测试里直接断言字段与数值。
//! 每个 artifact 都带 `source.path`（证据卷内相对路径）与 `source.paths`；
//! zip 内条目另带 `source.archive` / `source.entry`，便于在结果面板回溯来源。

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, Finding, ResultColumn, ResultNode, Severity, Value,
};

use crate::dedup::{Aggregation, DuplicateGroup, FileReport, SheetReport, TripleRow};
use crate::header::Field;
use crate::parse::Link;

/// 结果树节点类型（命名空间 `sfxlsx.`）。
pub const NODE_DUPLICATE: &str = "sfxlsx.duplicate";
pub const NODE_INCOMPLETE: &str = "sfxlsx.incomplete";
pub const NODE_SHEET: &str = "sfxlsx.sheet";
pub const NODE_SOURCE_FILE: &str = "sfxlsx.sourcefile";
pub const NODE_SKIPPED: &str = "sfxlsx.skipped";

/// LPP 上限：最多 10000 条记录、64 个结果节点。
pub const MAX_RESULT_ITEMS: usize = 10_000;

/// 展示结果。
pub struct Presentation {
    pub result: AnalysisResult,
    pub aggregation_value: Value,
}

fn optional_text(value: Option<&str>) -> Value {
    value.map(Value::from).unwrap_or(Value::Nil)
}

fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().map(|item| Value::from(item.as_str())).collect())
}

/// 来源属性：`source.root` + `source.path` + `source.paths`。
fn source_attributes(link: &Link) -> Attributes {
    let mut attributes = Attributes::new();
    let (path, root) = match link {
        Link::File { file_id } => (format!("file:{file_id}"), String::from("file")),
        Link::Evidence { root, path } => (path.clone(), root.clone()),
    };
    attributes.insert("source.root", root);
    attributes.insert("source.path", path.clone());
    attributes.insert("source.paths", Value::Array(vec![Value::from(path)]));
    attributes
}

/// zip 内条目：文件显示名格式为 `归档::条目`。
fn split_display(display: &str) -> (&str, Option<&str>) {
    match display.split_once("::") {
        Some((archive, entry)) => (archive, Some(entry)),
        None => (display, None),
    }
}

fn archive_attributes(attributes: &mut Attributes, display: &str) {
    if let (archive, Some(entry)) = split_display(display) {
        attributes.insert("source.archive", archive.to_owned());
        attributes.insert("source.entry", entry.to_owned());
    }
}

/// `文件!工作表!行号`。
fn location_text(file: &str, sheet: &str, row: u32) -> String {
    format!("{file}!{sheet}!{row}")
}

fn duplicate_artifact(group: &DuplicateGroup) -> Artifact {
    let mut attributes = source_attributes(&group.first.link);
    archive_attributes(&mut attributes, &group.first.file);
    attributes.insert("sfxlsx.key.name", group.key.masked_name());
    attributes.insert("sfxlsx.key.phone", group.key.masked_phone());
    attributes.insert("sfxlsx.key.address", group.key.masked_address());
    attributes.insert("sfxlsx.occurrences", group.occurrences as u64);
    attributes.insert("sfxlsx.first_source", group.first.location());
    attributes.insert("sfxlsx.file", group.first.file.clone());
    attributes.insert("sfxlsx.sheet", group.first.sheet.clone());
    attributes.insert("sfxlsx.row", group.first.row as u64);
    attributes.insert(
        "sfxlsx.sources",
        Value::Array(
            group
                .sources
                .iter()
                .map(|source| Value::from(source.location()))
                .collect(),
        ),
    );
    attributes.insert("sfxlsx.sources.truncated", group.truncated);
    let sources_display: Vec<String> = group
        .sources
        .iter()
        .map(|source| source.location())
        .collect();
    Artifact {
        artifact_type: NODE_DUPLICATE.to_owned(),
        title: format!("{} × {}", group.key.masked_display(), group.occurrences),
        value: Some(Value::from(format!(
            "{} ｜ 出现 {} 次 ｜ 来源: {}",
            group.key.masked_display(),
            group.occurrences,
            sources_display.join(", ")
        ))),
        attributes,
    }
}

fn incomplete_artifact(row: &TripleRow) -> Artifact {
    let mut attributes = source_attributes(&row.link);
    attributes.insert("sfxlsx.sheet", row.sheet.clone());
    attributes.insert("sfxlsx.row", row.row as u64);
    attributes.insert(
        "sfxlsx.missing",
        strings(
            &row.missing
                .iter()
                .map(|field| field.label().to_string())
                .collect::<Vec<_>>(),
        ),
    );
    attributes.insert("sfxlsx.name", row.name.clone());
    attributes.insert(
        "sfxlsx.phone",
        crate::normalize::mask_phone(&row.phone),
    );
    attributes.insert("sfxlsx.address", row.address.clone());
    let missing: Vec<&str> = row.missing.iter().map(|field| field.label()).collect();
    Artifact {
        artifact_type: NODE_INCOMPLETE.to_owned(),
        title: format!("{}!{} 缺 {}", row.sheet, row.row, missing.join("、")),
        value: Some(Value::from(location_text(
            row.link.describe().as_str(),
            &row.sheet,
            row.row,
        ))),
        attributes,
    }
}

fn sheet_artifact(sheet: &SheetReport) -> Artifact {
    let archive = split_display(&sheet.file);
    let link = sheet.link.clone().unwrap_or(Link::Evidence {
        root: String::from("evidence"),
        path: archive.0.to_owned(),
    });
    let mut attributes = source_attributes(&link);
    archive_attributes(&mut attributes, &sheet.file);
    let header = sheet.header.as_ref();
    attributes.insert("sfxlsx.file", sheet.file.clone());
    attributes.insert("sfxlsx.sheet", sheet.sheet.clone());
    attributes.insert("sfxlsx.row_count", sheet.total_rows as u64);
    attributes.insert("sfxlsx.valid_rows", sheet.valid_rows as u64);
    attributes.insert("sfxlsx.incomplete_rows", sheet.incomplete_rows as u64);
    attributes.insert(
        "sfxlsx.header_source",
        header
            .map(|h| h.source.as_str().to_owned())
            .unwrap_or_else(|| "skipped".to_owned()),
    );
    attributes.insert(
        "sfxlsx.header_row",
        header.map(|h| h.header_row as u64).unwrap_or(0),
    );
    let columns: Vec<String> = Field::ALL
        .iter()
        .map(|field| match header.and_then(|h| h.column(*field)) {
            Some(column) => format!("{}={}", field.key(), column + 1),
            None => format!("{}=缺", field.key()),
        })
        .collect();
    attributes.insert("sfxlsx.columns", strings(&columns));
    if let Some(reason) = sheet.skipped_reason.as_deref() {
        attributes.insert("sfxlsx.skipped_reason", reason.to_owned());
    }
    Artifact {
        artifact_type: NODE_SHEET.to_owned(),
        title: format!("{} · {}", sheet.file, sheet.sheet),
        value: Some(Value::from(format!(
            "表头来源 {} · 行 {} · 有效 {} · 缺项 {}",
            header.map(|h| h.source.as_str()).unwrap_or("skipped"),
            sheet.total_rows,
            sheet.valid_rows,
            sheet.incomplete_rows
        ))),
        attributes,
    }
}

fn file_artifact(file: &FileReport) -> Artifact {
    let archive = split_display(&file.file);
    let link = file.link.clone().unwrap_or(Link::Evidence {
        root: String::from("evidence"),
        path: archive.0.to_owned(),
    });
    let mut attributes = source_attributes(&link);
    archive_attributes(&mut attributes, &file.file);
    attributes.insert("sfxlsx.file", file.file.clone());
    attributes.insert("sfxlsx.sheets", file.sheets as u64);
    attributes.insert("sfxlsx.sheets_used", file.sheets_used as u64);
    attributes.insert("sfxlsx.row_count", file.total_rows as u64);
    attributes.insert("sfxlsx.valid_rows", file.valid_rows as u64);
    attributes.insert("sfxlsx.incomplete_rows", file.incomplete_rows as u64);
    attributes.insert(
        "sfxlsx.header_source",
        file.header_source
            .clone()
            .unwrap_or_else(|| "none".to_owned()),
    );
    attributes.insert("sfxlsx.skipped_sheets", strings(&file.skipped_sheets));
    Artifact {
        artifact_type: NODE_SOURCE_FILE.to_owned(),
        title: file.file.clone(),
        value: Some(Value::from(format!(
            "工作表 {}/{} 参与 · 行 {} · 有效 {} · 缺项 {}",
            file.sheets_used, file.sheets, file.total_rows, file.valid_rows, file.incomplete_rows
        ))),
        attributes,
    }
}

fn skipped_artifact(label: &str) -> Artifact {
    let mut attributes = Attributes::new();
    attributes.insert("sfxlsx.skipped", label.to_owned());
    Artifact {
        artifact_type: NODE_SKIPPED.to_owned(),
        title: label.to_owned(),
        value: Some(Value::from(label.to_owned())),
        attributes,
    }
}

fn column(key: &str, label: &str) -> ResultColumn {
    ResultColumn {
        key: key.to_owned(),
        label: label.to_owned(),
    }
}

fn nodes(truncated_sources: bool) -> Vec<ResultNode> {
    let mut duplicate_columns = vec![
        column("sfxlsx.key.name", "姓名(脱敏)"),
        column("sfxlsx.key.phone", "电话(前3后4)"),
        column("sfxlsx.key.address", "地址(脱敏)"),
        column("sfxlsx.occurrences", "出现次数"),
        column("sfxlsx.first_source", "首次出现"),
        column("sfxlsx.sources", "全部来源行"),
        column("source.path", "来源文件"),
    ];
    if truncated_sources {
        duplicate_columns.push(column("sfxlsx.sources.truncated", "来源行被截断"));
    }
    vec![
        ResultNode {
            node_type: NODE_DUPLICATE.to_owned(),
            name: "重复三元组".to_owned(),
            columns: duplicate_columns,
        },
        ResultNode {
            node_type: NODE_INCOMPLETE.to_owned(),
            name: "缺项行".to_owned(),
            columns: vec![
                column("sfxlsx.sheet", "工作表"),
                column("sfxlsx.row", "行号"),
                column("sfxlsx.missing", "缺失字段"),
                column("sfxlsx.name", "姓名"),
                column("sfxlsx.phone", "电话(脱敏)"),
                column("sfxlsx.address", "地址"),
                column("source.path", "来源文件"),
            ],
        },
        ResultNode {
            node_type: NODE_SHEET.to_owned(),
            name: "工作表统计".to_owned(),
            columns: vec![
                column("sfxlsx.file", "文件"),
                column("sfxlsx.sheet", "工作表"),
                column("sfxlsx.header_source", "表头来源"),
                column("sfxlsx.header_row", "表头行"),
                column("sfxlsx.columns", "列映射(1 基)"),
                column("sfxlsx.row_count", "行数"),
                column("sfxlsx.valid_rows", "有效行"),
                column("sfxlsx.incomplete_rows", "缺项行"),
                column("source.path", "来源"),
            ],
        },
        ResultNode {
            node_type: NODE_SOURCE_FILE.to_owned(),
            name: "源文件".to_owned(),
            columns: vec![
                column("sfxlsx.file", "文件"),
                column("sfxlsx.sheets", "工作表数"),
                column("sfxlsx.sheets_used", "参与表数"),
                column("sfxlsx.header_source", "表头来源"),
                column("sfxlsx.row_count", "行数"),
                column("sfxlsx.valid_rows", "有效行"),
                column("sfxlsx.incomplete_rows", "缺项行"),
                column("sfxlsx.skipped_sheets", "跳过的工作表"),
                column("source.path", "来源"),
            ],
        },
        ResultNode {
            node_type: NODE_SKIPPED.to_owned(),
            name: "跳过/无法解析".to_owned(),
            columns: vec![column("sfxlsx.skipped", "说明")],
        },
    ]
}

fn field_map(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

/// 汇总字段的 `Value`（字段名与需求 ④ 一致，数值全部来自实际解析）。
pub fn aggregation_value(aggregation: &Aggregation) -> Value {
    let duplicate_groups = Value::Array(
        aggregation
            .duplicate_groups
            .iter()
            .map(|group| {
                let sources = group
                    .sources
                    .iter()
                    .map(|source| Value::from(source.location()))
                    .collect();
                field_map(vec![
                    ("key.name", Value::from(group.key.masked_name())),
                    ("key.phone", Value::from(group.key.masked_phone())),
                    ("key.address", Value::from(group.key.masked_address())),
                    ("maskedKey", Value::from(group.key.masked_display())),
                    ("occurrences", Value::from(group.occurrences as u64)),
                    (
                        "first",
                        field_map(vec![
                            ("file", Value::from(group.first.file.as_str())),
                            ("sheet", Value::from(group.first.sheet.as_str())),
                            ("row", Value::from(group.first.row as u64)),
                        ]),
                    ),
                    ("sources", Value::Array(sources)),
                    ("truncated", Value::from(group.truncated)),
                    ("source", Value::from(group.first.link.describe())),
                ])
            })
            .collect(),
    );
    let per_file = Value::Array(
        aggregation
            .per_file
            .iter()
            .map(|file| {
                field_map(vec![
                    ("file", Value::from(file.file.as_str())),
                    ("sheets", Value::from(file.sheets as u64)),
                    ("sheetsUsed", Value::from(file.sheets_used as u64)),
                    ("rows", Value::from(file.total_rows as u64)),
                    ("validRows", Value::from(file.valid_rows as u64)),
                    ("incompleteRows", Value::from(file.incomplete_rows as u64)),
                    ("headerSource", optional_text(file.header_source.as_deref())),
                    ("skippedSheets", strings(&file.skipped_sheets)),
                ])
            })
            .collect(),
    );
    let sheets = Value::Array(
        aggregation
            .sheets
            .iter()
            .map(|sheet| {
                let header = sheet.header.as_ref();
                let columns = Value::Map(
                    Field::ALL
                        .iter()
                        .map(|field| {
                            (
                                Value::from(field.key()),
                                header
                                    .and_then(|h| h.column(*field))
                                    .map(|column| Value::from(column as u64 + 1))
                                    .unwrap_or(Value::Nil),
                            )
                        })
                        .collect(),
                );
                field_map(vec![
                    ("file", Value::from(sheet.file.as_str())),
                    ("sheet", Value::from(sheet.sheet.as_str())),
                    (
                        "headerSource",
                        header
                            .map(|h| Value::from(h.source.as_str()))
                            .unwrap_or(Value::Nil),
                    ),
                    (
                        "headerRow",
                        header
                            .map(|h| Value::from(h.header_row as u64))
                            .unwrap_or(Value::Nil),
                    ),
                    ("columns", columns),
                    ("rows", Value::from(sheet.total_rows as u64)),
                    ("validRows", Value::from(sheet.valid_rows as u64)),
                    ("incompleteRows", Value::from(sheet.incomplete_rows as u64)),
                    ("skippedReason", optional_text(sheet.skipped_reason.as_deref())),
                ])
            })
            .collect(),
    );
    let rejected = Value::Array(
        aggregation
            .rejected
            .iter()
            .map(|item| {
                field_map(vec![
                    ("source", Value::from(item.link.describe())),
                    ("display", Value::from(item.display.as_str())),
                    ("code", Value::from(item.code)),
                    ("message", Value::from(item.message.as_str())),
                ])
            })
            .collect(),
    );
    let incomplete = Value::Array(
        aggregation
            .incomplete_shown
            .iter()
            .map(|row| {
                field_map(vec![
                    (
                        "source",
                        Value::from(location_text(row.link.describe().as_str(), &row.sheet, row.row)),
                    ),
                    (
                        "missing",
                        strings(
                            &row.missing
                                .iter()
                                .map(|field| field.label().to_string())
                                .collect::<Vec<_>>(),
                        ),
                    ),
                    ("name", Value::from(row.name.as_str())),
                    ("phone", Value::from(crate::normalize::mask_phone(&row.phone))),
                    ("address", Value::from(row.address.as_str())),
                ])
            })
            .collect(),
    );
    field_map(vec![
        ("totalRows", Value::from(aggregation.total_rows as u64)),
        ("validRows", Value::from(aggregation.valid_rows as u64)),
        ("uniqueCount", Value::from(aggregation.unique_count as u64)),
        (
            "duplicateCount",
            Value::from(aggregation.duplicate_count as u64),
        ),
        (
            "incompleteRows",
            Value::from(aggregation.incomplete_rows as u64),
        ),
        ("duplicateGroups", duplicate_groups),
        ("perFileRows", per_file),
        ("sheets", sheets),
        (
            "headerSource",
            optional_text(aggregation.header_source.as_deref()),
        ),
        ("skippedSheets", strings(&aggregation.skipped_sheets)),
        ("filesParsed", strings(&aggregation.files_parsed)),
        ("duplicateInputs", strings(&aggregation.duplicate_inputs)),
        ("rejected", rejected),
        ("incompleteRowsSample", incomplete),
        (
            "keySpaceExhaustedAt",
            aggregation
                .key_space_exhausted_at
                .map(|at| Value::from(at as u64))
                .unwrap_or(Value::Boolean(false)),
        ),
        ("limitations", strings(&aggregation.limitations)),
    ])
}

fn summary_text(aggregation: &Aggregation, shown_groups: usize) -> String {
    let mut parts = vec![format!(
        "收件人表去重：totalRows={} validRows={} uniqueCount={} duplicateCount={} incompleteRows={}",
        aggregation.total_rows,
        aggregation.valid_rows,
        aggregation.unique_count,
        aggregation.duplicate_count,
        aggregation.incomplete_rows
    )];
    parts.push(format!(
        "参与文件 {} 个，重复组 {} 组（结果内展示 {} 组）",
        aggregation.per_file.len(),
        aggregation.duplicate_groups.len(),
        shown_groups
    ));
    parts.push(format!(
        "headerSource={}",
        aggregation.header_source.as_deref().unwrap_or("none")
    ));
    if !aggregation.skipped_sheets.is_empty() {
        parts.push(format!(
            "跳过工作表 {} 个",
            aggregation.skipped_sheets.len()
        ));
    }
    if !aggregation.rejected.is_empty() {
        parts.push(format!(
            "无法解析输入 {} 个（见 rejected）",
            aggregation.rejected.len()
        ));
    }
    if !aggregation.duplicate_inputs.is_empty() {
        parts.push(format!(
            "重复传入 {} 次（只计一次）",
            aggregation.duplicate_inputs.len()
        ));
    }
    if aggregation.is_empty() {
        parts.push("没有任何有效/缺项行（空文件或无数据行，计数均为 0）".to_owned());
    }
    parts.join("；")
}

/// 组装 `AnalysisResult`。
pub fn present(aggregation: &Aggregation) -> Presentation {
    let mut artifacts = Vec::new();
    let budget = MAX_RESULT_ITEMS;
    let mut duplicates_included = 0usize;
    for group in &aggregation.duplicate_groups {
        if artifacts.len() >= budget {
            break;
        }
        artifacts.push(duplicate_artifact(group));
        duplicates_included += 1;
    }
    for row in &aggregation.incomplete_shown {
        if artifacts.len() >= budget {
            break;
        }
        artifacts.push(incomplete_artifact(row));
    }
    for sheet in &aggregation.sheets {
        if artifacts.len() >= budget {
            break;
        }
        artifacts.push(sheet_artifact(sheet));
    }
    for file in &aggregation.per_file {
        if artifacts.len() >= budget {
            break;
        }
        artifacts.push(file_artifact(file));
    }
    for label in &aggregation.skipped_sheets {
        if artifacts.len() >= budget {
            break;
        }
        artifacts.push(skipped_artifact(label));
    }
    for item in &aggregation.rejected {
        if artifacts.len() >= budget {
            break;
        }
        artifacts.push(skipped_artifact(&format!(
            "{}（{}：{}）",
            item.display, item.code, item.message
        )));
    }

    let findings = if aggregation.unique_count > 0 {
        vec![Finding {
            severity: Severity::Info,
            title: format!(
                "三元组去重结果：唯一 {} / 有效 {} 行",
                aggregation.unique_count, aggregation.valid_rows
            ),
            description: summary_text(aggregation, duplicates_included),
            attributes: Attributes::new(),
        }]
    } else {
        Vec::new()
    };

    Presentation {
        result: AnalysisResult {
            summary: Some(summary_text(aggregation, duplicates_included)),
            nodes: nodes(aggregation.duplicate_groups.iter().any(|group| group.truncated)),
            artifacts,
            timeline: Vec::new(),
            findings,
        },
        aggregation_value: aggregation_value(aggregation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dedup::{DuplicateGroup, Key, SourceRow};

    fn aggregation_with_one_group() -> Aggregation {
        let link = Link::Evidence {
            root: "part:0".to_owned(),
            path: "Users/a/顺丰1k.zip".to_owned(),
        };
        let first = SourceRow {
            link: link.clone(),
            file: "Users/a/顺丰1k.zip::顺丰1k.xlsx".to_owned(),
            sheet: "Sheet1".to_owned(),
            row: 2,
        };
        let second = SourceRow {
            link,
            file: "Users/a/顺丰1k.zip::顺丰1k.xlsx".to_owned(),
            sheet: "Sheet1".to_owned(),
            row: 4,
        };
        Aggregation {
            total_rows: 5,
            valid_rows: 4,
            unique_count: 3,
            duplicate_count: 1,
            incomplete_rows: 1,
            duplicate_groups: vec![DuplicateGroup {
                key: Key {
                    name: "张三".to_owned(),
                    phone: "13800138000".to_owned(),
                    address: "北京市海淀区中关村大街1号".to_owned(),
                },
                occurrences: 2,
                first: first.clone(),
                sources: vec![first, second],
                truncated: false,
            }],
            header_source: Some("header".to_owned()),
            limitations: vec!["同名不同电话按不同人处理".to_owned()],
            ..Aggregation::default()
        }
    }

    #[test]
    fn duplicate_artifact_keeps_masked_key_and_source_rows() {
        let aggregation = aggregation_with_one_group();
        let presentation = present(&aggregation);
        let duplicate = presentation
            .result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == NODE_DUPLICATE)
            .expect("duplicate artifact");
        assert!(duplicate.title.contains("138****8000"));
        assert!(!duplicate.title.contains("13800138000"));
        assert_eq!(
            duplicate
                .attributes
                .get("sfxlsx.occurrences")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            duplicate.attributes.get("sfxlsx.sources"),
            Some(&Value::Array(vec![
                Value::from("Users/a/顺丰1k.zip::顺丰1k.xlsx!Sheet1!2"),
                Value::from("Users/a/顺丰1k.zip::顺丰1k.xlsx!Sheet1!4"),
            ]))
        );
        assert_eq!(
            duplicate.attributes.get("source.path"),
            Some(&Value::from("Users/a/顺丰1k.zip"))
        );
        assert_eq!(
            duplicate.attributes.get("source.root"),
            Some(&Value::from("part:0"))
        );
        assert_eq!(
            duplicate.attributes.get("source.entry"),
            Some(&Value::from("顺丰1k.xlsx"))
        );
    }

    #[test]
    fn summary_and_aggregation_value_expose_required_fields() {
        let aggregation = aggregation_with_one_group();
        let presentation = present(&aggregation);
        let summary = presentation.result.summary.clone().unwrap_or_default();
        assert!(summary.contains("uniqueCount=3"));
        assert!(summary.contains("duplicateCount=1"));
        assert!(summary.contains("incompleteRows=1"));
        for key in [
            "totalRows",
            "validRows",
            "uniqueCount",
            "duplicateCount",
            "incompleteRows",
            "duplicateGroups",
            "perFileRows",
            "headerSource",
            "skippedSheets",
            "limitations",
        ] {
            assert!(
                crate::value::get(&presentation.aggregation_value, key).is_some(),
                "missing field {key}"
            );
        }
        assert_eq!(
            crate::value::get_u64(&presentation.aggregation_value, "uniqueCount"),
            Some(3)
        );
    }

    #[test]
    fn artifact_types_are_namespaced_lowercase() {
        let aggregation = aggregation_with_one_group();
        let presentation = present(&aggregation);
        for node in &presentation.result.nodes {
            assert!(node.node_type.starts_with("sfxlsx."));
        }
        for artifact in &presentation.result.artifacts {
            assert!(artifact
                .artifact_type
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch == '.' || ch.is_ascii_digit()));
            for (key, _) in artifact.attributes.iter() {
                assert!(key
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '.' || ch == '_' || ch.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn empty_aggregation_says_so_and_has_no_findings() {
        let aggregation = Aggregation {
            limitations: vec!["x".to_owned()],
            ..Aggregation::default()
        };
        let presentation = present(&aggregation);
        let summary = presentation.result.summary.clone().unwrap_or_default();
        assert!(summary.contains("uniqueCount=0"));
        assert!(summary.contains("计数均为 0"));
        assert!(presentation.result.findings.is_empty());
    }
}
