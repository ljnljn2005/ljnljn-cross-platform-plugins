//! Synthetic xlsx/zip tests. Fixtures are generated in memory by
//! `crate::fixtures`; no real workbook or case data is read.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRecord, TestRun};

use crate::fixtures::{xlsx_bytes, zip_bytes, Cell, RowSpec, SheetSpec, WorkbookSpec, ZipOptions};

struct TempDir {
    root: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "ljnljn-xlsx-v2-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn file(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
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
            // Same person: phone separators and full-width digits normalize.
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

fn workbook_bytes() -> Vec<u8> {
    let spec = WorkbookSpec::new(vec![sample_sheet()], Vec::new());
    xlsx_bytes(&spec, ZipOptions::default())
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_files(paths: &[&Path]) -> TestRun {
    harness()
        .run_with(
            "dedup_files",
            Fixture::files(paths),
            Default::default(),
            Default::default(),
        )
        .expect("run")
}

fn run_evidence(root: &Path) -> TestRun {
    harness()
        .run_with(
            "dedup_evidence",
            Fixture::evidence(&[("part:0", root)]),
            Default::default(),
            Default::default(),
        )
        .expect("run")
}

fn only<'a>(run: &'a TestRun, record_type: &str) -> &'a TestRecord {
    let records = run.of_type(record_type);
    assert_eq!(records.len(), 1, "{record_type} count");
    records[0]
}

fn list(record: &TestRecord, field: &str) -> Vec<String> {
    record
        .get(field)
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn file_analyzer_reports_counts_header_duplicates_and_sources() {
    let fixture = TempDir::new("files");
    let path = fixture.file("收件人.xlsx", &workbook_bytes());
    let run = run_files(&[&path]);

    let summary = only(&run, "xlsx.dedup.summary");
    assert_eq!(summary.text("analyzer"), Some("dedup_files"));
    assert_eq!(summary.int("total_rows"), Some(5), "header + 4 data rows");
    assert_eq!(summary.int("valid_rows"), Some(4));
    assert_eq!(summary.int("unique_count"), Some(3));
    assert_eq!(summary.int("duplicate_count"), Some(1));
    assert_eq!(summary.int("incomplete_rows"), Some(0));
    assert_eq!(summary.int("files_parsed"), Some(1));
    assert_eq!(summary.int("sheets_used"), Some(1));
    assert_eq!(summary.text("header_source"), Some("header"));

    let file = only(&run, "xlsx.dedup.file");
    assert_eq!(file.text("file"), Some("收件人.xlsx"));
    assert_eq!(file.int("sheets"), Some(1));
    assert_eq!(file.int("sheets_used"), Some(1));
    assert_eq!(file.int("row_count"), Some(5));
    assert_eq!(file.text("header_source"), Some("header"));
    assert_eq!(file.sources[0].root.as_deref(), Some("files"));

    let sheet = only(&run, "xlsx.dedup.sheet");
    assert_eq!(sheet.text("sheet"), Some("Sheet1"));
    assert_eq!(sheet.text("header_source"), Some("header"));
    assert_eq!(sheet.int("header_row"), Some(1));
    assert_eq!(sheet.int("name_column"), Some(2));
    assert_eq!(sheet.int("phone_column"), Some(3));
    assert_eq!(sheet.int("address_column"), Some(4));
    assert_eq!(sheet.int("row_count"), Some(5));
    assert_eq!(sheet.int("valid_rows"), Some(4));

    let duplicate = only(&run, "xlsx.dedup.duplicate");
    assert_eq!(duplicate.int("occurrences"), Some(2));
    assert_eq!(duplicate.int("first_row"), Some(2));
    assert_eq!(duplicate.text("first_sheet"), Some("Sheet1"));
    assert!(duplicate
        .text("phone")
        .unwrap_or("")
        .contains("138****8000"));
    assert!(duplicate.text("name").unwrap_or("").contains('张'));
    assert_eq!(list(duplicate, "sources").len(), 2);
    assert_eq!(duplicate.sources[0].root.as_deref(), Some("files"));
    assert!(duplicate.sources[0]
        .note
        .as_deref()
        .unwrap_or("")
        .contains("Sheet1!2"));

    assert!(run.summary.as_deref().unwrap_or("").contains("重复 1"));
}

#[test]
fn evidence_analyzer_walks_volumes_and_deduplicates_across_files() {
    let fixture = TempDir::new("evidence");
    let spec = WorkbookSpec::new(vec![sample_sheet()], Vec::new());
    let inner = xlsx_bytes(&spec, ZipOptions::default());
    fixture.file("Users/a/顺丰1k.xlsx", &inner);
    let archive = zip_bytes(
        &[("导出/顺丰2k.xlsx".to_owned(), inner.clone())],
        ZipOptions::default(),
    );
    fixture.file("Users/a/顺丰4k.zip", &archive);
    fixture.file("Users/a/说明.txt", b"ignored");

    let run = run_evidence(&fixture.root);

    let summary = only(&run, "xlsx.dedup.summary");
    assert_eq!(summary.text("analyzer"), Some("dedup_evidence"));
    assert_eq!(summary.int("files_parsed"), Some(2));
    assert_eq!(summary.int("total_rows"), Some(10));
    assert_eq!(summary.int("valid_rows"), Some(8));
    assert_eq!(summary.int("unique_count"), Some(3));
    assert_eq!(summary.int("duplicate_count"), Some(5));
    let files = list(summary, "files");
    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|file| file.ends_with("顺丰1k.xlsx")));
    assert!(files
        .iter()
        .any(|file| file.contains("顺丰4k.zip::导出/顺丰2k.xlsx")));

    assert_eq!(run.count("xlsx.dedup.file"), 2);
    assert_eq!(run.count("xlsx.dedup.sheet"), 2);
    // Each of the three distinct people occurs once per file, so every group
    // has two source rows spread over the two inputs.
    assert_eq!(run.count("xlsx.dedup.duplicate"), 3);
    let duplicate = run
        .of_type("xlsx.dedup.duplicate")
        .into_iter()
        .find(|record| record.text("name") == Some("张*"))
        .expect("masked Zhang group");
    // Zhang appears twice per workbook, four times across the two inputs.
    assert_eq!(duplicate.int("occurrences"), Some(4));
    assert_eq!(duplicate.sources[0].root.as_deref(), Some("part:0"));
    assert_eq!(list(duplicate, "sources").len(), 4);
    assert!(run.summary.as_deref().unwrap_or("").contains("文件 2 个"));
}

#[test]
fn headerless_sheet_uses_positional_fallback() {
    let fixture = TempDir::new("positional");
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
                    ],
                ),
                RowSpec::new(
                    2,
                    vec![
                        (0, inline("2")),
                        (1, inline("李四")),
                        (2, inline("13900139000")),
                        (3, inline("上海市浦东新区世纪大道100号")),
                    ],
                ),
            ],
        )],
        Vec::new(),
    );
    let path = fixture.file("无表头.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));
    let run = run_files(&[&path]);

    let summary = only(&run, "xlsx.dedup.summary");
    assert_eq!(summary.int("valid_rows"), Some(2));
    assert_eq!(summary.text("header_source"), Some("positional"));
    let sheet = only(&run, "xlsx.dedup.sheet");
    assert_eq!(sheet.text("header_source"), Some("positional"));
    assert_eq!(sheet.int("name_column"), Some(2));
    assert_eq!(sheet.int("phone_column"), Some(3));
    assert_eq!(sheet.int("address_column"), Some(4));
}

#[test]
fn missing_address_column_produces_incomplete_rows() {
    let fixture = TempDir::new("incomplete");
    let spec = WorkbookSpec::new(
        vec![SheetSpec::new(
            "缺地址列",
            vec![
                RowSpec::new(1, vec![(0, inline("姓名")), (1, inline("电话"))]),
                RowSpec::new(2, vec![(0, inline("张三")), (1, inline("13800138000"))]),
                RowSpec::new(3, vec![(0, inline("李四")), (1, inline("13900139000"))]),
            ],
        )],
        Vec::new(),
    );
    let path = fixture.file("缺地址.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));
    let run = run_files(&[&path]);

    let summary = only(&run, "xlsx.dedup.summary");
    assert_eq!(summary.int("total_rows"), Some(3));
    assert_eq!(summary.int("valid_rows"), Some(0));
    assert_eq!(summary.int("incomplete_rows"), Some(2));
    assert_eq!(run.count("xlsx.dedup.incomplete"), 2);
    assert_eq!(
        list(run.of_type("xlsx.dedup.incomplete")[0], "missing"),
        vec!["地址"]
    );
    let sheet = only(&run, "xlsx.dedup.sheet");
    assert_eq!(
        sheet.get("address_column").and_then(|value| value.as_i64()),
        None
    );
}

#[test]
fn non_zip_input_is_rejected_with_its_code() {
    let fixture = TempDir::new("rejected");
    let path = fixture.file("联系人.csv", b"id,name\r\n1,x\r\n");
    let run = run_files(&[&path]);

    assert_eq!(run.count("xlsx.dedup.duplicate"), 0);
    let rejected = only(&run, "xlsx.dedup.rejected");
    assert_eq!(rejected.text("code"), Some("not_zip_container"));
    assert!(rejected.text("file").unwrap_or("").ends_with("联系人.csv"));
    let summary = only(&run, "xlsx.dedup.summary");
    assert_eq!(summary.int("total_rows"), Some(0));
}

#[test]
fn empty_input_selection_is_an_explicit_warning() {
    let run = run_files(&[]);
    assert_eq!(run.count("xlsx.dedup.summary"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn multi_sheet_workbook_reports_each_sheet() {
    let fixture = TempDir::new("sheets");
    let spec = WorkbookSpec::new(
        vec![
            sample_sheet(),
            SheetSpec::new("空白表", Vec::new()),
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
        ],
        Vec::new(),
    );
    let path = fixture.file("多表.xlsx", &xlsx_bytes(&spec, ZipOptions::default()));
    let run = run_files(&[&path]);

    assert_eq!(run.count("xlsx.dedup.sheet"), 3);
    let skipped: Vec<&TestRecord> = run
        .of_type("xlsx.dedup.sheet")
        .into_iter()
        .filter(|record| record.text("header_source") == Some("skipped"))
        .collect();
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0]
        .text("skipped_reason")
        .unwrap_or("")
        .contains("空工作表"));
    let file = only(&run, "xlsx.dedup.file");
    assert_eq!(file.int("sheets"), Some(3));
    assert_eq!(file.int("sheets_used"), Some(2));
    assert_eq!(list(file, "skipped_sheets").len(), 1);
}

#[test]
fn manifest_declares_the_v2_identity() {
    let manifest = include_str!("../plugin.toml");
    assert!(manifest.contains("id = \"org.ljnljn.xlsx-dedup\""));
    assert!(manifest.contains("protocol = 2"));
    assert!(manifest.contains("library = \"ljnljn_xlsx_dedup\""));
    assert!(manifest.contains("id = \"dedup_files\""));
}
