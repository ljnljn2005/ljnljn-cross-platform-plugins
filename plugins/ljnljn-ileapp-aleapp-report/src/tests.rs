use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};
use lovelycarve_plugin::Value;

struct Root {
    path: PathBuf,
}

impl Root {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-mobile-report-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, content: &str) -> PathBuf {
        let path = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn run_file(&self, path: &Path) -> TestRun {
        Harness::new(super::plugin)
            .run_with(
                "report_files",
                Fixture::files(&[path]),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run")
    }

    fn run_evidence(&self) -> TestRun {
        Harness::new(super::plugin)
            .run_with(
                "report_evidence",
                Fixture::evidence(&[("part:1", &self.path)]),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run")
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn fixture() -> Root {
    let root = Root::new("all");
    root.write(
        "iLEAPP_Report/_TSV Exports/Photos.tsv",
        "\u{feff}Name\tDate\tCount\n\"a\tb\"\t2024-01-01\t3\nc\t2024-01-02\t4\n",
    );
    root.write(
        "ALEAPP_Report/_TSV Exports/SMS.tsv",
        "Address\tBody\n+123456789\thello world\n",
    );
    root
}

#[test]
fn selected_tsv_preserves_quoted_tabs_and_columns() {
    let root = Root::new("one");
    let path = root.write(
        "iLEAPP_Report/_TSV Exports/Photos.tsv",
        "\u{feff}Name\tDate\tCount\n\"a\tb\"\t2024-01-01\t3\nc\t2024-01-02\t4\n",
    );
    let run = root.run_file(&path);

    assert_eq!(run.count("mobile.report.file"), 1);
    assert_eq!(run.count("mobile.report.row"), 2);
    let file = run.of_type("mobile.report.file")[0];
    // 单文件输入只拿到文件名，路径里没有 iLEAPP/ALEAPP 报告目录名，
    // 工具归属如实记为 unknown；扫描报告目录时才能按目录名判定。
    assert_eq!(file.text("tool"), Some("unknown"));
    assert_eq!(file.text("module"), Some("Photos"));
    assert_eq!(file.int("row_count"), Some(2));
    assert_eq!(file.int("column_count"), Some(3));
    let first = run.of_type("mobile.report.row")[0];
    assert_eq!(first.text("module"), Some("Photos"));
    let values = first
        .get("values")
        .and_then(Value::as_array)
        .expect("values array");
    assert_eq!(values[0].as_str(), Some("a\tb"));
    assert_eq!(values[1].as_str(), Some("2024-01-01"));
    assert_eq!(
        first.get("columns").and_then(Value::as_array).map(Vec::len),
        Some(3)
    );
}

#[test]
fn quoted_newlines_and_escaped_quotes_stay_in_one_row() {
    let root = Root::new("multiline");
    let path = root.write(
        "ALEAPP_Report/_TSV Exports/SMS.tsv",
        "Address\tBody\r\n+1\t\"line one\r\nline \"\"two\"\"\"\r\n+2\tplain\r\n",
    );
    let run = root.run_file(&path);

    assert_eq!(run.count("mobile.report.row"), 2);
    let rows = run.of_type("mobile.report.row");
    let values = rows[0]
        .get("values")
        .and_then(Value::as_array)
        .expect("values array");
    assert_eq!(values[0].as_str(), Some("+1"));
    assert_eq!(values[1].as_str(), Some("line one\r\nline \"two\""));
    let second = rows[1]
        .get("values")
        .and_then(Value::as_array)
        .expect("values array");
    assert_eq!(second[1].as_str(), Some("plain"));
}

#[test]
fn ragged_rows_keep_extra_values_and_warn() {
    let root = Root::new("ragged");
    let path = root.write(
        "iLEAPP_Report/_TSV Exports/Ragged.tsv",
        "A\tB\tC\n1\t2\n1\t2\t3\t4\n",
    );
    let run = root.run_file(&path);

    assert_eq!(run.count("mobile.report.row"), 2);
    assert_eq!(
        run.of_type("mobile.report.file")[0].text("status"),
        Some("ragged")
    );
    let rows = run.of_type("mobile.report.row");
    assert_eq!(
        rows[0].get("values").and_then(Value::as_array).map(Vec::len),
        Some(3)
    );
    assert_eq!(
        rows[1].get("values").and_then(Value::as_array).map(Vec::len),
        Some(4)
    );
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "REPORT_STATUS"));
}

#[test]
fn evidence_scan_finds_both_tools_tsv_exports() {
    let root = fixture();
    let run = root.run_evidence();

    assert_eq!(run.count("mobile.report.file"), 2);
    assert_eq!(run.count("mobile.report.row"), 3);
    let tools: Vec<&str> = run
        .of_type("mobile.report.file")
        .iter()
        .filter_map(|file| file.text("tool"))
        .collect();
    assert!(tools.contains(&"ileapp"));
    assert!(tools.contains(&"aleapp"));
    let sms = run
        .of_type("mobile.report.row")
        .into_iter()
        .find(|row| row.text("module") == Some("SMS"))
        .expect("SMS row");
    assert_eq!(sms.text("tool"), Some("aleapp"));
}

#[test]
fn system_scope_finds_reports_at_the_system_root() {
    let root = fixture();
    let run = Harness::new(super::plugin)
        .run_with(
            "report_system",
            Fixture::system("ios", &root.path),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run");
    assert_eq!(run.count("mobile.report.file"), 2);
}

#[test]
fn empty_report_is_reported_without_fake_rows() {
    let root = Root::new("empty");
    let path = root.write("iLEAPP_Report/_TSV Exports/Empty.tsv", "");
    let run = root.run_file(&path);
    assert_eq!(run.count("mobile.report.file"), 1);
    assert_eq!(run.count("mobile.report.row"), 0);
    assert_eq!(run.of_type("mobile.report.file")[0].text("status"), Some("empty"));
}

#[test]
fn missing_report_directory_is_a_warning() {
    let root = Root::new("missing");
    let run = root.run_evidence();
    assert_eq!(run.count("mobile.report.file"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "REPORT_NOT_FOUND"));
}
