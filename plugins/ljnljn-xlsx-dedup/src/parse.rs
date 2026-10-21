//! 检材侧输入收集与格式分派：一个宿主文件、用户勾选的证据根/子目录、或证据自动发现，
//! 都转换成“逻辑句柄 + 显示名”的 [`InputFile`] 列表，再交给纯解析层。
//!
//! 宿主没有“命令行文件路径”参数，因此这里只有三类输入来源：
//! 1. `FileAnalyzer`：宿主传入的单个逻辑文件句柄；
//! 2. `EvidenceAnalyzer` + `params.targets`：用户在任务参数里给出的 POSIX 相对路径
//!    （可为逗号分隔多路径，可为目录）；
//! 3. `EvidenceAnalyzer` 无 `targets`：按关键词自动发现（文件名 / 关键词 / 深度，
//!    均有固定默认值并写入 limitations）。
//!
//! 重复输入按“字节来源同一（同 root + 同路径）或同显示名”只计一次；
//! zip 只取其中的 `.xlsx/.xlsm`，忽略 `__MACOSX/`、`~$` 临时文件与点开头的隐藏文件。

use lovelycarve_plugin::Value;

use crate::limits::MAX_INPUT_FILES;
use crate::xlsx::read_workbook;
use crate::zipread::{read_entries_from, Blob, ZipEntry};

/// 逻辑来源：宿主文件句柄，或证据卷内的文件路径。
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Link {
    File { file_id: String },
    Evidence { root: String, path: String },
}

impl Link {
    pub fn describe(&self) -> String {
        match self {
            Link::File { file_id } => format!("file:{file_id}"),
            Link::Evidence { root, path } => format!("{root}:{path}"),
        }
    }

    pub fn evidence_path(&self) -> Option<&str> {
        match self {
            Link::File { .. } => None,
            Link::Evidence { path, .. } => Some(path.as_str()),
        }
    }
}

/// 一个待解析的逻辑文件。
#[derive(Clone, Debug)]
pub struct InputFile {
    pub link: Link,
    /// 结果中展示的名称（宿主文件显示名，或卷内相对路径）。
    pub display: String,
    /// zip 内的条目路径（直接传入的 xlsx 为 `None`）。
    pub member: Option<String>,
}

impl InputFile {
    pub fn file(file_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            link: Link::File {
                file_id: file_id.into(),
            },
            display: name.into(),
            member: None,
        }
    }

    pub fn evidence(root: impl Into<String>, path: impl Into<String>) -> Self {
        let path = path.into();
        let display = path.clone();
        Self {
            link: Link::Evidence {
                root: root.into(),
                path,
            },
            display,
            member: None,
        }
    }

    pub fn with_member(mut self, member: impl Into<String>) -> Self {
        self.member = Some(member.into());
        self
    }
}

/// 按扩展名判断是否是支持的表格包。
pub fn is_spreadsheet_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".xlsx") || lower.ends_with(".xlsm")
}

pub fn is_zip_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".zip")
}

/// zip 内条目是否应当纳入分析：只取 xlsx/xlsm，忽略 __MACOSX 与临时/隐藏文件。
pub fn accept_zip_member(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if !is_spreadsheet_name(&lower) || lower.ends_with(".xls") {
        return false;
    }
    if lower.split('/').any(|segment| {
        segment.is_empty()
            || segment == "__macosx"
            || segment == ".ds_store"
            || segment.starts_with("._")
            || segment.starts_with("~$")
    }) {
        return false;
    }
    let file = lower.rsplit('/').next().unwrap_or(&lower);
    !(file.starts_with('.') || file.starts_with("~") || file.contains("~$"))
}

/// 从 zip 包内挑出待分析的 xlsx/xlsm 条目。
pub fn zip_members<B: Blob + ?Sized>(blob: &B) -> Result<Vec<String>, crate::error::DedupError> {
    let entries = read_entries_from(blob)?;
    Ok(entries
        .into_iter()
        .filter(|entry: &ZipEntry| accept_zip_member(&entry.name))
        .map(|entry| entry.name)
        .collect())
}

/// 一个文件的开头是不是 ZIP 包（`PK\x03\x04` / 空包 `PK\x05\x06`）。
pub fn head_looks_like_zip(head: &[u8]) -> bool {
    matches!(
        head.get(..4),
        Some(b"PK\x03\x04") | Some(b"PK\x05\x06") | Some(b"PK\x07\x08")
    )
}

/// 包是否为 xlsx/xlsm：有 `xl/workbook.xml` 或 `xl/worksheets/` 成员。
pub fn workbook_shape<B: Blob + ?Sized>(blob: &B) -> bool {
    match read_entries_from(blob) {
        Ok(entries) => entries
            .iter()
            .any(|entry| entry.name == "xl/workbook.xml" || entry.name.starts_with("xl/worksheets/")),
        Err(_) => false,
    }
}

/// 把 evidence 参数里的 `targets` 解析成路径列表。
///
/// 支持字符串（逗号/换行分隔）、字符串数组；空项忽略；去掉前导 `/`，
/// 统一 `\` 为 `/`，拒绝包含 `..` 的路径（避免越过卷根）。
pub fn parse_targets(params: &Value) -> Vec<String> {
    let raw = crate::value::get(params, "targets");
    let mut items: Vec<String> = Vec::new();
    if let Some(value) = raw {
        collect_targets(value, &mut items);
    }
    let mut targets = Vec::new();
    for item in items {
        for piece in item.split([',', '，', ';', '\n']) {
            let trimmed = piece.trim();
            if trimmed.is_empty() {
                continue;
            }
            let path = trimmed.replace('\\', "/");
            let path = path.trim_start_matches('/').to_owned();
            if path.is_empty() || path.split('/').any(|segment| segment == "..") {
                continue;
            }
            if !targets.contains(&path) {
                targets.push(path);
            }
        }
    }
    targets
}

fn collect_targets(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if let Some(text) = text.as_str() {
                out.push(text.to_owned());
            } else {
                out.push(String::from_utf8_lossy(text.as_bytes()).into_owned());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_targets(item, out);
            }
        }
        Value::Nil => {}
        other => {
            if let Some(text) = other.as_str() {
                out.push(text.to_owned());
            }
        }
    }
}

/// 输入去重：同一逻辑来源或同一显示名只保留首次出现。
pub struct InputSet {
    seen: Vec<(Link, String)>,
    pub duplicates: Vec<String>,
}

impl InputSet {
    pub fn new() -> Self {
        Self {
            seen: Vec::new(),
            duplicates: Vec::new(),
        }
    }

    /// 返回 `true` 表示是新增输入。
    pub fn admit(&mut self, input: &InputFile) -> bool {
        let key_display = match &input.member {
            Some(member) => format!("{}::{}", input.display, member),
            None => input.display.clone(),
        };
        if self
            .seen
            .iter()
            .any(|(link, display)| *link == input.link && *display == key_display)
        {
            self.duplicates.push(key_display);
            return false;
        }
        self.seen.push((input.link.clone(), key_display));
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for InputSet {
    fn default() -> Self {
        Self::new()
    }
}

/// 输入数量是否已到上限。
pub fn at_input_limit(count: usize) -> bool {
    count >= MAX_INPUT_FILES
}

/// 读取 `xl/workbook.xml` 的结构（纯解析层入口，供 `hostio` 调用）。
pub fn load_workbook<B: Blob + ?Sized>(blob: &B) -> Result<crate::xlsx::Workbook, crate::error::DedupError> {
    read_workbook(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spreadsheet_and_zip_names_are_detected_case_insensitively() {
        assert!(is_spreadsheet_name("顺丰1k.XLSX"));
        assert!(is_spreadsheet_name("a.xlsm"));
        assert!(!is_spreadsheet_name("a.xls"));
        assert!(!is_spreadsheet_name("a.csv"));
        assert!(is_zip_name("顺丰4k.ZIP"));
    }

    #[test]
    fn zip_members_skip_macosx_and_temp_files() {
        assert!(accept_zip_member("顺丰1k.xlsx"));
        assert!(accept_zip_member("子目录/顺丰2k.XLSM"));
        assert!(!accept_zip_member("__MACOSX/._顺丰1k.xlsx"));
        assert!(!accept_zip_member("~$顺丰1k.xlsx"));
        assert!(!accept_zip_member("子目录/~$临时.xlsx"));
        assert!(!accept_zip_member(".hidden.xlsx"));
        assert!(!accept_zip_member("顺丰1k.xls"));
        assert!(!accept_zip_member("说明.txt"));
        assert!(!accept_zip_member("a.docx"));
    }

    #[test]
    fn targets_accept_strings_arrays_and_normalize_paths() {
        let params = crate::value::map([(
            "targets",
            Value::from(" /Users/a/顺丰1k.zip , Users/b, , /etc/../secret"),
        )]);
        assert_eq!(
            parse_targets(&params),
            vec![
                "Users/a/顺丰1k.zip".to_string(),
                "Users/b".to_string()
            ]
        );
        let array = crate::value::map([(
            "targets",
            Value::Array(vec![
                Value::from("Users/a\\顺丰2k.zip"),
                Value::from("Users/b"),
            ]),
        )]);
        assert_eq!(
            parse_targets(&array),
            vec!["Users/a/顺丰2k.zip".to_string(), "Users/b".to_string()]
        );
        assert!(parse_targets(&Value::Nil).is_empty());
    }

    #[test]
    fn duplicate_inputs_are_admitted_once() {
        let mut set = InputSet::new();
        let first = InputFile::evidence("part:0", "Users/a/顺丰1k.zip");
        assert!(set.admit(&first));
        assert!(!set.admit(&first.clone()));
        let same_name_other_root = InputFile::evidence("part:1", "Users/a/顺丰1k.zip");
        assert!(set.admit(&same_name_other_root));
        assert_eq!(set.duplicates.len(), 1);
        assert_eq!(set.len(), 2);
    }
}
