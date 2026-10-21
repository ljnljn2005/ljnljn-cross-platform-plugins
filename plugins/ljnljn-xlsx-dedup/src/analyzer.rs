//! 分析器：同一 analyzer id 同时提供 `file_analyzer` 与 `evidence_analyzer` 两种入口。
//!
//! - `FileAnalyzer`：宿主在多文件列表里对单个 .xlsx/.xlsm/.zip 调用；
//! - `EvidenceAnalyzer`：用户可在任务参数 `targets` 里给出逗号分隔的 POSIX 相对路径
//!   （文件或目录）；没有 `targets` 时按固定默认关键词在卷内自动发现。
//!
//! 所有读取都经过 SDK 只读句柄；不执行宏、不访问网络、不写检材。

use lovelycarve_plugin::{
    AnalysisResult, Evidence, EvidenceAnalyzer, EvidenceVolume, File, FileAnalyzer, LogLevel,
    Result, Value,
};

use crate::dedup::Accumulator;
use crate::hostio::{FileBlob, VolumeBlob};
use crate::limits::{MAX_INPUT_FILES, MAX_MEMBER_BYTES};
use crate::parse::{
    at_input_limit, head_looks_like_zip, is_spreadsheet_name, is_zip_name, parse_targets,
    workbook_shape, zip_members, InputFile, InputSet, Link,
};
use crate::report::present;
use crate::value::{get_string_list, get_u64};

/// analyzer 名（与 plugin.toml 的 `analyzer` 完全一致）。
pub const ANALYZER: &str = "ljnljn.xlsx-dedup";
pub const ANALYZER_FILE: &str = "ljnljn.xlsx-dedup.file";
pub const ANALYZER_EVIDENCE: &str = "ljnljn.xlsx-dedup.evidence";

/// 自动发现的默认参数（宿主未提供任务参数时使用；README 记录这些默认值）。
pub const DEFAULT_NAME_KEYWORDS: &[&str] = &["顺丰", "快递", "运单", "收件", "发货"];
pub const DEFAULT_MAX_DEPTH: u64 = 6;

/// 宿主参数（LPP 没有额外的插件参数 API，只从任务参数里读）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub targets: Vec<String>,
    pub name_keywords: Vec<String>,
    pub max_depth: u64,
}

impl Options {
    pub fn from_params(params: &Value) -> Self {
        let targets = parse_targets(params);
        let mut name_keywords = get_string_list(params, "nameKeywords");
        if name_keywords.is_empty() {
            name_keywords = DEFAULT_NAME_KEYWORDS.iter().map(|s| (*s).to_string()).collect();
        }
        let max_depth = get_u64(params, "maxDepth").unwrap_or(DEFAULT_MAX_DEPTH).min(16);
        Self {
            targets,
            name_keywords,
            max_depth,
        }
    }
}

/// 分析器（无状态，可安全并发复用）。
#[derive(Clone, Copy, Debug, Default)]
pub struct RecipientDedup;

impl RecipientDedup {
    pub fn new() -> Self {
        Self
    }
}

impl FileAnalyzer for RecipientDedup {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let mut accumulator = Accumulator::new();
        let blob = FileBlob::new(file);
        let link = Link::File {
            file_id: file.id().to_owned(),
        };
        let display = if file.name().is_empty() {
            file.id().to_owned()
        } else {
            file.name().to_owned()
        };
        parse_input(&mut accumulator, link, &display, &blob);
        Ok(present(&accumulator.finish()).result)
    }
}

impl EvidenceAnalyzer for RecipientDedup {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let options = Options::from_params(evidence.params());
        // 子项勾选：空表示全部分析（桌面快速分析总是发空）。
        if !evidence.sub_items().is_empty() {
            let wanted = evidence.sub_items().iter().any(|item| {
                item.contains("去重") || item.contains("xlsx") || item.contains("收件")
            });
            if !wanted {
                return Ok(AnalysisResult {
                    summary: Some(format!(
                        "子项 {:?} 与本分析器无关，未执行",
                        evidence.sub_items()
                    )),
                    ..AnalysisResult::default()
                });
            }
        }
        let mut accumulator = Accumulator::new();
        let mut set = InputSet::new();
        let mut discovered: Vec<InputFile> = Vec::new();
        let mut scanned_roots = 0usize;
        for root in evidence.roots()? {
            evidence.context().check_cancelled()?;
            let volume = evidence.volume(&root.root_id);
            scanned_roots += 1;
            let paths = match collect_paths(&volume, &options, &mut accumulator) {
                Ok(paths) => paths,
                Err(error) => {
                    accumulator.reject(
                        Link::Evidence {
                            root: root.root_id.clone(),
                            path: String::new(),
                        },
                        root.root_id.clone(),
                        "evidence.walk",
                        error.message.clone(),
                    );
                    continue;
                }
            };
            for path in paths {
                if at_input_limit(discovered.len()) {
                    accumulator.note(format!("输入文件超过 {MAX_INPUT_FILES} 上限，其余未分析"));
                    break;
                }
                let input = InputFile::evidence(root.root_id.clone(), path);
                if set.admit(&input) {
                    discovered.push(input);
                }
            }
        }
        for duplicate in set.duplicates.clone() {
            accumulator.mark_duplicate_input(duplicate);
        }
        if scanned_roots == 0 {
            return Ok(AnalysisResult {
                summary: Some("检材没有可浏览的分区根，无法分析".to_owned()),
                ..AnalysisResult::default()
            });
        }
        if discovered.is_empty() {
            accumulator
                .note("未找到目标 xlsx/xlsm 或包含 xlsx 的 zip；可用任务参数 targets 指定路径");
            let mut result = present(&accumulator.finish()).result;
            result.summary = Some(format!(
                "{}（已检查 {scanned_roots} 个分区根；关键词 {:?}；深度 ≤ {}）",
                result.summary.unwrap_or_default(),
                options.name_keywords,
                options.max_depth
            ));
            return Ok(result);
        }
        for (index, input) in discovered.iter().enumerate() {
            evidence.context().check_cancelled()?;
            evidence.progress(
                index as u64 + 1,
                Some(discovered.len() as u64),
                Some(&input.display),
            )?;
            let Link::Evidence { root, path } = &input.link else {
                continue;
            };
            // 输入已经从同一卷枚举得到，这里直接重新打开该卷句柄。
            let volume = evidence.volume(root);
            match VolumeBlob::open(&volume, path) {
                Ok(Some(blob)) => parse_input(&mut accumulator, input.link.clone(), &input.display, &blob),
                Ok(None) => accumulator.reject(
                    input.link.clone(),
                    input.display.clone(),
                    "not_found",
                    "枚举后文件不再存在或不是普通文件",
                ),
                Err(error) if error.is_cancelled() => return Err(error),
                Err(error) => accumulator.reject(
                    input.link.clone(),
                    input.display.clone(),
                    "host.read",
                    error.message,
                ),
            }
        }
        let aggregation = accumulator.finish();
        evidence
            .context()
            .log(
                LogLevel::Info,
                &format!(
                    "{}：totalRows={} validRows={} uniqueCount={} duplicateCount={} incompleteRows={}",
                    ANALYZER,
                    aggregation.total_rows,
                    aggregation.valid_rows,
                    aggregation.unique_count,
                    aggregation.duplicate_count,
                    aggregation.incomplete_rows
                ),
            );
        Ok(present(&aggregation).result)
    }
}

/// 依据 `targets`（或默认关键词发现）得到卷内相对路径列表。
fn collect_paths(
    volume: &EvidenceVolume,
    options: &Options,
    accumulator: &mut Accumulator,
) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    if !options.targets.is_empty() {
        for target in &options.targets {
            match volume.stat(target) {
                Ok(Some(node)) if node.is_dir() => {
                    let mut found = Vec::new();
                    walk(volume, target, options, 0, &mut found, accumulator)?;
                    paths.extend(found);
                }
                Ok(Some(node)) if node.is_file() => paths.push(target.clone()),
                Ok(Some(_)) => accumulator.reject(
                    Link::Evidence {
                        root: volume.root_id().to_owned(),
                        path: target.clone(),
                    },
                    target,
                    "unsupported_input",
                    "输入对象不是普通文件或目录",
                ),
                Ok(None) => accumulator.reject(
                    Link::Evidence {
                        root: volume.root_id().to_owned(),
                        path: target.clone(),
                    },
                    target,
                    "not_found",
                    "指定的路径在卷内不存在",
                ),
                Err(error) if error.is_cancelled() => return Err(error),
                Err(error) => accumulator.reject(
                    Link::Evidence {
                        root: volume.root_id().to_owned(),
                        path: target.clone(),
                    },
                    target,
                    "host.stat",
                    error.message,
                ),
            }
        }
        return Ok(paths);
    }
    walk(volume, "", options, 0, &mut paths, accumulator)?;
    Ok(paths)
}

/// 有界目录遍历：跳过系统目录，只收 xlsx/xlsm 与 zip。
fn walk(
    volume: &EvidenceVolume,
    directory: &str,
    options: &Options,
    depth: u64,
    out: &mut Vec<String>,
    accumulator: &mut Accumulator,
) -> Result<()> {
    if depth > options.max_depth || out.len() >= MAX_INPUT_FILES {
        if depth > options.max_depth {
            accumulator.note(format!(
                "目录遍历深度超过 {}，更深层的文件未枚举",
                options.max_depth
            ));
        }
        return Ok(());
    }
    volume.context().check_cancelled()?;
    let nodes = match volume.list(directory) {
        Ok(nodes) => nodes,
        Err(error) if error.is_cancelled() => return Err(error),
        Err(error) if error.code == "EVIDENCE_PATH_NOT_FOUND" => return Ok(()),
        Err(error) => {
            accumulator.reject(
                Link::Evidence {
                    root: volume.root_id().to_owned(),
                    path: directory.to_owned(),
                },
                directory,
                "evidence.list",
                error.message,
            );
            return Ok(());
        }
    };
    for node in nodes {
        if out.len() >= MAX_INPUT_FILES {
            break;
        }
        let child = if directory.is_empty() {
            node.name.clone()
        } else {
            format!("{directory}/{}", node.name)
        };
        if node.is_dir() {
            if is_skipped_directory(&node.name) {
                continue;
            }
            walk(volume, &child, options, depth + 1, out, accumulator)?;
            continue;
        }
        if !node.is_file() || node.size == 0 {
            continue;
        }
        if is_spreadsheet_name(&node.name) || is_zip_name(&node.name) {
            out.push(child);
        }
    }
    Ok(())
}

/// 自动发现时跳过的系统目录（用户数据里不会有它们的表格）。
fn is_skipped_directory(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "windows" | "winnt" | "$recycle.bin" | "system volume information" | "proc" | "sys" | "dev"
    )
}

/// 解析一个逻辑输入：直接 xlsx、或 zip 内 xlsx/xlsm。失败原因如实记录。
pub fn parse_input<B: crate::zipread::Blob + ?Sized>(
    accumulator: &mut Accumulator,
    link: Link,
    display: &str,
    blob: &B,
) {
    let total = blob.len();
    if total == 0 {
        accumulator.reject(link, display, "empty_file", "文件长度为 0");
        return;
    }
    let head = match blob.read_at(0, 8) {
        Ok(head) => head,
        Err(error) => {
            accumulator.reject(link, display, error.code, error.message);
            return;
        }
    };
    if !head_looks_like_zip(&head) {
        accumulator.reject(
            link,
            display,
            "not_zip_container",
            "不是 ZIP 容器（xlsx/xlsm 本质上是 ZIP），可能是 .xls/.csv/.txt 或损坏文件",
        );
        return;
    }
    if !workbook_shape(blob) {
        // 是 zip：只展开其中的 xlsx/xlsm 成员。
        let members = match zip_members(blob) {
            Ok(members) => members,
            Err(error) => {
                accumulator.reject(link, display, error.code, error.message);
                return;
            }
        };
        if members.is_empty() {
            accumulator.reject(
                link,
                display,
                "zip.no_spreadsheet",
                "ZIP 内没有 .xlsx/.xlsm 成员（已忽略 __MACOSX 与临时文件）",
            );
            return;
        }
        let entries = match crate::zipread::read_entries_from(blob) {
            Ok(entries) => entries,
            Err(error) => {
                accumulator.reject(link, display, error.code, error.message);
                return;
            }
        };
        let mut set = InputSet::new();
        for member in members {
            if !set.admit(&InputFile::evidence("zip", &member)) {
                continue;
            }
            let Some(entry) = entries.iter().find(|entry| entry.name == member) else {
                continue;
            };
            let bytes = match crate::zipread::read_entry(blob, entry, MAX_MEMBER_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    accumulator.reject(
                        link.clone(),
                        format!("{display}::{member}"),
                        error.code,
                        error.message,
                    );
                    continue;
                }
            };
            analyze_package(accumulator, link.clone(), &format!("{display}::{member}"), &bytes);
        }
        return;
    }
    analyze_package(accumulator, link, display, blob);
}

fn analyze_package<B: crate::zipread::Blob + ?Sized>(
    accumulator: &mut Accumulator,
    link: Link,
    display: &str,
    blob: &B,
) {
    match crate::parse::load_workbook(blob) {
        Ok(workbook) => accumulator.analyze_workbook(link, display, blob, &workbook),
        Err(error) => accumulator.reject(link, display, error.code, error.message),
    }
}

/// 供 README/日志展示的 analyzer 摘要。
pub fn analyzer_description() -> String {
    format!(
        "{ANALYZER}：收件人表格（xlsx/xlsm/zip 内 xlsx）姓名+电话+地址三元组去重统计；\
默认关键词 {:?}；默认深度 {}",
        DEFAULT_NAME_KEYWORDS, DEFAULT_MAX_DEPTH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_use_documented_defaults() {
        let options = Options::from_params(&Value::Nil);
        assert!(options.targets.is_empty());
        assert_eq!(options.name_keywords, vec!["顺丰", "快递", "运单", "收件", "发货"]);
        assert_eq!(options.max_depth, DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn options_read_targets_keywords_and_depth() {
        let params = crate::value::map([
            ("targets", Value::from("Users/a/顺丰1k.zip,Users/b")),
            (
                "nameKeywords",
                Value::Array(vec![Value::from("自定义")]),
            ),
            ("maxDepth", Value::from(3u64)),
        ]);
        let options = Options::from_params(&params);
        assert_eq!(options.targets.len(), 2);
        assert_eq!(options.name_keywords, vec!["自定义"]);
        assert_eq!(options.max_depth, 3);
        let capped = Options::from_params(&crate::value::map([("maxDepth", Value::from(99u64))]));
        assert_eq!(capped.max_depth, 16);
    }

    #[test]
    fn system_directories_are_skipped_in_discovery() {
        assert!(is_skipped_directory("Windows"));
        assert!(is_skipped_directory("$Recycle.Bin"));
        assert!(is_skipped_directory("System Volume Information"));
        assert!(!is_skipped_directory("Users"));
        assert!(!is_skipped_directory("新建文件夹"));
    }

    #[test]
    fn non_zip_and_empty_inputs_are_rejected_with_reasons() {
        let mut accumulator = Accumulator::new();
        parse_input(
            &mut accumulator,
            Link::File {
                file_id: "f1".to_owned(),
            },
            "a.csv",
            b"id,name\r\n1,x\r\n".as_slice(),
        );
        parse_input(
            &mut accumulator,
            Link::File {
                file_id: "f2".to_owned(),
            },
            "empty.xlsx",
            b"".as_slice(),
        );
        let aggregation = accumulator.finish();
        let codes: Vec<&str> = aggregation.rejected.iter().map(|item| item.code).collect();
        assert_eq!(codes, vec!["not_zip_container", "empty_file"]);
    }
}


/// 文件入口与检材入口使用不同 analyzer 名，避免宿主判重复。
#[derive(Clone, Copy, Debug, Default)]
pub struct RecipientDedupFile(pub RecipientDedup);
#[derive(Clone, Copy, Debug, Default)]
pub struct RecipientDedupEvidence(pub RecipientDedup);

impl FileAnalyzer for RecipientDedupFile {
    fn analyzer(&self) -> &str { ANALYZER_FILE }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> { self.0.analyze(file) }
}

impl EvidenceAnalyzer for RecipientDedupEvidence {
    fn analyzer(&self) -> &str { ANALYZER_EVIDENCE }
    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        self.0.analyze_evidence(evidence)
    }
}
