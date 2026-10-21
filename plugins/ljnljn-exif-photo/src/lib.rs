//! 照片元数据（EXIF/GPS）检材级 + 文件级分析器。
//!
//! 能力来源：知识库素材 `mulakgi41k66gz`（草稿、未验证）只有一条“DCIM/Camera
//! 下照片数 = App 分页条数”的人工比对结论，没有任何可复现步骤，因此本插件
//! **不复用其结论与案件取值**，只实现它归纳出的通用离线能力：
//!
//! 1. 递归枚举照片目录（或单个照片文件）中扩展名为 jpg/jpeg/png/heic/heif 的
//!    候选文件，按文件头魔数确认真实格式；扩展名与内容不符的非图片文件跳过并计数。
//! 2. 解析 JPEG APP1 `Exif\0\0` 段 / PNG `eXIf` 块的 TIFF 结构（IFD0、ExifIFD、
//!    GPS IFD），逐 Tag 输出原值与文件内偏移；PNG 另读 tEXt/iTXt/zTXt 与
//!    `XML:com.adobe.xmp`。
//! 3. 输出拍摄时间原值（不改时区、不补年份）+ 原始精度标记、经度/纬度十进制度、
//!    缺失字段列表，以及整批汇总（文件数、含 EXIF、含 GPS、无 GPS、失败原因）。
//!
//! 输入全部来自 SDK 的只读逻辑句柄（`Evidence` / `EvidenceVolume` / `File`），
//! 不使用 `std::fs` 读取检材，也不执行检材内任何程序。
//!
//! 可选参数（宿主 `params` 里存在才生效，否则用默认值并在 summary 中说明）：
//! - `path`：相对 root 的单个照片文件路径（与目录二选一，文件优先）；
//! - `photoDir`：相对 root 的起始目录，默认按 [`DEFAULT_PHOTO_DIRS`] 依次尝试；
//! - `maxFiles`：最多解析多少张候选照片，默认 [`DEFAULT_MAX_FILES`]；
//! - `includeNoExif`：是否保留无 EXIF 的照片记录，默认 `true`。

mod container;
pub mod exif;
pub mod fields;
mod format;
mod record;
mod report;
mod sha256;

/// 测试支持 API（见 src/testing.rs 说明）：只暴露内存解析与样例构造，
/// 供 `tests/` 集成测试复用；宿主运行路径不经过这里。
pub mod testing;

pub mod fixtures;

use std::collections::BTreeMap;

use lovelycarve_plugin::{
    export_plugin, value, AnalysisResult, Artifact, Attributes, Evidence, EvidenceAnalyzer,
    EvidenceVolume, File, FileAnalyzer, Finding, LogLevel, Plugin, Result, ResultColumn,
    ResultNode, Severity, Value,
};

use record::{accumulate, Outcome, PhotoRecord, RunSummary};

pub const PLUGIN_ID: &str = "org.ljnljn.exif-photo";
pub const PLUGIN_NAME: &str = "照片元数据(EXIF/GPS)";
pub const EVIDENCE_ANALYZER: &str = "ljnljn.exif-photo";
pub const FILE_ANALYZER: &str = "ljnljn.exif-photo.file";

/// Hard cap on candidate photos parsed per run (overridable via `params.maxFiles`).
pub const DEFAULT_MAX_FILES: usize = 5000;
/// Absolute ceiling for `params.maxFiles`.
pub const MAX_FILES_CEILING: usize = 20_000;
/// Root-relative directories searched for photos, in preference order.
pub const DEFAULT_PHOTO_DIRS: &[&str] = &["DCIM/Camera", "DCIM", "Pictures", "sdcard/DCIM"];
/// Photos larger than this are rejected and recorded.
pub const MAX_PHOTO_BYTES: u64 = 64 * 1024 * 1024;
/// Bounded recursion.
pub const MAX_DEPTH: usize = 24;
pub const MAX_DIRECTORIES: usize = 50_000;
/// The host accepts at most 10,000 result items per run.
pub const MAX_ARTIFACTS: usize = 9_000;
/// Host limit on declared result columns.
const MAX_COLUMNS: usize = 64;

/// Analysis options resolved from the host params.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub max_files: usize,
    pub include_no_exif: bool,
    pub photo_dir: Option<String>,
    pub file_path: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            include_no_exif: true,
            photo_dir: None,
            file_path: None,
        }
    }
}

impl Options {
    /// Reads optional host params; malformed values fall back to defaults.
    pub fn from_params(params: &Value) -> (Self, Vec<String>) {
        let mut options = Self::default();
        let mut notes = Vec::new();
        if let Some(param) = value::get(params, "maxFiles") {
            match param.as_u64() {
                Some(0) => notes.push("参数 maxFiles=0 无效，改用默认值".to_owned()),
                Some(count) => {
                    let count = usize::try_from(count).unwrap_or(MAX_FILES_CEILING);
                    if count > MAX_FILES_CEILING {
                        notes.push(format!(
                            "参数 maxFiles={count} 超过上限 {MAX_FILES_CEILING}，已截断"
                        ));
                    }
                    options.max_files = count.min(MAX_FILES_CEILING);
                }
                None => notes.push("参数 maxFiles 不是无符号整数，改用默认值".to_owned()),
            }
        }
        if let Some(param) = value::get(params, "includeNoExif") {
            match param.as_bool() {
                Some(flag) => options.include_no_exif = flag,
                None => notes.push("参数 includeNoExif 不是布尔值，改用默认值 true".to_owned()),
            }
        }
        if let Some(text) = value::get(params, "photoDir").and_then(Value::as_str) {
            match normalize_relative(text) {
                Some(path) => options.photo_dir = Some(path),
                None => notes.push(format!("参数 photoDir='{text}' 不可用，忽略")),
            }
        }
        if let Some(text) = value::get(params, "path").and_then(Value::as_str) {
            match normalize_relative(text) {
                Some(path) => options.file_path = Some(path),
                None => notes.push(format!("参数 path='{text}' 不可用，忽略")),
            }
        }
        (options, notes)
    }
}

/// Trims slashes and rejects traversal / empty paths.
fn normalize_relative(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_matches('/');
    if trimmed.is_empty() || trimmed.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    Some(trimmed.to_owned())
}

// ---------------------------------------------------------------------------
// Evidence analyzer (directory / single-photo mode)
// ---------------------------------------------------------------------------

pub struct PhotoMetadataEvidence;

impl EvidenceAnalyzer for PhotoMetadataEvidence {
    fn analyzer(&self) -> &str {
        EVIDENCE_ANALYZER
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let (options, mut notes) = Options::from_params(evidence.params());
        let mut collector = Collector::new(&options, &mut notes);
        for root in evidence.roots()? {
            let volume = evidence.volume(&root.root_id);
            if analyze_volume(&volume, evidence, &options, &mut collector)? {
                break;
            }
        }
        Ok(collector.finish())
    }
}

/// Analyzes one root. Returns true when a photo source was found here.
fn analyze_volume(
    volume: &EvidenceVolume,
    evidence: &Evidence,
    options: &Options,
    collector: &mut Collector,
) -> Result<bool> {
    let context = volume.context();
    let starts: Vec<String> = match &options.file_path {
        Some(path) => vec![path.clone()],
        None => match &options.photo_dir {
            Some(directory) => vec![directory.clone()],
            None => DEFAULT_PHOTO_DIRS.iter().map(|dir| (*dir).to_owned()).collect(),
        },
    };
    let mut found: Option<String> = None;
    for start in &starts {
        let context = context;
        context.check_cancelled()?;
        match volume.stat(start) {
            Ok(Some(_)) => {
                found = Some(start.clone());
                break;
            }
            Ok(None) => {
                collector
                    .notes
                    .push(format!("根 {} 下没有 '{start}'", volume.root_id()));
            }
            Err(error) if error.is_cancelled() => return Err(error),
            Err(error) => collector.notes.push(format!(
                "根 {} 访问 '{start}' 失败（{}: {}）",
                volume.root_id(),
                error.code,
                error.message
            )),
        }
    }
    let Some(start) = found else {
        return Ok(false);
    };
    collector.source = Some(start.clone());
    // Every emitted artifact is attributed to the root it was read from.
    collector.root_id = volume.root_id().to_owned();
    if options.file_path.is_some() {
        parse_one(volume, &start, options, collector)?;
        return Ok(true);
    }
    let mut stack: Vec<(String, usize)> = vec![(start, 0)];
    let mut directories = 0usize;
    while let Some((path, depth)) = stack.pop() {
        context.check_cancelled()?;
        if collector.reached_limit() {
            // Candidate files of directories already listed were counted when
            // they were skipped; a pending directory is not itself an unparsed
            // photo, so enumeration simply stops here.
            break;
        }
        directories += 1;
        if directories > MAX_DIRECTORIES {
            collector
                .notes
                .push(format!("目录数超过 {MAX_DIRECTORIES}，已停止枚举"));
            break;
        }
        let entries = match volume.list(&path) {
            Ok(entries) => entries,
            Err(error) if error.is_cancelled() => return Err(error),
            Err(error) => {
                collector.notes.push(format!(
                    "目录 '{path}' 无法枚举（{}: {}）",
                    error.code, error.message
                ));
                continue;
            }
        };
        for entry in entries {
            let child = format!("{path}/{}", entry.name);
            // `EvidenceNode::kind` is the LPP string form: file/dir/link/unallocated.
            match entry.kind.as_str() {
                "dir" => {
                    if entry.deleted {
                        collector.notes.push(format!("跳过已删除目录 '{child}'"));
                        continue;
                    }
                    if depth + 1 > MAX_DEPTH {
                        collector
                            .notes
                            .push(format!("目录 '{child}' 超过深度上限 {MAX_DEPTH}，未展开"));
                        continue;
                    }
                    stack.push((child, depth + 1));
                }
                "file" => {
                    if entry.deleted {
                        collector.notes.push(format!("跳过已删除文件 '{child}'"));
                        continue;
                    }
                    if format::ExtensionKind::from_name(&entry.name).is_none() {
                        continue;
                    }
                    if collector.reached_limit() {
                        collector.summary.skipped_beyond_limit += 1;
                        continue;
                    }
                    collector.candidates += 1;
                    if collector.candidates % 200 == 0 {
                        let _ = evidence.progress(
                            collector.candidates as u64,
                            Some(options.max_files as u64),
                            Some("解析照片元数据"),
                        );
                    }
                    parse_one(volume, &child, options, collector)?;
                }
                // Symlinks are not followed for traversal and unallocated
                // nodes carry no readable content.
                _ => {}
            }
        }
    }
    Ok(true)
}

fn parse_one(
    volume: &EvidenceVolume,
    path: &str,
    options: &Options,
    collector: &mut Collector,
) -> Result<()> {
    if collector.reached_limit() {
        collector.summary.skipped_beyond_limit += 1;
        return Ok(());
    }
    let context = volume.context();
    let name = path.rsplit('/').next().unwrap_or(path).to_owned();
    if format::ExtensionKind::from_name(&name).is_none() && options.file_path.is_some() {
        collector.summary.record_excluded("extension_not_photo");
        collector.issues.push(Issue {
            path: path.to_owned(),
            reason: "extension_not_photo".to_owned(),
            text: "扩展名不在 jpg/jpeg/png/heic/heif 内，未按照片解析".to_owned(),
            size: 0,
        });
        return Ok(());
    }
    let size = match volume.size(path) {
        Ok(Some(size)) => size,
        Ok(None) => {
            collector
                .notes
                .push(format!("'{path}' 在枚举后消失，已跳过"));
            return Ok(());
        }
        Err(error) if error.is_cancelled() => return Err(error),
        Err(error) => {
            collector.summary.record_failure("stat_failed");
            collector.issues.push(Issue {
                path: path.to_owned(),
                reason: "stat_failed".to_owned(),
                text: format!("读取属性失败（{}: {}）", error.code, error.message),
                size: 0,
            });
            return Ok(());
        }
    };
    if size == 0 {
        return collector.reject(path, "empty", "文件长度为 0", 0);
    }
    if size > MAX_PHOTO_BYTES {
        return collector.reject(
            path,
            "too_large",
            &format!("文件 {size} 字节超过单文件上限 {MAX_PHOTO_BYTES}"),
            size,
        );
    }
    let head = match volume.read(path, 0, Some(format::HEADER_PROBE as u64)) {
        Ok(head) => head,
        Err(error) if error.is_cancelled() => return Err(error),
        Err(error) => {
            return collector.reject(
                path,
                "read_failed",
                &format!("读取文件头失败（{}: {}）", error.code, error.message),
                size,
            )
        }
    };
    if format::sniff(&head) == format::RealFormat::Unknown {
        collector.summary.record_excluded("not_image");
        collector.issues.push(Issue {
            path: path.to_owned(),
            reason: "not_image".to_owned(),
            text: format!(
                "扩展名声称照片但文件头不是 JPEG/PNG/HEIC/HEIF（前 {} 字节：{}）",
                head.len(),
                hex(&head)
            ),
            size,
        });
        return Ok(());
    }
    let bytes = match volume.read(path, 0, Some(size)) {
        Ok(bytes) => bytes,
        Err(error) if error.is_cancelled() => return Err(error),
        Err(error) => {
            return collector.reject(
                path,
                "read_failed",
                &format!("读取文件失败（{}: {}）", error.code, error.message),
                size,
            )
        }
    };
    if bytes.len() as u64 != size {
        return collector.reject(
            path,
            "short_read",
            &format!("读取长度 {} 与声明长度 {size} 不一致", bytes.len()),
            size,
        );
    }
    let outcome = record::parse_file(path, &bytes);
    collector.absorb(outcome, path, size, context);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

struct Issue {
    path: String,
    reason: String,
    text: String,
    size: u64,
}

/// Accumulates outcomes across a run and emits bounded SDK results.
pub struct Collector {
    options: Options,
    notes: Vec<String>,
    pub summary: RunSummary,
    pub candidates: usize,
    source: Option<String>,
    root_id: String,
    records: Vec<PhotoRecord>,
    issues: Vec<Issue>,
    overflow: usize,
}

impl Collector {
    pub fn new(options: &Options, notes: &mut Vec<String>) -> Self {
        Self {
            options: options.clone(),
            notes: std::mem::take(notes),
            summary: RunSummary::default(),
            candidates: 0,
            source: None,
            root_id: String::new(),
            records: Vec::new(),
            issues: Vec::new(),
            overflow: 0,
        }
    }

    pub fn reached_limit(&self) -> bool {
        self.summary.total >= self.options.max_files
    }

    fn reject(&mut self, path: &str, reason: &str, text: &str, size: u64) -> Result<()> {
        self.summary.record_failure(reason);
        self.issues.push(Issue {
            path: path.to_owned(),
            reason: reason.to_owned(),
            text: text.to_owned(),
            size,
        });
        Ok(())
    }

    fn absorb(
        &mut self,
        outcome: Outcome,
        path: &str,
        size: u64,
        context: &lovelycarve_plugin::Context,
    ) {
        accumulate(&mut self.summary, &outcome);
        match outcome {
            Outcome::Photo(mut record) => {
                // Provenance: the record must carry the root it came from.
                record.root_id = self.root_id.clone();
                // `accumulate` already recorded `record.reason` for photos
                // without EXIF; do not count the same reason twice.
                if !record.skipped_exif.is_empty() {
                    context.log(
                        LogLevel::Debug,
                        &format!("{}: {}", record.path, record.skipped_exif.join("; ")),
                    );
                }
                if record.exif_present || self.options.include_no_exif {
                    if self.records.len() + self.issues.len() < MAX_ARTIFACTS {
                        self.records.push(*record);
                    } else {
                        self.overflow += 1;
                    }
                }
            }
            Outcome::Rejected(error) => {
                if self.records.len() + self.issues.len() < MAX_ARTIFACTS {
                    self.issues.push(Issue {
                        path: path.to_owned(),
                        reason: error.reason.to_owned(),
                        text: error.message,
                        size,
                    });
                } else {
                    self.overflow += 1;
                }
            }
            Outcome::NotPhoto { detail, .. } => {
                if self.records.len() + self.issues.len() < MAX_ARTIFACTS {
                    self.issues.push(Issue {
                        path: path.to_owned(),
                        reason: "not_image".to_owned(),
                        text: detail,
                        size,
                    });
                } else {
                    self.overflow += 1;
                }
            }
            Outcome::NotCandidate => {}
        }
    }

    /// Builds the final SDK result (summary artifact last).
    pub fn finish(mut self) -> AnalysisResult {
        if self.summary.total == 0 && self.source.is_none() {
            self.summary.finish();
            let mut summary = format!("未找到照片目录：{}", self.summary.text);
            if !self.notes.is_empty() {
                summary.push_str("；说明：");
                summary.push_str(&self.notes.join("；"));
            }
            return AnalysisResult {
                summary: Some(summary),
                ..AnalysisResult::default()
            };
        }
        self.summary.finish();
        let mut artifacts: Vec<Artifact> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        for record in &mut self.records {
            let has_issues = !record.warnings.is_empty();
            artifacts.push(report::photo_artifact(record));
            if has_issues {
                let mut attributes: Attributes = Attributes::new();
                attributes.insert("source.root", record.root_id.clone());
                attributes.insert("source.path", record.path.clone());
                attributes.insert("photo.path", record.path.clone());
                findings.push(Finding {
                    severity: Severity::Low,
                    title: format!("{} 记录不完整", record.path),
                    description: record.warnings.join("；"),
                    attributes,
                });
            }
        }
        for issue in &self.issues {
            let mut attributes: Attributes = Attributes::new();
            attributes.insert("source.root", self.root_id.clone());
            attributes.insert("source.path", issue.path.clone());
            attributes.insert("photo.path", issue.path.clone());
            attributes.insert("photo.reason", issue.reason.clone());
            attributes.insert("photo.reason_text", issue.text.clone());
            attributes.insert("photo.bytes", issue.size);
            artifacts.push(Artifact {
                artifact_type: "photo.issue".to_owned(),
                title: format!("{} [{}]", issue.path, issue.reason),
                value: Some(Value::from(issue.path.clone())),
                attributes,
            });
        }
        if self.overflow > 0 {
            self.summary.text.push_str(&format!(
                "；另有 {} 条记录因结果上限未输出（请调小 maxFiles）",
                self.overflow
            ));
        }
        let records = self.records.len();
        artifacts.push(report::summary_artifact(&self.summary, records));
        let mut summary = format!(
            "{}；起点 {}",
            self.summary.text,
            self.source.clone().unwrap_or_else(|| "-".to_owned())
        );
        if !self.notes.is_empty() {
            summary.push_str("；说明：");
            summary.push_str(&self.notes.join("；"));
        }
        let nodes = result_nodes(&artifacts);
        AnalysisResult {
            summary: Some(summary),
            nodes,
            artifacts,
            timeline: Vec::new(),
            findings,
        }
    }
}

/// Declares one result node per artifact type, with the columns that have data.
fn result_nodes(artifacts: &[Artifact]) -> Vec<ResultNode> {
    let mut types: BTreeMap<&str, usize> = BTreeMap::new();
    for artifact in artifacts {
        *types.entry(artifact.artifact_type.as_str()).or_default() += 1;
    }
    let mut nodes = Vec::new();
    for artifact_type in types.keys() {
        let (display, schema) = match *artifact_type {
            "photo.exif" => ("照片元数据(EXIF/GPS)", report::PHOTO_COLUMNS),
            "photo.issue" => ("照片解析失败/跳过", report::ISSUE_COLUMNS),
            "photo.summary" => ("照片元数据汇总", &[] as &[(&str, &str)]),
            other => {
                nodes.push(ResultNode {
                    node_type: other.to_owned(),
                    name: other.to_owned(),
                    columns: Vec::new(),
                });
                continue;
            }
        };
        let matching: Vec<&Artifact> = artifacts
            .iter()
            .filter(|artifact| artifact.artifact_type == *artifact_type)
            .collect();
        let mut columns = Vec::new();
        for (key, label) in schema.iter().take(MAX_COLUMNS) {
            if matching.iter().any(|artifact| {
                artifact
                    .attributes
                    .get(key)
                    .is_some_and(|value| !matches!(value, Value::Nil))
            }) {
                columns.push(ResultColumn {
                    key: (*key).to_owned(),
                    label: (*label).to_owned(),
                });
            }
        }
        nodes.push(ResultNode {
            node_type: (*artifact_type).to_owned(),
            name: display.to_owned(),
            columns,
        });
    }
    nodes
}

// ---------------------------------------------------------------------------
// File analyzer (single photo)
// ---------------------------------------------------------------------------

pub struct PhotoMetadataFile;

impl FileAnalyzer for PhotoMetadataFile {
    fn analyzer(&self) -> &str {
        FILE_ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        if file.size() > MAX_PHOTO_BYTES {
            return Err(lovelycarve_plugin::Error::new(
                "RESOURCE_LIMIT",
                format!("文件 {} 字节超过单文件上限 {MAX_PHOTO_BYTES}", file.size()),
            ));
        }
        let name = if file.name().is_empty() {
            "unknown".to_owned()
        } else {
            file.name().to_owned()
        };
        let length = usize::try_from(file.size()).unwrap_or(usize::MAX);
        let bytes = file.read(0, length)?;
        if bytes.len() as u64 != file.size() {
            return Err(lovelycarve_plugin::Error::new(
                "SHORT_READ",
                format!("读取 {} 字节，声明 {} 字节", bytes.len(), file.size()),
            ));
        }
        let outcome = record::parse_file(&name, &bytes);
        let mut summary = RunSummary::default();
        accumulate(&mut summary, &outcome);
        summary.finish();
        let mut artifacts = Vec::new();
        let mut findings = Vec::new();
        let result_summary;
        match outcome {
            Outcome::Photo(mut record) => {
                record.root_id = format!("file:{}", file.id());
                // `accumulate` already recorded a missing-EXIF reason; only the
                // per-record warnings are handled here.
                if !record.warnings.is_empty() {
                    let mut attributes: Attributes = Attributes::new();
                    attributes.insert("source.path", record.path.clone());
                    attributes.insert("photo.path", record.path.clone());
                    findings.push(Finding {
                        severity: Severity::Low,
                        title: format!("{} 记录不完整", record.path),
                        description: record.warnings.join("；"),
                        attributes,
                    });
                }
                artifacts.push(report::photo_artifact(&record));
                summary.finish();
                result_summary = summary.text.clone();
            }
            Outcome::Rejected(error) => {
                result_summary = format!("解析失败[{}]：{}", error.reason, error.message);
                artifacts.push(issue_artifact(&name, error.reason, &error.message, file.size()));
            }
            Outcome::NotPhoto { detail, format } => {
                result_summary = format!("非图片内容：{detail}");
                artifacts.push(issue_artifact(&name, "not_image", &detail, file.size()));
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: format!("{name} 扩展名与内容不符"),
                    description: format!(
                        "扩展名声称照片，真实格式 {}（{}）",
                        format.label(),
                        detail
                    ),
                    attributes: [("source.path", name.as_str())]
                        .into_iter()
                        .collect(),
                });
            }
            Outcome::NotCandidate => {
                result_summary = "扩展名不在 jpg/jpeg/png/heic/heif 内，未按照片解析".to_owned();
                artifacts.push(issue_artifact(
                    &name,
                    "extension_not_photo",
                    &result_summary,
                    file.size(),
                ));
            }
        }
        let nodes = result_nodes(&artifacts);
        Ok(AnalysisResult {
            summary: Some(format!("{result_summary}；文件 {name}")),
            nodes,
            artifacts,
            timeline: Vec::new(),
            findings,
        })
    }
}

fn issue_artifact(path: &str, reason: &str, text: &str, size: u64) -> Artifact {
    let mut attributes: Attributes = Attributes::new();
    attributes.insert("source.path", path);
    attributes.insert("photo.path", path);
    attributes.insert("photo.reason", reason);
    attributes.insert("photo.reason_text", text);
    attributes.insert("photo.bytes", size);
    Artifact {
        artifact_type: "photo.issue".to_owned(),
        title: format!("{path} [{reason}]"),
        value: Some(Value::from(path)),
        attributes,
    }
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, env!("CARGO_PKG_VERSION"))
        .evidence_analyzer(PhotoMetadataEvidence)
        .file_analyzer(PhotoMetadataFile)
}

export_plugin!(plugin);
