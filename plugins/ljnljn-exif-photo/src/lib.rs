//! Photo format detection and EXIF/GPS metadata (LPP v2).
//!
//! Port of the v1 `ljnljn.exif-photo` analyzers. The container walker, TIFF
//! reader, field interpreter and format sniffer are carried over unchanged
//! (`container`, `exif`, `fields`, `format`, `record`, `sha256`); this crate
//! adds typed records and two LPP v2 analyzers:
//!
//! - `exif_files` (scope `files`): every selected jpg/jpeg/png/heic/heif file;
//! - `exif_evidence` (scope `evidence`): recursive walk of the evidence view
//!   (depth ≤ [`MAX_DEPTH`], at most [`MAX_DIRECTORIES`] directories), parsing
//!   each photo candidate with the same code path.
//!
//! Preserved behavior:
//! - the extension decides candidacy, the file header decides the real format;
//!   a mismatch is recorded and the real format is parsed;
//! - EXIF `DateTimeOriginal` stays verbatim in `datetime_original_raw`;
//!   `capture_time` is a *local* wall-clock timestamp (no offset) and is not
//!   time-zone shifted. The declared `OffsetTimeOriginal`, when present, is
//!   recorded next to it and never applied;
//! - GPS degrees/minutes/seconds are converted to signed decimal degrees,
//!   with the sign coming only from the N/S/E/W reference;
//! - truncated, cyclic or out-of-bounds EXIF rejects the file with an explicit
//!   issue record instead of emitting empty fields;
//! - HEIC/HEIF are identified by magic; their ISO-BMFF EXIF is not parsed.
//!
//! `include_no_exif` (default true) keeps photos without EXIF as records;
//! `max_files` (default 5000, ceiling 20000) bounds every run.

mod container;
pub mod exif;
pub mod fields;
mod format;
mod record;
mod sha256;

#[cfg(test)]
pub mod fixtures;
#[cfg(test)]
mod tests;

use lovelycarve_plugin::{
    export_plugin, FileRef, Plugin, Record, Result, Run, Timestamp, Value, View,
};

use crate::fields::{Coordinate, MetadataFields, Origin};
use crate::format::{ExtensionKind, RealFormat};
use crate::record::{parse_file, Outcome, PhotoRecord, RunSummary};

/// File-scope analyzer id (must match `plugin.toml`).
pub const ANALYZER_FILES: &str = "exif_files";
/// Evidence-scope analyzer id (must match `plugin.toml`).
pub const ANALYZER_EVIDENCE: &str = "exif_evidence";
/// Default cap of parsed photo candidates per run.
pub const DEFAULT_MAX_FILES: usize = 5000;
/// Absolute cap of parsed photo candidates per run.
pub const MAX_FILES_CEILING: usize = 20_000;
/// Photos larger than this are rejected and recorded.
pub const MAX_PHOTO_BYTES: u64 = 64 * 1024 * 1024;
/// Bounded recursion for the evidence walk.
pub const MAX_DEPTH: usize = 24;
/// Bounded directory count for the evidence walk.
pub const MAX_DIRECTORIES: usize = 50_000;
/// Host-accepted records per run; the remainder is counted.
const MAX_EMIT_RECORDS: usize = 9_000;

/// One photo's metadata.
#[derive(Record)]
#[record(id = "photo.exif", label = "照片元数据", title = "{path} ({format})")]
struct PhotoRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "文件名")]
    name: String,
    #[field(
        label = "真实格式",
        kind = "enum",
        choices = "jpeg=JPEG,png=PNG,heic=HEIC,heif=HEIF,unknown=Unknown"
    )]
    format: String,
    #[field(label = "容器")]
    container: String,
    #[field(label = "声明扩展名")]
    declared_extension: String,
    #[field(label = "扩展名与格式不符")]
    extension_mismatch: bool,
    #[field(label = "字节长度", kind = "size")]
    size: u64,
    #[field(label = "SHA-256", kind = "hash")]
    sha256: String,
    #[field(label = "含 EXIF")]
    exif_present: bool,
    #[field(label = "含 GPS")]
    gps_present: bool,
    #[field(label = "GPS 参考缺失（按正值输出）")]
    gps_ref_defaulted: bool,
    #[field(label = "拍摄时间（原值）")]
    datetime_original_raw: Option<String>,
    #[field(label = "拍摄时间偏移（原值，未应用）")]
    datetime_original_offset: Option<String>,
    #[field(label = "拍摄时间精度")]
    datetime_original_precision: Option<String>,
    #[field(label = "拍摄时间（本地墙钟）")]
    capture_time: Option<Timestamp>,
    #[field(label = "修改时间（原值）")]
    datetime_raw: Option<String>,
    #[field(label = "数字化时间（原值）")]
    datetime_digitized_raw: Option<String>,
    #[field(label = "厂商")]
    make: Option<String>,
    #[field(label = "机型")]
    model: Option<String>,
    #[field(label = "镜头")]
    lens_model: Option<String>,
    #[field(label = "软件")]
    software: Option<String>,
    #[field(label = "宽")]
    image_width: Option<i64>,
    #[field(label = "高")]
    image_height: Option<i64>,
    #[field(label = "PNG 宽")]
    png_width: Option<i64>,
    #[field(label = "PNG 高")]
    png_height: Option<i64>,
    #[field(label = "方向")]
    orientation: Option<i64>,
    #[field(label = "方向说明")]
    orientation_label: Option<String>,
    #[field(label = "纬度参考")]
    latitude_ref: Option<String>,
    #[field(label = "纬度（度分秒）")]
    latitude_dms: Option<String>,
    #[field(label = "纬度（十进制度）")]
    latitude_decimal: Option<f64>,
    #[field(label = "经度参考")]
    longitude_ref: Option<String>,
    #[field(label = "经度（度分秒）")]
    longitude_dms: Option<String>,
    #[field(label = "经度（十进制度）")]
    longitude_decimal: Option<f64>,
    #[field(label = "海拔（米，按参考修正）")]
    altitude: Option<f64>,
    #[field(label = "海拔原值（米）")]
    altitude_raw: Option<f64>,
    #[field(label = "海拔参考")]
    altitude_ref: Option<String>,
    #[field(label = "GPS 时间")]
    gps_timestamp: Option<String>,
    #[field(label = "GPS 日期")]
    gps_datestamp: Option<String>,
    #[field(label = "GPS 卫星")]
    gps_satellites: Option<String>,
    #[field(label = "缺失字段", kind = "list")]
    missing: Vec<String>,
    #[field(label = "字段来源偏移")]
    origin: Option<String>,
    #[field(label = "EXIF 载体")]
    exif_carrier: Option<String>,
    #[field(label = "容器偏移", kind = "size")]
    container_offset: Option<u64>,
    #[field(label = "TIFF 偏移", kind = "size")]
    tiff_offset: Option<u64>,
    #[field(label = "字节序")]
    byte_order: Option<String>,
    #[field(label = "IFD 偏移")]
    ifd_offsets: Option<String>,
    #[field(label = "EXIF 标签数")]
    tag_count: i64,
    #[field(label = "EXIF 候选段数")]
    exif_candidates: i64,
    #[field(label = "跳过的 EXIF 项", kind = "list")]
    exif_skipped: Vec<String>,
    #[field(label = "XMP 偏移", kind = "size")]
    xmp_offset: Option<u64>,
    #[field(label = "XMP 创建时间")]
    xmp_date: Option<String>,
    #[field(label = "XMP 工具")]
    xmp_tool: Option<String>,
    #[field(label = "XMP 被截断")]
    xmp_truncated: bool,
    #[field(label = "PNG 文本块", kind = "list")]
    png_texts: Vec<String>,
    #[field(label = "记录完整")]
    complete: bool,
    #[field(label = "警告", kind = "list")]
    warnings: Vec<String>,
}

/// A file that could not be parsed as a photo.
#[derive(Record)]
#[record(
    id = "photo.issue",
    label = "照片解析失败/跳过",
    title = "{path} [{code}]"
)]
struct IssueRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "原因代码")]
    code: String,
    #[field(label = "原因说明")]
    reason_text: String,
    #[field(label = "字节长度", kind = "size")]
    size: u64,
}

/// Run-level counters (same definitions as the v1 summary artifact).
#[derive(Record)]
#[record(
    id = "photo.summary",
    label = "照片元数据汇总",
    title = "{analyzer} · {scope}"
)]
struct SummaryRow {
    #[field(label = "作用域", key)]
    scope: String,
    #[field(label = "分析器")]
    analyzer: String,
    #[field(label = "文件数")]
    files: i64,
    #[field(label = "含 EXIF")]
    with_exif: i64,
    #[field(label = "含 GPS")]
    with_gps: i64,
    #[field(label = "无 GPS")]
    without_gps: i64,
    #[field(label = "无 EXIF")]
    without_exif: i64,
    #[field(label = "解析失败")]
    failed: i64,
    #[field(label = "非图片/扩展名不符跳过")]
    excluded_non_image: i64,
    #[field(label = "超出上限未解析")]
    skipped_beyond_limit: i64,
    #[field(label = "失败原因（代码×次数）", kind = "list")]
    reasons: Vec<String>,
    #[field(label = "汇总说明")]
    text: String,
}

struct RunOptions {
    include_no_exif: bool,
    max_files: usize,
}

impl RunOptions {
    fn read(run: &Run) -> Self {
        let include_no_exif = run
            .options()
            .get("include_no_exif")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let max_files = run
            .options()
            .get("max_files")
            .and_then(|value| {
                value
                    .as_str()
                    .and_then(|text| text.trim().parse::<usize>().ok())
                    .or_else(|| value.as_u64().map(|value| value as usize))
            })
            .unwrap_or(DEFAULT_MAX_FILES)
            .clamp(1, MAX_FILES_CEILING);
        Self {
            include_no_exif,
            max_files,
        }
    }
}

struct Emitter<'a> {
    run: &'a Run,
    options: RunOptions,
    summary: RunSummary,
    records: usize,
    overflow: usize,
}

impl<'a> Emitter<'a> {
    fn new(run: &'a Run, options: RunOptions) -> Self {
        Self {
            run,
            options,
            summary: RunSummary::default(),
            records: 0,
            overflow: 0,
        }
    }

    fn emit_issue(
        &mut self,
        file: Option<&FileRef>,
        path: &str,
        code: &str,
        text: &str,
        size: u64,
    ) -> Result<()> {
        if self.records >= MAX_EMIT_RECORDS {
            self.overflow += 1;
            return Ok(());
        }
        let record = IssueRow {
            path: path.to_owned(),
            code: code.to_owned(),
            reason_text: text.to_owned(),
            size,
        };
        let mut emit = self.run.record(&record);
        if let Some(file) = file {
            emit = emit.from(file);
        }
        emit.note(format!("{path} [{code}]")).emit()?;
        self.records += 1;
        Ok(())
    }

    fn absorb(
        &mut self,
        outcome: Outcome,
        file: Option<&FileRef>,
        display: &str,
        size: u64,
    ) -> Result<()> {
        match outcome {
            Outcome::Photo(record) => {
                record::accumulate(&mut self.summary, &Outcome::Photo(record.clone()));
                if record.exif_present || self.options.include_no_exif {
                    self.emit_photo(file, display, &record)?;
                }
                Ok(())
            }
            Outcome::Rejected(error) => {
                self.summary.record_failure(error.reason);
                self.emit_issue(file, display, error.reason, &error.message, size)
            }
            Outcome::NotPhoto { format, detail } => {
                self.summary.record_excluded("not_image");
                self.emit_issue(
                    file,
                    display,
                    "not_image",
                    &format!("{}：{detail}", format.label()),
                    size,
                )
            }
            Outcome::NotCandidate => {
                self.summary.record_excluded("extension_not_photo");
                self.emit_issue(
                    file,
                    display,
                    "extension_not_photo",
                    "扩展名不在 jpg/jpeg/png/heic/heif 内，未按照片解析",
                    size,
                )
            }
        }
    }

    fn emit_photo(
        &mut self,
        file: Option<&FileRef>,
        display: &str,
        record: &PhotoRecord,
    ) -> Result<()> {
        if self.records >= MAX_EMIT_RECORDS {
            self.overflow += 1;
            return Ok(());
        }
        let row = photo_row(display, record);
        let mut emit = self.run.record(&row);
        if let Some(file) = file {
            emit = emit.from(file);
        }
        emit.note(format!(
            "{}；{}；{}",
            record.path,
            record.format.label(),
            record.sha256
        ))
        .emit()?;
        self.records += 1;
        Ok(())
    }

    fn finish(mut self, scope: &str, analyzer: &str) -> Result<()> {
        self.summary.finish();
        if self.overflow > 0 {
            self.summary.text.push_str(&format!(
                "；另有 {} 条记录因结果上限未输出（请调小 max_files）",
                self.overflow
            ));
        }
        let reasons: Vec<String> = self
            .summary
            .reasons
            .iter()
            .map(|(code, count)| format!("{code}×{count}"))
            .collect();
        let row = SummaryRow {
            scope: scope.to_owned(),
            analyzer: analyzer.to_owned(),
            files: self.summary.total as i64,
            with_exif: self.summary.with_exif as i64,
            with_gps: self.summary.with_gps as i64,
            without_gps: self.summary.without_gps as i64,
            without_exif: self.summary.without_exif as i64,
            failed: self.summary.failed as i64,
            excluded_non_image: self.summary.excluded_non_image as i64,
            skipped_beyond_limit: self.summary.skipped_beyond_limit as i64,
            reasons,
            text: self.summary.text.clone(),
        };
        self.run.record(&row).emit()?;
        self.run.set_summary(self.summary.text);
        Ok(())
    }
}

fn photo_row(display: &str, record: &PhotoRecord) -> PhotoRow {
    let metadata = &record.fields;
    let latitude = metadata.latitude.as_ref();
    let longitude = metadata.longitude.as_ref();
    let altitude = metadata.altitude.as_ref();
    let (png_width, png_height) = metadata
        .png_dimensions
        .map(|(width, height)| (Some(i64::from(width)), Some(i64::from(height))))
        .unwrap_or((None, None));
    let mut png_texts: Vec<String> = record
        .png_texts
        .iter()
        .map(|text| {
            format!(
                "{}@0x{:x}={}{}",
                text.chunk_type,
                text.offset,
                text.key,
                if text.truncated {
                    "(未解压/已截断)"
                } else {
                    ""
                }
            )
        })
        .collect();
    png_texts.truncate(4096);
    PhotoRow {
        path: display.to_owned(),
        name: record.name.clone(),
        format: match record.format {
            RealFormat::Jpeg => "jpeg",
            RealFormat::Png => "png",
            RealFormat::Heic => "heic",
            RealFormat::Heif => "heif",
            RealFormat::Unknown => "unknown",
        }
        .to_owned(),
        container: record.container.clone(),
        declared_extension: record.extension.label().to_owned(),
        extension_mismatch: record.extension_mismatch,
        size: record.size,
        sha256: record.sha256.clone(),
        exif_present: record.exif_present,
        gps_present: metadata.has_gps(),
        gps_ref_defaulted: latitude.map(|c| c.ref_defaulted).unwrap_or(false)
            || longitude.map(|c| c.ref_defaulted).unwrap_or(false)
            || altitude.map(|a| a.ref_defaulted).unwrap_or(false),
        datetime_original_raw: metadata
            .datetime_original
            .as_ref()
            .map(|time| time.raw.clone()),
        datetime_original_offset: metadata
            .datetime_original
            .as_ref()
            .and_then(|time| time.offset_time.clone()),
        datetime_original_precision: metadata
            .datetime_original
            .as_ref()
            .map(|time| time.precision.to_owned()),
        capture_time: metadata
            .datetime_original
            .as_ref()
            .and_then(|time| exif_local_timestamp(&time.raw)),
        datetime_raw: metadata.datetime.as_ref().map(|time| time.raw.clone()),
        datetime_digitized_raw: metadata
            .datetime_digitized
            .as_ref()
            .map(|time| time.raw.clone()),
        make: metadata.make.as_ref().map(|value| value.value.clone()),
        model: metadata.model.as_ref().map(|value| value.value.clone()),
        lens_model: metadata
            .lens_model
            .as_ref()
            .map(|value| value.value.clone()),
        software: metadata.software.as_ref().map(|value| value.value.clone()),
        image_width: metadata
            .image_width
            .as_ref()
            .map(|(width, _)| *width as i64),
        image_height: metadata
            .image_height
            .as_ref()
            .map(|(height, _)| *height as i64),
        png_width,
        png_height,
        orientation: metadata
            .orientation
            .as_ref()
            .map(|(code, _, _)| i64::from(*code)),
        orientation_label: metadata
            .orientation
            .as_ref()
            .map(|(_, label, _)| label.clone()),
        latitude_ref: latitude.and_then(|coordinate| coordinate.reference.clone()),
        latitude_dms: latitude.map(dms_text),
        latitude_decimal: latitude.map(|coordinate| coordinate.decimal),
        longitude_ref: longitude.and_then(|coordinate| coordinate.reference.clone()),
        longitude_dms: longitude.map(dms_text),
        longitude_decimal: longitude.map(|coordinate| coordinate.decimal),
        altitude: altitude.map(|altitude| altitude.signed_meters),
        altitude_raw: altitude.map(|altitude| altitude.meters),
        altitude_ref: altitude.and_then(|altitude| altitude.reference.clone()),
        gps_timestamp: metadata.gps_timestamp.clone(),
        gps_datestamp: metadata.gps_datestamp.clone(),
        gps_satellites: metadata
            .gps_satellites
            .as_ref()
            .map(|value| value.value.clone()),
        missing: metadata
            .missing()
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        origin: Some(collect_origins(metadata).join("; ")).filter(|text| !text.is_empty()),
        exif_carrier: record
            .exif_block
            .as_ref()
            .map(|block| block.carrier.to_owned()),
        container_offset: record
            .exif_block
            .as_ref()
            .map(|block| u64::from(block.container_offset)),
        tiff_offset: record
            .exif_block
            .as_ref()
            .map(|block| u64::from(block.tiff_offset)),
        byte_order: record
            .exif_block
            .as_ref()
            .map(|block| block.block.byte_order.to_owned()),
        ifd_offsets: record.exif_block.as_ref().map(|block| {
            block
                .block
                .ifd_offsets
                .iter()
                .map(|(kind, offset)| format!("{}@0x{offset:x}", kind.label()))
                .collect::<Vec<_>>()
                .join(",")
        }),
        tag_count: record
            .exif_block
            .as_ref()
            .map(|block| block.block.tags.len() as i64)
            .unwrap_or(0),
        exif_candidates: record.exif_candidates as i64,
        exif_skipped: record.skipped_exif.clone(),
        xmp_offset: record.xmp.as_ref().map(|xmp| u64::from(xmp.offset)),
        xmp_date: record.xmp.as_ref().and_then(|xmp| xmp.date_created.clone()),
        xmp_tool: record.xmp.as_ref().and_then(|xmp| xmp.creator_tool.clone()),
        xmp_truncated: record
            .xmp
            .as_ref()
            .map(|xmp| xmp.packet_truncated)
            .unwrap_or(false),
        png_texts,
        complete: record.warnings.is_empty(),
        warnings: record.warnings.clone(),
    }
}

fn dms_text(coordinate: &Coordinate) -> String {
    format!(
        "{}°{}′{:.2}″",
        coordinate.degrees, coordinate.minutes, coordinate.seconds
    )
}

fn collect_origins(metadata: &MetadataFields) -> Vec<String> {
    let mut origins = Vec::new();
    let mut push = |label: &str, origin: Option<&Origin>| {
        if let Some(origin) = origin {
            origins.push(format!("{label}={}", origin.locator()));
        }
    };
    push(
        "datetime_original",
        metadata.datetime_original.as_ref().map(|time| &time.origin),
    );
    push("make", metadata.make.as_ref().map(|value| &value.origin));
    push("model", metadata.model.as_ref().map(|value| &value.origin));
    push(
        "lens_model",
        metadata.lens_model.as_ref().map(|value| &value.origin),
    );
    push("image_width", metadata.image_width.as_ref().map(|(_, o)| o));
    push(
        "image_height",
        metadata.image_height.as_ref().map(|(_, o)| o),
    );
    push(
        "orientation",
        metadata.orientation.as_ref().map(|(_, _, o)| o),
    );
    push("latitude", metadata.latitude.as_ref().map(|c| &c.origin));
    push(
        "latitude_ref",
        metadata
            .latitude
            .as_ref()
            .and_then(|c| c.reference_origin.as_ref()),
    );
    push("longitude", metadata.longitude.as_ref().map(|c| &c.origin));
    push(
        "longitude_ref",
        metadata
            .longitude
            .as_ref()
            .and_then(|c| c.reference_origin.as_ref()),
    );
    push("altitude", metadata.altitude.as_ref().map(|c| &c.origin));
    push(
        "altitude_ref",
        metadata
            .altitude
            .as_ref()
            .and_then(|c| c.reference_origin.as_ref()),
    );
    origins
}

/// Parses the EXIF `YYYY:MM:DD HH:MM:SS` shape into a time-zone-less local
/// timestamp. Invalid or partial values yield `None`; the raw text is always
/// kept in the record.
fn exif_local_timestamp(raw: &str) -> Option<Timestamp> {
    let (date, time) = raw.trim().split_once(' ')?;
    let mut date_parts = date.split(':');
    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;
    let second_text = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    let second: u32 = second_text
        .split('.')
        .next()
        .and_then(|value| value.parse().ok())?;
    Timestamp::local(year, month, day, hour, minute, second)
}

fn exif_files(run: &Run) -> Result<()> {
    if run.inputs().is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "没有选中任何照片（分析器声明扩展名 jpg、jpeg、png、heic、heif）",
        )?;
        run.set_summary("未找到可分析的照片");
        return Ok(());
    }
    let options = RunOptions::read(run);
    let mut emitter = Emitter::new(run, options);
    for file in run.inputs() {
        run.check_cancelled()?;
        let display = display_name(file);
        let outcome = parse_one(file, &display)?;
        emitter.absorb(outcome, Some(file), &display, file.size())?;
    }
    emitter.finish("files", ANALYZER_FILES)
}

fn exif_evidence(run: &Run) -> Result<()> {
    let view = run.require_view()?;
    let options = RunOptions::read(run);
    let max_files = options.max_files;
    let mut emitter = Emitter::new(run, options);
    let collected = collect_photos(run, view, max_files)?;
    if collected.over_limit > 0 {
        emitter.summary.skipped_beyond_limit += collected.over_limit;
    }
    if collected.depth_limited > 0 {
        run.warn(
            "DEPTH_LIMIT",
            format!(
                "{} 个目录超过深度上限 {MAX_DEPTH}，未展开",
                collected.depth_limited
            ),
        )?;
    }
    if collected.walk_failures > 0 {
        run.warn(
            "WALK_FAILED",
            format!("{} 个目录无法枚举，已跳过", collected.walk_failures),
        )?;
    }
    if collected.paths.is_empty() {
        run.warn(
            "NO_PHOTO_FOUND",
            format!(
                "遍历 {} 个目录后未找到 jpg/jpeg/png/heic/heif 文件",
                collected.directories
            ),
        )?;
    }
    let total = collected.paths.len();
    for (index, path) in collected.paths.iter().enumerate() {
        run.check_cancelled()?;
        if index % 200 == 0 {
            run.progress(index as u64 + 1, Some(total as u64), Some(path))?;
        }
        let Some(file) = view.open(path)? else {
            emitter.summary.record_failure("not_found");
            emitter.emit_issue(
                None,
                path,
                "not_found",
                "枚举后文件不再存在或不是普通文件",
                0,
            )?;
            continue;
        };
        let size = file.size();
        if size == 0 {
            emitter.summary.record_failure("empty");
            emitter.emit_issue(Some(&file), path, "empty", "文件长度为 0", 0)?;
            continue;
        }
        let outcome = parse_one(&file, path)?;
        emitter.absorb(outcome, Some(&file), path, size)?;
    }
    emitter.finish("evidence", ANALYZER_EVIDENCE)
}

fn parse_one(file: &FileRef, display: &str) -> Result<Outcome> {
    if file.size() == 0 {
        return Ok(Outcome::Rejected(container::ContainerError::new(
            exif::reason::TRUNCATED,
            "文件为空",
        )));
    }
    if file.size() > MAX_PHOTO_BYTES {
        return Ok(Outcome::Rejected(container::ContainerError::new(
            "too_large",
            format!("文件 {} 字节超过单文件上限 {MAX_PHOTO_BYTES}", file.size()),
        )));
    }
    let bytes = match file.read_all(MAX_PHOTO_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(Outcome::Rejected(container::ContainerError::new(
                "read_failed",
                format!("读取失败（{}）", error.message),
            )));
        }
    };
    Ok(parse_file(display, &bytes))
}

struct CollectedPhotos {
    paths: Vec<String>,
    directories: usize,
    over_limit: usize,
    depth_limited: usize,
    walk_failures: usize,
}

/// Recursive evidence walk. Candidates are selected by extension only; the
/// real format check happens after reading the file header.
fn collect_photos(run: &Run, view: &View, max_files: usize) -> Result<CollectedPhotos> {
    let mut paths = Vec::new();
    let mut directories = 0usize;
    let mut over_limit = 0usize;
    let mut depth_limited = 0usize;
    let mut walk_failures = 0usize;
    let mut stack = vec![(String::new(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        run.check_cancelled()?;
        directories += 1;
        if directories > MAX_DIRECTORIES {
            run.warn(
                "DIRECTORY_LIMIT",
                format!("目录数超过 {MAX_DIRECTORIES}，已停止枚举"),
            )?;
            break;
        }
        let nodes = match view.list(&directory) {
            Ok(nodes) => nodes,
            Err(error) if error.is_cancelled() => return Err(error),
            Err(_) => {
                walk_failures += 1;
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
                if depth < MAX_DEPTH {
                    stack.push((child, depth + 1));
                } else {
                    depth_limited += 1;
                }
                continue;
            }
            if !node.is_file() || node.size == 0 {
                continue;
            }
            if ExtensionKind::from_name(&node.name).is_none() {
                continue;
            }
            if paths.len() >= max_files {
                over_limit += 1;
                continue;
            }
            paths.push(child);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(CollectedPhotos {
        paths,
        directories,
        over_limit,
        depth_limited,
        walk_failures,
    })
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
    Plugin::new("org.ljnljn.exif-photo")
        .record::<PhotoRow>()
        .record::<IssueRow>()
        .record::<SummaryRow>()
        .analyzer(ANALYZER_FILES, exif_files)
        .analyzer(ANALYZER_EVIDENCE, exif_evidence)
}

export_plugin!(plugin);
