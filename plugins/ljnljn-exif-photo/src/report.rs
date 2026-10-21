//! 结果装配：把一张照片的解析结论转换成 LPP v1 的 `Artifact`（含来源属性）。

use lovelycarve_plugin::{Artifact, Attributes, Value};

use crate::fields::{Coordinate, MetadataFields, Origin};
use crate::record::PhotoRecord;

/// Namespace prefix of every artifact type and attribute key.
pub const NS: &str = "photo";

pub fn photo_artifact_type() -> String {
    format!("{NS}.exif")
}

/// Record columns declared in `AnalysisResult::nodes` (key, Chinese label).
pub const PHOTO_COLUMNS: &[(&str, &str)] = &[
    ("photo.path", "源文件路径"),
    ("photo.format", "真实格式"),
    ("photo.bytes", "字节长度"),
    ("photo.sha256", "SHA-256"),
    ("photo.datetime_original", "拍摄时间(原值)"),
    ("photo.make", "厂商"),
    ("photo.model", "机型"),
    ("photo.lens_model", "镜头"),
    ("photo.image_width", "宽"),
    ("photo.image_height", "高"),
    ("photo.orientation", "方向"),
    ("photo.latitude_ref", "纬度参考"),
    ("photo.latitude_dms", "纬度(度分秒)"),
    ("photo.latitude_decimal", "纬度(十进制度)"),
    ("photo.longitude_ref", "经度参考"),
    ("photo.longitude_dms", "经度(度分秒)"),
    ("photo.longitude_decimal", "经度(十进制度)"),
    ("photo.altitude", "海拔(米)"),
    ("photo.altitude_ref", "海拔参考"),
    ("photo.missing", "缺失字段"),
    ("photo.origin", "来源偏移"),
    ("photo.tiff_offset", "TIFF 偏移"),
    ("photo.byte_order", "字节序"),
    ("photo.complete", "记录完整"),
    ("source.path", "证据路径"),
];

/// Column list for the container-failure table.
pub const ISSUE_COLUMNS: &[(&str, &str)] = &[
    ("photo.path", "源文件路径"),
    ("photo.reason", "原因代码"),
    ("photo.reason_text", "原因说明"),
    ("photo.bytes", "字节长度"),
    ("source.path", "证据路径"),
];

fn text_attr(attributes: &mut Attributes, key: &str, value: Option<&str>) {
    match value {
        Some(value) => attributes.insert(key, value),
        None => attributes.insert(key, Value::Nil),
    }
}

fn number_attr(attributes: &mut Attributes, key: &str, value: Option<f64>) {
    match value {
        Some(value) => attributes.insert(key, value),
        None => attributes.insert(key, Value::Nil),
    }
}

/// Builds the one artifact of a successfully parsed photo.
pub fn photo_artifact(record: &PhotoRecord) -> Artifact {
    let metadata = &record.fields;
    let mut attributes = Attributes::new();
    text_attr(&mut attributes, "photo.path", Some(record.path.as_str()));
    text_attr(&mut attributes, "photo.name", Some(record.name.as_str()));
    text_attr(&mut attributes, "source.root", Some(record.root_id.as_str()));
    text_attr(&mut attributes, "source.path", Some(record.path.as_str()));
    attributes.insert("photo.format", record.format.label());
    attributes.insert("photo.container", record.container.as_str());
    attributes.insert("photo.bytes", record.size);
    text_attr(&mut attributes, "photo.sha256", Some(record.sha256.as_str()));
    text_attr(&mut attributes, "photo.declared_ext", Some(record.extension.label()));
    attributes.insert("photo.ext_mismatch", record.extension_mismatch);
    attributes.insert("photo.exif", record.exif_present);
    attributes.insert("photo.gps", metadata.has_gps());

    text_attr(
        &mut attributes,
        "photo.datetime_original",
        metadata
            .datetime_original
            .as_ref()
            .map(|time| time.raw.as_str()),
    );
    text_attr(
        &mut attributes,
        "photo.datetime_original_offset",
        metadata
            .datetime_original
            .as_ref()
            .and_then(|time| time.offset_time.as_deref()),
    );
    text_attr(
        &mut attributes,
        "photo.datetime_original_precision",
        metadata
            .datetime_original
            .as_ref()
            .map(|time| time.precision),
    );
    text_attr(
        &mut attributes,
        "photo.datetime",
        metadata.datetime.as_ref().map(|time| time.raw.as_str()),
    );
    text_attr(
        &mut attributes,
        "photo.datetime_digitized",
        metadata
            .datetime_digitized
            .as_ref()
            .map(|time| time.raw.as_str()),
    );
    text_attr(&mut attributes, "photo.make", metadata.make.as_ref().map(|v| v.value.as_str()));
    text_attr(&mut attributes, "photo.model", metadata.model.as_ref().map(|v| v.value.as_str()));
    text_attr(
        &mut attributes,
        "photo.lens_model",
        metadata.lens_model.as_ref().map(|v| v.value.as_str()),
    );
    text_attr(
        &mut attributes,
        "photo.software",
        metadata.software.as_ref().map(|v| v.value.as_str()),
    );
    match &metadata.image_width {
        Some((width, _)) => attributes.insert("photo.image_width", *width),
        None => attributes.insert("photo.image_width", Value::Nil),
    }
    match &metadata.image_height {
        Some((height, _)) => attributes.insert("photo.image_height", *height),
        None => attributes.insert("photo.image_height", Value::Nil),
    }
    match &metadata.orientation {
        Some((code, label, _)) => {
            attributes.insert("photo.orientation", u64::from(*code));
            attributes.insert("photo.orientation_raw", *code);
            attributes.insert("photo.orientation_label", label.as_str());
        }
        None => {
            attributes.insert("photo.orientation", Value::Nil);
            attributes.insert("photo.orientation_label", Value::Nil);
        }
    }
    if let Some((width, height)) = metadata.png_dimensions {
        attributes.insert("photo.png_width", u64::from(width));
        attributes.insert("photo.png_height", u64::from(height));
    }

    let latitude = metadata.latitude.as_ref();
    let longitude = metadata.longitude.as_ref();
    let altitude = metadata.altitude.as_ref();
    text_attr(
        &mut attributes,
        "photo.latitude_ref",
        latitude.and_then(|c| c.reference.as_deref()),
    );
    text_attr(&mut attributes, "photo.latitude_dms", latitude.map(dms_text).as_deref());
    text_attr(
        &mut attributes,
        "photo.latitude_raw",
        latitude.map(|c| c.origin.locator()).as_deref(),
    );
    number_attr(
        &mut attributes,
        "photo.latitude_decimal",
        latitude.map(|c| c.decimal),
    );
    text_attr(
        &mut attributes,
        "photo.longitude_ref",
        longitude.and_then(|c| c.reference.as_deref()),
    );
    text_attr(&mut attributes, "photo.longitude_dms", longitude.map(dms_text).as_deref());
    text_attr(
        &mut attributes,
        "photo.longitude_raw",
        longitude.map(|c| c.origin.locator()).as_deref(),
    );
    number_attr(
        &mut attributes,
        "photo.longitude_decimal",
        longitude.map(|c| c.decimal),
    );
    match altitude {
        Some(altitude) => {
            attributes.insert("photo.altitude", altitude.signed_meters);
            attributes.insert("photo.altitude_raw", altitude.meters);
            text_attr(
                &mut attributes,
                "photo.altitude_ref",
                altitude.reference.as_deref(),
            );
        }
        None => {
            attributes.insert("photo.altitude", Value::Nil);
            attributes.insert("photo.altitude_ref", Value::Nil);
        }
    }
    text_attr(&mut attributes, "photo.gps_timestamp", metadata.gps_timestamp.as_deref());
    text_attr(&mut attributes, "photo.gps_datestamp", metadata.gps_datestamp.as_deref());
    text_attr(
        &mut attributes,
        "photo.gps_satellites",
        metadata.gps_satellites.as_ref().map(|v| v.value.as_str()),
    );
    let missing = metadata.missing();
    attributes.insert(
        "photo.missing",
        Value::Array(missing.iter().map(|name| Value::from(*name)).collect()),
    );

    // Provenance: where each interpreted field lives in the file.
    let origins = collect_origins(metadata);
    attributes.insert("photo.origin", origins.join("; "));
    if let Some(block) = &record.exif_block {
        attributes.insert("photo.exif_carrier", block.carrier);
        attributes.insert("photo.container_offset", u64::from(block.container_offset));
        attributes.insert("photo.tiff_offset", u64::from(block.tiff_offset));
        attributes.insert("photo.ifd0_offset", u64::from(block.block.ifd0_offset));
        attributes.insert("photo.byte_order", block.block.byte_order);
        attributes.insert(
            "photo.ifd_offsets",
            block
                .block
                .ifd_offsets
                .iter()
                .map(|(kind, offset)| format!("{}@0x{offset:x}", kind.label()))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    attributes.insert(
        "photo.tag_count",
        record
            .exif_block
            .as_ref()
            .map(|block| block.block.tags.len() as u64)
            .unwrap_or(0),
    );
    if !record.warnings.is_empty() {
        attributes.insert(
            "photo.warnings",
            Value::Array(
                record
                    .warnings
                    .iter()
                    .map(|warning| Value::from(warning.as_str()))
                    .collect(),
            ),
        );
    }
    attributes.insert("photo.complete", record.warnings.is_empty());
    attributes.insert("photo.candidates", record.exif_candidates);
    if !record.skipped_exif.is_empty() {
        attributes.insert(
            "photo.exif_skipped",
            Value::Array(
                record
                    .skipped_exif
                    .iter()
                    .map(|item| Value::from(item.as_str()))
                    .collect(),
            ),
        );
    }
    if let Some(xmp) = &record.xmp {
        attributes.insert("photo.xmp_offset", u64::from(xmp.offset));
        text_attr(&mut attributes, "photo.xmp_date", xmp.date_created.as_deref());
        text_attr(
            &mut attributes,
            "photo.xmp_tool",
            xmp.creator_tool.as_deref(),
        );
    }
    if !record.png_texts.is_empty() {
        attributes.insert(
            "photo.png_text_sources",
            Value::Array(
                record
                    .png_texts
                    .iter()
                    .map(|text| {
                        Value::from(format!(
                            "{}@0x{:x}={}{}",
                            text.chunk_type,
                            text.offset,
                            text.key,
                            if text.truncated { "(未解压/已截断)" } else { "" }
                        ))
                    })
                    .collect(),
            ),
        );
    }

    let title = format!("{} ({})", record.path, record.format.label());
    Artifact {
        artifact_type: photo_artifact_type(),
        title,
        value: Some(Value::from(record.path.as_str())),
        attributes,
    }
}

fn collect_origins(metadata: &MetadataFields) -> Vec<String> {
    let mut origins: Vec<String> = Vec::new();
    let mut push = |label: &str, origin: Option<&Origin>| {
        if let Some(origin) = origin {
            origins.push(format!("{label}={}", origin.locator()));
        }
    };
    push(
        "datetime_original",
        metadata.datetime_original.as_ref().map(|time| &time.origin),
    );
    push("make", metadata.make.as_ref().map(|v| &v.origin));
    push("model", metadata.model.as_ref().map(|v| &v.origin));
    push("lens_model", metadata.lens_model.as_ref().map(|v| &v.origin));
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

fn dms_text(coordinate: &Coordinate) -> String {
    format!(
        "{}°{}′{:.2}″",
        coordinate.degrees, coordinate.minutes, coordinate.seconds
    )
}

/// Artifact summarizing the whole run (counts + reasons).
pub fn summary_artifact(summary: &crate::record::RunSummary, artifacts: usize) -> Artifact {
    let mut attributes = Attributes::new();
    attributes.insert("photo.files", summary.total as u64);
    attributes.insert("photo.exif", summary.with_exif as u64);
    attributes.insert("photo.gps", summary.with_gps as u64);
    attributes.insert("photo.no_gps", summary.without_gps as u64);
    attributes.insert("photo.failed", summary.failed as u64);
    attributes.insert("photo.no_exif", summary.without_exif as u64);
    attributes.insert("photo.excluded_non_image", summary.excluded_non_image as u64);
    attributes.insert("photo.skipped_limit", summary.skipped_beyond_limit as u64);
    attributes.insert("photo.records", artifacts as u64);
    if !summary.reasons.is_empty() {
        attributes.insert(
            "photo.fail_reasons",
            Value::Array(
                summary
                    .reasons
                    .iter()
                    .map(|(reason, count)| {
                        Value::Array(vec![
                            Value::from(reason.as_str()),
                            Value::from(*count as u64),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        );
    }
    Artifact {
        artifact_type: format!("{NS}.summary"),
        title: "照片元数据汇总".to_owned(),
        value: Some(Value::from(summary.text.as_str())),
        attributes,
    }
}

