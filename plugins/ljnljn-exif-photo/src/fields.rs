//! 字段解释：把 TIFF 原始 Tag 映射为输出字段，并完成 GPS 十进制度换算。
//!
//! 时间处理原则（需求硬约束）：EXIF 时间只做**字符串原样输出**。
//! - 不做时区换算，不补年份，不把本地时间拼接成 RFC 3339；
//! - 只有当 EXIF 自带 `OffsetTimeOriginal` 且时间串本身合法时才记录该偏移，
//!   并且仍然以“原值 + 原偏移”两段字符串并列展示，不参与任何计算。
//!
//! GPS 处理原则：度分秒按 `度 + 分/60 + 秒/3600` 求和，再按 Ref 决定符号：
//! 纬度 `S` 取负、`N` 取正；经度 `W` 取负、`E` 取正。Ref 缺失时标记
//! `ref_defaulted`，不猜测方向（一律按正值输出并在缺失字段中说明）。
//! 分/秒哪怕出现负数也不参与符号推断——符号只来自 Ref，见
//! [`signed_decimal`]。

use crate::exif::{tag, Ifd, TagValue, TiffBlock, ValueKind};

const IFD0: &[Ifd] = &[Ifd::Ifd0];
const EXIF_IFD: &[Ifd] = &[Ifd::Exif];
const GPS_IFD: &[Ifd] = &[Ifd::Gps];

/// Fields required by the task description; missing ones are listed per record
/// and counted in the summary.
pub const REQUIRED_FIELDS: &[&str] = &[
    "datetime_original",
    "make",
    "model",
    "lens_model",
    "image_width",
    "image_height",
    "orientation",
    "gps_latitude",
    "gps_latitude_ref",
    "gps_longitude",
    "gps_longitude_ref",
    "gps_altitude",
    "gps_altitude_ref",
];

/// Where an interpreted field came from (file offset + container segment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub carrier: &'static str,
    pub ifd: Ifd,
    pub tag: u16,
    /// File offset of the tag's payload (TIFF-relative offset + block base).
    pub file_offset: u64,
    pub length: usize,
}

impl Origin {
    /// Human-readable locator kept in every artifact's attributes.
    pub fn locator(&self) -> String {
        format!(
            "{} {} tag:0x{:04x} @0x{:x} len:{}",
            self.carrier,
            self.ifd.label(),
            self.tag,
            self.file_offset,
            self.length
        )
    }
}

/// A text value kept verbatim next to its origin.
#[derive(Clone, Debug, PartialEq)]
pub struct TextField {
    pub value: String,
    pub origin: Origin,
}

/// EXIF timestamp plus its declared offset (never applied).
#[derive(Clone, Debug, PartialEq)]
pub struct TimeField {
    /// EXIF string exactly as stored (`2023:08:15 10:30:00`).
    pub raw: String,
    /// `OffsetTimeOriginal` value when present and well formed (`+08:00`).
    pub offset_time: Option<String>,
    /// Precision marker describing how the raw value was interpreted.
    pub precision: &'static str,
    pub origin: Origin,
}

/// GPS coordinate in degrees/minutes/seconds and decimal degrees.
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinate {
    /// `N`/`S` for latitude, `E`/`W` for longitude; `None` when absent.
    pub reference: Option<String>,
    pub degrees: f64,
    pub minutes: f64,
    pub seconds: f64,
    /// Signed decimal degrees (negative for S/W).
    pub decimal: f64,
    /// True when no Ref tag existed, so the sign could not be decided.
    pub ref_defaulted: bool,
    pub origin: Origin,
    pub reference_origin: Option<Origin>,
}

/// Altitude value and its `0`(above sea level)/`1`(below) reference.
#[derive(Clone, Debug, PartialEq)]
pub struct Altitude {
    pub reference: Option<String>,
    pub meters: f64,
    /// Altitude relative to sea level (negative for below).
    pub signed_meters: f64,
    pub ref_defaulted: bool,
    pub origin: Origin,
    pub reference_origin: Option<Origin>,
}

/// Interpreted EXIF field set for one photo.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MetadataFields {
    pub datetime_original: Option<TimeField>,
    pub datetime: Option<TimeField>,
    pub datetime_digitized: Option<TimeField>,
    pub make: Option<TextField>,
    pub model: Option<TextField>,
    pub lens_model: Option<TextField>,
    pub software: Option<TextField>,
    pub image_width: Option<(u64, Origin)>,
    pub image_height: Option<(u64, Origin)>,
    pub orientation: Option<(u16, String, Origin)>,
    /// `(w, h)` from PNG IHDR when the container carries it.
    pub png_dimensions: Option<(u32, u32)>,
    pub latitude: Option<Coordinate>,
    pub longitude: Option<Coordinate>,
    pub altitude: Option<Altitude>,
    pub gps_timestamp: Option<String>,
    pub gps_datestamp: Option<String>,
    pub gps_satellites: Option<TextField>,
    /// Tags that were present in the file but could not be interpreted.
    pub skipped: Vec<String>,
}

impl MetadataFields {
    pub fn has_gps(&self) -> bool {
        self.latitude.is_some()
            || self.longitude.is_some()
            || self.altitude.is_some()
            || self.gps_timestamp.is_some()
            || self.gps_datestamp.is_some()
            || self.gps_satellites.is_some()
    }

    /// Names (see [`REQUIRED_FIELDS`]) of the fields not present.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.datetime_original.is_none() {
            missing.push("datetime_original");
        }
        if self.make.is_none() {
            missing.push("make");
        }
        if self.model.is_none() {
            missing.push("model");
        }
        if self.lens_model.is_none() {
            missing.push("lens_model");
        }
        if self.image_width.is_none() {
            missing.push("image_width");
        }
        if self.image_height.is_none() {
            missing.push("image_height");
        }
        if self.orientation.is_none() {
            missing.push("orientation");
        }
        if self.latitude.is_none() {
            missing.push("gps_latitude");
        }
        if self
            .latitude
            .as_ref()
            .and_then(|coordinate| coordinate.reference.as_ref())
            .is_none()
        {
            missing.push("gps_latitude_ref");
        }
        if self.longitude.is_none() {
            missing.push("gps_longitude");
        }
        if self
            .longitude
            .as_ref()
            .and_then(|coordinate| coordinate.reference.as_ref())
            .is_none()
        {
            missing.push("gps_longitude_ref");
        }
        if self.altitude.is_none() {
            missing.push("gps_altitude");
        }
        if self
            .altitude
            .as_ref()
            .and_then(|altitude| altitude.reference.as_ref())
            .is_none()
        {
            missing.push("gps_altitude_ref");
        }
        missing
    }
}

/// `block_base` is the file offset of the TIFF header (already includes the
/// `Exif\0\0` prefix for JPEG).
pub fn interpret(block: &TiffBlock, carrier: &'static str, block_base: u64) -> MetadataFields {
    let mut fields = MetadataFields::default();
    let origin_of = |value: &TagValue| -> Origin {
        Origin {
            carrier,
            ifd: value.ifd,
            tag: value.tag,
            file_offset: block_base + u64::from(value.value_offset),
            length: value.value_length,
        }
    };
    let find = |ifd: &[Ifd], tag_id: u16| block.first(ifd, tag_id);

    let text = |ifd: &[Ifd], tag_id: u16| -> Option<TextField> {
        let value = find(ifd, tag_id)?;
        let text = value.kind.ascii()?.trim_matches('\0').trim();
        if text.is_empty() {
            return None;
        }
        Some(TextField {
            value: text.to_owned(),
            origin: origin_of(value),
        })
    };

    fields.make = text(IFD0, tag::MAKE);
    fields.model = text(IFD0, tag::MODEL);
    fields.software = text(IFD0, tag::SOFTWARE);
    fields.lens_model = text(EXIF_IFD, tag::LENS_MODEL).or_else(|| text(EXIF_IFD, tag::LENS_MAKE));

    fields.datetime_original = time_field(find(EXIF_IFD, tag::DATETIME_ORIGINAL), |tag_value| origin_of(tag_value));
    fields.datetime_digitized =
        time_field(find(EXIF_IFD, tag::DATETIME_DIGITIZED), |tag_value| origin_of(tag_value));
    fields.datetime = time_field(find(IFD0, tag::DATETIME), |tag_value| origin_of(tag_value));

    // OffsetTimeOriginal is only reported when it is itself well formed.
    if let Some(origin_time) = fields.datetime_original.as_mut() {
        if let Some(value) = find(EXIF_IFD, tag::OFFSET_TIME_ORIGINAL) {
            if let Some(text) = value.kind.ascii() {
                let candidate = text.trim_matches('\0').trim();
                if is_valid_offset(candidate) {
                    origin_time.offset_time = Some(candidate.to_owned());
                } else {
                    fields.skipped.push(format!(
                        "OffsetTimeOriginal 值 '{candidate}' 不是有效的 ±HH:MM 偏移，已忽略"
                    ));
                }
            }
        }
    }

    // Dimensions: TIFF/IFD0 first, then ExifIFD pixel dimensions.
    let width = find(IFD0, tag::IMAGE_WIDTH).and_then(|value| {
        value
            .kind
            .first_u32()
            .map(|width| (u64::from(width), origin_of(value)))
    });
    let width = width.or_else(|| {
        find(EXIF_IFD, tag::PIXEL_X_DIMENSION).and_then(|value| {
            value
                .kind
                .first_u32()
                .map(|width| (u64::from(width), origin_of(value)))
        })
    });
    let height = find(IFD0, tag::IMAGE_HEIGHT).and_then(|value| {
        value
            .kind
            .first_u32()
            .map(|height| (u64::from(height), origin_of(value)))
    });
    let height = height.or_else(|| {
        find(EXIF_IFD, tag::PIXEL_Y_DIMENSION).and_then(|value| {
            value
                .kind
                .first_u32()
                .map(|height| (u64::from(height), origin_of(value)))
        })
    });
    fields.image_width = width;
    fields.image_height = height;

    if let Some(value) = find(IFD0, tag::ORIENTATION) {
        match value.kind.first_u32() {
            Some(code) if (1..=8).contains(&code) => {
                fields.orientation = Some((
                    code as u16,
                    orientation_label(code as u16).to_owned(),
                    origin_of(value),
                ));
            }
            Some(other) => fields.skipped.push(format!(
                "Orientation 值 {other} 不在 1..=8，按缺失处理（未猜测）"
            )),
            None => fields
                .skipped
                .push("Orientation 值类型不可解释，按缺失处理".to_owned()),
        }
    }

    fields.latitude = coordinate(
        find(GPS_IFD, tag::GPS_LATITUDE),
        find(GPS_IFD, tag::GPS_LATITUDE_REF),
        &["N", "S"],
        &mut fields.skipped,
        |tag_value| origin_of(tag_value),
    );
    fields.longitude = coordinate(
        find(GPS_IFD, tag::GPS_LONGITUDE),
        find(GPS_IFD, tag::GPS_LONGITUDE_REF),
        &["E", "W"],
        &mut fields.skipped,
        |tag_value| origin_of(tag_value),
    );
    fields.altitude = altitude(
        find(GPS_IFD, tag::GPS_ALTITUDE),
        find(GPS_IFD, tag::GPS_ALTITUDE_REF),
        &mut fields.skipped,
        |tag_value| origin_of(tag_value),
    );
    fields.gps_timestamp = find(GPS_IFD, tag::GPS_TIMESTAMP).map(|value| value.kind.display());
    fields.gps_datestamp = find(GPS_IFD, tag::GPS_DATESTAMP)
        .and_then(|value| value.kind.ascii())
        .map(|text| text.trim_matches('\0').trim().to_owned());
    fields.gps_satellites = text(GPS_IFD, tag::GPS_SATELLITES);
    fields
}

fn time_field(
    value: Option<&TagValue>,
    origin_of: impl Fn(&TagValue) -> Origin,
) -> Option<TimeField> {
    let value = value?;
    let text = value.kind.ascii()?.trim_matches('\0').trim();
    if text.is_empty() {
        return None;
    }
    let precision = match timestamp_shape(text) {
        TimestampShape::Full => "second",
        TimestampShape::DateOnly => "date-only",
        TimestampShape::Blank => "blank",
        TimestampShape::Malformed => "malformed-raw",
    };
    Some(TimeField {
        raw: text.to_owned(),
        offset_time: None,
        precision,
        origin: origin_of(value),
    })
}

/// Recognised EXIF timestamp shapes; anything else keeps its raw text only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampShape {
    Full,
    DateOnly,
    Blank,
    Malformed,
}

/// `YYYY:MM:DD HH:MM:SS` (19 chars) → Full; `YYYY:MM:DD` → DateOnly;
/// all-zero date placeholder → Blank (files still write `0000:00:00 00:00:00`).
pub fn timestamp_shape(text: &str) -> TimestampShape {
    if text.len() == 4 && text.chars().all(|c| c == '0' || c == ' ' || c == ':') {
        return TimestampShape::Blank;
    }
    let bytes = text.as_bytes();
    let digit = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    let separator = |index: usize, allowed: &[u8]| {
        bytes.get(index).is_some_and(|byte| allowed.contains(byte))
    };
    if text.len() >= 10
        && digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && separator(4, b":-")
        && digit(5)
        && digit(6)
        && separator(7, b":-")
        && digit(8)
        && digit(9)
    {
        if text.len() == 10 {
            return TimestampShape::DateOnly;
        }
        if text.len() >= 19
            && matches!(bytes[10], b' ' | b'T')
            && digit(11)
            && digit(12)
            && separator(13, b":")
            && digit(14)
            && digit(15)
            && separator(16, b":")
            && digit(17)
            && digit(18)
        {
            if text[..4] == *"0000" {
                return TimestampShape::Blank;
            }
            return TimestampShape::Full;
        }
    }
    if text.len() == 10 && text.chars().all(|c| c == '0' || c == ' ') {
        return TimestampShape::Blank;
    }
    TimestampShape::Malformed
}

fn is_valid_offset(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 6
        && matches!(bytes[0], b'+' | b'-')
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3] == b':'
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && text[1..3].parse::<u32>().is_ok_and(|hours| hours <= 14)
        && text[4..6].parse::<u32>().is_ok_and(|minutes| minutes <= 59)
}

fn coordinate(
    value: Option<&TagValue>,
    reference: Option<&TagValue>,
    allowed_refs: &[&str],
    skipped: &mut Vec<String>,
    origin_of: impl Fn(&TagValue) -> Origin,
) -> Option<Coordinate> {
    let value = value?;
    let Some(numbers) = value.kind.numbers_f64() else {
        skipped.push(format!(
            "GPS 坐标 tag 0x{:04x} 值类型不可换算（原始值 '{}'），按缺失处理",
            value.tag,
            value.kind.display()
        ));
        return None;
    };
    if numbers.is_empty() {
        skipped.push(format!(
            "GPS 坐标 tag 0x{:04x} 数量为 0，按缺失处理",
            value.tag
        ));
        return None;
    }
    let reference_origin = reference.map(&origin_of);
    let reference_text = reference
        .and_then(|tag_value| tag_value.kind.ascii())
        .map(|text| text.trim_matches('\0').trim().to_ascii_uppercase());
    let reference_text = match reference_text {
        Some(text) if allowed_refs.contains(&text.as_str()) => Some(text),
        Some(other) => {
            skipped.push(format!(
                "GPS Ref 值 '{other}' 不属于 {:?}，按缺失处理（未猜测方向）",
                allowed_refs
            ));
            None
        }
        None => None,
    };
    Some(decimal_coordinate(
        &numbers,
        reference_text,
        reference_origin,
        origin_of(value),
    ))
}

/// Degrees + minutes/60 + seconds/3600, sign taken only from the reference.
pub fn signed_decimal(
    degrees: f64,
    minutes: f64,
    seconds: f64,
    reference: Option<&str>,
) -> f64 {
    // Absolute magnitudes: a sender may store "-0/1 -15/1" style values, and
    // the direction must still come from the Ref character only.
    let magnitude = degrees.abs() + minutes.abs() / 60.0 + seconds.abs() / 3600.0;
    match reference {
        Some("S") | Some("W") => -magnitude,
        _ => magnitude,
    }
}

fn decimal_coordinate(
    numbers: &[f64],
    reference: Option<String>,
    reference_origin: Option<Origin>,
    origin: Origin,
) -> Coordinate {
    let degrees = numbers.first().copied().unwrap_or(0.0);
    let minutes = numbers.get(1).copied().unwrap_or(0.0);
    let seconds = numbers.get(2).copied().unwrap_or(0.0);
    let decimal = signed_decimal(degrees, minutes, seconds, reference.as_deref());
    Coordinate {
        ref_defaulted: reference.is_none(),
        reference,
        degrees,
        minutes,
        seconds,
        decimal,
        origin,
        reference_origin,
    }
}

fn altitude(
    value: Option<&TagValue>,
    reference: Option<&TagValue>,
    skipped: &mut Vec<String>,
    origin_of: impl Fn(&TagValue) -> Origin,
) -> Option<Altitude> {
    let value = value?;
    let Some(numbers) = value.kind.numbers_f64() else {
        skipped.push(format!(
            "GPSAltitude 值类型不可换算（原始值 '{}'），按缺失处理",
            value.kind.display()
        ));
        return None;
    };
    let Some(meters) = numbers.first().copied() else {
        skipped.push("GPSAltitude 数量为 0，按缺失处理".to_owned());
        return None;
    };
    let reference_origin = reference.map(&origin_of);
    let reference_text = reference.and_then(altitude_reference_text);
    let reference_text = match reference_text {
        Some(text) if text == "0" => Some(text),
        Some(text) if text == "1" => Some(text),
        Some(other) => {
            skipped.push(format!(
                "GPSAltitudeRef 值 '{other}' 不是 0/1，按缺失处理（未猜测方向）"
            ));
            None
        }
        None => None,
    };
    // Altitude ref 1 = below sea level, which makes the height negative; the
    // magnitude itself is always stored unsigned by cameras.
    let signed_meters = if reference_text.as_deref() == Some("1") {
        -meters.abs()
    } else {
        meters.abs()
    };
    Some(Altitude {
        ref_defaulted: reference_text.is_none(),
        reference: reference_text,
        meters,
        signed_meters,
        origin: origin_of(value),
        reference_origin,
    })
}

/// `GPSAltitudeRef` is a BYTE (type 1) or UNDEFINED (type 7) tag in EXIF;
/// some writers store ASCII `"0"`/`"1"` instead. All forms are accepted.
fn altitude_reference_text(value: &TagValue) -> Option<String> {
    match &value.kind {
        ValueKind::Ascii(text) => {
            let text = text.trim_matches('\0').trim();
            (!text.is_empty()).then(|| text.to_owned())
        }
        ValueKind::Bytes { bytes, .. } => bytes.first().map(u8::to_string),
        ValueKind::Short(values) => values.first().map(u16::to_string),
        ValueKind::Long(values) => values.first().map(u32::to_string),
        ValueKind::Rational(_) | ValueKind::SRational(_) => None,
    }
}

/// EXIF orientation 1..=8 (the value is recorded verbatim next to the label).
pub fn orientation_label(code: u16) -> &'static str {
    match code {
        1 => "正常(0°)",
        2 => "水平镜像",
        3 => "旋转180°",
        4 => "垂直镜像",
        5 => "镜像后顺时针旋转90°",
        6 => "顺时针旋转90°",
        7 => "镜像后顺时针旋转270°",
        8 => "顺时针旋转270°",
        _ => "未知",
    }
}
