//! Synthetic photo tests: JPEG/PNG files are built in memory by
//! `crate::fixtures`; nothing is read from a real case.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRecord, TestRun};
use lovelycarve_plugin::Value;

use crate::fixtures::{ExifSample, JpegSample, PngSample};
use crate::record::{parse_file, Outcome};
use crate::sha256::Sha256;

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
            "ljnljn-exif-v2-{tag}-{}-{nanos}",
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

fn jpeg_with_gps() -> Vec<u8> {
    JpegSample {
        exif: Some(ExifSample::with_gps()),
        with_app0: true,
        with_scan: true,
        ..JpegSample::default()
    }
    .build()
    .0
}

fn jpeg_without_gps() -> Vec<u8> {
    JpegSample {
        exif: Some(ExifSample::without_gps()),
        with_scan: true,
        ..JpegSample::default()
    }
    .build()
    .0
}

fn jpeg_without_exif() -> Vec<u8> {
    JpegSample {
        with_app0: true,
        with_scan: true,
        ..JpegSample::default()
    }
    .build()
    .0
}

fn png_with_exif() -> Vec<u8> {
    let mut sample = ExifSample::with_gps();
    sample.little_endian = true;
    PngSample {
        width: 640,
        height: 480,
        exif: Some(sample),
        texts: vec![("Software".to_owned(), "SyntheticCam 1.0".to_owned())],
        ..PngSample::default()
    }
    .build()
    .0
}

fn text_disguised_as_jpeg() -> Vec<u8> {
    b"this is not a photo, just text\n".repeat(8)
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_files(paths: &[&Path], options: BTreeMap<String, Value>) -> TestRun {
    harness()
        .run_with(
            "exif_files",
            Fixture::files(paths),
            options,
            Default::default(),
        )
        .expect("run")
}

fn run_evidence(root: &Path, options: BTreeMap<String, Value>) -> TestRun {
    harness()
        .run_with(
            "exif_evidence",
            Fixture::evidence(&[("part:0", root)]),
            options,
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
fn jpeg_with_gps_emits_typed_fields_timestamp_and_source() {
    let fixture = TempDir::new("gps");
    let bytes = jpeg_with_gps();
    let path = fixture.file("DCIM/Camera/IMG_0001.jpg", &bytes);
    let run = run_files(&[&path], BTreeMap::new());

    assert_eq!(run.count("photo.exif"), 1);
    assert_eq!(run.count("photo.issue"), 0);
    let photo = only(&run, "photo.exif");
    assert_eq!(photo.text("format"), Some("jpeg"));
    assert_eq!(photo.text("declared_extension"), Some("jpg/jpeg"));
    assert_eq!(
        photo.get("exif_present").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        photo.get("gps_present").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(photo.int("size"), Some(bytes.len() as i64));
    assert_eq!(
        photo.text("sha256"),
        Some(Sha256::digest_hex(&bytes).as_str())
    );
    assert_eq!(photo.text("make"), Some("TestMake"));
    assert_eq!(photo.text("model"), Some("ModelX-100"));
    assert_eq!(photo.text("lens_model"), Some("EF24-70mm f/2.8L"));
    assert_eq!(photo.int("image_width"), Some(4032));
    assert_eq!(photo.int("image_height"), Some(3024));
    assert_eq!(photo.int("orientation"), Some(6));
    assert_eq!(
        photo.text("datetime_original_raw"),
        Some("2023:08:15 10:30:00")
    );
    assert_eq!(photo.text("datetime_original_offset"), Some("+08:00"));
    assert_eq!(photo.text("datetime_original_precision"), Some("second"));
    // A time-zone-less local timestamp: never rendered with a Z suffix.
    assert_eq!(photo.text("capture_time"), Some("2023-08-15T10:30:00"));

    assert_eq!(photo.text("latitude_ref"), Some("S"));
    let latitude = photo
        .get("latitude_decimal")
        .and_then(|v| v.as_f64())
        .unwrap();
    assert!((latitude - -37.823_019_444).abs() < 1e-6, "{latitude}");
    assert_eq!(photo.text("longitude_ref"), Some("E"));
    let longitude = photo
        .get("longitude_decimal")
        .and_then(|v| v.as_f64())
        .unwrap();
    assert!((longitude - 144.962_702_777_8).abs() < 1e-6, "{longitude}");
    let altitude = photo.get("altitude").and_then(|v| v.as_f64()).unwrap();
    assert!((altitude - 12.34).abs() < 1e-9);

    let missing = list(photo, "missing");
    assert!(!missing.contains(&"datetime_original".to_owned()));
    assert_eq!(photo.text("byte_order"), Some("big-endian"));
    assert!(photo.int("tag_count").unwrap_or(0) > 0);
    assert_eq!(photo.sources.len(), 1);
    assert_eq!(photo.sources[0].root.as_deref(), Some("files"));
    assert!(photo.sources[0]
        .note
        .as_deref()
        .unwrap_or("")
        .contains("JPEG"));

    let summary = only(&run, "photo.summary");
    assert_eq!(summary.int("files"), Some(1));
    assert_eq!(summary.int("with_exif"), Some(1));
    assert_eq!(summary.int("with_gps"), Some(1));
}

#[test]
fn png_exif_and_text_chunks_are_reported() {
    let fixture = TempDir::new("png");
    let path = fixture.file("Pictures/thumb.png", &png_with_exif());
    let run = run_files(&[&path], BTreeMap::new());

    let photo = only(&run, "photo.exif");
    assert_eq!(photo.text("format"), Some("png"));
    assert_eq!(photo.int("png_width"), Some(640));
    assert_eq!(photo.int("png_height"), Some(480));
    assert_eq!(photo.text("make"), Some("TestMake"));
    let texts = list(photo, "png_texts");
    assert!(texts.iter().any(|text| text.contains("Software")));
    assert!(texts.iter().any(|text| text.contains("Software")));
}

#[test]
fn text_disguised_as_jpeg_is_an_issue_not_a_record() {
    let fixture = TempDir::new("disguised");
    let path = fixture.file("fake.jpg", &text_disguised_as_jpeg());
    let run = run_files(&[&path], BTreeMap::new());

    assert_eq!(run.count("photo.exif"), 0);
    let issue = only(&run, "photo.issue");
    assert_eq!(issue.text("code"), Some("not_image"));
    let summary = only(&run, "photo.summary");
    assert_eq!(summary.int("excluded_non_image"), Some(1));
    assert_eq!(summary.int("with_exif"), Some(0));
}

#[test]
fn truncated_jpeg_is_rejected_with_a_reason() {
    let fixture = TempDir::new("truncated");
    let bytes = jpeg_with_gps();
    let path = fixture.file("IMG_truncated.jpg", &bytes[..bytes.len() / 3]);
    let run = run_files(&[&path], BTreeMap::new());

    assert_eq!(run.count("photo.exif"), 0);
    let issue = only(&run, "photo.issue");
    assert_eq!(issue.text("code"), Some("truncated"));
    let summary = only(&run, "photo.summary");
    assert_eq!(summary.int("failed"), Some(1));
}

#[test]
fn photos_without_exif_are_kept_by_default_and_hideable() {
    let fixture = TempDir::new("noexif");
    let path = fixture.file("NoExif.jpg", &jpeg_without_exif());
    let run = run_files(&[&path], BTreeMap::new());
    let photo = only(&run, "photo.exif");
    assert_eq!(
        photo.get("exif_present").and_then(|v| v.as_bool()),
        Some(false)
    );
    let summary = only(&run, "photo.summary");
    assert_eq!(summary.int("without_exif"), Some(1));

    let mut options = BTreeMap::new();
    options.insert("include_no_exif".to_owned(), Value::from(false));
    let run = run_files(&[&path], options);
    assert_eq!(run.count("photo.exif"), 0);
    let summary = only(&run, "photo.summary");
    assert_eq!(summary.int("files"), Some(1));
    assert_eq!(summary.int("without_exif"), Some(1));
}

#[test]
fn evidence_walk_recurses_skips_non_photos_and_attributes_sources() {
    let fixture = TempDir::new("evidence");
    fixture.file("DCIM/Camera/IMG_0001.jpg", &jpeg_with_gps());
    fixture.file("DCIM/Camera/Sub/IMG_0002.jpg", &jpeg_without_gps());
    fixture.file("DCIM/Camera/fake.jpg", &text_disguised_as_jpeg());
    fixture.file("DCIM/Camera/note.txt", b"ignore me");
    let run = run_evidence(&fixture.root, BTreeMap::new());

    assert_eq!(run.count("photo.exif"), 2);
    assert_eq!(run.count("photo.issue"), 1);
    let summary = only(&run, "photo.summary");
    assert_eq!(summary.text("scope"), Some("evidence"));
    assert_eq!(summary.int("files"), Some(3), "two photos + one non-image");
    assert_eq!(summary.int("with_exif"), Some(2));
    assert_eq!(summary.int("with_gps"), Some(1));
    assert_eq!(summary.int("excluded_non_image"), Some(1));
    for photo in run.of_type("photo.exif") {
        assert_eq!(photo.sources[0].root.as_deref(), Some("part:0"));
    }
    let paths: Vec<&str> = run
        .of_type("photo.exif")
        .iter()
        .filter_map(|photo| photo.text("path"))
        .collect();
    assert!(paths
        .iter()
        .any(|path| path.ends_with("DCIM/Camera/IMG_0001.jpg")));
    assert!(paths.iter().any(|path| path.contains("Sub/IMG_0002.jpg")));
}

#[test]
fn max_files_bounds_the_evidence_walk() {
    let fixture = TempDir::new("limit");
    fixture.file("DCIM/Camera/a.jpg", &jpeg_with_gps());
    fixture.file("DCIM/Camera/b.jpg", &jpeg_with_gps());
    fixture.file("DCIM/Camera/c.jpg", &jpeg_with_gps());
    let mut options = BTreeMap::new();
    options.insert("max_files".to_owned(), Value::from("2"));
    let run = run_evidence(&fixture.root, options);

    assert_eq!(run.count("photo.exif"), 2);
    let summary = only(&run, "photo.summary");
    assert_eq!(summary.int("skipped_beyond_limit"), Some(1));
}

#[test]
fn parser_keeps_offsets_and_sha256_for_the_same_bytes() {
    let sample = JpegSample {
        exif: Some(ExifSample::with_gps()),
        with_app0: true,
        with_scan: true,
        ..JpegSample::default()
    };
    let (bytes, first_payload, layout) = sample.build();
    let layout = layout.expect("layout");
    let outcome = parse_file("DCIM/Camera/IMG_0001.jpg", &bytes);
    let record = match outcome {
        Outcome::Photo(record) => record,
        other => panic!("expected a photo, got {other:?}"),
    };
    assert_eq!(record.sha256, Sha256::digest_hex(&bytes));
    let block = record.exif_block.as_ref().expect("exif block");
    assert_eq!(block.carrier, "jpeg-app1");
    assert_eq!(
        block.container_offset,
        first_payload.expect("payload offset")
    );
    assert_eq!(block.tiff_offset, first_payload.unwrap() + 6);
    let datetime = record.fields.datetime_original.as_ref().expect("datetime");
    let expected = u64::from(block.tiff_offset) + u64::from(layout.value_offsets[&0x9003]);
    assert_eq!(datetime.origin.file_offset, expected);
    let start = datetime.origin.file_offset as usize;
    assert_eq!(&bytes[start..start + 19], b"2023:08:15 10:30:00");
}

#[test]
fn manifest_declares_the_v2_identity() {
    let manifest = include_str!("../plugin.toml");
    assert!(manifest.contains("id = \"org.ljnljn.exif-photo\""));
    assert!(manifest.contains("protocol = 2"));
    assert!(manifest.contains("library = \"ljnljn_exif_photo\""));
    assert!(manifest.contains("id = \"exif_files\""));
}
