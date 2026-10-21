use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};
use lovelycarve_plugin::{Severity, Value};

use super::synth::{self, SampleSpec, VolumeSpec};
use crate::ewf::{EWF1_FILE_HEADER_SIZE, EWF2_FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE};

const ANALYZER: &str = "ewf_header";
const SEGMENT: &str = "ewf.segment";
const HEADER: &str = "ewf.header";
const SECTION: &str = "ewf.section";

struct FixtureDir {
    path: PathBuf,
}

impl FixtureDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-ewf-v2-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let file = self.path.join(name);
        fs::write(&file, bytes).unwrap();
        file
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_files(paths: &[&Path]) -> TestRun {
    Harness::new(super::plugin)
        .run(ANALYZER, Fixture::files(paths))
        .expect("run")
}

fn build(name: &str) -> Vec<u8> {
    synth::build(&SampleSpec {
        name: name.to_owned(),
        ..SampleSpec::default()
    })
}

#[test]
fn healthy_ewf1_emits_segment_header_and_every_section_with_source_ranges() {
    let fixture = FixtureDir::new("healthy");
    let bytes = build("case.E01");
    let path = fixture.write("case.E01", &bytes);
    let run = run_files(&[&path]);

    assert_eq!(run.count(SEGMENT), 1);
    assert_eq!(run.count(HEADER), 1);
    assert_eq!(run.count(SECTION), 4);
    assert_eq!(
        run.counts().get(SECTION).copied(),
        Some(4),
        "header, volume, table, done"
    );

    let segment = run.of_type(SEGMENT)[0];
    assert_eq!(segment.text("file"), Some("case.E01"));
    assert_eq!(segment.int("file_size"), Some(bytes.len() as i64));
    assert_eq!(segment.text("format"), Some("ewf1"));
    assert_eq!(segment.text("format_kind"), Some("encase-ewf1"));
    assert_eq!(segment.int("segment_number"), Some(1));
    assert_eq!(segment.int("extension_number"), Some(1));
    assert_eq!(segment.get("extension_match"), Some(&Value::Boolean(true)));
    assert_eq!(segment.int("header_offset"), Some(0));
    assert_eq!(segment.int("header_end"), Some(13));
    assert_eq!(segment.text("first_section_type"), Some("header"));
    assert_eq!(
        segment.int("first_section_length"),
        Some((SECTION_DESCRIPTOR_SIZE as usize + synth::DEFAULT_HEADER_SECTION_LEN) as i64)
    );
    assert_eq!(segment.int("section_count"), Some(4));
    assert_eq!(segment.get("chain_limited"), Some(&Value::Boolean(false)));
    assert_eq!(segment.get("has_table"), Some(&Value::Boolean(true)));
    assert_eq!(segment.get("has_done"), Some(&Value::Boolean(true)));
    assert_eq!(segment.int("number_of_chunks"), Some(32));
    assert_eq!(segment.int("sectors_per_chunk"), Some(64));
    assert_eq!(segment.int("sector_size"), Some(512));
    assert_eq!(segment.int("sector_count"), Some(2048));
    assert_eq!(segment.int("media_size_bytes"), Some(2048 * 512));
    assert_eq!(segment.text("compression"), Some("fast/good (0x01)"));
    assert_eq!(
        segment.get("volume_checksum_ok"),
        Some(&Value::Boolean(true))
    );
    assert_eq!(segment.int("error_count"), Some(0));
    assert_eq!(segment.severity, None);
    assert_eq!(segment.sources.len(), 1);
    assert_eq!(segment.sources[0].offset, Some(0));
    assert_eq!(segment.sources[0].length, Some(bytes.len() as u64));
    assert_eq!(segment.sources[0].root.as_deref(), Some("files"));
    assert_eq!(segment.sources[0].path.as_deref(), Some("case.E01"));

    let header = run.of_type(HEADER)[0];
    assert_eq!(header.text("file"), Some("case.E01"));
    assert_eq!(header.int("offset"), Some(0));
    assert_eq!(header.int("size"), Some(13));
    assert_eq!(header.get("signature_ok"), Some(&Value::Boolean(true)));
    assert_eq!(header.int("signature_length"), Some(8));
    assert_eq!(header.text("format"), Some("ewf1"));
    assert_eq!(header.int("format_id"), Some(0x01));
    assert_eq!(header.int("fields_start"), Some(0x01));
    assert_eq!(header.text("fields_end"), Some("0100"));
    assert_eq!(header.int("segment_number"), Some(1));
    assert_eq!(header.text("sha256").map(str::len), Some(64));
    assert_eq!(header.get("truncated"), Some(&Value::Boolean(false)));
    assert_eq!(header.text("hex").map(str::len), Some(13 * 2));
    assert_eq!(header.sources[0].offset, Some(0));
    assert_eq!(header.sources[0].length, Some(13));

    let sections = run.of_type(SECTION);
    let types: Vec<&str> = sections
        .iter()
        .filter_map(|section| section.text("section_type"))
        .collect();
    assert_eq!(types, vec!["header", "volume", "table", "done"]);
    let first = sections[0];
    let first_length =
        (SECTION_DESCRIPTOR_SIZE as usize + synth::DEFAULT_HEADER_SECTION_LEN) as u64;
    assert_eq!(first.int("offset"), Some(13));
    assert_eq!(first.int("length"), Some(first_length as i64));
    assert_eq!(
        first.int("body_offset"),
        Some((13 + SECTION_DESCRIPTOR_SIZE) as i64)
    );
    assert_eq!(
        first.int("body_length"),
        Some(first_length as i64 - SECTION_DESCRIPTOR_SIZE as i64)
    );
    assert_eq!(first.sources[0].offset, Some(13));
    assert_eq!(first.sources[0].length, Some(first_length));
    assert_eq!(first.sources[0].note.as_deref(), Some("节段描述符与内容"));
    assert_eq!(
        sections[1].int("offset"),
        Some(13 + first_length as i64),
        "volume follows the header section"
    );
    assert_eq!(sections[1].text("section_type"), Some("volume"));
    assert_eq!(sections[1].get("checksum_ok"), Some(&Value::Boolean(true)));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("4 个节段描述符"));
}

#[test]
fn ewf2_and_ex01_headers_are_reported_without_sections() {
    for (name, format) in [("disk.E01", "EWF2"), ("disk.Ex01", "Ex01")] {
        let fixture = FixtureDir::new("v2");
        let bytes = synth::build(&SampleSpec {
            name: name.to_owned(),
            format,
            ..SampleSpec::default()
        });
        let path = fixture.write(name, &bytes);
        let run = run_files(&[&path]);

        assert_eq!(run.count(SEGMENT), 1);
        assert_eq!(run.count(HEADER), 1);
        assert_eq!(run.count(SECTION), 0);
        let segment = run.of_type(SEGMENT)[0];
        assert_eq!(
            segment.text("format"),
            Some(if format == "EWF2" { "ewf2" } else { "ex01" })
        );
        assert_eq!(
            segment.int("header_end"),
            Some(EWF2_FILE_HEADER_SIZE as i64)
        );
        assert_eq!(segment.int("section_count"), Some(0));
        assert_eq!(segment.get("sectors_per_chunk"), None);
        assert_eq!(segment.get("sector_size"), None);
        assert_eq!(segment.get("media_size_bytes"), None);
        assert_eq!(segment.int("error_count"), Some(0));

        let header = run.of_type(HEADER)[0];
        assert_eq!(header.get("signature_ok"), Some(&Value::Boolean(true)));
        assert_eq!(header.int("size"), Some(EWF2_FILE_HEADER_SIZE as i64));
        assert_eq!(header.int("major_version"), Some(2));
        assert_eq!(header.int("minor_version"), Some(1));
        assert_eq!(header.int("compression_method"), Some(1));
        assert_eq!(
            header.text("set_identifier").map(str::len),
            Some(32),
            "16 bytes as hex"
        );
    }
}

#[test]
fn invalid_signature_is_reported_with_errors_and_a_warning() {
    let fixture = FixtureDir::new("signature");
    let mut bytes = build("broken.E01");
    bytes[0] = b'X';
    let path = fixture.write("broken.E01", &bytes);
    let run = run_files(&[&path]);

    assert_eq!(run.count(SEGMENT), 1);
    assert_eq!(run.count(HEADER), 1);
    assert_eq!(run.count(SECTION), 0);
    let segment = run.of_type(SEGMENT)[0];
    assert_eq!(segment.get("format"), None);
    assert!(segment.int("error_count").unwrap_or(0) > 0);
    assert_eq!(segment.severity, Some(Severity::Medium));
    let errors = segment
        .get("errors")
        .and_then(Value::as_array)
        .expect("errors");
    assert!(errors
        .iter()
        .any(|error| error.as_str().unwrap_or("").contains("未找到 EVF 签名")));
    let header = run.of_type(HEADER)[0];
    assert_eq!(header.get("signature_ok"), Some(&Value::Boolean(false)));
    assert_eq!(header.get("format"), None);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "EWF_STRUCTURE_ERRORS"));
}

#[test]
fn segment_number_mismatch_is_an_error_with_extension_match_false() {
    let fixture = FixtureDir::new("mismatch");
    let bytes = synth::build(&SampleSpec {
        name: "disk.E01".to_owned(),
        segment_number: 2,
        ..SampleSpec::default()
    });
    let path = fixture.write("disk.E01", &bytes);
    let run = run_files(&[&path]);

    let segment = run.of_type(SEGMENT)[0];
    assert_eq!(segment.int("segment_number"), Some(2));
    assert_eq!(segment.int("extension_number"), Some(1));
    assert_eq!(segment.get("extension_match"), Some(&Value::Boolean(false)));
    assert!(segment.int("error_count").unwrap_or(0) > 0);
}

#[test]
fn a_missing_volume_section_leaves_volume_candidates_empty() {
    let fixture = FixtureDir::new("novolume");
    let bytes = synth::build(&SampleSpec {
        name: "case.E01".to_owned(),
        volume: None,
        ..SampleSpec::default()
    });
    let path = fixture.write("case.E01", &bytes);
    let run = run_files(&[&path]);

    let segment = run.of_type(SEGMENT)[0];
    assert_eq!(segment.get("sectors_per_chunk"), None);
    assert_eq!(segment.get("sector_size"), None);
    assert_eq!(segment.get("sector_count"), None);
    assert_eq!(segment.get("media_size_bytes"), None);
    assert_eq!(segment.get("has_table"), Some(&Value::Boolean(true)));
    assert_eq!(segment.get("has_done"), Some(&Value::Boolean(true)));
    let notes = segment
        .get("volume_notes")
        .and_then(Value::as_array)
        .expect("volume notes");
    assert!(notes
        .iter()
        .any(|note| note.as_str().unwrap_or("").contains("没有找到")));
}

#[test]
fn a_bad_section_checksum_is_a_warning_and_a_low_severity_section() {
    let fixture = FixtureDir::new("checksum");
    let mut bytes = build("case.E01");
    bytes[synth::HEADER_LEN + 72] ^= 0xff;
    let path = fixture.write("case.E01", &bytes);
    let run = run_files(&[&path]);

    let section = run.of_type(SECTION)[0];
    assert_eq!(section.get("checksum_ok"), Some(&Value::Boolean(false)));
    assert_eq!(section.severity, Some(Severity::Low));
    let segment = run.of_type(SEGMENT)[0];
    assert!(segment.int("warning_count").unwrap_or(0) > 0);
    assert_eq!(segment.int("error_count"), Some(0));
    assert_eq!(segment.text("first_section_type"), Some("header"));
}

#[test]
fn a_zero_length_file_is_reported_not_silently_accepted() {
    let fixture = FixtureDir::new("empty");
    let path = fixture.write("empty.e01", b"");
    let run = run_files(&[&path]);

    assert_eq!(run.count(SEGMENT), 1);
    assert_eq!(run.count(HEADER), 1);
    assert_eq!(run.count(SECTION), 0);
    let segment = run.of_type(SEGMENT)[0];
    assert_eq!(segment.int("file_size"), Some(0));
    assert_eq!(segment.get("format"), None);
    assert!(segment.int("error_count").unwrap_or(0) > 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "EWF_STRUCTURE_ERRORS"));
}

#[test]
fn an_empty_selection_is_an_explicit_warning() {
    let run = Harness::new(super::plugin)
        .run(ANALYZER, Fixture::Files(Vec::new()))
        .expect("run");
    assert_eq!(run.count(SEGMENT), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn volume_candidates_use_the_public_ewf1_offsets() {
    let fixture = FixtureDir::new("volume");
    let bytes = synth::build(&SampleSpec {
        name: "case.E01".to_owned(),
        volume: Some(VolumeSpec {
            media_type: 0x01,
            number_of_chunks: 7,
            sectors_per_chunk: 128,
            sector_size: 4096,
            sector_count: 9999,
            media_flags: 0x03,
            compression_level: 0x02,
        }),
        ..SampleSpec::default()
    });
    let path = fixture.write("case.E01", &bytes);
    let run = run_files(&[&path]);

    let segment = run.of_type(SEGMENT)[0];
    assert_eq!(segment.int("number_of_chunks"), Some(7));
    assert_eq!(segment.int("sectors_per_chunk"), Some(128));
    assert_eq!(segment.int("sector_size"), Some(4096));
    assert_eq!(segment.int("sector_count"), Some(9999));
    assert_eq!(segment.int("media_size_bytes"), Some(9999 * 4096));
    assert_eq!(segment.text("compression"), Some("best (0x02)"));
    let header_section_len =
        (SECTION_DESCRIPTOR_SIZE as usize + synth::DEFAULT_HEADER_SECTION_LEN) as u64;
    assert_eq!(
        segment.int("volume_section_offset"),
        Some((EWF1_FILE_HEADER_SIZE + header_section_len) as i64)
    );
}

#[test]
fn plugin_identity_matches_the_manifest() {
    let harness = Harness::new(super::plugin);
    let hello = harness.hello();
    assert_eq!(hello.protocol, 2);
    assert_eq!(hello.plugin, "org.ljnljn.ewf-header");
    assert_eq!(hello.analyzers, vec!["ewf_header"]);
    let manifest = include_str!("../plugin.toml");
    assert!(manifest.contains("id = \"org.ljnljn.ewf-header\""));
    assert!(manifest.contains("library = \"ljnljn_ewf_header\""));
    assert!(manifest.contains("id = \"ewf_header\""));
    assert!(manifest.contains("scope = \"files\""));
    assert!(manifest.contains("extensions = [\"e01\", \"ewf\"]"));
}
