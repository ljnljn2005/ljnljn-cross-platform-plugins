use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRecord, TestRun};
use lovelycarve_plugin::{Severity, Value};

use super::synth::{self, PcapEntry, UdpPacket};

const ANALYZER: &str = "dns_heartbeat";
const DOMAIN: &str = "dns.heartbeat.domain";
const SUMMARY: &str = "dns.capture.summary";

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
            "ljnljn-dns-v2-{label}-{}-{unique}",
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

fn entries(queries: &[(f64, &str, u16)]) -> Vec<PcapEntry> {
    queries
        .iter()
        .map(|(epoch, name, qtype)| {
            PcapEntry::Udp(UdpPacket::to_dns(
                synth::epoch_sec(*epoch),
                synth::frac_of(*epoch),
                synth::dns_query_name(name, *qtype),
            ))
        })
        .collect()
}

fn run_files(paths: &[&Path]) -> TestRun {
    Harness::new(super::plugin)
        .run(ANALYZER, Fixture::files(paths))
        .expect("run")
}

fn float(record: &TestRecord, field: &str) -> Option<f64> {
    record.get(field).and_then(Value::as_f64)
}

fn periodic_queries(base: f64, count: usize, interval: f64) -> Vec<(f64, &'static str, u16)> {
    (0..count)
        .map(|index| (base + index as f64 * interval, "heartbeat-a.example", 1))
        .collect()
}

#[test]
fn fixed_interval_domain_emits_a_typed_periodic_record_and_summary() {
    let fixture = FixtureDir::new("periodic");
    let base = 1_700_000_000.0;
    let queries = periodic_queries(base, 8, 3.0);
    let bytes = synth::build_pcap(&entries(&queries));
    let path = fixture.write("periodic.pcap", &bytes);
    let run = run_files(&[&path]);

    assert_eq!(run.count(DOMAIN), 1);
    assert_eq!(run.count(SUMMARY), 1);
    let record = run.of_type(DOMAIN)[0];
    assert_eq!(record.text("qname"), Some("heartbeat-a.example"));
    assert_eq!(record.text("qtype_name"), Some("A"));
    assert_eq!(record.int("qtype"), Some(1));
    assert_eq!(record.int("query_count"), Some(8));
    assert_eq!(record.int("interval_count"), Some(7));
    assert_eq!(record.get("interval_median"), Some(&Value::F64(3.0)));
    assert_eq!(float(record, "stability_pct"), Some(100.0));
    assert_eq!(record.text("verdict"), Some("periodic"));
    assert_eq!(record.get("periodic"), Some(&Value::Boolean(true)));
    assert_eq!(record.text("first_seen"), Some("2023-11-14T22:13:20Z"));
    assert_eq!(record.text("last_seen"), Some("2023-11-14T22:13:41Z"));
    assert_eq!(record.severity, Some(Severity::Low));
    assert!(record.title.contains("疑似周期心跳"), "{}", record.title);
    let samples = record
        .get("interval_samples")
        .and_then(Value::as_array)
        .expect("interval samples");
    assert_eq!(samples.len(), 7);
    assert_eq!(samples[0], Value::F64(3.0));

    // The source points at the whole run of packet records that carried it.
    assert_eq!(record.sources.len(), 1);
    let source = &record.sources[0];
    let dns_len = synth::dns_query_name("heartbeat-a.example", 1).len();
    let frame_len = 14 + 20 + 8 + dns_len;
    assert_eq!(source.offset, Some(24));
    assert_eq!(source.length, Some((8 * (16 + frame_len)) as u64));
    assert_eq!(source.root.as_deref(), Some("files"));
    assert_eq!(source.path.as_deref(), Some("periodic.pcap"));
    assert!(source.note.as_deref().unwrap_or("").contains("#0..#7"));

    let summary = run.of_type(SUMMARY)[0];
    assert_eq!(summary.text("file"), Some("periodic.pcap"));
    assert_eq!(summary.int("file_size"), Some(bytes.len() as i64));
    assert_eq!(summary.text("format"), Some("pcap"));
    assert_eq!(summary.int("record_count"), Some(8));
    assert_eq!(summary.int("frame_count"), Some(8));
    assert_eq!(summary.int("dns_query_messages"), Some(8));
    assert_eq!(summary.int("queries_counted"), Some(8));
    assert_eq!(summary.int("group_count"), Some(1));
    assert_eq!(summary.int("periodic_groups"), Some(1));
    assert_eq!(summary.int("min_samples"), Some(5));
    assert_eq!(summary.get("tolerance"), Some(&Value::F64(0.1)));
    assert_eq!(summary.get("stability_threshold"), Some(&Value::F64(0.8)));
    assert_eq!(summary.int("detail_limit"), Some(16));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("疑似周期心跳 1 个"));
}

#[test]
fn irregular_intervals_are_reported_as_irregular_without_severity() {
    let fixture = FixtureDir::new("irregular");
    let base = 1_700_000_000.0;
    let offsets = [0.0, 4.0, 21.0, 22.5, 60.0, 61.5, 200.0, 201.0];
    let queries: Vec<(f64, &str, u16)> = offsets
        .iter()
        .map(|offset| (base + offset, "random-b.example", 1))
        .collect();
    let path = fixture.write("random.pcap", &synth::build_pcap(&entries(&queries)));
    let run = run_files(&[&path]);

    let record = run.of_type(DOMAIN)[0];
    assert_eq!(record.text("verdict"), Some("irregular"));
    assert_eq!(record.get("periodic"), Some(&Value::Boolean(false)));
    assert_eq!(record.severity, None);
    assert!(float(record, "stability_pct").unwrap_or(100.0) < 80.0);
}

#[test]
fn fewer_samples_than_the_threshold_is_insufficient_not_periodic() {
    let fixture = FixtureDir::new("insufficient");
    let base = 1_700_000_000.0;
    let queries = periodic_queries(base, 3, 2.0);
    let path = fixture.write("few.pcap", &synth::build_pcap(&entries(&queries)));
    let run = run_files(&[&path]);

    let record = run.of_type(DOMAIN)[0];
    assert_eq!(record.int("query_count"), Some(3));
    assert_eq!(record.int("interval_count"), Some(2));
    assert_eq!(record.text("verdict"), Some("insufficient"));
    assert_eq!(
        record.get("insufficient_samples"),
        Some(&Value::Boolean(true))
    );
    assert_eq!(record.get("periodic"), Some(&Value::Boolean(false)));
}

#[test]
fn responses_ipv6_and_foreign_udp_ports_are_counted_not_parsed() {
    let fixture = FixtureDir::new("skips");
    let base = 1_700_000_000.0;
    let mut entries = entries(&[(base, "counted.example", 1)]);
    entries.push(PcapEntry::Udp(UdpPacket::to_dns(
        synth::epoch_sec(base + 1.0),
        synth::frac_of(base + 1.0),
        synth::dns_response("counted.example", 1),
    )));
    entries.push(PcapEntry::RawFrame {
        ts_sec: synth::epoch_sec(base + 2.0),
        ts_frac: 0,
        frame: {
            let mut frame = vec![0u8; 12];
            frame.extend_from_slice(&[0x86, 0xDD]);
            frame.extend_from_slice(&[0u8; 40]);
            frame
        },
    });
    // A UDP payload that looks like a DNS header but is not on port 53.
    let mut payload = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&[1, b'x', 0, 0x00, 0x01, 0x00, 0x01]);
    let mut packet = UdpPacket::to_dns(1_700_000_003, 0, payload);
    packet.src_port = 44818;
    packet.dst_port = 44818;
    entries.push(PcapEntry::Udp(packet));

    let path = fixture.write("skips.pcap", &synth::build_pcap(&entries));
    let run = run_files(&[&path]);

    let summary = run.of_type(SUMMARY)[0];
    assert_eq!(summary.int("record_count"), Some(4));
    assert_eq!(summary.int("dns_query_messages"), Some(1));
    assert_eq!(summary.int("skipped_dns_response"), Some(1));
    assert_eq!(summary.int("skipped_ipv6"), Some(1));
    assert_eq!(summary.int("skipped_not_dns_port"), Some(1));
    let record = run.of_type(DOMAIN)[0];
    assert_eq!(record.text("qname"), Some("counted.example"));
    assert_eq!(record.int("query_count"), Some(1));
}

#[test]
fn a_capture_without_dns_keeps_only_the_typed_summary() {
    let fixture = FixtureDir::new("nodns");
    let entries = vec![
        PcapEntry::Udp(UdpPacket::to_dns(
            1_700_000_000,
            0,
            synth::non_dns_payload_of(8),
        )),
        PcapEntry::RawFrame {
            ts_sec: 1_700_000_001,
            ts_frac: 0,
            frame: {
                let mut frame = vec![
                    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08,
                    0x00,
                ];
                frame.extend_from_slice(&[
                    0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00, 10, 0, 0, 1,
                    10, 0, 0, 2,
                ]);
                frame.extend_from_slice(&[0u8; 20]);
                frame
            },
        },
    ];
    let path = fixture.write("empty.pcap", &synth::build_pcap(&entries));
    let run = run_files(&[&path]);

    assert_eq!(run.count(DOMAIN), 0);
    assert_eq!(run.count(SUMMARY), 1);
    let summary = run.of_type(SUMMARY)[0];
    assert_eq!(summary.int("group_count"), Some(0));
    assert_eq!(summary.int("dns_query_messages"), Some(0));
    assert_eq!(summary.int("skipped_not_dns"), Some(1));
    assert_eq!(summary.int("skipped_tcp"), Some(1));
}

#[test]
fn out_of_order_capture_source_range_covers_the_whole_file_order_span() {
    let fixture = FixtureDir::new("shuffled");
    let base = 1_700_000_000.0;
    let offsets = [0.0, 9.0, 3.0, 6.0, 12.0];
    let queries: Vec<(f64, &str, u16)> = offsets
        .iter()
        .map(|offset| (base + offset, "shuffled-d.example", 1))
        .collect();
    let path = fixture.write("shuffled.pcap", &synth::build_pcap(&entries(&queries)));
    let run = run_files(&[&path]);

    let record = run.of_type(DOMAIN)[0];
    assert_eq!(record.text("first_seen"), Some("2023-11-14T22:13:20Z"));
    assert_eq!(record.text("last_seen"), Some("2023-11-14T22:13:32Z"));
    assert_eq!(record.int("out_of_order"), Some(2));
    assert_eq!(record.int("first_slot"), Some(0));
    assert_eq!(record.int("last_slot"), Some(4));
    let dns_len = synth::dns_query_name("shuffled-d.example", 1).len();
    let frame_len = 14 + 20 + 8 + dns_len;
    assert_eq!(
        record.sources[0].length,
        Some((5 * (16 + frame_len)) as u64)
    );
}

#[test]
fn unsupported_pcapng_is_a_warning_not_a_silent_empty_success() {
    let fixture = FixtureDir::new("pcapng");
    let mut bytes = vec![0x0A, 0x0D, 0x0D, 0x0A];
    bytes.extend_from_slice(&[0x1C, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A]);
    bytes.extend_from_slice(&[0u8; 32]);
    let path = fixture.write("disk.pcap", &bytes);
    let run = run_files(&[&path]);

    assert_eq!(run.count(DOMAIN), 0);
    assert_eq!(run.count(SUMMARY), 0);
    assert!(run.warnings.iter().any(
        |(code, message, _)| code == "UNSUPPORTED_CAPTURE_FORMAT" && message.contains("pcapng")
    ));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("1 个文件无法解析"));
}

#[test]
fn truncated_and_header_only_captures_report_specific_warning_codes() {
    let fixture = FixtureDir::new("broken");
    let base = 1_700_000_000.0;
    let mut truncated = synth::build_pcap(&entries(&[(base, "x.example", 1)]));
    truncated.truncate(truncated.len() - 3);
    let truncated_path = fixture.write("truncated.pcap", &truncated);
    let run = run_files(&[&truncated_path]);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "TRUNCATED_CAPTURE"));

    let header_only = synth::build_pcap(&[]);
    let header_path = fixture.write("header.pcap", &header_only);
    let run = run_files(&[&header_path]);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "NO_VALID_TIMESTAMP"));
}

#[test]
fn one_broken_file_does_not_discard_the_other_files() {
    let fixture = FixtureDir::new("mixed");
    let base = 1_700_000_000.0;
    let good = fixture.write(
        "good.pcap",
        &synth::build_pcap(&entries(&periodic_queries(base, 6, 2.0))),
    );
    let bad = fixture.write("bad.pcap", b"not a capture");
    let run = run_files(&[&good, &bad]);

    assert_eq!(run.count(DOMAIN), 1);
    assert_eq!(run.count(SUMMARY), 1);
    assert_eq!(run.warnings.len(), 1);
    assert_eq!(run.warnings[0].0, "UNSUPPORTED_CAPTURE_FORMAT");
    assert_eq!(run.warnings[0].2.as_deref(), Some("bad.pcap"));
}

#[test]
fn the_reserved_pcap_field_is_recorded_but_never_shift_the_timestamps() {
    let fixture = FixtureDir::new("reserved");
    let base = 1_700_000_000.0;
    let mut bytes = synth::build_pcap(&entries(&periodic_queries(base, 6, 4.0)));
    bytes[8..12].copy_from_slice(&28_800i32.to_le_bytes());
    let path = fixture.write("tz.pcap", &bytes);
    let run = run_files(&[&path]);

    let summary = run.of_type(SUMMARY)[0];
    assert_eq!(summary.int("reserved_field"), Some(28_800));
    assert!(summary
        .text("time_basis")
        .unwrap_or("")
        .contains("reserved_field_ignored"));
    let record = run.of_type(DOMAIN)[0];
    assert_eq!(record.text("first_seen"), Some("2023-11-14T22:13:20Z"));
}

#[test]
fn an_empty_selection_yields_an_explicit_warning() {
    let run = Harness::new(super::plugin)
        .run(ANALYZER, Fixture::Files(Vec::new()))
        .expect("run");

    assert_eq!(run.count(DOMAIN), 0);
    assert_eq!(run.count(SUMMARY), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn plugin_identity_matches_the_manifest() {
    let harness = Harness::new(super::plugin);
    let hello = harness.hello();
    assert_eq!(hello.protocol, 2);
    assert_eq!(hello.plugin, "org.ljnljn.dns-heartbeat");
    assert_eq!(hello.analyzers, vec!["dns_heartbeat"]);
    let manifest = include_str!("../plugin.toml");
    assert!(manifest.contains("id = \"org.ljnljn.dns-heartbeat\""));
    assert!(manifest.contains("library = \"ljnljn_dns_heartbeat\""));
    assert!(manifest.contains("id = \"dns_heartbeat\""));
    assert!(manifest.contains("scope = \"files\""));
}
