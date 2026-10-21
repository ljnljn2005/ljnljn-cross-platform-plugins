//! Synthetic SQLCipher tests. All databases are built by
//! `crate::profile::build_synthetic` (a real PBKDF2/HMAC chain over pseudo-
//! random "ciphertext"); no real key or case file is used.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRecord, TestRun};
use lovelycarve_plugin::Value;

use crate::profile::{build_synthetic, SyntheticParams, DEFAULT_KDF_ITER, SQLITE_PLAINTEXT_MAGIC};

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
            "ljnljn-sqlcipher-v2-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_file(path: &Path, options: BTreeMap<String, Value>) -> TestRun {
    harness()
        .run_with(
            "sqlcipher_header",
            Fixture::files(&[path]),
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

fn synthetic() -> Vec<u8> {
    build_synthetic(&SyntheticParams::default())
}

#[test]
fn no_key_gives_a_structural_profile_and_no_hmac_check() {
    let fixture = TempDir::new("profile");
    let path = fixture.file("account.db", &synthetic());
    let run = run_file(&path, BTreeMap::new());

    let profile = only(&run, "sqlcipher.profile");
    assert_eq!(profile.text("header_kind"), Some("encrypted_sqlite_likely"));
    assert_eq!(profile.int("file_length"), Some(2048));
    assert_eq!(profile.int("page_size"), Some(1024));
    assert_eq!(profile.int("reserve_size"), Some(48));
    assert_eq!(profile.int("kdf_iter"), Some(i64::from(DEFAULT_KDF_ITER)));
    assert_eq!(profile.text("hmac_algorithm"), Some("SHA512"));
    assert_eq!(profile.text("key_check"), Some("not_attempted"));
    assert!(profile.int("checks_total").unwrap_or(0) > 0);
    assert_eq!(profile.int("checks_passed"), profile.int("checks_total"));
    assert_eq!(
        profile.text("salt_hex"),
        Some("53514c43697068657253796e74683031")
    );
    assert_eq!(run.count("sqlcipher.key_attempt"), 0);
    assert_eq!(run.count("sqlcipher.plaintext_sqlite"), 0);
    assert_eq!(run.count("sqlcipher.page_read"), 0);

    let evidence = list(profile, "evidence");
    assert!(evidence
        .iter()
        .any(|line| line.contains("0x00000000..0x00000010")));
    let limitations = list(profile, "limitations");
    assert!(limitations
        .iter()
        .any(|line| line.contains("没有 passphrase/key_hex")));
    assert!(run.summary.as_deref().unwrap_or("").contains("未提供密钥"));
    assert_eq!(profile.sources[0].root.as_deref(), Some("files"));
}

#[test]
fn supplied_correct_passphrase_passes_the_first_page_hmac_check() {
    let fixture = TempDir::new("pass");
    let path = fixture.file("account.db", &synthetic());
    let mut options = BTreeMap::new();
    options.insert(
        "passphrase".to_owned(),
        Value::from(SyntheticParams::default().passphrase.as_str()),
    );
    options.insert("kdf_iter".to_owned(), Value::from("256000"));
    let run = run_file(&path, options);

    let profile = only(&run, "sqlcipher.profile");
    assert_eq!(profile.text("key_check"), Some("passed"));
    let attempt = only(&run, "sqlcipher.key_attempt");
    assert_eq!(attempt.text("key_source"), Some("passphrase"));
    assert_eq!(attempt.get("passed").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(attempt.int("kdf_iterations"), Some(256_000));
    assert_eq!(attempt.text("hmac_algorithm"), Some("SHA512"));
    assert!(!attempt.text("computed_hmac_hex").unwrap_or("").is_empty());
    assert_eq!(
        attempt.text("computed_hmac_hex"),
        attempt.text("stored_hmac_hex")
    );
    let page = only(&run, "sqlcipher.page_read");
    assert_eq!(page.int("page_offset"), Some(0));
    assert_eq!(page.int("requested"), Some(1024));
    assert_eq!(page.int("received"), Some(1024));
    assert_eq!(page.get("complete").and_then(|v| v.as_bool()), Some(true));
    assert!(run.summary.as_deref().unwrap_or("").contains("已提供密钥"));
}

#[test]
fn wrong_passphrase_fails_the_hmac_check_with_a_warning() {
    let fixture = TempDir::new("wrong");
    let path = fixture.file("account.db", &synthetic());
    let mut options = BTreeMap::new();
    options.insert("passphrase".to_owned(), Value::from("wrong-passphrase"));
    let run = run_file(&path, options);

    let profile = only(&run, "sqlcipher.profile");
    assert_eq!(profile.text("key_check"), Some("failed"));
    let attempt = only(&run, "sqlcipher.key_attempt");
    assert_eq!(attempt.get("passed").and_then(|v| v.as_bool()), Some(false));
    assert_ne!(
        attempt.text("computed_hmac_hex"),
        attempt.text("stored_hmac_hex")
    );
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "HMAC_CHECK_FAILED"));
    assert!(list(run.of_type("sqlcipher.profile")[0], "limitations")
        .iter()
        .any(|line| line.contains("HMAC 校验失败")));
}

#[test]
fn plaintext_sqlite_is_detected_and_gets_its_own_record() {
    let fixture = TempDir::new("plain");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SQLITE_PLAINTEXT_MAGIC);
    bytes.extend_from_slice(&1024_u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 1, 0, 64, 1, 1]);
    bytes.extend_from_slice(&7_u32.to_be_bytes());
    bytes.resize(1024, 0);
    let path = fixture.file("plain.db", &bytes);
    let run = run_file(&path, BTreeMap::new());

    let profile = only(&run, "sqlcipher.profile");
    assert_eq!(profile.text("header_kind"), Some("plaintext_sqlite"));
    assert_eq!(profile.text("key_check"), Some("not_attempted"));
    assert_eq!(profile.int("checks_total"), Some(0));
    let plaintext = only(&run, "sqlcipher.plaintext_sqlite");
    assert_eq!(plaintext.text("magic"), Some("SQLite format 3"));
    assert_eq!(
        plaintext.text("magic_offset"),
        Some("0x00000000..0x00000010")
    );
}

#[test]
fn empty_and_tiny_files_emit_an_unknown_profile_with_a_warning() {
    let fixture = TempDir::new("unknown");
    let empty = fixture.file("empty.db", b"");
    let tiny = fixture.file("tiny.db", &[0xde, 0xad, 0xbe]);
    let run = harness()
        .run_with(
            "sqlcipher_header",
            Fixture::files(&[&empty, &tiny]),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run");

    assert_eq!(run.count("sqlcipher.profile"), 2);
    for profile in run.of_type("sqlcipher.profile") {
        assert_eq!(profile.text("header_kind"), Some("unknown"));
        assert_eq!(profile.text("key_check"), Some("not_attempted"));
    }
    let tiny_profile = run
        .of_type("sqlcipher.profile")
        .into_iter()
        .find(|profile| profile.int("file_length") == Some(3))
        .expect("tiny profile");
    assert_eq!(tiny_profile.int("file_length"), Some(3));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "UNKNOWN_HEADER"));
}

#[test]
fn invalid_key_hex_is_ignored_with_explicit_warnings() {
    let fixture = TempDir::new("badkey");
    let path = fixture.file("account.db", &synthetic());
    let mut options = BTreeMap::new();
    options.insert("key_hex".to_owned(), Value::from("zzzz"));
    let run = run_file(&path, options);

    let profile = only(&run, "sqlcipher.profile");
    assert_eq!(profile.text("key_check"), Some("not_attempted"));
    assert_eq!(run.count("sqlcipher.key_attempt"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INVALID_KEY_HEX"));
}

#[test]
fn sha256_option_is_recorded_even_when_the_sample_is_sha512() {
    let fixture = TempDir::new("sha256");
    let path = fixture.file("account.db", &synthetic());
    let mut options = BTreeMap::new();
    options.insert(
        "passphrase".to_owned(),
        Value::from(SyntheticParams::default().passphrase.as_str()),
    );
    options.insert("hmac".to_owned(), Value::from("sha256"));
    let run = run_file(&path, options);

    let attempt = only(&run, "sqlcipher.key_attempt");
    assert_eq!(attempt.text("hmac_algorithm"), Some("SHA256"));
    assert_eq!(attempt.get("passed").and_then(|v| v.as_bool()), Some(false));
    let profile = only(&run, "sqlcipher.profile");
    assert_eq!(profile.text("hmac_algorithm"), Some("SHA256"));
    assert_eq!(profile.text("key_check"), Some("failed"));
}

#[test]
fn manifest_analyzer_id_constant_is_stable() {
    assert_eq!(crate::ANALYZER, "sqlcipher_header");
    let manifest = include_str!("../plugin.toml");
    assert!(manifest.contains("protocol = 2"));
    assert!(manifest.contains("id = \"sqlcipher_header\""));
    assert!(manifest.contains("default = \"\""));
}
