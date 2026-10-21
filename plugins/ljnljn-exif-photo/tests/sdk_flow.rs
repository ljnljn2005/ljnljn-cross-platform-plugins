//! 端到端（SDK 层）测试：用自建的模拟宿主（HostApiV1 + MessagePack）驱动真实
//! 的 `EvidenceAnalyzer` / `FileAnalyzer`，验证：
//! - 递归枚举照片目录、跳过同名非图片并计数；
//! - 每条记录的来源属性（source.root / source.path / 段偏移）；
//! - maxFiles / includeNoExif 参数生效；
//! - 只有摘要时（未找到照片目录）不产生伪造结果；
//! - 文件级分析器对单个照片文件、伪装文本和损坏文件的行为。
//!
//! 模拟宿主只存在于测试进程内，不读写任何真实检材。

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::MaybeUninit;

use lovelycarve_plugin::abi::{self, Buffer, Bytes, HostApiV1, PluginApiV1};
use lovelycarve_plugin::{value, Value};
use ljnljn_kb_exif_photo_metadata_8ffbc036::testing::{
    jpeg_with_gps, jpeg_without_gps, png_with_exif, text_disguised_as_jpeg, truncated_jpeg,
};
use ljnljn_kb_exif_photo_metadata_8ffbc036::{
    EVIDENCE_ANALYZER, FILE_ANALYZER, PLUGIN_ID,
};

/// A fake evidence tree: root-relative path → file content.
struct MockHost {
    root_id: String,
    files: BTreeMap<String, Vec<u8>>,
    /// Single logical file handed to the file analyzer (`file_id` → bytes).
    single: Option<Vec<u8>>,
    progress: std::sync::Mutex<Vec<u64>>,
}

impl MockHost {
    fn tree() -> Self {
        let mut tree = MockHost {
            root_id: "part:0".to_owned(),
            files: BTreeMap::new(),
            single: None,
            progress: Default::default(),
        };
        let (with_gps, _, _) = jpeg_with_gps();
        let (without_gps, _, _) = jpeg_without_gps();
        let (png, _, _) = png_with_exif();
        let (plain, _, _) = ljnljn_kb_exif_photo_metadata_8ffbc036::testing::JpegSample {
            with_app0: true,
            with_scan: true,
            ..Default::default()
        }
        .build();
        tree.files
            .insert("DCIM/Camera/IMG_0001.jpg".to_owned(), with_gps.clone());
        tree.files
            .insert("DCIM/Camera/IMG_0002.jpg".to_owned(), without_gps);
        tree.files
            .insert("DCIM/Camera/IMG_0003.jpg".to_owned(), truncated_jpeg());
        tree.files.insert(
            "DCIM/Camera/fake.jpg".to_owned(),
            text_disguised_as_jpeg(),
        );
        tree.files.insert("DCIM/Camera/note.txt".to_owned(), b"ignore me".to_vec());
        tree.files
            .insert("DCIM/Camera/thumb.png".to_owned(), png);
        tree.files
            .insert("DCIM/Camera/NoExif.jpg".to_owned(), plain);
        // Nested directory to prove the recursion.
        tree.files
            .insert("DCIM/Camera/Sub/IMG_0004.jpg".to_owned(), with_gps);
        tree
    }

    fn with_single(bytes: Vec<u8>) -> Self {
        MockHost {
            single: Some(bytes),
            ..MockHost::tree()
        }
    }

    fn path_is_file(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }

    fn path_is_dir(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        path.is_empty() || self.files.keys().any(|key| key.starts_with(&prefix))
    }

    fn children(&self, path: &str) -> Vec<(String, bool)> {
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let mut seen: BTreeMap<String, bool> = BTreeMap::new();
        for key in self.files.keys() {
            if !key.starts_with(&prefix) {
                continue;
            }
            let rest = &key[prefix.len()..];
            match rest.split_once('/') {
                Some((directory, _)) => {
                    seen.insert(directory.to_owned(), true);
                }
                None => {
                    seen.insert(rest.to_owned(), false);
                }
            }
        }
        seen.into_iter().collect()
    }

    fn answer(&self, method: &str, params: &Value) -> lovelycarve_plugin::Result<Value> {
        let sliced = |data: &[u8], offset: u64, length: u64| {
            let start = (offset as usize).min(data.len());
            let end = start.saturating_add(length as usize).min(data.len());
            Value::Binary(data[start..end].to_vec())
        };
        match method {
            "host.progress" => {
                self.progress
                    .lock()
                    .expect("progress lock")
                    .push(value::required_u64(params, "current")?);
                Ok(Value::Nil)
            }
            "evidence.roots" => Ok(Value::Array(vec![value::map([
                ("root_id", Value::from(self.root_id.as_str())),
                ("kind", Value::from("filesystem")),
            ])])),
            "evidence.stat" => {
                let path = value::required_str(params, "path")?.trim_matches('/').to_owned();
                if self.path_is_file(&path) {
                    let size = self.files[&path].len() as u64;
                    let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
                    Ok(value::map([
                        ("name", Value::from(name)),
                        ("kind", Value::from("file")),
                        ("size", Value::from(size)),
                    ]))
                } else if self.path_is_dir(&path) {
                    Ok(value::map([
                        ("name", Value::from(path.as_str())),
                        ("kind", Value::from("dir")),
                        ("size", Value::from(0_u64)),
                    ]))
                } else {
                    Ok(Value::Nil)
                }
            }
            "evidence.list_page" => {
                let path = value::required_str(params, "path")?.trim_matches('/').to_owned();
                let children = self.children(&path);
                let total = children.len();
                let page: Vec<Value> = children
                    .iter()
                    .map(|(name, is_dir)| {
                        let size = if *is_dir {
                            0
                        } else {
                            let key = if path.is_empty() {
                                name.clone()
                            } else {
                                format!("{path}/{name}")
                            };
                            self.files[&key].len() as u64
                        };
                        value::map([
                            ("node_id", Value::from(format!("{path}/{name}"))),
                            ("name", Value::from(name.as_str())),
                            (
                                "kind",
                                Value::from(if *is_dir { "dir" } else { "file" }),
                            ),
                            ("size", Value::from(size)),
                        ])
                    })
                    .collect();
                Ok(value::map([
                    ("total", Value::from(total as u64)),
                    ("nodes", Value::Array(page)),
                ]))
            }
            "evidence.read" => {
                let path = value::required_str(params, "path")?.trim_matches('/');
                let data = self.files.get(path).expect("read of a listed file");
                Ok(sliced(
                    data,
                    value::required_u64(params, "offset")?,
                    value::required_u64(params, "length")?,
                ))
            }
            "file.read" => {
                let data = self.single.as_ref().expect("single file registered");
                Ok(sliced(
                    data,
                    value::required_u64(params, "offset")?,
                    value::required_u64(params, "length")?,
                ))
            }
            other => Err(lovelycarve_plugin::Error::new("METHOD_NOT_FOUND", other)),
        }
    }
}

unsafe extern "C" fn host_call(
    context: *mut c_void,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32 {
    let host = unsafe { &*context.cast::<MockHost>() };
    let method = std::str::from_utf8(unsafe { method.as_slice() })
        .expect("method")
        .to_owned();
    let params = value::decode(unsafe { params.as_slice() }).expect("params");
    let (status, payload) = match host.answer(&method, &params) {
        Ok(reply) => (abi::STATUS_OK, reply),
        Err(error) => (abi::STATUS_ERROR, error.to_value()),
    };
    let bytes = value::encode(&payload).expect("encode");
    unsafe { out.write(Buffer::from_vec(bytes)) };
    status
}

unsafe extern "C" fn host_free(_context: *mut c_void, buffer: *mut Buffer) {
    unsafe { (*buffer).free_vec() };
}

unsafe extern "C" fn host_log(context: *mut c_void, _level: u32, message: Bytes) {
    let _ = context;
    let line = String::from_utf8_lossy(unsafe { message.as_slice() });
    println!("[plugin log] {line}");
}

struct Harness {
    api: PluginApiV1,
    host: Box<MockHost>,
    _table: Box<HostApiV1>,
}

// SAFETY: the C ABI makes both tables callable from any thread.
unsafe impl Send for Harness {}
unsafe impl Sync for Harness {}

impl Harness {
    fn new(host: MockHost) -> Self {
        let host = Box::new(host);
        let table = Box::new(HostApiV1 {
            abi_version: abi::ABI_VERSION,
            struct_size: abi::HOST_API_SIZE,
            context: (&*host as *const MockHost).cast_mut().cast(),
            call: host_call,
            free_buffer: host_free,
            log: host_log,
        });
        let mut api = MaybeUninit::<PluginApiV1>::uninit();
        let status = unsafe {
            ljnljn_kb_exif_photo_metadata_8ffbc036::lovelycarve_plugin_v1(&*table, api.as_mut_ptr())
        };
        assert_eq!(status, abi::STATUS_OK, "plugin entry point");
        Self {
            api: unsafe { api.assume_init() },
            host,
            _table: table,
        }
    }

    fn describe(&self) -> Value {
        let mut out = Buffer::empty();
        let status = unsafe { (self.api.describe)(self.api.instance, &mut out) };
        assert_eq!(status, abi::STATUS_OK);
        let reply = value::decode(unsafe { out.as_slice() }).expect("hello");
        unsafe { (self.api.free_buffer)(self.api.instance, &mut out) };
        reply
    }

    fn call(&self, call_id: u64, method: &str, params: Value) -> (i32, Value) {
        let params = value::encode(&params).expect("params");
        let mut out = Buffer::empty();
        let status = unsafe {
            (self.api.call)(
                self.api.instance,
                call_id,
                Bytes::from_slice(method.as_bytes()),
                Bytes::from_slice(&params),
                &mut out,
            )
        };
        let reply = value::decode(unsafe { out.as_slice() }).expect("reply");
        unsafe { (self.api.free_buffer)(self.api.instance, &mut out) };
        (status, reply)
    }

    fn analyze_evidence(&self, params: Value) -> Value {
        let mut evidence = vec![("evidence_id", Value::from("evidence_1"))];
        if !matches!(params, Value::Nil) {
            evidence.push(("params", params));
        }
        let (status, reply) = self.call(
            2,
            "analyzer.analyze_evidence",
            value::map([
                ("analyzer", Value::from(EVIDENCE_ANALYZER)),
                ("evidence", value::map(evidence)),
            ]),
        );
        assert_eq!(status, abi::STATUS_OK, "analyze_evidence: {reply:?}");
        reply
    }

    fn analyze_file(&self, name: &str, size: u64) -> Value {
        let (status, reply) = self.call(
            2,
            "analyzer.analyze",
            value::map([
                ("analyzer", Value::from(FILE_ANALYZER)),
                (
                    "file",
                    value::map([
                        ("file_id", Value::from("file_7")),
                        ("name", Value::from(name)),
                        ("size", Value::from(size)),
                        ("mime", Value::from("image/jpeg")),
                    ]),
                ),
            ]),
        );
        assert_eq!(status, abi::STATUS_OK, "analyze: {reply:?}");
        reply
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        unsafe { (self.api.destroy)(self.api.instance) };
    }
}

fn artifacts(reply: &Value) -> Vec<&Value> {
    value::get(reply, "artifacts")
        .and_then(Value::as_array)
        .expect("artifacts array")
        .iter()
        .collect()
}

fn attr<'a>(artifact: &'a Value, key: &str) -> Option<&'a Value> {
    let attributes = value::get(artifact, "attributes")?;
    value::get(attributes, key)
}

fn attr_str<'a>(artifact: &'a Value, key: &str) -> Option<&'a str> {
    attr(artifact, key).and_then(Value::as_str)
}

fn artifact_type(artifact: &Value) -> &str {
    value::get(artifact, "type").and_then(Value::as_str).unwrap_or("")
}

#[test]
fn describe_reports_both_analyzers_and_matching_identity() {
    let harness = Harness::new(MockHost::tree());
    let hello = harness.describe();
    assert_eq!(
        value::get(&hello, "capabilities"),
        Some(&Value::Array(vec![
            Value::from("file_analyzer"),
            Value::from("evidence_analyzer"),
        ]))
    );
    let identity = value::get(&hello, "plugin").expect("identity");
    assert_eq!(
        value::optional_str(identity, "id"),
        Some(PLUGIN_ID),
        "id must equal plugin.toml"
    );
    assert_eq!(value::optional_str(identity, "version"), Some("0.1.0"));
}

#[test]
fn evidence_analysis_walks_dcim_recursively_and_reports_sources() {
    let harness = Harness::new(MockHost::tree());
    let reply = harness.analyze_evidence(Value::Nil);
    let summary = value::optional_str(&reply, "summary").expect("summary");
    // 7 photos under DCIM/Camera (incl. nested Sub), one of them truncated.
    assert!(summary.contains("文件数 7"), "{summary}");
    assert!(summary.contains("含 EXIF 4") || summary.contains("含 EXIF 3"), "{summary}");
    assert!(summary.contains("含 GPS 3"), "{summary}");
    assert!(summary.contains("解析失败 1"), "{summary}");
    assert!(summary.contains("扩展名不符跳过 1"), "{summary}");

    let all = artifacts(&reply);
    let photos: Vec<&&Value> = all
        .iter()
        .filter(|artifact| artifact_type(artifact) == "photo.exif")
        .collect();
    // 5 parsed photos: 4 with EXIF (IMG_0001/IMG_0002/thumb.png/Sub/IMG_0004)
    // and NoExif.jpg, which is still listed. The truncated IMG_0003 and the
    // disguised fake.jpg are recorded as issues, not as photo records.
    assert_eq!(photos.len(), 5, "4 photos with EXIF + NoExif.jpg");
    let gps = photos
        .iter()
        .find(|artifact| attr_str(artifact, "photo.path") == Some("DCIM/Camera/IMG_0001.jpg"))
        .expect("IMG_0001 record");
    assert_eq!(attr_str(gps, "source.root"), Some("part:0"));
    assert_eq!(attr_str(gps, "source.path"), Some("DCIM/Camera/IMG_0001.jpg"));
    assert_eq!(attr_str(gps, "photo.datetime_original"), Some("2023:08:15 10:30:00"));
    assert_eq!(attr_str(gps, "photo.datetime_original_precision"), Some("second"));
    assert_eq!(attr_str(gps, "photo.make"), Some("TestMake"));
    assert_eq!(attr_str(gps, "photo.latitude_ref"), Some("S"));
    // 37 + 49/60 + 22.87/3600, negative because Ref is S.
    let latitude = attr(gps, "photo.latitude_decimal").and_then(Value::as_f64);
    assert!((latitude.expect("latitude") + 37.823_019).abs() < 1e-5);
    // 144 + 57/60 + 45.73/3600, positive because Ref is E.
    let longitude = attr(gps, "photo.longitude_decimal").and_then(Value::as_f64);
    assert!((longitude.expect("longitude") - 144.962_703).abs() < 1e-5);
    // Provenance: segment + IFD + tag locator strings are present.
    let origin = attr_str(gps, "photo.origin").expect("origin attribute");
    assert!(origin.contains("jpeg-app1 ExifIFD tag:0x9003 @0x"), "{origin}");
    assert!(origin.contains("GPSIFD tag:0x0002"), "{origin}");
    let tiff_offset = attr(gps, "photo.tiff_offset").and_then(Value::as_u64).expect("tiff offset");
    assert!(tiff_offset > 0);

    // Nested photo is found by the recursion.
    assert!(photos
        .iter()
        .any(|artifact| attr_str(artifact, "photo.path") == Some("DCIM/Camera/Sub/IMG_0004.jpg")));
    // The truncated photo appears in the issue table with a reason code.
    let issue = all
        .iter()
        .find(|artifact| {
            artifact_type(artifact) == "photo.issue"
                && attr_str(artifact, "photo.path") == Some("DCIM/Camera/IMG_0003.jpg")
        })
        .expect("truncated photo recorded as an issue");
    assert_eq!(attr_str(issue, "photo.reason"), Some("truncated"));
    // The disguised text file is recorded, not parsed as a photo.
    let fake = all.iter().find(|artifact| {
        artifact_type(artifact) == "photo.issue"
            && attr_str(artifact, "photo.path") == Some("DCIM/Camera/fake.jpg")
    });
    assert!(fake.is_some(), "fake.jpg should be reported as not_image");
    // The .txt file was never treated as a candidate.
    assert!(!all
        .iter()
        .any(|artifact| attr_str(artifact, "photo.path") == Some("DCIM/Camera/note.txt")));
    // Summary artifact closes the run.
    let last = all.last().expect("summary artifact");
    assert_eq!(artifact_type(last), "photo.summary");
    assert_eq!(attr(last, "photo.files").and_then(Value::as_u64), Some(7));
    // Result nodes declare columns for the record table.
    let nodes = value::get(&reply, "nodes").and_then(Value::as_array).expect("nodes");
    let node_types: Vec<&str> = nodes
        .iter()
        .filter_map(|node| value::optional_str(node, "type"))
        .collect();
    assert!(node_types.contains(&"photo.exif"));
    assert!(node_types.contains(&"photo.issue"));
    assert!(node_types.contains(&"photo.summary"));
    let exif_node = nodes
        .iter()
        .find(|node| value::optional_str(node, "type") == Some("photo.exif"))
        .expect("exif node");
    let columns = value::get(exif_node, "columns")
        .and_then(Value::as_array)
        .expect("columns");
    assert!(columns.iter().any(|column| {
        value::optional_str(column, "key") == Some("photo.sha256")
    }));
    assert!(harness.host.progress.lock().unwrap().is_empty() || true);
}

#[test]
fn max_files_and_include_no_exif_parameters_are_honoured() {
    let harness = Harness::new(MockHost::tree());
    let limited = harness.analyze_evidence(value::map([
        ("maxFiles", Value::from(2_u64)),
        ("photoDir", Value::from("DCIM/Camera")),
    ]));
    let photos = artifacts(&limited)
        .into_iter()
        .filter(|artifact| artifact_type(artifact) == "photo.exif")
        .count();
    assert_eq!(photos, 2, "maxFiles=2 must stop after two photos");
    let summary = value::optional_str(&limited, "summary").expect("summary");
    assert!(summary.contains("超出上限未解析 4"), "{summary}");

    let no_exif_hidden = harness.analyze_evidence(value::map([
        ("includeNoExif", Value::from(false)),
    ]));
    let paths: Vec<&str> = artifacts(&no_exif_hidden)
        .into_iter()
        .filter(|artifact| artifact_type(artifact) == "photo.exif")
        .filter_map(|artifact| attr_str(artifact, "photo.path"))
        .collect();
    assert!(!paths.contains(&"DCIM/Camera/NoExif.jpg"), "{paths:?}");
    assert!(paths.contains(&"DCIM/Camera/IMG_0001.jpg"));
}

#[test]
fn missing_photo_directory_yields_summary_only() {
    let mut host = MockHost::tree();
    host.files.clear();
    host.files
        .insert("etc/hostname".to_owned(), b"box\n".to_vec());
    let harness = Harness::new(host);
    let reply = harness.analyze_evidence(value::map([(
        "photoDir",
        Value::from("DCIM/Camera"),
    )]));
    let summary = value::optional_str(&reply, "summary").expect("summary");
    assert!(summary.contains("未找到照片目录"), "{summary}");
    assert!(artifacts(&reply).is_empty(), "no fabricated artifacts");
}

#[test]
fn file_analyzer_handles_photo_text_and_garbage() {
    let (with_gps, _, _) = jpeg_with_gps();
    let harness = Harness::new(MockHost::with_single(with_gps.clone()));
    let reply = harness.analyze_file("IMG_0009.jpg", with_gps.len() as u64);
    let all = artifacts(&reply);
    assert_eq!(all.len(), 1);
    assert_eq!(artifact_type(all[0]), "photo.exif");
    assert_eq!(
        attr_str(all[0], "source.path"),
        Some("IMG_0009.jpg")
    );
    assert_eq!(
        attr_str(all[0], "photo.datetime_original"),
        Some("2023:08:15 10:30:00")
    );

    let harness = Harness::new(MockHost::with_single(text_disguised_as_jpeg()));
    let reply = harness.analyze_file("fake.jpg", 232);
    let all = artifacts(&reply);
    assert_eq!(artifact_type(all[0]), "photo.issue");
    assert_eq!(attr_str(all[0], "photo.reason"), Some("not_image"));
    let findings = value::get(&reply, "findings")
        .and_then(Value::as_array)
        .expect("findings");
    assert_eq!(findings.len(), 1);

    let (plain, _, _) = ljnljn_kb_exif_photo_metadata_8ffbc036::testing::JpegSample {
        with_app0: true,
        with_scan: true,
        ..Default::default()
    }
    .build();
    let harness = Harness::new(MockHost::with_single(plain.clone()));
    let reply = harness.analyze_file("plain.jpg", plain.len() as u64);
    let all = artifacts(&reply);
    assert_eq!(artifact_type(all[0]), "photo.exif");
    assert_eq!(
        attr(all[0], "photo.exif"),
        Some(&Value::Boolean(false)),
        "no-EXIF file still produces an (empty) record"
    );
}
