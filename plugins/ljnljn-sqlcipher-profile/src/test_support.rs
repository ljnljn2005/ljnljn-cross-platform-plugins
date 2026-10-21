//! 测试支撑：一个最小"假宿主"，让 `File` 句柄也能在单元测试里被端到端验证。
//!
//! 背景：SDK 的 `File` 只有 `pub(crate)` 构造器，插件无法直接造一个。这里
//! 走 SDK 公开的 C ABI v1（`abi::HostApiV1` + `lovelycarve_plugin_v1` 入口），
//! 用一份内存中的字节流应答 `file.read`，再调用 `analyzer.analyze`，从而覆盖
//! "句柄读取 → 解析 → 结果映射"的整条链路；不依赖宿主程序，也不读真实检材。

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use lovelycarve_plugin::abi::{
    self, Buffer, Bytes, HostApiV1, PluginApiV1, ENTRY_SYMBOL, HOST_API_SIZE,
};
use lovelycarve_plugin::{AnalysisResult, Value};
use lovelycarve_plugin::value;
use lovelycarve_plugin::Value as RawValue;

/// 每个测试进程只登记一份字节流（测试串行化由 `host_lock()` 保证）。
fn fixture() -> &'static Mutex<Vec<u8>> {
    static FIXTURE: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
    FIXTURE.get_or_init(|| Mutex::new(Vec::new()))
}

fn host_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

unsafe extern "C" fn fake_call(
    _context: *mut c_void,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32 {
    let method = String::from_utf8_lossy(unsafe { method.as_slice() }).to_string();
    let params = unsafe { params.as_slice() };
    let reply = match method.as_str() {
        "file.read" => {
            let offset = field_u64(params, "offset").unwrap_or(0) as usize;
            let length = field_u64(params, "length").unwrap_or(0) as usize;
            let data = fixture().lock().expect("fixture lock");
            if offset >= data.len() {
                RawValue::Binary(Vec::new())
            } else {
                let end = offset.saturating_add(length).min(data.len());
                RawValue::Binary(data[offset..end].to_vec())
            }
        }
        "host.progress" => RawValue::Nil,
        _ => RawValue::Map(vec![
            (RawValue::from("code"), RawValue::from("METHOD_NOT_FOUND")),
            (
                RawValue::from("message"),
                RawValue::from(method.as_str()),
            ),
        ]),
    };
    let ok = method == "file.read" || method == "host.progress";
    let encoded = value::encode(&reply).expect("encode reply");
    unsafe {
        *out = Buffer::from_vec(encoded);
    }
    if ok {
        abi::STATUS_OK
    } else {
        abi::STATUS_ERROR
    }
}

unsafe extern "C" fn fake_free_buffer(_context: *mut c_void, buffer: *mut Buffer) {
    unsafe {
        (*buffer).free_vec();
    }
}

unsafe extern "C" fn fake_log(_context: *mut c_void, _level: u32, _message: Bytes) {}

fn field_u64(encoded: &[u8], key: &str) -> Option<u64> {
    let value = value::decode(encoded).ok()?;
    value
        .as_map()?
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .and_then(|(_, entry_value)| entry_value.as_u64())
}

/// 用内存数据跑一次 `analyzer.analyze`，返回 LPP 结果。
pub fn analyze_bytes(name: &str, data: &[u8]) -> (AnalysisResult, Value) {
    let _guard = host_lock().lock().expect("host lock");
    *fixture().lock().expect("fixture lock") = data.to_vec();

    // 通过 SDK 导出的入口创建实例（与宿主加载路径一致）。
    let entry = {
        let symbol = std::ffi::CStr::from_bytes_with_nul(ENTRY_SYMBOL).expect("entry symbol");
        libc_like_load(symbol)
    };
    let mut plugin = PluginApiV1 {
        abi_version: abi::ABI_VERSION,
        struct_size: abi::PLUGIN_API_SIZE,
        instance: std::ptr::null_mut(),
        describe: describe_stub,
        call: call_stub,
        cancel: cancel_stub,
        free_buffer: free_stub,
        destroy: destroy_stub,
    };
    let host = HostApiV1 {
        abi_version: abi::ABI_VERSION,
        struct_size: HOST_API_SIZE,
        context: std::ptr::null_mut(),
        call: fake_call,
        free_buffer: fake_free_buffer,
        log: fake_log,
    };
    let status = unsafe { entry(&host, &mut plugin) };
    assert_eq!(status, abi::STATUS_OK, "entry point failed");

    // 构造 analyzer.analyze 参数：{analyzer, file: {file_id, name, size, mime}}
    let handle = RawValue::Map(vec![
        (RawValue::from("file_id"), RawValue::from("fixture-file")),
        (RawValue::from("name"), RawValue::from(name)),
        (RawValue::from("size"), RawValue::from(data.len() as u64)),
        (
            RawValue::from("mime"),
            RawValue::from("application/octet-stream"),
        ),
    ]);
    let params = RawValue::Map(vec![
        (
            RawValue::from("analyzer"),
            RawValue::from(crate::analyzer::ANALYZER_NAME),
        ),
        (RawValue::from("file"), handle),
    ]);
    let encoded = value::encode(&params).expect("encode params");
    let mut out = Buffer::empty();
    let status = unsafe {
        (plugin.call)(
            plugin.instance,
            2,
            Bytes::from_slice(b"analyzer.analyze"),
            Bytes::from_slice(&encoded),
            &mut out,
        )
    };
    let bytes = unsafe { out.as_slice().to_vec() };
    unsafe {
        (plugin.free_buffer)(plugin.instance, &mut out);
        (plugin.destroy)(plugin.instance);
    }
    let raw = value::decode(&bytes).expect("decode result");
    assert_eq!(status, abi::STATUS_OK, "analyze failed: {raw:?}");
    let result = decode_result(&raw);
    drop(_guard);
    (result, Value::Nil)
}

fn decode_result(raw: &RawValue) -> AnalysisResult {
    let text = |value: Option<&RawValue>| value.and_then(RawValue::as_str).map(str::to_owned);
    let array = |value: Option<&RawValue>| -> Vec<RawValue> {
        value.and_then(RawValue::as_array).cloned().unwrap_or_default()
    };
    let get = |value: &RawValue, key: &str| -> Option<RawValue> {
        value
            .as_map()?
            .iter()
            .find(|(entry_key, _)| entry_key.as_str() == Some(key))
            .map(|(_, entry_value)| entry_value.clone())
    };
    let mut result = AnalysisResult::default();
    result.summary = text(get(raw, "summary").as_ref());
    for item in array(get(raw, "artifacts").as_ref()) {
        let mut attributes = lovelycarve_plugin::Attributes::new();
        if let Some(RawValue::Map(entries)) = get(&item, "attributes") {
            for (key, value) in entries {
                if let Some(key) = key.as_str() {
                    attributes.insert(key, value.clone());
                }
            }
        }
        result.artifacts.push(lovelycarve_plugin::Artifact {
            artifact_type: text(get(&item, "type").as_ref()).unwrap_or_default(),
            title: text(get(&item, "title").as_ref()).unwrap_or_default(),
            value: get(&item, "value"),
            attributes,
        });
    }
    result
}

// 占位表项：真正被调用的是入口返回的表，这里只是初始化占位。
unsafe extern "C" fn describe_stub(_instance: *mut c_void, _out: *mut Buffer) -> i32 {
    abi::STATUS_ERROR
}
unsafe extern "C" fn call_stub(
    _instance: *mut c_void,
    _call_id: u64,
    _method: Bytes,
    _params: Bytes,
    _out: *mut Buffer,
) -> i32 {
    abi::STATUS_ERROR
}
unsafe extern "C" fn cancel_stub(_instance: *mut c_void, _call_id: u64) {}
unsafe extern "C" fn free_stub(_instance: *mut c_void, buffer: *mut Buffer) {
    unsafe {
        (*buffer).free_vec();
    }
}
unsafe extern "C" fn destroy_stub(_instance: *mut c_void) {}

/// 在测试进程内取入口符号：测试二进制的 cdylib 与本 crate 同源，
/// 直接通过 `linkme` 式符号查找不可用，因此走 `dlsym` 的替代——
/// 从本 crate 导出的符号表里取。
fn libc_like_load(symbol: &std::ffi::CStr) -> abi::EntryFn {
    // SAFETY: `lovelycarve_plugin_v1` 由 export_plugin! 以 C ABI 导出，
    // 签名与 `EntryFn` 一致。
    extern "C" {
        fn lovelycarve_plugin_v1(host: *const HostApiV1, plugin: *mut PluginApiV1) -> i32;
    }
    let _ = symbol;
    unsafe { std::mem::transmute::<_, abi::EntryFn>(lovelycarve_plugin_v1 as unsafe extern "C" fn(*const HostApiV1, *mut PluginApiV1) -> i32) }
}
