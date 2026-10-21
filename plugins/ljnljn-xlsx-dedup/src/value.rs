//! LPP `Value` 小工具：宿主参数与结果都用 MessagePack 值表达。

use lovelycarve_plugin::Value;

/// 构造字符串键的 map（参数与结果构造的便捷函数）。
pub fn map<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

/// 取 `key` 的字符串值（nil / 非字符串为 `None`）。
pub fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_map()?.iter().find_map(|(entry_key, entry_value)| {
        (entry_key.as_str() == Some(key)).then_some(entry_value)
    })
}

pub fn get_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    get(value, key).and_then(Value::as_str)
}

pub fn get_u64(value: &Value, key: &str) -> Option<u64> {
    get(value, key).and_then(Value::as_u64)
}

pub fn get_bool(value: &Value, key: &str) -> Option<bool> {
    get(value, key).and_then(Value::as_bool)
}

/// 字符串数组（兼容单个字符串）。
pub fn get_string_list(value: &Value, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    match get(value, key) {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(text) = item.as_str() {
                    out.push(text.to_owned());
                }
            }
        }
        Some(other) => {
            if let Some(text) = other.as_str() {
                out.push(text.to_owned());
            }
        }
        None => {}
    }
    out
}

/// 构造 `{code, message}` 错误值。
pub fn error_value(code: &str, message: &str) -> Value {
    Value::Map(vec![
        (Value::from("code"), Value::from(code)),
        (Value::from("message"), Value::from(message)),
    ])
}
