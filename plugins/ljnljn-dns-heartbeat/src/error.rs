//! 分析错误类型：带稳定 code 与中文可读信息的解析失败原因。
//!
//! 插件对外（LPP）返回 `lovelycarve_plugin::Error`；内部各解析层使用
//! [`AnalyzeError`]，到分析器边界统一转换成 LPP 错误，避免"吞错误成空成功"。

use std::fmt;

use lovelycarve_plugin::{Error as PluginError, Result as PluginResult};

/// 稳定错误码。小写蛇形，便于测试与日志逐字断言。
pub const E_NO_TIMESTAMP: &str = "no_valid_timestamp";
pub const E_TRUNCATED_CAPTURE: &str = "truncated_capture";
pub const E_UNSUPPORTED_FORMAT: &str = "unsupported_capture_format";
pub const E_CORRUPT_BLOCK: &str = "corrupt_pcapng_block";
pub const E_CORRUPT_PACKET: &str = "corrupt_packet_record";
pub const E_IO: &str = "read_error";
pub const E_CANCELLED: &str = "cancelled";
pub const E_INVALID_OPTION: &str = "invalid_option";

/// DNS 心跳周期分析的内部错误。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalyzeError {
    pub code: &'static str,
    pub message: String,
    /// 出错的记录槽位号（0 起）；未知时为 `None`。
    pub record_index: Option<u64>,
    /// 该槽位在抓包文件中的字节偏移；未知时为 `None`。
    pub offset: Option<u64>,
}

impl AnalyzeError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            record_index: None,
            offset: None,
        }
    }

    /// 附上文件内定位信息（槽位号与字节偏移），便于回溯到抓包位置。
    pub fn at(mut self, record_index: u64, offset: u64) -> Self {
        self.record_index = Some(record_index);
        self.offset = Some(offset);
        self
    }

    /// 转成 LPP 错误：code 保持原样，message 里带文件内定位。
    pub fn into_plugin(self) -> PluginError {
        let mut message = self.message;
        if let Some(index) = self.record_index {
            message.push_str(&format!("；记录槽位 #{index}"));
        }
        if let Some(offset) = self.offset {
            message.push_str(&format!("（文件偏移 {offset}）"));
        }
        PluginError::new(self.code, message)
    }
}

impl fmt::Display for AnalyzeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl From<PluginError> for AnalyzeError {
    fn from(error: PluginError) -> Self {
        // 宿主调用错误（取消、RESOURCE_LIMIT、句柄失效）保持原有 code。
        let code: &'static str = match error.code.as_str() {
            "CANCELLED" => E_CANCELLED,
            _ => E_IO,
        };
        Self::new(
            code,
            format!("宿主读取失败 {}: {}", error.code, error.message),
        )
    }
}

impl From<AnalyzeError> for PluginError {
    fn from(error: AnalyzeError) -> Self {
        error.into_plugin()
    }
}

/// 便捷别名：`AnalyzeResult<T>` 为内部结果类型。
pub type AnalyzeResult<T> = std::result::Result<T, AnalyzeError>;

/// 把内部结果转成 LPP 结果。
pub fn to_plugin<T>(result: AnalyzeResult<T>) -> PluginResult<T> {
    result.map_err(AnalyzeError::into_plugin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_error_message_keeps_location() {
        let error = AnalyzeError::new(E_CORRUPT_BLOCK, "坏块").at(7, 4096);
        let plugin = error.into_plugin();
        assert_eq!(plugin.code, "corrupt_pcapng_block");
        assert!(plugin.message.contains("记录槽位 #7"), "{}", plugin.message);
        assert!(
            plugin.message.contains("文件偏移 4096"),
            "{}",
            plugin.message
        );
    }

    #[test]
    fn cancellation_code_survives_conversion() {
        let error = AnalyzeError::from(PluginError::cancelled());
        assert_eq!(error.code, E_CANCELLED);
        assert_eq!(PluginError::from(error).code, "cancelled");
    }
}
