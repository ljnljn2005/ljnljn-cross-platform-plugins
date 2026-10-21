//! 解析层错误：稳定 `code` + 中文说明，便于在结果里区分“不存在 / 超限 / 损坏 / 不支持”。
//!
//! 解析层不依赖宿主；`From<DedupError> for lovelycarve_plugin::Error` 只在
//! [`crate::hostio`] 中做一次转换，保证纯解析代码可以在单元测试里独立运行。

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DedupError {
    pub code: &'static str,
    pub message: String,
}

impl DedupError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 超出资源上限（宿主应把这类失败当作 RESOURCE_LIMIT 上报）。
    pub fn resource(message: impl Into<String>) -> Self {
        Self::new("RESOURCE_LIMIT", message)
    }

    pub fn is_resource(&self) -> bool {
        self.code == "RESOURCE_LIMIT"
    }
}

impl std::fmt::Display for DedupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DedupError {}
