//! LovelyCarve 插件 `org.ljnljn.sqlcipher-profile`
//! （analyzer `ljnljn.sqlcipher-profile`）。
//!
//! 能力范围（唯一可离线复用、且不含案件特有硬编码口令的部分）：
//! **识别单个文件是否为 SQLCipher 加密的 SQLite 数据库**，并基于文件头与
//! 第一页结构推断加密参数、可选地做单页 HMAC 试校验。
//!
//! 明确**不做**：从二进制/APK 中提取密钥（libeasyjni.so .rodata 的 base64、
//! TEA 变换等属于案件特有逆向链）、整套 SQLCipher 解密与表读取、
//! WAL/journal 处理。插件内不内置任何历史口令或主密钥，密钥只能来自
//! 调用参数（本版本由 [`profile::Options`] 显式传入）。
//!
//! 模块：
//! * [`sha512`] / [`hmac`] / [`hex`]：无第三方依赖的 SHA-512/256、HMAC、PBKDF2；
//! * [`profile`]：纯解析（头部解析、结构检查、参数画像、页 HMAC 试校验、
//!   合成样例构造）；
//! * [`analyzer`]：`FileAnalyzer` 实现，只经 SDK 只读句柄读取字节。

pub mod analyzer;
pub mod hex;
pub mod hmac;
pub mod profile;
pub mod sha512;

#[cfg(test)]
mod test_support;

use lovelycarve_plugin::{export_plugin, Plugin};

pub use analyzer::{SqlCipherHeaderProfile, ANALYZER_NAME, NS};

/// 插件 id，必须与 plugin.toml 的 `id`、`Plugin::new` 完全一致。
pub const PLUGIN_ID: &str = "org.ljnljn.sqlcipher-profile";
/// 显示名，必须与 plugin.toml 的 `name` 一致。
pub const PLUGIN_NAME: &str = "SQLCipher 文件头画像";
/// 版本，与 Cargo 包版本和 plugin.toml 一致。
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, PLUGIN_VERSION)
        .file_analyzer(SqlCipherHeaderProfile::profile_only())
}

export_plugin!(plugin);

#[cfg(test)]
mod identity_tests {
    use super::*;
    use lovelycarve_plugin::FileAnalyzer;

    #[test]
    fn analyzer_trait_object_is_registered_under_the_manifest_name() {
        // 用与 plugin() 完全相同的构造路径，确认 analyzer 名可分发。
        let analyzer: Box<dyn FileAnalyzer> = Box::new(SqlCipherHeaderProfile::profile_only());
        assert_eq!(analyzer.analyzer(), ANALYZER_NAME);
    }

    #[test]
    fn identity_strings_are_stable() {
        assert_eq!(
            PLUGIN_ID,
            "org.ljnljn.sqlcipher-profile"
        );
        assert_eq!(PLUGIN_NAME, "SQLCipher 文件头画像");
        assert_eq!(PLUGIN_VERSION, "0.1.0");
    }
}
