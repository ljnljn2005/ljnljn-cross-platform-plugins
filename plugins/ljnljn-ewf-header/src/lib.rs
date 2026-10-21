#![recursion_limit = "256"]

//! LovelyCarve 插件 `org.ljnljn.ewf-header`
//! （analyzer `ljnljn.ewf-header`）。
//!
//! 能力：**EWF/E01 段文件头部元数据的最小离线解析**——按公开 EWF1 结构
//! 识别 8 字节 EVF 签名、13 字节文件头（fields_start、u16 段号、fields_end）、
//! 段号与扩展名序号一致性、文件头之后第一枚 76 字节节段描述符的
//! `headerLength` 及越界错误，并在有界窗口内遍历节段链、对 EWF1 volume
//! 节段读取卷头候选值（sectors_per_chunk、sector_size、sector_count、
//! media_flags、compression_level 与推导的 media_size_bytes）。
//! EWF2/Ex01 只识别 32 字节 v2 文件头，明确不解析其后布局。
//!
//! 明确不做：chunk 表遍历、数据解压、哈希重算、逻辑卷大小计算、
//! MBR/$Boot 分区层交叉印证。任何异常写入 results 的 errors/findings，
//! 不静默置零。
//!
//! 模块：
//! * [`ewf`]：纯解析（签名、段号、格式、头部区、节段描述符、卷头候选值）；
//! * [`synth`]：按公开结构自造的合成段文件（测试与独立样例共用）；
//! * [`analyzer`]：`FileAnalyzer` 实现，只经 SDK 只读句柄有界读取。

pub mod analyzer;
pub mod ewf;
pub mod synth;

use lovelycarve_plugin::{export_plugin, Plugin};

pub use analyzer::{EwfHeaderMetadata, ANALYZER_NAME, NS};
pub use ewf::{parse_segment, SegmentRecord};

/// 插件 id，必须与 plugin.toml 的 `id`、`Plugin::new` 一致。
pub const PLUGIN_ID: &str = "org.ljnljn.ewf-header";
/// 显示名，必须与 plugin.toml 的 `name` 一致。
pub const PLUGIN_NAME: &str = "EWF/E01 头部元数据";
/// 版本，与 Cargo 包版本、plugin.toml 一致。
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, PLUGIN_VERSION).file_analyzer(EwfHeaderMetadata::new())
}

export_plugin!(plugin);

#[cfg(test)]
mod identity_tests {
    use super::*;
    use lovelycarve_plugin::FileAnalyzer;

    #[test]
    fn analyzer_is_registered_under_the_manifest_name() {
        let analyzer: Box<dyn FileAnalyzer> = Box::new(EwfHeaderMetadata::new());
        assert_eq!(analyzer.analyzer(), ANALYZER_NAME);
        assert_eq!(ANALYZER_NAME, "ljnljn.ewf-header");
    }

    #[test]
    fn identity_strings_match_the_manifest() {
        assert_eq!(PLUGIN_ID, "org.ljnljn.ewf-header");
        assert_eq!(PLUGIN_NAME, "EWF/E01 头部元数据");
        assert_eq!(PLUGIN_VERSION, "0.1.0");
    }

    #[test]
    fn plugin_manifest_values_are_consistent() {
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains(&format!("id = \"{PLUGIN_ID}\"")));
        assert!(manifest.contains(&format!("name = \"{PLUGIN_NAME}\"")));
        assert!(manifest.contains(&format!("analyzer = \"{ANALYZER_NAME}\"")));
        assert!(manifest.contains(&format!(
            "path = \"{}\"",
            "ljnljn_kb_ewf_header_metadata_3bcc39e8"
        )));
        assert!(manifest.contains("type = \"file_analyzer\""));
        assert!(manifest.contains("isolation = \"process\""));
    }
}
