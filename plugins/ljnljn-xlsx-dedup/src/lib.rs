//! 收件人表格去重统计：LovelyCarve 离线分析插件（LPP v1）。
//!
//! # 能力
//! 读取用户提供的 `.xlsx` / `.xlsm`（或含 xlsx 的 `.zip`），遍历全部工作表，
//! 逐表定位姓名/电话/地址列（中英文别名，无表头时按已知列序回退并标记
//! `headerSource=positional`），把单元格值规范化后按 (姓名, 电话, 地址)
//! 三元组做跨文件去重，输出 `totalRows` / `validRows` / `uniqueCount` /
//! `duplicateCount` / `incompleteRows` / `perFileRows` / `duplicateGroups[]` /
//! `headerSource` / `skippedSheets` / `limitations`。
//!
//! # 模块
//! - [`zipread`]：只读 ZIP 容器（STORED/DEFLATE、CRC32、zip-slip 防护、ZIP64）
//! - [`xlsx`]：流式工作表解析（共享字符串、内联串、日期样式、合并单元格）
//! - [`header`]：表头别名与列序回退
//! - [`normalize`]：全角转半角、空白压缩、电话/地址/姓名规范化与脱敏
//! - [`dedup`]：三元组去重与统计聚合（纯解析层）
//! - [`parse`] / [`hostio`]：宿主句柄输入与只读读取
//! - [`report`]：LPP 结果组装（summary / nodes / artifacts / findings）
//!
//! # 安全边界
//! 插件只读 SDK 句柄，不执行宏、不访问网络、不写检材；
//! 所有读取都有字节上限，超限返回 `RESOURCE_LIMIT`。

pub mod analyzer;
pub mod dedup;
pub mod error;
pub mod header;
pub mod hostio;
pub mod limits;
pub mod normalize;
pub mod parse;
pub mod report;
pub mod value;
pub mod xlsx;
pub mod zipread;

/// 合成 xlsx/zip 夹具与自检工具；只编译进测试，部署的 DLL 不含任何夹具代码。
#[cfg(test)]
pub mod fixtures;

use lovelycarve_plugin::Plugin;

pub use analyzer::{ANALYZER, ANALYZER_EVIDENCE, ANALYZER_FILE};

/// 插件构造器：id / name / version 必须与 plugin.toml 完全一致，
/// 且注册的 analyzer id 与两个 capabilities 的 `analyzer` 一致。
fn plugin() -> Plugin {
    Plugin::new(
        "org.ljnljn.xlsx-dedup",
        "收件人表去重统计(姓名+电话+地址)",
        env!("CARGO_PKG_VERSION"),
    )
    .file_analyzer(analyzer::RecipientDedupFile::default())
    .evidence_analyzer(analyzer::RecipientDedupEvidence::default())
}

lovelycarve_plugin::export_plugin!(plugin);

#[cfg(test)]
mod identity_tests {
    use super::*;
    use lovelycarve_plugin::{EvidenceAnalyzer, FileAnalyzer};

    #[test]
    fn analyzer_id_matches_every_registration() {
        assert_eq!(FileAnalyzer::analyzer(&analyzer::RecipientDedupFile::default()), ANALYZER_FILE);
        assert_eq!(EvidenceAnalyzer::analyzer(&analyzer::RecipientDedupEvidence::default()), ANALYZER_EVIDENCE);
        assert_eq!(ANALYZER, "ljnljn.xlsx-dedup");
    }

    #[test]
    fn manifest_matches_code_identity() {
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains("id = \"org.ljnljn.xlsx-dedup\""));
        assert!(manifest.contains("version = \"0.1.0\""));
        assert!(manifest.contains(&format!("analyzer = \"{ANALYZER_FILE}\"")));
        assert!(manifest.contains(&format!("analyzer = \"{ANALYZER_EVIDENCE}\"")));
        assert!(manifest.contains(
            "path = \"ljnljn_kb_sf_xlsx_dedup_count_9756f644\""
        ));
        assert!(manifest.contains("permissions = [\"emit_artifacts\"]"));
    }
}
