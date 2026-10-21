//! 资源上限（与宿主 LPP v1 限制对齐，超出即显式报 RESOURCE_LIMIT，不静默截断）。

/// 单个 xlsx/xlsm 包内成员总解压字节上限（防 zip 炸弹）。
pub const MAX_SHEET_XML_BYTES: u64 = 64 * 1024 * 1024;
/// `sharedStrings.xml` / `styles.xml` 等单个成员上限。
pub const MAX_AUX_XML_BYTES: u64 = 48 * 1024 * 1024;
/// 单个 xlsx 包内最多成员数。
pub const MAX_ZIP_ENTRIES: u64 = 4096;
/// 一个工作表最多处理的行数（首行表头之外的数据行）。
pub const MAX_ROWS_PER_SHEET: u64 = 300_000;
/// 一个工作表最多处理的列数（A..ZZ 足够，超出列忽略并在 limitations 记录）。
pub const MAX_COLUMNS_PER_SHEET: usize = 128;
/// 单条工作表 XML 事件里允许的最大文本缓冲（防单格巨串）。
pub const MAX_CELL_TEXT: usize = 32_768;
/// 去重用的唯一键数量上限；超过后不再累计并在 limitations 记录。
pub const MAX_UNIQUE_KEYS: usize = 200_000;
/// 单个去重键最多保留的来源行（避免结果爆炸）；超出部分只计数。
pub const MAX_SOURCES_PER_KEY: usize = 50;
/// 返回的重复组明细上限（按重复次数降序）。
pub const MAX_DUPLICATE_GROUPS: usize = 200;
/// 返回的缺失项行明细上限。
pub const MAX_INCOMPLETE_SHOWN: usize = 200;
/// 一个分析任务最多收集的源文件数（evidence/file zip 展开后）。
pub const MAX_INPUT_FILES: usize = 512;
/// 结果中最多列出的跳过/失败文件条目。
pub const MAX_REPORT_ENTRIES: usize = 200;
/// zip 内单个 xlsx/xlsm 成员的整体上限（含同体积的压缩数据读取）。
pub const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;
