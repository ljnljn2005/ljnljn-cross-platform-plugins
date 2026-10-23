# ljnljn-ileapp-aleapp-report

LovelyCarve **LPP v2** 插件：导入 [iLEAPP](https://github.com/abrignoni/iLEAPP)
与 [ALEAPP](https://github.com/abrignoni/ALEAPP) 生成的 TSV 报告。

- 插件 ID：`org.ljnljn.ileapp-aleapp-report`
- 记录：`mobile.report.file`、`mobile.report.row`

## 为什么导入报告，而不是在插件里运行工具

iLEAPP / ALEAPP 是 Python 工具，需要完整可写的解包目录，并会启动自己的模块
体系。LovelyCarve v2 的插件运行在隔离的 `lc-plugin-host` 进程里，拿到的是只读、
不透明路径的检材视图，不允许访问网络，也不适合在分析器内派生任意子进程。

因此集成点放在**报告层**：先用 iLEAPP / ALEAPP 在外部完成解析，再用本插件把
`_TSV Exports/*.tsv` 结构化入库。这样报告里的每一行都能进入 LovelyCarve 的时间线、
搜索和关联视图，同时保持插件只读、可复现。

## 使用方式

1. 用 iLEAPP / ALEAPP 处理镜像或文件系统，保持默认的
   `<报告目录>/_TSV Exports/` 布局。
2. 在 LovelyCarve 中任选一个分析器：

   - `report_files`：手动选择一个或多个 `.tsv` 文件；
   - `report_system`：在识别出的系统分区中按 `_TSV Exports/` 查找；
   - `report_evidence`：遍历检材各卷，查找
     `**/_TSV Exports/*.tsv`。

3. 每个报告文件输出一条 `mobile.report.file`，每行数据输出一条
   `mobile.report.row`。行记录保留表头（`columns`）与整行值（`values`），
   并带来源文件、行号和模块名。

## 解析行为

- 按 Python `csv.writer` 的 TSV 规则解析：引号内的制表符、换行和 `""`
  转义都保留在字段中；支持 UTF-8 BOM 与 CRLF。
- 工具归属取路径中的 `iLEAPP` / `ALEAPP` 目录名；单文件输入若路径里没有
  工具名，`tool` 记为 `unknown`。
- 模块名取 TSV 文件名（去掉 `.tsv`）。
- 单个文件最多读取 128 MiB、输出 100,000 行；超出时
  `mobile.report.file.status = "truncated"` 并给出告警。
- 短行用空值补齐到表头列数；长行保留全部值并标记
  `status = "ragged"`、给出 `REPORT_STATUS` 告警，不静默截断。
- 空报告输出 `status = "empty"`，不伪造数据行；找不到报告目录时告警
  `REPORT_NOT_FOUND`。

## 构建

```bash
cargo test --locked
cargo build --release --locked
```

需要 LovelyCarve v2 宿主（protocol 2）。Release 中的 `.lcpkg` 可直接安装。

## 边界

- 不执行 iLEAPP / ALEAPP，不解析它们的数据源（SQLite、plist、备份文件等）。
- 不解释模块字段含义；报告列名与值按原样保存，便于后续检索和复核。
- 不解压、不修改报告目录，只读取 `.tsv` 文件。
- 截断警告表示该文件只导入了前 100,000 行，需要缩小报告范围后重新导入。

## 许可证

AGPL-3.0-only。
