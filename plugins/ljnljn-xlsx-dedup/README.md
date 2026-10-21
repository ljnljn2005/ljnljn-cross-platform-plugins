# ljnljn-xlsx-dedup

LovelyCarve **LPP v2** 插件：收件人表格（`.xlsx` / `.xlsm` / 含 xlsx 的 `.zip`）
按「姓名 + 电话 + 地址」三元组去重统计。

- 插件 ID：`org.ljnljn.xlsx-dedup`
- 版本：`0.1.0`（SDK `lovelycarve-plugin 0.2.0`）
- 分析器：
  - `dedup_files`（`scope = "files"`，扩展名 `xlsx`、`xlsm`、`zip`）
  - `dedup_evidence`（`scope = "evidence"`，递归遍历检材卷）
- 记录类型：`xlsx.dedup.summary`、`.file`、`.sheet`、`.duplicate`、`.incomplete`、
  `.rejected`
- 权限：无
- 结构哈希：`fnv1a64:d9a6313f74e97a97`

## 能力

容器、工作簿、表头、规范化与去重层从 v1 原样复用（`zipread` / `xlsx` / `header` /
`normalize` / `dedup` / `parse`），未重写 ZIP、XML 或去重逻辑：

- 只接受 STORED/DEFLATE，校验 CRC32，防 zip-slip 与 zip 炸弹；忽略
  `__MACOSX`、`~$` 临时文件与隐藏文件；
- 流式读取共享字符串、内联串、日期样式与合并单元格；
- **表头识别**：前三行中英文别名匹配；未命中时按已知列序回退并标记
  `header_source = positional`（`ID,姓名,电话,地址,省,市,10` 或三列布局）；
- **规范化**：全角转半角、空白压缩、电话只保留数字与一个前导 `+`、地址标点与
  常见分隔符归一、姓名去空白；
- **去重计数**：
  - `total_rows`：参与工作表（表头已确定）的非空行数，含表头行；
  - `valid_rows`：姓名/电话/地址三项规范化后都非空；
  - `unique_count`：规范化三元组的去重数量；
  - `duplicate_count = valid_rows - unique_count`；
  - `incomplete_rows`：至少一项为空，不参与去重；
  - 跨文件、跨工作表共享同一去重键空间；重复组按出现次数降序输出。
- `.zip` 输入会展开其中的 `xlsx`/`xlsm` 成员，来源显示为 `归档::成员`。

重复组只输出**脱敏**键：姓名首字 + `*`、电话前 3 后 4、地址首 6 末 4；完整的
规范化姓名/电话/地址不会写进结果。

## 两个分析器

- `dedup_files`：用户选中的文件作为输入，一次运行内跨文件去重。
- `dedup_evidence`：从检材视图根开始的有界递归遍历（深度 ≤ 10），跳过
  `Windows`、`$Recycle.Bin`、`System Volume Information`、`proc`、`sys`、`dev`
  等系统目录；只收集表格与 zip，最多 512 个输入，超出会写入限制说明。

## 记录

| 类型 | 说明 |
| --- | --- |
| `xlsx.dedup.summary` | 全量计数、文件/工作表数、重复组数、表头来源、限制、达到行数上限的文件 |
| `xlsx.dedup.file` | 单个文件/归档成员的：工作表数、参与数、行数、有效/缺项、跳过表 |
| `xlsx.dedup.sheet` | 工作表表头来源、表头行、姓名/电话/地址列号、行数、跳过原因 |
| `xlsx.dedup.duplicate` | 脱敏三元组、出现次数、首次来源、全部来源 `文件!工作表!行号` |
| `xlsx.dedup.incomplete` | 缺项行的文件/工作表/行号、缺失字段、脱敏值 |
| `xlsx.dedup.rejected` | 无法解析的输入与稳定错误代码（`not_zip_container`、`zip.crc` …） |

每条文件/重复/缺项记录都带源文件引用（证据卷内路径或归档路径），并尽量带上
归档内条目说明。

## 构建与测试

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_xlsx_dedup.dll > schema.json
```

独立 workspace（`[workspace]`），SDK 路径 `../../_plugin-gen/_sdk_v2-official/sdk`；
`testing` feature 只在 dev-dependencies 启用。测试使用内存生成的合成 xlsx/zip。

## 安装包布局

```text
ljnljn-xlsx-dedup/
├── plugin.toml
├── ljnljn_xlsx_dedup.dll
├── schema.json
├── README.md
├── LICENSE
└── locales/{en,zh-CN}.toml
```

## 边界

- 同名不同电话、同电话不同名都视为不同人；不做拼音、地址分词或编辑距离等
  模糊相似去重。
- 不解析 `.xls`/`.csv`/`.docx`/`.pdf`，不递归解析 zip 内的非 xlsx 资源。
- 单元格日期保留原始序列值文本，不做时区或纪元换算；宏与外部链接从不执行。
- 每表最多 300,000 行、128 列；去重键上限 200,000；重复组最多输出 200 组、
  缺项行最多 200 行；文件/工作表级上限会在 `limitations` 中说明。
- 地址规范化可能把个别有语义的门牌号写法合并（与 v1 相同的已知取舍）。
- 只读逻辑句柄，不联网、不写检材。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
