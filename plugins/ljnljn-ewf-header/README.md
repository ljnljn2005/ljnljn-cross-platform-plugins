# ljnljn-ewf-header

LovelyCarve **LPP v2** 原生插件（pre-release）：离线、只读地解析 EWF/E01 段文件
的文件头与节段头部元数据。

- 插件 ID：`org.ljnljn.ewf-header`
- 版本：`0.1.0`
- SDK：`lovelycarve-plugin 0.2.0`（LPP v2，C ABI v1）
- 作用域：`files`，扩展名 `e01` / `ewf`
- 分析器：`ewf_header`
- 记录类型：`ewf.segment`、`ewf.header`、`ewf.section`
- 结构哈希：`fnv1a64:a762412a2575bfef`

本插件是 v1 `ljnljn.ewf-header` 的 LPP v2 移植：EVF 签名校验、EWF1 文件头与
节段描述符解析、有界节段链遍历、EWF1 volume 候选值全部原样复用，只重写了结果
映射。每个段文件输出一条段记录、一条文件头记录，以及窗口内每个节段一条记录。

## 解析范围

```text
EWF1 文件头（13 字节）
  ├─ 0..8   EVF\x09\x0d\x0a\xff\x00
  ├─ 8      fields_start（0x01）
  ├─ 9..11  段号（u16 LE，1 起算）
  └─ 11..13 fields_end（原样记录）

EWF1 节段描述符（76 字节）
  ├─ 0..16  类型（NUL 结尾 ASCII）
  ├─ 16..24 next 偏移（绝对，u64 LE）
  ├─ 24..32 节段长度（含描述符自身）
  └─ 72..76 adler32(0..72)

EWF1 volume 节段内容（1052 字节）
  ├─ 0       media_type
  ├─ 4..8    number_of_chunks
  ├─ 8..12   sectors_per_chunk
  ├─ 12..16  bytes_per_sector
  ├─ 16..24  number_of_sectors
  ├─ 36      media_flags
  ├─ 52      compression_level
  └─ 1048..1052 adler32(0..1048)
```

EWF2/Ex01 使用 32 字节 v2 文件头（签名、主/次版本、压缩方法、段号、16 字节集合
标识）。本插件识别并记录该文件头，**不解析其后的 v2 节段、volume/disk 布局**。

读取只有两次有界读取：文件头 512 字节 + 从偏移 13 开始、最多 64 KiB 的节段窗口。
节段链最多检查 64 枚描述符。

## 记录

### `ewf.segment` — 每个段文件一条

文件、文件大小、格式（`ewf1`/`ewf2`/`ex01`）、格式类别、段号、扩展名序号、
扩展名是否一致、文件头偏移/结束、首枚节段类型/长度、节段数、节段链是否受限、
是否含 `table`/`done` 节段、volume 节段偏移、chunk 数、每 chunk 扇区、扇区大小、
扇区总数、推导的媒体大小、压缩级别文本、volume adler32 结论、错误/告警数、
错误/告警/volume 说明 JSON、文件修改时间（带 `modified` 时间线角色，仅在宿主
提供可解析的时间戳时）。有结构错误时记录级别为 `medium`。

`segment_count_contiguous` 与 `is_last_segment` **不输出**：单个段文件无法确定，
多段连续性需要上层把同名 E01/E02… 逐个调度后比对段号。

### `ewf.header` — 每个段文件一条

文件头偏移/大小、签名是否有效、签名长度、格式、字节 8、`fields_start`、
`fields_end`（hex）、主/次版本、压缩方法、集合标识、段号、文件头 SHA-256、
是否截断、文件头十六进制（最多 512 个字节的 hex 截断）。来源精确指向文件头
字节区间。

### `ewf.section` — 窗口内每个 EWF1 节段一条

节段类型、节段偏移、节段长度、内容偏移、内容长度、下一节段偏移、adler32 自检
结果（记录值为 0 时为缺失）。adler32 不一致时记录级别为 `low`，但字段仍按原值
保留。来源指向描述符 + 内容区间。

## 构建与测试

```bash
cargo test --locked          # 37 passed
cargo build --release --locked
```

Windows 产物：`target/release/ljnljn_ewf_header.dll`。

`schema.json` 由 v2 宿主导出：

```bash
lc-plugin-host --describe --library target/release/ljnljn_ewf_header.dll > schema.json
```

测试全部基于合成 EWF 段文件（`src/synth.rs`），覆盖：健康 EWF1 的
header/volume/table/done 链、EWF2/Ex01 32 字节文件头、签名错误/不完整、
文件头截断、段号与扩展名不一致、Ex01 扩展名配 EWF1 头、节段长度为 0/过短/越界、
next 不前进、next 落入本节段内容、节段链超出 64 KiB 窗口、volume 缺失/disk 节段、
adler32 不一致、空文件，以及 Harness 端到端的段/文件头/节段记录与来源偏移。

## 安装

```text
ljnljn-ewf-header/
├── plugin.toml
├── ljnljn_ewf_header.dll
├── schema.json
└── locales/
    ├── en.toml
    └── zh-CN.toml
```

在文件列表中选中 `.e01` / `.ewf` 段文件，执行「EWF/E01 头部元数据（段级）」。

## 边界（明确未覆盖）

- **只做头部/节段元数据**：不遍历 chunk 表、不解压数据、不重算流哈希、不计算
  逻辑卷大小、不解析分区或文件系统。因此不能据此证明镜像内容完整或未被篡改。
- **EWF2/Ex01 只识别 32 字节文件头**：v2 节段描述符、volume/disk 布局未实现，
  节段与卷候选值全部为空。
- 节段链只在文件头之后 64 KiB 的有界窗口内、最多 64 枚描述符；窗口之外停止并
  在告警中说明，`table`/`done` 标记与 volume 查找可能不完整。
- EWF1 标准节段没有 `disk`；`disk` 节段属于 EWF2/Ex01 布局，不按 volume 解析。
- `sectors_per_chunk` / `number_of_sectors` 保持镜像原始值；`media_size_bytes`
  只是 `number_of_sectors × bytes_per_sector` 的推导值。
- adler32 只做展示性比对，不因校验失败中止解析。
- 扩展名序号只识别 `E01..E99` 与 `Ex01..Ex99`；`EAA/EAB` 等字母序号扩展名无法
  比对。清单只声明 `.e01` / `.ewf` 两种扩展名，因此 `E02…`、`Ex01` 需要由
  operator 另行选择或在清单中补充后才会被调度。
- 这是使用新 SDK 的 pre-release：已通过单元测试、release 构建和 v2 宿主
  `--describe` 校验，尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。
