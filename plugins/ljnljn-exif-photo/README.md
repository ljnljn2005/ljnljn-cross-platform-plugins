# ljnljn-exif-photo

LovelyCarve **LPP v2** 插件：照片真实格式识别与 EXIF/GPS 元数据解析。

- 插件 ID：`org.ljnljn.exif-photo`
- 版本：`0.1.0`（SDK `lovelycarve-plugin 0.2.0`）
- 分析器：
  - `exif_files`（`scope = "files"`，扩展名 `jpg`、`jpeg`、`png`、`heic`、`heif`）
  - `exif_evidence`（`scope = "evidence"`，递归遍历检材卷）
- 记录类型：`photo.exif`、`photo.issue`、`photo.summary`
- 权限：无
- 结构哈希：`fnv1a64:6c148622508158dd`

## 能力

容器扫描、TIFF/IFD 读取、字段解释与格式嗅探从 v1 原样复用
（`container` / `exif` / `fields` / `format` / `record` / `sha256`）：

- 扩展名只决定候选；**真实格式由文件头魔数决定**（JPEG SOI、PNG 签名、
  ISO-BMFF `ftyp` 的 HEIC/HEIF 品牌）。扩展名与真实格式不符时按真实格式解析，
  并在记录中标记 `extension_mismatch`；
- 解析 JPEG APP1 `Exif\0\0` 与 PNG `eXIf` 的 TIFF 结构：IFD0、ExifIFD、GPS IFD；
- 输出拍摄时间、厂商、机型、镜头、软件、像素尺寸、方向、GPS 经纬度/海拔、
  GPS 日期/时间/卫星、缺失字段、每个字段的文件内偏移；
- PNG 额外读取 `tEXt`/`iTXt`/`zTXt` 与 XMP 包摘要；
- 截断、越界、循环 IFD 会拒绝整张照片并生成 `photo.issue`，不输出伪装成成功的
  空字段记录；非图片内容（文本改名为 `.jpg`）也会记录原因；
- 文件 SHA-256 复用内置实现。

**时间处理**：`datetime_original_raw` 保留 EXIF 原串（如
`2023:08:15 10:30:00`）。`capture_time` 是同一组数字的**本地墙钟**时间戳
（RFC 3339 无偏移），不补年份、不换算时区；`datetime_original_offset` 只记录
EXIF 自带偏移，从不应用。带偏移的时间不会进入案件时间线。

**GPS**：度 + 分/60 + 秒/3600，符号只来自 `N/S/E/W` 参考；参考缺失时按正值输出，
并在 `gps_ref_defaulted` 标记，不猜测方向。

## 选项

两个分析器都支持：

| 选项 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `include_no_exif` | flag | `true` | 是否保留无 EXIF 的照片记录（仍计入汇总） |
| `max_files` | text | `5000` | 每次运行最多解析的照片数，上限 20,000 |

## 记录

| 类型 | 说明 |
| --- | --- |
| `photo.exif` | 一张照片的格式、哈希、EXIF/GPS 字段、原始时间/偏移、缺失字段、来源偏移、PNG 文本、警告 |
| `photo.issue` | 无法解析/跳过的文件：原因代码、说明、字节数 |
| `photo.summary` | 文件数、含 EXIF/GPS、无 GPS/EXIF、失败、非图片跳过、超限、失败原因 |

每个照片记录都带源文件引用；证据模式使用卷键 + 卷内路径。

## 检材递归模式

`exif_evidence` 从检材视图根开始深度优先遍历：深度 ≤ 24、目录数 ≤ 50,000，
跳过已删除节点与链接，只把扩展名属于 jpg/jpeg/png/heic/heif 的普通文件作为
候选；超过 `max_files` 的候选只计数。每个候选用与文件模式完全相同的字节解析
路径。

## 构建与测试

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_exif_photo.dll > schema.json
```

独立 workspace（`[workspace]`），SDK 路径 `../../_plugin-gen/_sdk_v2-official/sdk`；
`testing` feature 只在 dev-dependencies 启用。测试用内存合成 JPEG/PNG（含 GPS、
无 GPS、截断、伪装文本）。

## 安装包布局

```text
ljnljn-exif-photo/
├── plugin.toml
├── ljnljn_exif_photo.dll
├── schema.json
├── README.md
├── LICENSE
└── locales/{en,zh-CN}.toml
```

## 边界

- 单张照片上限 64 MiB；HEIC/HEIF 只做格式识别，不解析 ISO-BMFF 内的 EXIF；
- 不生成缩略图、不做图像内容识别、不做 GPS 反查地址；
- 不读取/执行照片中的任何可执行内容，不联网；
- EXIF 时间不推断时区，`capture_time` 因此没有偏移、不会进入全局时间线；
- 只处理宿主提供的逻辑文件句柄。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
