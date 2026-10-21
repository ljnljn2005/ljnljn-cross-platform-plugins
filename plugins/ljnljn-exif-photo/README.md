# ljnljn-exif-photo

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.exif-photo`。

递归识别照片真实格式并解析 EXIF/GPS 等元数据。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 整份检材 | `ljnljn.exif-photo` | — |
| 单文件 | `ljnljn.exif-photo.file` | — |

## 覆盖范围

- 照片目录递归枚举
- 真实格式识别(扩展名+魔数)
- EXIF IFD0/ExifIFD/GPS IFD
- PNG eXIf/tEXt/XMP
- 经纬度十进制度换算
- 汇总统计与失败原因

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_exif_photo_metadata_8ffbc036.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_exif_photo_metadata_8ffbc036.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

依赖文件内嵌元数据；缺失字段不会推断。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
