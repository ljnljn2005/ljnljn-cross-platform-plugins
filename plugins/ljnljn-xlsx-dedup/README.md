# ljnljn-xlsx-dedup

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.xlsx-dedup`。

按姓名、电话、地址对 xlsx 收件人表去重计数。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 整份检材 | `ljnljn.xlsx-dedup.evidence` | — |
| 单文件 | `ljnljn.xlsx-dedup.file` | xlsx, xlsm, zip |

## 覆盖范围

- xlsx 工作表枚举
- 表头识别(中英文别名/列序回退)
- zip 内 xlsx 展开
- 单元格值规范化(全角转半角/空白/电话/地址标点)
- 姓名+电话+地址三元组去重计数
- 重复组明细与来源文件/行号
- 源文件查找(文件名关键词)

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_sf_xlsx_dedup_count_9756f644.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_sf_xlsx_dedup_count_9756f644.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

只解析表格内容，不执行公式或宏。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
