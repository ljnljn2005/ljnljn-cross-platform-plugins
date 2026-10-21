# ljnljn-ewf-header

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.ewf-header`。

解析 EWF1 头部、节段描述与磁盘大小。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.ewf-header` | E01, E02, E03, E04, E05, E06, E07, E08, E09, E10, e01, e02, e03, e04, e05, e06, e07, e08, e09, e10, Ex01, ex01 |

## 覆盖范围

- EVF 文件签名校验
- EWF1/EWF2/Ex01 格式标识识别
- 段号与扩展名序号一致性
- 头部区长度/越界校验
- 头部区字节区间与 SHA-256
- EWF1 卷头候选值（sectors_per_chunk/sector_size/sector_count/compression）
- 头部区节段表与 done 标记

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_ewf_header_metadata_3bcc39e8.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_ewf_header_metadata_3bcc39e8.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

未实现 chunk 解压与源盘流哈希。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
