# ljnljn-cross-platform-plugins

跨平台文件与日志取证插件。本仓库按**平台**组织：一个平台一个仓库，统一使用 git tag 与 GitHub
topic `lovelycarve-plugins`。

这些分析器不依赖某个操作系统，直接读取 pcap、Web 日志、xlsx、照片、EWF 与 SQLCipher 文件。

| 插件 | LPP | 能力 |
| --- | --- | --- |
| `ljnljn-dns-heartbeat` | v1 | classic pcap DNS 心跳周期 |
| `ljnljn-weblog-sqli` | v1 | Web 访问日志 sqlmap 注入参数定位 |
| `ljnljn-xlsx-dedup` | v1 | xlsx 按姓名、电话、地址去重统计 |
| `ljnljn-exif-photo` | v1 | 照片 EXIF/GPS 与真实格式识别 |
| `ljnljn-ewf-header` | v1 | EWF/E01 头部与节段元数据 |
| `ljnljn-sqlcipher-profile` | v1 | SQLCipher 4 头画像与单页 HMAC 试校验 |

每个插件是独立 Cargo 工程，共享仓库根目录的 SDK；进入插件目录即可单独测试与构建：

```bash
cd plugins/<插件目录>
cargo test --locked
cargo build --release --locked
```


Release 提供各插件的 `.lcpkg`、完整平台包与 `SHA256SUMS.txt`。也可以手动把
`plugin.toml`、DLL（v2 还包括 `schema.json` 与 `locales/`）放进插件包目录后重启
LovelyCarve。

插件只读检材，不执行检材内容，不访问网络。源码采用 AGPL-3.0-only。
