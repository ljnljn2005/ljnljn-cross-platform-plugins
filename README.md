# ljnljn-cross-platform-plugins

跨平台文件与日志插件，全部使用 LovelyCarve **LPP v2**（protocol 2）与类型化记录。
统一 git tag 与 GitHub topic：`lovelycarve-plugins`。

| 插件 | LPP | 能力 |
| --- | --- | --- |
| `ljnljn-dns-heartbeat` | v2 | classic pcap DNS 心跳周期 |
| `ljnljn-weblog-sqli` | v2 | Web 访问日志 sqlmap 注入参数定位 |
| `ljnljn-ewf-header` | v2 | EWF/E01 头部与节段元数据 |
| `ljnljn-sqlcipher-profile` | v2 | SQLCipher 4 头画像与单页 HMAC 试校验 |

每个插件是独立 Cargo 工程，仓库根目录提供共享 SDK v2：

```bash
cd plugins/<插件目录>
cargo test --locked
cargo build --release --locked
```

Release 提供各插件 `.lcpkg`、完整平台 zip、`INDEX.json` 和
`SHA256SUMS.txt`。插件只读检材，不执行检材内容，不访问网络；结果需要
取证员复核。源码采用 AGPL-3.0-only。
