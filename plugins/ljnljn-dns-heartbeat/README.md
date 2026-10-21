# ljnljn-dns-heartbeat

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.dns-heartbeat`。

解析 classic pcap 中的 DNS 查询，按域名统计间隔并判定周期心跳。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.dns-heartbeat` | pcap, cap, dmp |

## 覆盖范围

- classic pcap 解析（pcapng 不支持）
- Ethernet/VLAN → IPv4 → UDP → 端口 53 → DNS 查询提取
- 按域名与 qtype 分组（不区分发起客户端）
- 相邻查询间隔统计（中位数/均值/标准差/最小/最大，单位毫秒）
- 稳定性与周期心跳候选判定（比例输出为百分比）
- 源文件句柄/显示名/长度，以及源记录槽位与文件字节偏移区间

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_dns_heartbeat_periodicity_64075a55.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_dns_heartbeat_periodicity_64075a55.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

仅支持 classic pcap；pcapng 会明确报不支持。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
