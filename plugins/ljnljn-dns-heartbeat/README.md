# ljnljn-dns-heartbeat

LovelyCarve **LPP v2** 原生插件（pre-release）：对 classic pcap 抓包做纯离线、
只读的 DNS 查询心跳周期分析。

- 插件 ID：`org.ljnljn.dns-heartbeat`
- 版本：`0.1.0`
- SDK：`lovelycarve-plugin 0.2.0`（LPP v2，C ABI v1）
- 作用域：`files`，扩展名 `pcap` / `cap` / `dmp`
- 分析器：`dns_heartbeat`
- 记录类型：`dns.heartbeat.domain`、`dns.capture.summary`
- 结构哈希：`fnv1a64:493f57b14211782a`

本插件是 v1 `ljnljn.dns-heartbeat` 的 LPP v2 移植：classic pcap 读取、链路层/
IPv4/UDP 提取、DNS 问题段解析、间隔统计与判定逻辑原样复用，只重写了结果映射。

## 分析链路

```text
classic pcap（4 种魔数：大小端 × 微秒/纳秒）
  └─ Ethernet（含 1–2 层 802.1Q/QinQ VLAN）或 DLT_RAW
       └─ IPv4（按 IHL 处理选项）
            └─ UDP（源端口或目的端口 = 53）
                 └─ DNS 查询（QR=0）的问题名与 qtype
                      └─ 按 (qname, qtype) 分组 → 时间排序 → 相邻间隔统计
```

时间基准为 `epoch = ts_sec + ts_frac / 分辨率`。pcap 文件头偏移 8 的 32 位保留
字段（旧文档称 `thiszone`）**不参与换算**，只原样记录在摘要记录里。乱序记录保留
原始时间戳，统计前排序。

判定阈值固定为 `N=5`、`tolerance=0.1`、`stability>=0.8`、间隔明细 16 条。
插件没有声明运行选项，阈值不随任务变化。

## 记录

### `dns.heartbeat.domain` — 每个域名·类型一条

- `rank`、`qname`、`qtype`、`qtype_name`、`query_count`
- `first_seen` / `last_seen`：RFC 3339 UTC 时间戳，带 `dns` 时间线角色
- `interval_median` / `interval_mean` / `interval_stdev` / `interval_min` /
  `interval_max`：**秒**（`duration` 字段）
- `stability_pct`（0–100）、`candidate_score`（0–1）
- `verdict`：`periodic` / `irregular` / `insufficient` / `no_intervals`
- `periodic`、`insufficient_samples`、`out_of_order`、`truncated_samples`
- `first_slot` / `last_slot`：源包记录槽位
- `interval_samples`：前 16 个间隔（秒）的 JSON 数组

来源指向该分组首末包记录在抓包文件中的字节区间，`note` 写明槽位区间与偏移区间，
可据此回到 pcap 复核每条查询。疑似周期记录带 `low` 级别。

### `dns.capture.summary` — 每个抓包文件一条

pcap 元数据（格式、链路类型、snaplen、保留字段、纳秒标志、时间基准）、包记录/
帧/DNS 查询报文/计入统计查询数、分组数、疑似周期分组数、12 个跳过计数
（非 UDP、非 53 端口 UDP、IPv6、IP 分片、TCP-DNS、链路类型、截断、头部畸形、
非 DNS、DNS 响应、畸形 DNS、后缀过滤）以及四个判定阈值。

## 构建与测试

```bash
cargo test --locked          # 53 passed
cargo build --release --locked
```

Windows 产物：`target/release/ljnljn_dns_heartbeat.dll`。

`schema.json` 由 v2 宿主导出：

```bash
lc-plugin-host --describe --library target/release/ljnljn_dns_heartbeat.dll > schema.json
```

测试全部基于合成 pcap（`src/synth.rs`）与纯解析单元测试，不读取真实检材：

- 固定 3 s × 8 条 → `periodic`、中位数 3 s、稳定性 100%
- 随机间隔 → `irregular`、稳定性 < 80%
- 缺失一条 → 出现一个 6 s 间隔，稳定性 6/7
- 乱序写入 → 排序后间隔为正、乱序计数正确，来源区间仍覆盖文件顺序的完整跨度
- 响应 / IPv6 / 非 53 端口 / 分片 / TCP / 非 DNS → 跳过计数正确
- 截断、只有文件头、未知魔数、pcapng → 对应告警码，不产生空成功
- 保留字段非零 → 时间戳不平移
- Harness 端到端：记录字段、时间戳、来源偏移区间、严重级别、摘要

## 安装

插件包目录需要包含：

```text
ljnljn-dns-heartbeat/
├── plugin.toml
├── ljnljn_dns_heartbeat.dll
├── schema.json
└── locales/
    ├── en.toml
    └── zh-CN.toml
```

在文件列表中选中 `.pcap` / `.cap` / `.dmp` 文件，执行「DNS 查询心跳周期分析」。

## 边界（明确未覆盖）

- **只支持 classic pcap**。pcapng（Section Header 魔数）返回
  `UNSUPPORTED_CAPTURE_FORMAT` 告警；不会误当 pcap 解析。
- **只支持 Ethernet / VLAN / DLT_RAW + IPv4 + UDP 端口 53**。IPv6、IP 分片
  （含首片）、TCP 承载的 DNS、Linux SLL/SLL2/loopback 等链路类型、非 53 端口
  的 UDP 都不解析，只计入跳过计数。
- **不区分发起客户端**：分组键只有 `(qname, qtype)`，多个客户端查询同一域名会
  合并成一条时间序列，可能低估或伪造周期。
- **不做 IDNA 解码**：`xn--` 标签按 ASCII 原文保留；非 ASCII 字节按
  ISO-8859-1 一一映射。
- **不计算源文件哈希**：解析器按需随机读取，读回调字节序不等于文件字节序。
- **periodic 只是时序规律，不代表恶意**；不做域名信誉、CDN/缓存/重试区分。
- 单个分组的查询时间戳上限 65536 条，超出只计数（`truncated_samples`）。
- 格式错误/不支持的抓包按文件记为告警，不使整个运行失败；运行摘要会给出无法
  解析的文件数。没有输入文件时记 `INPUT_NOT_FOUND` 告警。
- 这是使用新 SDK 的 pre-release：已通过单元测试、release 构建和 v2 宿主
  `--describe` 校验，尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。
