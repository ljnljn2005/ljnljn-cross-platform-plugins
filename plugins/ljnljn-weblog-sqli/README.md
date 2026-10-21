# ljnljn-weblog-sqli

LovelyCarve **LPP v2** 原生插件（pre-release）：解析 Apache/Nginx 访问日志，
按请求窗口识别可疑的 SQL 注入 **query 参数**。

- 插件 ID：`org.ljnljn.weblog-sqli`
- 版本：`0.1.0`
- SDK：`lovelycarve-plugin 0.2.0`（LPP v2，C ABI v1）
- 分析器：
  - `weblog_files`：`files`，扩展名 `log` / `txt`，分析用户选中的日志文件
  - `weblog_evidence`：`evidence`，遍历每个卷的固定 Web 日志目录
- 记录类型：`weblog.document`、`weblog.candidate`
- 结构哈希：`fnv1a64:769c4e7f918abdde`

本插件是 v1 `ljnljn.weblog-sqli` 的 LPP v2 移植：行布局解析、`%XX` 解码、
特征族匹配、滑窗判定与参数聚合原样复用，只重写了结果映射，并补充了精确的
行号/字节区间来源。

## 分析链路

```text
Apache/Nginx common / combined（以及仍带 `ip - - [time] "METHOD target HTTP/x"`
前缀的其它布局）
  └─ 时间、客户端 IP、方法、目标、状态码、字节数、Referer、UA
       └─ 目标拆成 path + rawQuery
            └─ 每个 query 参数：%XX 解码后匹配 8 个可解释特征族
                 └─ 按 (path, param) 聚合 → 滑窗扫描 → 可疑候选
```

特征族（大小写不敏感的正则）：

| 族 | 形式（示例） |
| --- | --- |
| `time-func` | `WAITFOR DELAY`、`PG_SLEEP(`、`SLEEP(`、`BENCHMARK(` |
| `order-by` | `ORDER BY <数字>` |
| `union-select` | `UNION [ALL] SELECT` |
| `metadata` | `information_schema`、`sysobjects`、`xp_cmdshell` |
| `extract` | `EXTRACTVALUE(`、`UPDATEXML(`、`LOAD_FILE(` |
| `comment-trunc` | `-- `、`#`、`/*` |
| `stacked` | `; SELECT/INSERT/UPDATE/DELETE/DROP` |
| `quote-escape` | `'... OR 1=1` |

**可疑判定**：某个 `(path, param)` 在任意 `window_seconds=600` 的窗口内满足
请求数 ≥ 5、窗口内不同客户端 IP ≤ 3、命中 ≥ 2 个特征族。窗口按日志自身时间轴
计算，不应用时区偏移。置信度 0–1 由命中族数、请求量、IP 收敛度等加权。

编码：BOM 优先；否则严格 UTF-8，失败回退 GB18030（GBK 的超集）。

## 记录

### `weblog.document` — 每个解析成功的日志文件一条

文件、编码（`utf8`/`utf16le`/`utf16be`/`gb18030`）、文件大小、总行数/已解析行/
未解析行、combined/common/其它布局行数、首次/末次请求时间戳（带 `request`
时间线角色；无偏移的本地时间不进入全局时间线）、涉及年月、ident/user 列表、
解码替换字符数、是否截断、未解析原因 JSON、可疑候选数。来源为整个文件。

### `weblog.candidate` — 每个可疑 `(path, param)` 一条

- `method`（多个方法以逗号连接）、`methods` 列表、`path`、`param`、`location=query`
- `family`（`time-func:1,order-by:2,...`）与 `family_count`
- `request_count`、`window_requests`、`distinct_ips`、`window_ips`
- `first_seen` / `last_seen` / `window_first_seen` / `window_last_seen`
- `confidence`、`verdict`（判定依据原文）
- `line_start` / `line_end`：证据行号范围
- `text_offset_start` / `text_offset_end`：**解码后文本**中的证据字节范围
  （结束不含；不是源文件字节偏移）
- `source_exact`：来源偏移是否精确映射回源文件
- `status_distribution`：窗口状态码分布 JSON
- `samples`：前 3 条样例（行号、偏移、长度、原始时间、方法、状态码、客户端 IP、
  原始编码值、行文本）JSON

来源在 UTF-8（含 BOM 时自动 +3 偏移）且解码未改变字节布局时精确指向证据字节
区间；UTF-16/GB18030 解码后重新编码为 UTF-8，字节偏移不能映射回源文件，此时
来源指向整个文件，`note` 仍写明行号范围（`source_exact=false`）。置信度 ≥0.8
记 `high`，≥0.6 记 `medium`，其余 `low`。

## 构建与测试

```bash
cargo test --locked          # 35 passed
cargo build --release --locked
```

Windows 产物：`target/release/ljnljn_weblog_sqli.dll`。

`schema.json` 由 v2 宿主导出：

```bash
lc-plugin-host --describe --library target/release/ljnljn_weblog_sqli.dll > schema.json
```

测试全部基于合成日志，覆盖 combined/common 布局、`%XX` 解码与原文保留、8 个
特征族、业务参数负例（`spm`、`page`、散文 “order by”）、窗口阈值、跨年时间原样
保留、CRLF/空行行号、GB18030 解码、UTF-8 BOM/GB18030 的来源偏移策略、长行
截断、字段映射覆盖、非法参数，以及 `files`/`evidence` 两个分析器的 Harness
端到端记录与来源区间。

## 安装

```text
ljnljn-weblog-sqli/
├── plugin.toml
├── ljnljn_weblog_sqli.dll
├── schema.json
└── locales/
    ├── en.toml
    └── zh-CN.toml
```

单文件：文件列表选中 `.log` / `.txt` →「Web 访问日志注入参数（单文件）」。
检材级：对整个检材执行「Web 访问日志注入参数（检材级）」。

## 边界（明确未覆盖）

- **仅基于模式匹配**：8 个可解释特征族是线索，不是 SQL 语法分析；编码/加密
  载荷不会被还原。
- **只分析 query 参数**：POST 表单、JSON/XML body、请求头全量、Cookie 不在
  覆盖范围。
- **不判定攻击是否成功**：状态码分布只是观测值，不能据此证明注入成功或数据
  外泄。
- **时间原样保留**：不做年份补齐、不做时区归一；窗口按日志自身时间轴计算，
  跨年边界不会被合并。日志无偏移的时间以本地时间保存，不进入案件全局时间线。
- **不解析 IP 地理位置、账户关联、会话 Cookie，也不做 pcap 还原**。
- **检材级扫描根固定**：`var/log/nginx`、`var/log/httpd`、`var/log/apache2`、
  `var/www/logs`、`var/www/log`、`logs`、`log`；只接受文件名含
  `access`/`nginx`/`apache`/`httpd`/`www.log`/`web.log` 的文件；深度 ≤6，
  最多 400 个文件，单文件最多 128 MiB（超出只解析前 128 MiB 并记录说明）。
- 单文件分析超过 128 MiB 时不截断，记 `RESOURCE_LIMIT` 告警并跳过。
- 非访问日志内容记 `NOT_ACCESS_LOG` 告警；没有输入或没有找到日志时分别记
  `INPUT_NOT_FOUND` / `NO_LOG_FILES` 告警，不产生空成功。
- 这是使用新 SDK 的 pre-release：已通过单元测试、release 构建和 v2 宿主
  `--describe` 校验，尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。
