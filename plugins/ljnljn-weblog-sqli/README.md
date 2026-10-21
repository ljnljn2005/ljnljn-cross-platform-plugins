# ljnljn-weblog-sqli

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.weblog-sqli`。

在访问日志中定位 sqlmap 风格注入参数、会话与证据区间。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.weblog-sqli.file` | log, txt |
| 整份检材 | `ljnljn.weblog-sqli.evidence` | — |

## 覆盖范围

- Apache/Nginx common/combined 访问日志解析
- query 参数提取与 SQL 注入特征族检测
- 按请求窗口聚合可疑参数
- 保留来源行号、原始行和原始编码值

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_weblog_sqli_param_detect_30a22be5.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_weblog_sqli_param_detect_30a22be5.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

基于日志模式判定，不连接目标站点。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
