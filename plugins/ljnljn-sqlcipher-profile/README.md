# ljnljn-sqlcipher-profile

LovelyCarve **LPP v2** 插件：SQLCipher 4 / 明文 SQLite 文件头结构指纹与参数画像，
可选做第一页 HMAC 试校验。

- 插件 ID：`org.ljnljn.sqlcipher-profile`
- 版本：`0.1.0`（SDK `lovelycarve-plugin 0.2.0`）
- 分析器：`sqlcipher_header`（`scope = "files"`，扩展名 `db`、`sqlite`、`db3`、
  `sqlcipher`；MIME 含 `application/octet-stream`）
- 记录类型：`sqlcipher.profile`、`.header_check`、`.key_attempt`、
  `.plaintext_sqlite`、`.page_read`
- 权限：无
- 结构哈希：`fnv1a64:4c189c19a9249a2e`

## 能力

SHA-512/256、HMAC、PBKDF2、文件头解析与 HMAC 试校验从 v1 原样复用
（`profile` / `hmac` / `sha512` / `hex`）：

- 前 16 字节为 `SQLite format 3\0` → `plaintext_sqlite`，停止加密参数推断；
- 否则按 SQLCipher 4 布局解释：16 字节 salt、大端页大小（1 表示 65536）、
  读写版本、reserve 字节数、payload 分数、文件格式读写版本、文件修改计数；
- 逐字段结构检查（页大小、版本、reserve、payload 分数、修改计数）并输出
  实测值/期望值；全部通过才判 `encrypted-sqlite-likely`；
- 可选：用口令或 32 字节 hex 主密钥做 PBKDF2，再派生第一页密钥，比较页尾
  reserve 区中的 HMAC 摘要（只比较摘要，不解密任何页、不读取表/记录）。

## 密钥选项与「无密钥」行为

| 选项 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `passphrase` | text | 空 | 候选口令（UTF-8） |
| `key_hex` | text | 空 | 64 个十六进制字符（32 字节原始主密钥），可带 `0x` |
| `kdf_iter` | text | `256000` | PBKDF2 迭代次数 |
| `hmac` | choice | `sha512` | `sha512`（SQLCipher 4 默认）或 `sha256` |
| `page_offset` | text | `0` | 试校验的页偏移（通常为页大小整数倍） |

**没有 `passphrase` 也没有 `key_hex` 时不会做任何 HMAC 校验**：`key_check =
not_attempted`，只给出结构级判定，并在 `limitations` 中明确说明。提供密钥也只
比较第一页摘要；校验失败不等于数据库不可解密（salt、页大小、reserve、KDF 参数
任一不符都会失败）。

插件不内置任何历史口令或主密钥。选项会随运行审计保存在案件库中，请按敏感
信息对待。无效的 `key_hex` / `kdf_iter` / `hmac` / `page_offset` 会回退默认值
并产生 `INVALID_*` 告警，不会静默猜测。

## 记录

| 类型 | 说明 |
| --- | --- |
| `sqlcipher.profile` | 头部判定、salt、页大小/reserve/版本/修改计数、KDF/HMAC、key_check、判定依据、检查通过数、页 HMAC 偏移、限制与取证依据 |
| `sqlcipher.header_check` | 单项结构检查：字段/偏移、实测值、期望值、是否通过 |
| `sqlcipher.key_attempt` | 密钥来源、迭代次数、HMAC 算法、派生密钥前缀、计算/存储摘要、是否通过 |
| `sqlcipher.plaintext_sqlite` | 明文 SQLite 魔数与区间 |
| `sqlcipher.page_read` | 第一页读取的偏移、请求/实读字节数与完整性 |

## 构建与测试

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_sqlcipher_profile.dll > schema.json
```

独立 workspace（`[workspace]`），SDK 路径 `../../_plugin-gen/_sdk_v2-official/sdk`；
`testing` feature 只在 dev-dependencies 启用。测试使用内置合成 SQLCipher 4 样例
（真实 PBKDF2/HMAC 链，伪随机密文），不读取真实检材或真实密钥。

## 安装包布局

```text
ljnljn-sqlcipher-profile/
├── plugin.toml
├── ljnljn_sqlcipher_profile.dll
├── schema.json
├── README.md
├── LICENSE
└── locales/{en,zh-CN}.toml
```

## 边界

- **不做实际解密**：不解 AES-CBC 页、不读表结构/记录、不处理 WAL/journal；
- HMAC/PRF 家族只支持 SHA-512 与 SHA-256；不含 SHA-1（SQLCipher 3 默认）与
  AES-256-CBC 明文校验；
- 只读文件前 4096 字节做头部解析，试校验时再读一页；不覆盖后续页或自由块；
- 只处理宿主提供的逻辑文件句柄；文件系统中的 SQLite 文件需先提取为单文件；
- 不联网、不写检材。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
