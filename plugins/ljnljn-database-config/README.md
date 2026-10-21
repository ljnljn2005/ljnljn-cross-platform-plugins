# ljnljn-database-config

LovelyCarve **LPP v2** 插件：结构化读取常见数据库服务的配置文件与凭据文件。

- 插件 ID：`org.ljnljn.database-config`
- 记录：`database.config.file`、`database.config.setting`、
  `database.config.credential`、`database.pg_hba.rule`

## 支持范围

| 产品 | 文件示例 |
| --- | --- |
| MySQL / MariaDB | `my.cnf`、`my.ini`、`mysql/**/*.cnf` |
| PostgreSQL | `postgresql.conf`、`postgresql.auto.conf`、`pg_hba.conf`、`pg_ident.conf`、`.pgpass` |
| Redis | `redis.conf`、`redis/**/*.conf` |
| MongoDB | `mongod.conf`、`mongod.cfg` |
| MSSQL | `mssql.conf` |
| Oracle | `listener.ora`、`tnsnames.ora`、`sqlnet.ora` |
| Elasticsearch | `elasticsearch.yml` |

三个分析器：

- `db_config_files`：分析用户选中的单个配置文件；
- `db_config_system`：在识别出的系统中按标准路径查找；
- `db_config_evidence`：遍历检材各卷的标准路径。

配置项保留来源文件、行号、段（section）和键值。密码类键会标记为敏感，并额外
输出凭据记录；`.pgpass` 和 Redis ACL 中的密码也会单独提取。PostgreSQL
`pg_hba.conf` 按连接类型、数据库、用户、地址、认证方法和选项输出。

## 构建

```bash
cargo test --locked
cargo build --release --locked
```

需要 LovelyCarve v2 宿主（protocol 2）。Release 中的 `.lcpkg` 可直接安装。

## 边界

- 只做静态配置解析，不连接数据库，不验证凭据是否有效。
- 不计算“最终生效配置”：`Include`、条件段和多文件优先级保留为配置项，需结合原始文件复核。
- YAML 解析覆盖常见键值和简单列表，不处理复杂锚点、合并键或多行块标量。
- 只按标准路径发现文件；非标准安装位置请用单文件分析器显式选择。
- 可能输出配置文件中的明文凭据；结果应按案件证据管理。

## 许可证

AGPL-3.0-only。
