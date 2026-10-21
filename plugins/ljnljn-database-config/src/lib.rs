//! Database service configuration analyzer (LPP v2).
//!
//! Supports MySQL/MariaDB, PostgreSQL (including pg_hba and .pgpass),
//! Redis, MongoDB, MSSQL, Oracle and Elasticsearch configuration files.
//! Settings are emitted with source file, line, section and value. Password
//! values are marked as sensitive and additionally emitted as credential
//! records so an examiner can find them without reading every setting.

mod parser;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, Plugin, Record, Result, Run};

const TEXT_CAP: u64 = 8 * 1024 * 1024;

const PATTERNS: &[&str] = &[
    "etc/my.cnf",
    "etc/my.ini",
    "etc/mysql/my.cnf",
    "etc/mysql/**/*.cnf",
    "etc/mysql/**/*.ini",
    "etc/postgresql/**/postgresql.conf",
    "etc/postgresql/**/postgresql.auto.conf",
    "etc/postgresql/**/pg_hba.conf",
    "etc/postgresql/**/pg_ident.conf",
    "etc/redis.conf",
    "etc/redis/**/*.conf",
    "etc/mongod.conf",
    "etc/mongodb.conf",
    "etc/elasticsearch/elasticsearch.yml",
    "etc/elasticsearch/**/*.yml",
    "etc/oracle/**/*.ora",
    "opt/oracle/**/*.ora",
    "u01/app/oracle/**/*.ora",
    "var/opt/mssql/mssql.conf",
    "opt/mssql/**/*.conf",
    "root/.my.cnf",
    "root/.pgpass",
    "home/*/.my.cnf",
    "home/*/.pgpass",
    "ProgramData/MySQL/**/*.ini",
    "ProgramData/MySQL/**/*.cnf",
    "Program Files/MySQL/**/*.ini",
    "ProgramData/PostgreSQL/**/*.conf",
    "ProgramData/MongoDB/**/*.cfg",
    "Program Files/MongoDB/**/*.cfg",
    "ProgramData/Redis/**/*.conf",
    "Program Files/Redis/**/*.conf",
    "ProgramData/Elasticsearch/**/*.yml",
];

#[derive(Record)]
#[record(
    id = "database.config.file",
    label = "数据库配置文件",
    title = "{product} / {path}"
)]
struct ConfigFile {
    #[field(label = "路径", key)]
    path: String,
    #[field(label = "产品")]
    product: String,
    #[field(label = "格式")]
    format: String,
    #[field(label = "大小", kind = "size")]
    size: u64,
    #[field(label = "配置项数")]
    setting_count: u64,
    #[field(label = "凭据数")]
    credential_count: u64,
    #[field(label = "状态")]
    status: String,
}

#[derive(Record)]
#[record(
    id = "database.config.setting",
    label = "数据库配置项",
    title = "{section}: {key}"
)]
struct SettingRecord {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    line: i64,
    #[field(label = "产品")]
    product: String,
    #[field(label = "段")]
    section: String,
    #[field(label = "键", key)]
    key: String,
    #[field(label = "值")]
    value: String,
    #[field(label = "是否为敏感项")]
    secret: bool,
}

#[derive(Record)]
#[record(
    id = "database.config.credential",
    label = "数据库凭据",
    title = "{product} / {user}"
)]
struct CredentialRecord {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    line: i64,
    #[field(label = "产品")]
    product: String,
    #[field(label = "用户")]
    user: String,
    #[field(label = "凭据类型")]
    kind: String,
    #[field(label = "凭据值")]
    value: String,
    #[field(label = "上下文")]
    context: String,
}

#[derive(Record)]
#[record(
    id = "database.pg_hba.rule",
    label = "PostgreSQL pg_hba 规则",
    title = "{type} {database} {db_user} {method}"
)]
struct HbaRecord {
    #[field(label = "来源文件", key)]
    source: String,
    #[field(label = "行号", key)]
    line: i64,
    #[field(label = "连接类型")]
    r#type: String,
    #[field(label = "数据库")]
    database: String,
    #[field(label = "用户")]
    db_user: String,
    #[field(label = "地址")]
    address: String,
    #[field(label = "认证方法")]
    method: String,
    #[field(label = "选项")]
    options: String,
}

fn db_config_files(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut settings = 0usize;
    let mut credentials = 0usize;
    let mut rules = 0usize;
    for file in run.inputs() {
        run.check_cancelled()?;
        let (s, c, h) = analyze_file(run, file)?;
        settings += s;
        credentials += c;
        rules += h;
        files += 1;
    }
    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未选择数据库配置文件")?;
    }
    run.set_summary(format!(
        "数据库配置：{files} 个文件，{settings} 个配置项，{credentials} 条凭据，{rules} 条 pg_hba 规则"
    ));
    Ok(())
}

fn db_config_system(run: &Run) -> Result<()> {
    analyze_view(run, "系统")
}

fn db_config_evidence(run: &Run) -> Result<()> {
    analyze_view(run, "检材")
}

fn analyze_view(run: &Run, label: &str) -> Result<()> {
    let view = run.require_view()?;
    let patterns = patterns_for(view.mounts());
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let paths = match view.find(&pattern_refs) {
        Ok(paths) => paths,
        Err(error) => {
            run.warn(&error.code, error.message.clone())?;
            return Ok(());
        }
    };
    let mut files = 0usize;
    let mut settings = 0usize;
    let mut credentials = 0usize;
    let mut rules = 0usize;
    for path in paths {
        run.check_cancelled()?;
        let Some(file) = view.open(&path)? else {
            continue;
        };
        let (s, c, h) = analyze_file(run, &file)?;
        settings += s;
        credentials += c;
        rules += h;
        files += 1;
    }
    if files == 0 {
        run.warn("CONFIG_NOT_FOUND", format!("未找到数据库{label}配置文件"))?;
    }
    run.set_summary(format!(
        "数据库配置（{label}）：{files} 个文件，{settings} 个配置项，{credentials} 条凭据，{rules} 条 pg_hba 规则"
    ));
    Ok(())
}

fn patterns_for(mounts: &[lovelycarve_plugin::MountInfo]) -> Vec<String> {
    let mut patterns = Vec::new();
    for mount in mounts {
        let prefix = mount.path.trim_matches('/');
        for pattern in PATTERNS {
            patterns.push(if prefix.is_empty() {
                (*pattern).to_owned()
            } else {
                format!("{prefix}/{pattern}")
            });
        }
    }
    patterns.sort();
    patterns.dedup();
    patterns
}

fn analyze_file(run: &Run, file: &lovelycarve_plugin::FileRef) -> Result<(usize, usize, usize)> {
    let source = source_path(file);
    let text = match file.read_text(TEXT_CAP) {
        Ok(text) => text,
        Err(error) => {
            run.warn_file(file, &error.code, error.message.clone())?;
            return Ok((0, 0, 0));
        }
    };
    let parsed = parser::parse(&source, &text);
    let product = parsed.product.as_str().to_owned();
    for setting in &parsed.settings {
        run.record(&SettingRecord {
            source: source.clone(),
            line: setting.line,
            product: product.clone(),
            section: setting.section.clone(),
            key: setting.key.clone(),
            value: setting.value.clone(),
            secret: setting.secret,
        })
        .from(file)
        .note(format!("第 {} 行", setting.line))
        .emit()?;
    }
    for credential in &parsed.credentials {
        run.record(&CredentialRecord {
            source: source.clone(),
            line: credential.line,
            product: product.clone(),
            user: credential.user.clone(),
            kind: credential.kind.clone(),
            value: credential.value.clone(),
            context: credential.context.clone(),
        })
        .from(file)
        .note(format!("第 {} 行", credential.line))
        .emit()?;
    }
    for rule in &parsed.hba {
        run.record(&HbaRecord {
            source: source.clone(),
            line: rule.line,
            r#type: rule.connection_type.clone(),
            database: rule.database.clone(),
            db_user: rule.user.clone(),
            address: rule.address.clone(),
            method: rule.method.clone(),
            options: rule.options.clone(),
        })
        .from(file)
        .note(format!("第 {} 行", rule.line))
        .emit()?;
    }
    run.record(&ConfigFile {
        path: source.clone(),
        product: product.clone(),
        format: parsed.format.as_str().to_owned(),
        size: file.size(),
        setting_count: parsed.settings.len() as u64,
        credential_count: parsed.credentials.len() as u64,
        status: parsed.status.to_owned(),
    })
    .from(file)
    .emit()?;
    if parsed.status != "ok" {
        run.warn_file(
            file,
            "UNSUPPORTED_CONFIG",
            format!("{source}: 未识别出配置项（status={}）", parsed.status),
        )?;
    }
    Ok((parsed.settings.len(), parsed.credentials.len(), parsed.hba.len()))
}

fn source_path(file: &lovelycarve_plugin::FileRef) -> String {
    file.view_path().unwrap_or_else(|| file.name()).to_owned()
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.database-config")
        .record::<ConfigFile>()
        .record::<SettingRecord>()
        .record::<CredentialRecord>()
        .record::<HbaRecord>()
        .analyzer("db_config_files", db_config_files)
        .analyzer("db_config_system", db_config_system)
        .analyzer("db_config_evidence", db_config_evidence)
}

export_plugin!(plugin);
