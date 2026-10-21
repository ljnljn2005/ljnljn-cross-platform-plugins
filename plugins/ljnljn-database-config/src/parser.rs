//! Database service configuration parsing for MySQL/MariaDB, PostgreSQL,
//! Redis, MongoDB, MSSQL, Oracle and Elasticsearch.
//!
//! The parser is deliberately format-oriented and line-oriented: it records
//! the original file, line, section/key and value instead of trying to
//! compute an "effective" configuration. Include directives are emitted as
//! settings; only the service configuration paths discovered by the analyzer
//! are read.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Product {
    Mysql,
    Postgres,
    Redis,
    Mongo,
    Mssql,
    Oracle,
    Elasticsearch,
    Unknown,
}

impl Product {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mysql => "mysql",
            Self::Postgres => "postgresql",
            Self::Redis => "redis",
            Self::Mongo => "mongodb",
            Self::Mssql => "mssql",
            Self::Oracle => "oracle",
            Self::Elasticsearch => "elasticsearch",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Ini,
    Postgres,
    Redis,
    Yaml,
    Oracle,
    Pgpass,
    PgHba,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ini => "ini",
            Self::Postgres => "postgresql",
            Self::Redis => "redis",
            Self::Yaml => "yaml",
            Self::Oracle => "oracle",
            Self::Pgpass => "pgpass",
            Self::PgHba => "pg_hba",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Setting {
    pub section: String,
    pub key: String,
    pub value: String,
    pub line: i64,
    pub secret: bool,
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub user: String,
    pub kind: String,
    pub value: String,
    pub context: String,
    pub line: i64,
}

#[derive(Clone, Debug)]
pub struct HbaRule {
    pub connection_type: String,
    pub database: String,
    pub user: String,
    pub address: String,
    pub method: String,
    pub options: String,
    pub line: i64,
}

pub struct ParsedFile {
    pub product: Product,
    pub format: Format,
    pub settings: Vec<Setting>,
    pub credentials: Vec<Credential>,
    pub hba: Vec<HbaRule>,
    pub status: &'static str,
}

pub fn parse(path: &str, text: &str) -> ParsedFile {
    let product = detect_product(path);
    let format = detect_format(path, product);
    let mut settings = Vec::new();
    let mut credentials = Vec::new();
    let mut hba = Vec::new();
    match format {
        Format::Pgpass => credentials = parse_pgpass(text),
        Format::PgHba => hba = parse_hba(text),
        Format::Yaml => settings = parse_yaml(text),
        Format::Ini => settings = parse_ini(text),
        Format::Postgres => settings = parse_postgres(text),
        Format::Redis => settings = parse_redis(text),
        Format::Oracle => settings = parse_oracle(text),
    }
    if format != Format::Pgpass && format != Format::PgHba {
        credentials = collect_credentials(product, &settings);
    }
    let status = if text.trim().is_empty() {
        "empty"
    } else if settings.is_empty() && credentials.is_empty() && hba.is_empty() {
        "unsupported"
    } else {
        "ok"
    };
    ParsedFile {
        product,
        format,
        settings,
        credentials,
        hba,
        status,
    }
}

fn detect_product(path: &str) -> Product {
    let path = path.to_ascii_lowercase();
    if path.contains("my.cnf") || path.contains("my.ini") || path.contains("mysql") || path.contains("mariadb") {
        Product::Mysql
    } else if path.contains(".pgpass") || path.contains("postgres") || path.contains("pg_hba") || path.contains("pg_ident") {
        Product::Postgres
    } else if path.contains("redis") {
        Product::Redis
    } else if path.contains("mongod") || path.contains("mongodb") {
        Product::Mongo
    } else if path.contains("mssql") {
        Product::Mssql
    } else if path.contains(".ora") || path.contains("oracle") || path.contains("tnsnames") || path.contains("listener") || path.contains("sqlnet") {
        Product::Oracle
    } else if path.contains("elasticsearch") {
        Product::Elasticsearch
    } else {
        Product::Unknown
    }
}

fn detect_format(path: &str, product: Product) -> Format {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".pgpass") {
        Format::Pgpass
    } else if lower.ends_with("pg_hba.conf") {
        Format::PgHba
    } else if lower.ends_with(".yml") || lower.ends_with(".yaml") || matches!(product, Product::Mongo | Product::Elasticsearch) {
        Format::Yaml
    } else if matches!(product, Product::Mysql | Product::Mssql) || lower.ends_with(".ini") {
        Format::Ini
    } else if product == Product::Postgres {
        Format::Postgres
    } else if product == Product::Redis {
        Format::Redis
    } else if product == Product::Oracle {
        Format::Oracle
    } else {
        Format::Ini
    }
}

fn parse_ini(text: &str) -> Vec<Setting> {
    let mut section = "(global)".to_owned();
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let value = unquote(strip_inline_comment(value.trim()));
            out.push(Setting { section: section.clone(), key: key.clone(), value, line: index as i64 + 1, secret: is_secret(&key) });
        }
    }
    out
}

fn parse_postgres(text: &str) -> Vec<Setting> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_inline_comment(raw);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let value = unquote(value.trim());
        out.push(Setting { section: "(global)".to_owned(), key: key.clone(), value, line: index as i64 + 1, secret: is_secret(&key) });
    }
    out
}

fn parse_redis(text: &str) -> Vec<Setting> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_inline_comment(raw);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or_default().to_ascii_lowercase();
        let value = unquote(parts.next().unwrap_or_default().trim());
        if key.is_empty() {
            continue;
        }
        out.push(Setting { section: "(global)".to_owned(), key: key.clone(), value, line: index as i64 + 1, secret: is_secret(&key) });
    }
    out
}

fn parse_oracle(text: &str) -> Vec<Setting> {
    let mut out: Vec<Setting> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('(') {
            if let Some(previous) = out.last_mut() {
                previous.value.push(' ');
                previous.value.push_str(line);
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            let value = unquote(value.trim());
            out.push(Setting { section: "(global)".to_owned(), key: key.clone(), value, line: index as i64 + 1, secret: is_secret(&key) });
        }
    }
    out
}

fn parse_yaml(text: &str) -> Vec<Setting> {
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_inline_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }
        let indent = raw.len().saturating_sub(raw.trim_start().len());
        if let Some(item) = trimmed.strip_prefix("- ") {
            let Some((_, key)) = stack.last() else { continue };
            let section = stack[..stack.len().saturating_sub(1)]
                .iter()
                .map(|(_, key)| key.as_str())
                .collect::<Vec<_>>()
                .join(".");
            out.push(Setting {
                section,
                key: key.clone(),
                value: unquote(item.trim()),
                line: index as i64 + 1,
                secret: is_secret(key),
            });
            continue;
        }
        while stack.last().is_some_and(|(level, _)| *level >= indent) {
            stack.pop();
        }
        let Some((key, value)) = trimmed.split_once(':') else { continue };
        let key = key.trim().trim_matches('"').trim_matches('\'').to_owned();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            stack.push((indent, key));
            continue;
        }
        let section = stack.iter().map(|(_, key)| key.as_str()).collect::<Vec<_>>().join(".");
        out.push(Setting {
            section,
            key: key.clone(),
            value: unquote(value),
            line: index as i64 + 1,
            secret: is_secret(&key),
        });
    }
    out
}

fn collect_credentials(product: Product, settings: &[Setting]) -> Vec<Credential> {
    let mut users: Vec<(String, String)> = Vec::new();
    for setting in settings {
        if matches!(setting.key.as_str(), "user" | "username" | "db_user" | "db_username") {
            users.push((setting.section.clone(), setting.value.clone()));
        }
    }
    let user_for = |section: &str| {
        users
            .iter()
            .find(|(candidate, _)| candidate == section)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for setting in settings {
        if product == Product::Redis && setting.key == "user" {
            let tokens: Vec<&str> = setting.value.split_whitespace().collect();
            if let Some(password) = tokens.iter().find(|token| token.starts_with('>') && token.len() > 1) {
                out.push(Credential {
                    user: tokens.first().copied().unwrap_or_default().to_owned(),
                    kind: "redis_acl_password".to_owned(),
                    value: password[1..].to_owned(),
                    context: tokens[..tokens.len().min(2)].join(" "),
                    line: setting.line,
                });
            }
        }
        if setting.secret && !setting.value.is_empty() {
            out.push(Credential {
                user: user_for(&setting.section),
                kind: "password".to_owned(),
                value: setting.value.clone(),
                context: setting.section.clone(),
                line: setting.line,
            });
        }
    }
    out
}

fn parse_pgpass(text: &str) -> Vec<Credential> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_escaped_colon(line);
        if fields.len() < 5 {
            continue;
        }
        out.push(Credential {
            user: fields[3].clone(),
            kind: "pgpass_password".to_owned(),
            value: fields[4].clone(),
            context: format!("host={} port={} db={}", fields[0], fields[1], fields[2]),
            line: index as i64 + 1,
        });
    }
    out
}

fn parse_hba(text: &str) -> Vec<HbaRule> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_inline_comment(raw);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let connection_type = fields[0].to_owned();
        let database = fields[1].to_owned();
        let user = fields[2].to_owned();
        let (address, method, options) = if connection_type == "local" {
            ("".to_owned(), fields.get(3).copied().unwrap_or_default().to_owned(), fields.get(4..).unwrap_or_default().join(" "))
        } else {
            (fields.get(3).copied().unwrap_or_default().to_owned(), fields.get(4).copied().unwrap_or_default().to_owned(), fields.get(5..).unwrap_or_default().join(" "))
        };
        out.push(HbaRule {
            connection_type,
            database,
            user,
            address,
            method,
            options,
            line: index as i64 + 1,
        });
    }
    out
}

fn split_escaped_colon(text: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in text.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    fields.push(current);
    fields
}

fn unquote(text: &str) -> String {
    let text = text.trim();
    if text.len() >= 2 && ((text.starts_with('\'') && text.ends_with('\'')) || (text.starts_with('"') && text.ends_with('"'))) {
        text[1..text.len() - 1].to_owned()
    } else {
        text.to_owned()
    }
}

fn is_secret(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    ["password", "passwd", "pwd", "secret", "requirepass", "masterauth"]
        .iter()
        .any(|needle| key.contains(needle))
}

fn strip_inline_comment(text: &str) -> &str {
    let mut quote = None;
    for (index, character) in text.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '#' && (index == 0 || text[..index].chars().last().is_some_and(char::is_whitespace)) {
            return &text[..index];
        }
    }
    text
}
