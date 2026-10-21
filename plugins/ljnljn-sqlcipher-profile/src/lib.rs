//! SQLCipher 4 / plaintext SQLite header profile (LPP v2).
//!
//! Port of the v1 `ljnljn.sqlcipher-profile` analyzer. The pure analyzer
//! (`profile`), SHA-512/256, HMAC, PBKDF2 and hex helpers are carried over
//! unchanged; this crate adds typed records and an explicit LPP v2 option
//! channel for the optional key trial:
//!
//! - `passphrase` — candidate passphrase (UTF-8);
//! - `key_hex` — 64 hex characters (32-byte raw master key);
//! - `kdf_iter` — PBKDF2 iteration count (default 256000);
//! - `hmac` — `sha512` (default) or `sha256`;
//! - `page_offset` — offset of the page whose trailing HMAC is checked.
//!
//! **No key means no HMAC check.** Without `passphrase` and `key_hex` the
//! analyzer only derives a structural verdict (`encrypted-sqlite-likely` /
//! `plaintext-sqlite` / `unknown`) and records `key_check = not_attempted`.
//! A supplied key never decrypts anything: only the trailing HMAC digest of
//! the first page is compared, and only its prefix that fits the reserve area.
//!
//! No key material is built into the plugin. Options are part of the run
//! audit in the case database, so treat them as evidence-adjacent data.
//! SHA-1 (SQLCipher 3) and AES-CBC plaintext verification are not implemented.

pub mod hex;
pub mod hmac;
pub mod profile;
pub mod sha512;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, FileRef, Plugin, Record, Result, Run};

use crate::profile::{
    page_plan, parse_header, verify_page, HeaderKind, KeyCheck, Options, PageBytes, Profile,
    HEADER_WINDOW, SQLITE_PLAINTEXT_MAGIC,
};
use crate::sha512::DigestKind;

/// Analyzer id (must match `plugin.toml`).
pub const ANALYZER: &str = "sqlcipher_header";

/// One structural profile per input file.
#[derive(Record)]
#[record(
    id = "sqlcipher.profile",
    label = "SQLCipher 文件头画像",
    title = "{path}"
)]
struct ProfileRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "文件名")]
    name: String,
    #[field(label = "文件长度", kind = "size")]
    file_length: u64,
    #[field(
        label = "头部判定",
        kind = "enum",
        choices = "plaintext_sqlite=明文 SQLite,encrypted_sqlite_likely=疑似 SQLCipher 加密,unknown=未知"
    )]
    header_kind: String,
    #[field(label = "salt（hex）", kind = "hash")]
    salt_hex: Option<String>,
    #[field(label = "页大小原值")]
    page_size_raw: Option<i64>,
    #[field(label = "页大小")]
    page_size: Option<i64>,
    #[field(label = "写版本")]
    write_version: Option<i64>,
    #[field(label = "读版本")]
    read_version: Option<i64>,
    #[field(label = "reserve 字节数")]
    reserve_size: Option<i64>,
    #[field(label = "payload 分数")]
    payload_fraction: Option<i64>,
    #[field(label = "文件格式读版本")]
    file_format_read: Option<i64>,
    #[field(label = "文件格式写版本")]
    file_format_write: Option<i64>,
    #[field(label = "文件修改计数")]
    file_change_counter: Option<i64>,
    #[field(label = "KDF 迭代次数")]
    kdf_iter: i64,
    #[field(label = "HMAC 算法")]
    hmac_algorithm: String,
    #[field(
        label = "密钥校验",
        kind = "enum",
        choices = "not_attempted=未试校验,passed=通过,failed=不通过"
    )]
    key_check: String,
    #[field(label = "判定依据")]
    verdict_basis: String,
    #[field(label = "通过的结构检查数")]
    checks_passed: i64,
    #[field(label = "结构检查总数")]
    checks_total: i64,
    #[field(label = "页尾 HMAC 偏移", kind = "size")]
    page_hmac_offset: Option<u64>,
    #[field(label = "页尾存储的 HMAC（hex）", kind = "hash")]
    stored_page_hmac_hex: Option<String>,
    #[field(label = "第一页偏移", kind = "size")]
    page_read_offset: Option<u64>,
    #[field(label = "第一页请求字节数", kind = "size")]
    page_read_requested: Option<u64>,
    #[field(label = "第一页读到的字节数", kind = "size")]
    page_read_received: Option<u64>,
    #[field(label = "第一页读取完整")]
    page_read_complete: bool,
    #[field(label = "取证依据", kind = "list")]
    evidence: Vec<String>,
    #[field(label = "限制与覆盖说明", kind = "list")]
    limitations: Vec<String>,
}

/// One header-field comparison.
#[derive(Record)]
#[record(
    id = "sqlcipher.header_check",
    label = "文件头结构检查",
    title = "{path} · {name}"
)]
struct HeaderCheckRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "检查项", key)]
    name: String,
    #[field(label = "通过")]
    passed: bool,
    #[field(label = "字段/偏移")]
    field: String,
    #[field(label = "实测值")]
    observed: String,
    #[field(label = "期望")]
    expected: String,
    #[field(label = "头部判定")]
    header_kind: String,
}

/// One key/HMAC trial (only emitted when a key was supplied).
#[derive(Record)]
#[record(
    id = "sqlcipher.key_attempt",
    label = "首库页 HMAC 试校验",
    title = "{path} · {key_source}"
)]
struct KeyAttemptRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "密钥来源", key)]
    key_source: String,
    #[field(label = "KDF 迭代次数")]
    kdf_iterations: i64,
    #[field(label = "HMAC 算法")]
    hmac_algorithm: String,
    #[field(label = "派生密钥前缀（hex）", kind = "hash")]
    derived_key_prefix_hex: String,
    #[field(label = "通过")]
    passed: bool,
    #[field(label = "计算出的 HMAC（hex）", kind = "hash")]
    computed_hmac_hex: String,
    #[field(label = "页尾存储的 HMAC（hex）", kind = "hash")]
    stored_hmac_hex: String,
}

/// Plaintext SQLite marker (kept as its own record like the v1 artifact).
#[derive(Record)]
#[record(
    id = "sqlcipher.plaintext_sqlite",
    label = "明文 SQLite 文件头",
    title = "{path}"
)]
struct PlaintextRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "魔数")]
    magic: String,
    #[field(label = "魔数区间")]
    magic_offset: String,
}

/// The bounded first-page read performed for the HMAC check.
#[derive(Record)]
#[record(id = "sqlcipher.page_read", label = "第一页读取记录", title = "{path}")]
struct PageReadRow {
    #[field(label = "源文件路径", key)]
    path: String,
    #[field(label = "页偏移", kind = "size")]
    page_offset: u64,
    #[field(label = "请求字节数", kind = "size")]
    requested: u64,
    #[field(label = "实读字节数", kind = "size")]
    received: u64,
    #[field(label = "读取完整")]
    complete: bool,
}

struct TrialOptions {
    profile: Options,
    /// `key_hex`/`passphrase` present but invalid; reported once per run.
    warned: bool,
}

/// Reads and validates the analyzer options. Malformed values fall back to
/// the documented defaults with a run warning (never a silent guess).
fn trial_options(run: &Run) -> TrialOptions {
    let mut warned = false;
    let mut options = Options::profile_only();
    if let Some(text) = run.options().text("passphrase") {
        let text = text.trim();
        if !text.is_empty() {
            options.passphrase = Some(text.to_owned());
        }
    }
    if let Some(text) = run.options().text("key_hex") {
        let text = text.trim();
        let text = text.strip_prefix("0x").unwrap_or(text);
        if !text.is_empty() {
            match hex::decode(text) {
                Some(bytes) if bytes.len() == 32 => options.raw_master_key = Some(bytes),
                _ => {
                    let _ = run.warn(
                        "INVALID_KEY_HEX",
                        "key_hex 必须是 64 个十六进制字符（32 字节），已忽略",
                    );
                    warned = true;
                }
            }
        }
    }
    let kdf_iter = match run.options().text("kdf_iter") {
        Some(text) => match text.trim().parse::<u32>() {
            Ok(value) if value > 0 => value,
            _ => {
                let _ = run.warn("INVALID_KDF_ITER", "kdf_iter 不是正整数，改用 256000");
                warned = true;
                profile::DEFAULT_KDF_ITER
            }
        },
        None => profile::DEFAULT_KDF_ITER,
    };
    options.kdf_iterations = vec![kdf_iter];
    let hmac = match run.options().text("hmac") {
        Some("sha256") => DigestKind::Sha256,
        Some("sha512") | None => DigestKind::Sha512,
        Some(other) => {
            let _ = run.warn(
                "INVALID_HMAC_OPTION",
                format!("hmac={other} 不是 sha512/sha256，改用 sha512"),
            );
            warned = true;
            DigestKind::Sha512
        }
    };
    options.hmac_algorithms = vec![hmac];
    if let Some(text) = run.options().text("page_offset") {
        if let Ok(offset) = text.trim().parse::<u64>() {
            options.page_offset = offset;
        } else if !text.trim().is_empty() {
            let _ = run.warn("INVALID_PAGE_OFFSET", "page_offset 不是无符号整数，改用 0");
            warned = true;
        }
    }
    TrialOptions {
        profile: options,
        warned,
    }
}

fn sqlcipher(run: &Run) -> Result<()> {
    if run.inputs().is_empty() {
        run.warn("INPUT_NOT_FOUND", "没有选中任何数据库文件")?;
        run.set_summary("未找到可分析的文件");
        return Ok(());
    }
    let options = trial_options(run);
    let mut summaries = Vec::new();
    for file in run.inputs() {
        run.check_cancelled()?;
        let display = display_name(file);
        let size = file.size();
        let window_len = usize::try_from(size.min(HEADER_WINDOW as u64)).unwrap_or(0);
        let window = match file.read_at(0, window_len) {
            Ok(window) => window,
            Err(error) => {
                run.warn_file(
                    file,
                    &error.code,
                    format!("{display}: 读取文件头失败：{}", error.message),
                )?;
                continue;
            }
        };
        let mut profile = parse_header(&window, size, &options.profile);
        add_standard_limitations(&mut profile, size);

        let mut page_note = None;
        if let Some(plan) = page_plan(&profile, &options.profile) {
            run.check_cancelled()?;
            let page = file.read_at(plan.page_offset, plan.read_len)?;
            page_note = Some((plan.page_offset, plan.read_len as u64, page.len() as u64));
            verify_page(
                &mut profile,
                &options.profile,
                &plan,
                PageBytes {
                    page: &page,
                    requested: plan.read_len,
                },
            );
            if profile.key_check == KeyCheck::Failed {
                run.warn_file(
                    file,
                    "HMAC_CHECK_FAILED",
                    format!(
                        "{display}: 第一页 HMAC 校验未通过（口令/主密钥、salt、页大小、reserve 或 KDF 参数至少一项不符）"
                    ),
                )?;
            }
        } else if options.profile.has_key()
            && profile.header_kind != HeaderKind::EncryptedSqliteLikely
        {
            run.warn_file(
                file,
                "KEY_NOT_APPLICABLE",
                format!(
                    "{display}: 头部判定为 {}，未进行 HMAC 试校验",
                    profile.header_kind.as_str()
                ),
            )?;
        }
        if profile.header_kind == HeaderKind::Unknown {
            run.warn_file(
                file,
                "UNKNOWN_HEADER",
                format!("{display}: 文件头不符合明文 SQLite 或 SQLCipher 4 可解析布局"),
            )?;
        }

        emit_profile(run, file, &display, &profile, page_note)?;
        for check in &profile.checks {
            emit_check(run, file, &display, &profile, check)?;
        }
        for attempt in &profile.attempts {
            emit_attempt(run, file, &display, attempt)?;
        }
        if profile.header_kind == HeaderKind::PlaintextSqlite {
            emit_plaintext(run, file, &display)?;
        }
        if let Some((offset, requested, received)) = page_note {
            emit_page_read(run, file, &display, offset, requested, received)?;
        }

        summaries.push(format!(
            "{}: {} (salt={}, pageSize={}, reserve={}, keyCheck={})",
            display,
            profile.header_kind.as_str(),
            profile.salt_hex.as_deref().unwrap_or("-"),
            profile
                .page_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            profile
                .reserve_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            profile.key_check.as_str()
        ));
    }
    let key_note = if options.profile.has_key() {
        "已提供密钥并尝试首库页 HMAC 校验"
    } else {
        "未提供密钥：只做结构判定，未做 HMAC 校验"
    };
    if options.warned {
        let _ = run.warn("OPTIONS_ADJUSTED", "部分分析选项无效，已回退到默认值");
    }
    run.set_summary(format!(
        "SQLCipher 文件头画像：{}；{key_note}",
        if summaries.is_empty() {
            "没有可分析的文件".to_owned()
        } else {
            summaries.join("；")
        }
    ));
    Ok(())
}

fn add_standard_limitations(profile: &mut Profile, size: u64) {
    if (profile.window_len as u64) < size {
        profile.limitations.push(format!(
            "只读取了文件前 {} 字节（文件共 {} 字节）：不覆盖后续页、WAL/journal 或自由块。",
            profile.window_len, size
        ));
    }
    profile.limitations.push(
        "本版本不做实际解密：不解 AES-CBC 页，不读取表结构/记录，也不处理 WAL/journal。".to_owned(),
    );
    profile.limitations.push(
        "不提供密钥时只能做结构级判定（encrypted-sqlite-likely），不能证明可解密；\
         没有 passphrase/key_hex 就不会执行任何 HMAC 校验（key_check=not-attempted）。"
            .to_owned(),
    );
    profile.limitations.push(
        "密钥只能来自本次任务选项（passphrase/key_hex）；插件不内置任何口令或主密钥，\
         选项会随运行审计保存在案件库中。"
            .to_owned(),
    );
    profile.limitations.push(
        "支持的 HMAC/PRF 家族为 SHA512（SQLCipher 4 默认）与 SHA256；不含 SHA1（SQLCipher 3 默认）\
         与 AES-256-CBC 明文校验。"
            .to_owned(),
    );
    profile.limitations.push(
        "只处理宿主提供的逻辑文件句柄；位于文件系统中的 SQLite 文件需先提取为单文件。".to_owned(),
    );
}

fn emit_profile(
    run: &Run,
    file: &FileRef,
    display: &str,
    profile: &Profile,
    page_note: Option<(u64, u64, u64)>,
) -> Result<()> {
    let record = ProfileRow {
        path: display.to_owned(),
        name: file.name().to_owned(),
        file_length: profile.file_len,
        header_kind: enum_slug(profile.header_kind.as_str()),
        salt_hex: profile.salt_hex.clone(),
        page_size_raw: profile.page_size_raw.map(i64::from),
        page_size: profile.page_size.map(i64::from),
        write_version: profile.write_version.map(i64::from),
        read_version: profile.read_version.map(i64::from),
        reserve_size: profile.reserve_size.map(i64::from),
        payload_fraction: profile.payload_fraction.map(i64::from),
        file_format_read: profile.file_format_read.map(i64::from),
        file_format_write: profile.file_format_write.map(i64::from),
        file_change_counter: profile.file_change_counter.map(i64::from),
        kdf_iter: i64::from(profile.kdf_iter),
        hmac_algorithm: profile.hmac_algorithm.to_owned(),
        key_check: enum_slug(profile.key_check.as_str()),
        verdict_basis: profile.verdict_basis.clone(),
        checks_passed: profile.checks.iter().filter(|check| check.passed).count() as i64,
        checks_total: profile.checks.len() as i64,
        page_hmac_offset: profile.page_hmac_offset,
        stored_page_hmac_hex: profile.stored_page_hmac_hex.clone(),
        page_read_offset: page_note.map(|(offset, _, _)| offset),
        page_read_requested: page_note.map(|(_, requested, _)| requested),
        page_read_received: page_note.map(|(_, _, received)| received),
        page_read_complete: page_note
            .map(|(_, requested, received)| requested == received)
            .unwrap_or(false),
        evidence: evidence_lines(profile, page_note),
        limitations: profile.limitations.clone(),
    };
    run.record(&record)
        .from(file)
        .note(format!(
            "headerKind={} keyCheck={}",
            profile.header_kind.as_str(),
            profile.key_check.as_str()
        ))
        .emit()
}

fn emit_check(
    run: &Run,
    file: &FileRef,
    display: &str,
    profile: &Profile,
    check: &profile::Check,
) -> Result<()> {
    let record = HeaderCheckRow {
        path: display.to_owned(),
        name: check.name.to_owned(),
        passed: check.passed,
        field: check.field.clone(),
        observed: check.observed.clone(),
        expected: check.expected.clone(),
        header_kind: enum_slug(profile.header_kind.as_str()),
    };
    run.record(&record)
        .from(file)
        .note(format!(
            "{} = {}（期望 {}）",
            check.field, check.observed, check.expected
        ))
        .emit()
}

fn emit_attempt(
    run: &Run,
    file: &FileRef,
    display: &str,
    attempt: &profile::Attempt,
) -> Result<()> {
    let record = KeyAttemptRow {
        path: display.to_owned(),
        key_source: attempt.key_source.to_owned(),
        kdf_iterations: i64::from(attempt.kdf_iterations),
        hmac_algorithm: attempt.hmac_algorithm.to_owned(),
        derived_key_prefix_hex: attempt.derived_key_prefix_hex.clone(),
        passed: attempt.passed,
        computed_hmac_hex: attempt.computed_hmac_hex.clone(),
        stored_hmac_hex: attempt.stored_hmac_hex.clone(),
    };
    run.record(&record)
        .from(file)
        .note(format!(
            "PBKDF2-HMAC {} × {}，只比较页尾摘要",
            attempt.hmac_algorithm, attempt.kdf_iterations
        ))
        .emit()
}

fn emit_plaintext(run: &Run, file: &FileRef, display: &str) -> Result<()> {
    let record = PlaintextRow {
        path: display.to_owned(),
        magic: String::from_utf8_lossy(SQLITE_PLAINTEXT_MAGIC)
            .trim_end_matches('\u{0}')
            .to_owned(),
        magic_offset: "0x00000000..0x00000010".to_owned(),
    };
    run.record(&record)
        .from(file)
        .note("前 16 字节为明文 SQLite 魔数")
        .emit()
}

fn emit_page_read(
    run: &Run,
    file: &FileRef,
    display: &str,
    offset: u64,
    requested: u64,
    received: u64,
) -> Result<()> {
    let record = PageReadRow {
        path: display.to_owned(),
        page_offset: offset,
        requested,
        received,
        complete: requested == received,
    };
    run.record(&record)
        .from(file)
        .note(format!("read({offset}, {requested}) 实读 {received} 字节"))
        .emit()
}

fn evidence_lines(profile: &Profile, page_note: Option<(u64, u64, u64)>) -> Vec<String> {
    let mut lines = vec![format!(
        "read(0, {}): 0x00000000..0x{:08x} header window ({} bytes read, fileLen={})",
        HEADER_WINDOW, profile.window_len, profile.window_len, profile.file_len
    )];
    if let Some(salt) = &profile.salt_hex {
        lines.push(format!("salt: 0x00000000..0x00000010 = {salt}"));
        if let Some(raw) = profile.page_size_raw {
            lines.push(format!(
                "pageSize: 0x00000010..0x00000012 (BE u16) = 0x{raw:04x}"
            ));
        }
        for (name, range, field) in [
            (
                "writeVersion",
                "0x00000012..0x00000013",
                "offset 0x12 (18), 1 字节",
            ),
            (
                "readVersion",
                "0x00000013..0x00000014",
                "offset 0x13 (19), 1 字节",
            ),
            (
                "reserveSize",
                "0x00000014..0x00000015",
                "offset 0x14 (20), 1 字节",
            ),
            (
                "payloadFraction",
                "0x00000015..0x00000016",
                "offset 0x15 (21), 1 字节",
            ),
        ] {
            if let Some(observed) = profile
                .checks
                .iter()
                .find(|item| item.field == field)
                .map(|item| item.observed.clone())
            {
                lines.push(format!("{name}: {range} = {observed}"));
            }
        }
        if let Some(counter) = profile.file_change_counter {
            lines.push(format!(
                "fileChangeCounter: 0x00000018..0x0000001c (BE u32) = {counter}"
            ));
        }
    }
    if let Some(offset) = profile.page_hmac_offset {
        let end = offset + 64;
        lines.push(format!(
            "pageHMAC: 0x{offset:08x}..0x{end:08x} (reserve 区最后 64 字节) = {}",
            profile.stored_page_hmac_hex.as_deref().unwrap_or("")
        ));
    }
    if let Some((offset, requested, received)) = page_note {
        lines.push(format!(
            "read({offset}, {requested}): 第一页，实读 {received} 字节，完整={}",
            requested == received
        ));
    }
    lines
}

/// Enum choice ids allow only a-z/0-9/_; the v1 verdict strings use hyphens.
fn enum_slug(value: &str) -> String {
    value.replace('-', "_")
}

fn display_name(file: &FileRef) -> String {
    let name = file.name().trim();
    if !name.is_empty() {
        return name.replace('\\', "/");
    }
    file.view_path()
        .or_else(|| file.root_path())
        .map(|path| path.replace('\\', "/"))
        .unwrap_or_else(|| file.id().to_owned())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.sqlcipher-profile")
        .record::<ProfileRow>()
        .record::<HeaderCheckRow>()
        .record::<KeyAttemptRow>()
        .record::<PlaintextRow>()
        .record::<PageReadRow>()
        .analyzer(ANALYZER, sqlcipher)
}

export_plugin!(plugin);
