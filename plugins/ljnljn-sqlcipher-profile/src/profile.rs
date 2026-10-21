//! SQLCipher / 明文 SQLite 文件头结构指纹与参数画像（纯解析，不碰 SDK）。
//!
//! 输入是"调用方从逻辑文件句柄读到的字节"，因此这里的所有逻辑都可以用
//! 合成数组直接单元测试，不依赖宿主、不依赖真实检材。
//!
//! ## 算法要点（与需求逐条对应）
//!
//! 1. 前 16 字节等于 `SQLite format 3\0` → `plaintext-sqlite`，立即返回；
//! 2. 否则按 SQLCipher 4 头布局解释前 16 字节为 salt，随后
//!    `[16..18]` 大端页大小（1 表示 65536，须是 512 的二次幂或 65536）、
//!    `[18]` 写版本、`[19]` 读版本、`[20]` reserved 保留字节数、
//!    `[21]` payload 分数、`[22..24]` 文件格式读/写版本、
//!    `[24..28]` 文件修改计数（大端）；
//! 3. 输出 pageSize / reserveSize（报告真实读值，默认 48 只作为比较基线）/
//!    kdfIter 默认 256000 / hmac 默认 SHA512；
//! 4. 提供口令或 64 位 hex 主密钥时，用 PBKDF2-HMAC-SHA512(salt, iter)
//!    派生密钥，对第一页做 HMAC 试校验（比较页尾 reserve 区最后的摘要）；
//! 5. 不提供密钥时只做结构合理性判定 `encrypted-sqlite-likely` / `unknown`，
//!    并列出所依据的字段。**不内置任何密钥，也不猜测密钥。**

use crate::hex;
use crate::hmac::{pbkdf2, HmacKey};
use crate::sha512::DigestKind;

/// 明文 SQLite 文件头（不校验尾字节是否可打印，避免误绕过）。
pub const SQLITE_PLAINTEXT_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// SQLCipher 4 的默认 KDF 迭代次数（pbkdf2_hmac 参数）。
pub const DEFAULT_KDF_ITER: u32 = 256_000;
/// SQLCipher 4 默认 HMAC 算法。
pub const DEFAULT_HMAC: DigestKind = DigestKind::Sha512;
/// SQLCipher 4 默认 reserve 区长度。
pub const DEFAULT_RESERVE: u8 = 48;
/// SQLite 页大小的合法取值上界。
pub const MAX_PAGE_SIZE: u32 = 65_536;
/// SQLite 页大小的合法取值下界。
pub const MIN_PAGE_SIZE: u32 = 512;
/// SQLCipher 第一页的页号（用于每页密钥派生）。
pub const PAGE_NO_FIRST: u32 = 1;

/// 需求要求的头部观察窗口：文件前 4096 字节。
pub const HEADER_WINDOW: usize = 4096;

/// `headerKind` 输出取值。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderKind {
    PlaintextSqlite,
    EncryptedSqliteLikely,
    Unknown,
}

impl HeaderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlaintextSqlite => "plaintext-sqlite",
            Self::EncryptedSqliteLikely => "encrypted-sqlite-likely",
            Self::Unknown => "unknown",
        }
    }
}

/// `keyCheck` 输出取值（需求中为连字符形式）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyCheck {
    NotAttempted,
    Passed,
    Failed,
}

impl KeyCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not-attempted",
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

/// 调用参数。CLI 里的"可选参数"在 SDK 里没有宿主参数通道，
/// 因此由调用方显式构造；analyzer 默认使用 [`Options::default_from_env`]。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Options {
    /// 候选口令（UTF-8 原文）。`None` 表示未提供。
    pub passphrase: Option<String>,
    /// 64 位 hex 主密钥（32 字节）。
    pub raw_master_key: Option<Vec<u8>>,
    /// 第一页偏移，必须是页大小（1024/2048/4096/8192）的整数倍，默认 0。
    pub page_offset: u64,
    /// 覆盖页大小（当头部页大小字段被破坏时由调用方指定）。
    pub page_size_override: Option<u32>,
    /// 覆盖 reserve 长度。
    pub reserve_override: Option<u8>,
    /// KDF 迭代次数候选。
    pub kdf_iterations: Vec<u32>,
    /// HMAC 摘要候选。
    pub hmac_algorithms: Vec<DigestKind>,
}

impl Options {
    /// 不带任何密钥的默认参数画像。
    pub fn profile_only() -> Self {
        Self {
            kdf_iterations: vec![DEFAULT_KDF_ITER],
            hmac_algorithms: vec![DEFAULT_HMAC],
            ..Self::default()
        }
    }

    pub fn has_key(&self) -> bool {
        self.passphrase.is_some() || self.raw_master_key.is_some()
    }
}

/// 结构检查的单个结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Check {
    /// 机器可读名称，例如 `page_size_range`。
    pub name: &'static str,
    pub passed: bool,
    /// "读取偏移与字节区间"的人类可读说明。
    pub field: String,
    pub observed: String,
    pub expected: String,
}

/// 密钥试校验尝试记录。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub key_source: &'static str,
    pub kdf_iterations: u32,
    pub hmac_algorithm: &'static str,
    /// 派生出的 32 字节加密密钥的前 8 字节 hex（用于配对/复现，不是候选密钥）。
    pub derived_key_prefix_hex: String,
    pub passed: bool,
    pub computed_hmac_hex: String,
    pub stored_hmac_hex: String,
}

/// 结构画像结果。
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub header_kind: HeaderKind,
    pub salt_hex: Option<String>,
    /// 头部页大小字段的原始字节值（未解释前）。
    pub page_size_raw: Option<u16>,
    pub page_size: Option<u32>,
    pub write_version: Option<u8>,
    pub read_version: Option<u8>,
    pub reserve_size: Option<u8>,
    pub payload_fraction: Option<u8>,
    pub file_format_read: Option<u8>,
    pub file_format_write: Option<u8>,
    pub file_change_counter: Option<u32>,
    pub kdf_iter: u32,
    pub hmac_algorithm: &'static str,
    pub checks: Vec<Check>,
    /// 结构判定依据（通过/失败的字段摘要）。
    pub verdict_basis: String,
    /// 第一页读取信息：(offset, length_read, bytes_read)。
    pub page_read: Option<(u64, usize, bool)>,
    pub page_hmac_offset: Option<u64>,
    pub stored_page_hmac_hex: Option<String>,
    pub attempts: Vec<Attempt>,
    pub key_check: KeyCheck,
    pub limitations: Vec<String>,
    /// 实际用于分析的字节数（= min(文件长度, HEADER_WINDOW)，合成样例可能更大）。
    pub window_len: usize,
    pub file_len: u64,
}

impl Profile {
    fn unknown(file_len: u64, window_len: usize, reason: &str) -> Self {
        let mut limitations = vec![
            "文件头不符合明文 SQLite 或 SQLCipher 4 可解析布局，未做任何密钥推算。".to_string(),
        ];
        if file_len < 16 {
            limitations.push(format!(
                "文件仅有 {file_len} 字节，短于 16 字节 salt/魔数区间。"
            ));
        }
        Self {
            header_kind: HeaderKind::Unknown,
            salt_hex: None,
            page_size_raw: None,
            page_size: None,
            write_version: None,
            read_version: None,
            reserve_size: None,
            payload_fraction: None,
            file_format_read: None,
            file_format_write: None,
            file_change_counter: None,
            kdf_iter: DEFAULT_KDF_ITER,
            hmac_algorithm: DEFAULT_HMAC.name(),
            checks: Vec::new(),
            verdict_basis: reason.to_string(),
            page_read: None,
            page_hmac_offset: None,
            stored_page_hmac_hex: None,
            attempts: Vec::new(),
            key_check: KeyCheck::NotAttempted,
            limitations,
            window_len,
            file_len,
        }
    }
}

/// 页大小合法性：1 → 65536；否则必须是 512 的二次幂且 ≤ 65536。
pub fn valid_page_size(raw: u16) -> Option<u32> {
    if raw == 1 {
        return Some(MAX_PAGE_SIZE);
    }
    let value = u32::from(raw);
    if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&value) {
        return None;
    }
    if value.is_power_of_two() && value % MIN_PAGE_SIZE == 0 {
        Some(value)
    } else {
        None
    }
}

/// 解析第一页头部；`window` 是调用方从文件句柄读到的前若干字节。
///
/// 只要 `window.len() >= 28` 且页大小合法即视为可解析的 SQLCipher 布局。
/// 页大小非法时**不报错、不越界**，返回 `unknown` 并记录原因。
pub fn parse_header(window: &[u8], file_len: u64, options: &Options) -> Profile {
    if window.len() >= 16 && &window[..16] == SQLITE_PLAINTEXT_MAGIC {
        let mut limitations = vec![
            "已确认明文 SQLite（前 16 字节为 \"SQLite format 3\\0\"），按要求不再做加密参数推断。"
                .to_string(),
        ];
        limitations.push(plaintext_note(window));
        return Profile {
            header_kind: HeaderKind::PlaintextSqlite,
            salt_hex: None,
            page_size_raw: None,
            // 明文头 16..18 也存放页大小，可直接读出（不属于加密参数推断）。
            page_size: plaintext_page_size(window),
            write_version: window.get(18).copied(),
            read_version: window.get(19).copied(),
            reserve_size: window.get(20).copied(),
            payload_fraction: window.get(21).copied(),
            file_format_read: window.get(22).copied(),
            file_format_write: window.get(23).copied(),
            file_change_counter: read_u32(window, 24),
            kdf_iter: DEFAULT_KDF_ITER,
            hmac_algorithm: DEFAULT_HMAC.name(),
            checks: Vec::new(),
            verdict_basis: "前 16 字节命中明文 SQLite 魔数，直接判定 plaintext-sqlite 并退出。"
                .to_string(),
            page_read: None,
            page_hmac_offset: None,
            stored_page_hmac_hex: None,
            attempts: Vec::new(),
            key_check: KeyCheck::NotAttempted,
            limitations,
            window_len: window.len(),
            file_len,
        };
    }

    if window.len() < 28 {
        return Profile::unknown(
            file_len,
            window.len(),
            &format!(
                "可读字节数 {} 少于 SQLCipher 4 头所需 28 字节，无法解析参数；既不匹配明文魔数，\
                 也不足以判定为加密库。",
                window.len()
            ),
        );
    }

    let salt = &window[..16];
    let page_size_raw = u16::from_be_bytes([window[16], window[17]]);
    let page_size = match (options.page_size_override, valid_page_size(page_size_raw)) {
        (Some(override_size), _)
            if valid_page_size(override_size as u16) == Some(override_size) =>
        {
            Some(override_size)
        }
        (Some(_), _) => {
            return Profile::unknown(
                file_len,
                window.len(),
                &format!(
                    "调用方覆盖的页大小 {} 不是合法 SQLite 页大小（512..65536 的二次幂或 65536 \
                     记作 1），拒绝使用。",
                    options.page_size_override.unwrap_or(0)
                ),
            );
        }
        (None, parsed) => parsed,
    };
    let Some(page_size) = page_size else {
        let mut profile = Profile::unknown(
            file_len,
            window.len(),
            &format!(
                "页大小字段 [0x10..0x12) = 0x{page_size_raw:04x} 非法（应为 1 表示 65536，或 512 的\
                 二次幂且 ≤ 65536），结构不符，不做加密判定也不读取后续页。"
            ),
        );
        // 仍如实上报读到的字段，便于人工复核"为什么判 unknown"。
        profile.salt_hex = Some(hex::encode(salt));
        profile.page_size_raw = Some(page_size_raw);
        profile.reserve_size = Some(window[20]);
        profile.payload_fraction = Some(window[21]);
        profile.file_change_counter = read_u32(window, 24);
        return profile;
    };

    let write_version = window[18];
    let read_version = window[19];
    let reserve_size = options.reserve_override.unwrap_or(window[20]);
    let payload_fraction = window[21];
    let file_format_read = window[22];
    let file_format_write = window[23];
    let file_change_counter = read_u32(window, 24).unwrap_or(0);

    let mut checks = Vec::new();
    checks.push(check(
        "salt_len",
        true,
        "offset 0x00..0x10 (0..16)",
        format!("{} bytes: {}", salt.len(), hex::encode(salt)),
        "16 字节随机 salt",
    ));
    checks.push(check(
        "page_size_range",
        true,
        "offset 0x10..0x12 (16..18), 大端 u16",
        format!("0x{page_size_raw:04x} -> {page_size}"),
        "1(=65536) 或 512 的二次幂且 ≤ 65536",
    ));
    checks.push(check(
        "file_bound_ok",
        file_len >= page_size as u64,
        "fileLen vs pageSize",
        format!("fileLen={file_len}, pageSize={page_size}"),
        "第一页须完整落在文件内（否则 HMAC 区被截断）",
    ));
    checks.push(check(
        "payload_fraction",
        payload_fraction == 64,
        "offset 0x15 (21), 1 字节",
        format!("{payload_fraction}"),
        "64（SQLCipher 建库时为 SQLite 默认值，异常值多见于随机数据误判）",
    ));
    checks.push(check(
        "file_format_versions",
        file_format_read == 1 && file_format_write == 1,
        "offset 0x16..0x18 (22..24), 2 字节",
        format!("read={file_format_read}, write={file_format_write}"),
        "1,1（SQLite 1 号文件格式；加密库通常保持，但本版本不据此否决）",
    ));
    // SQLite/ SQLCipher 的读写版本字节必须是 1 或 2；其余值说明不是正常库头。
    checks.push(check(
        "version_bytes_valid",
        matches!(write_version, 1 | 2) && matches!(read_version, 1 | 2),
        "offset 0x12..0x14 (18..20), 2 字节",
        format!("write={write_version}, read={read_version}"),
        "各自为 1 或 2（SQLite 合法的文件格式版本）",
    ));
    checks.push(check(
        "reserve_size_range",
        (32..=64).contains(&reserve_size),
        "offset 0x14 (20), 1 字节",
        format!("{reserve_size}"),
        "SQLCipher 4 默认 48；太小放不下 HMAC，太大常见于随机数据",
    ));
    checks.push(check(
        "page_change_counter_nonzero",
        file_change_counter > 0,
        "offset 0x18..0x1c (24..28), 大端 u32",
        format!("{file_change_counter}"),
        "通常 > 0；为 0 常见于随机数据（仅作参考）",
    ));

    let mut failed_soft = Vec::new();
    for item in &checks {
        if !item.passed {
            failed_soft.push(item.name);
        }
    }
    // 判定规则（需求 5）：结构检查全部通过 → likely；否则 unknown。
    let header_kind = if failed_soft.is_empty() {
        HeaderKind::EncryptedSqliteLikely
    } else {
        HeaderKind::Unknown
    };
    let verdict_basis = if failed_soft.is_empty() {
        format!(
            "16 字节 salt + 合法页大小 {page_size} + payload 分数 {payload_fraction} + \
             reserve {reserve_size} + 修改计数 {file_change_counter} 均符合 SQLCipher 4 头布局；\
             未提供密钥，因此只能给出结构级判定。"
        )
    } else {
        format!(
            "页大小合法但字段不符 SQLCipher 4 常见布局（未通过：{}），按保守策略判 unknown。",
            failed_soft.join(", ")
        )
    };

    let profile = Profile {
        header_kind,
        salt_hex: Some(hex::encode(salt)),
        page_size_raw: Some(page_size_raw),
        page_size: Some(page_size),
        write_version: Some(write_version),
        read_version: Some(read_version),
        reserve_size: Some(reserve_size),
        payload_fraction: Some(payload_fraction),
        file_format_read: Some(file_format_read),
        file_format_write: Some(file_format_write),
        file_change_counter: Some(file_change_counter),
        kdf_iter: options
            .kdf_iterations
            .first()
            .copied()
            .unwrap_or(DEFAULT_KDF_ITER),
        hmac_algorithm: options
            .hmac_algorithms
            .first()
            .copied()
            .unwrap_or(DEFAULT_HMAC)
            .name(),
        checks,
        verdict_basis,
        page_read: None,
        page_hmac_offset: None,
        stored_page_hmac_hex: None,
        attempts: Vec::new(),
        key_check: KeyCheck::NotAttempted,
        limitations: Vec::new(),
        window_len: window.len(),
        file_len,
    };
    profile
}

fn plaintext_note(window: &[u8]) -> String {
    match plaintext_page_size(window) {
        Some(size) => {
            format!("明文页大小字段 [0x10..0x12) = {size}（仅作说明，不做加密参数推断）。")
        }
        None => "明文页大小字段不可解释（文件短于 18 字节）。".to_string(),
    }
}

fn plaintext_page_size(window: &[u8]) -> Option<u32> {
    let raw = u16::from_be_bytes([*window.get(16)?, *window.get(17)?]);
    valid_page_size(raw)
}

fn read_u32(window: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = window.get(offset..end)?;
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(slice);
    Some(u32::from_be_bytes(bytes))
}

fn check(
    name: &'static str,
    passed: bool,
    field: impl Into<String>,
    observed: impl Into<String>,
    expected: impl Into<String>,
) -> Check {
    Check {
        name,
        passed,
        field: field.into(),
        observed: observed.into(),
        expected: expected.into(),
    }
}

/// 第一页校验所需的读取计划：需要读多少字节、HMAC 存在哪里。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagePlan {
    pub page_offset: u64,
    pub read_len: usize,
    /// 页尾 reserve 区最后 64 字节（HMAC-SHA512）的绝对偏移。
    pub hmac_offset: u64,
    pub salt: Vec<u8>,
    pub reserve_size: u8,
}

/// 需要读取的第一页长度（含页尾 HMAC 区）。
pub fn page_plan(profile: &Profile, options: &Options) -> Option<PagePlan> {
    if profile.header_kind != HeaderKind::EncryptedSqliteLikely || !options.has_key() {
        return None;
    }
    let page_size = profile.page_size?;
    let reserve_size = profile.reserve_size?;
    if page_size <= u64::from(reserve_size) as u32 + 8 {
        return None;
    }
    let salt = hex::decode(profile.salt_hex.as_deref()?)?;
    let read_len = page_size as usize;
    Some(PagePlan {
        page_offset: options.page_offset,
        read_len,
        hmac_offset: options.page_offset + page_size as u64 - u64::from(reserve_size),
        salt,
        reserve_size,
    })
}

/// 第一页试校验的输入：从页偏移开始读到的字节。
#[derive(Clone, Copy, Debug)]
pub struct PageBytes<'a> {
    pub page: &'a [u8],
    /// 调用方实际读到了多少字节（< read_len 表示文件被截断）。
    pub requested: usize,
}

/// 执行密钥试校验（需求 4）。返回 `key_check`、尝试记录与补充限制。
pub fn verify_page(
    profile: &mut Profile,
    options: &Options,
    plan: &PagePlan,
    page: PageBytes<'_>,
) -> KeyCheck {
    let Some(page_size) = profile.page_size else {
        return KeyCheck::NotAttempted;
    };
    let reserve = usize::from(plan.reserve_size);
    let bytes = page.page;
    if bytes.len() < page_size as usize {
        profile.limitations.push(format!(
            "第一页读取不完整：期望 {page_size} 字节，实得 {} 字节（请求 {}，文件长度 {}，页偏移 {}）。\
             无法校验页尾 HMAC。",
            bytes.len(),
            page.requested,
            profile.file_len,
            plan.page_offset
        ));
        profile.key_check = KeyCheck::Failed;
        return KeyCheck::Failed;
    }
    // SQLCipher 4 的 reserve 默认是 48 字节，而 SHA-512 摘要为 64 字节；
    // 真实库只把摘要的前 reserve 字节写入页尾。reserve 过小时无法形成
    // 有意义的截断 HMAC，直接拒绝而不是静默通过。
    const MIN_HMAC_BYTES: usize = 32;
    if reserve < MIN_HMAC_BYTES {
        profile.limitations.push(format!(
            "reserve 区仅 {reserve} 字节，小于可校验下限 32 字节（SHA-512 摘要 64 字节）；无法按 SQLCipher 4 布局校验。"
        ));
        profile.key_check = KeyCheck::Failed;
        return KeyCheck::Failed;
    }

    let page_start = page_size as usize - reserve;
    let reserved = &bytes[page_start..page_size as usize];

    let iterations_list = normalized_iterations(options);
    let algorithms = normalized_algorithms(options);
    let mut attempts = Vec::new();
    let mut passed = false;

    for algorithm in algorithms {
        let digest_len = algorithm.output_len();
        let stored_len = reserve.min(digest_len);
        let slice = &reserved[reserved.len() - stored_len..];
        let hmac_offset = plan.page_offset + page_size as u64 - stored_len as u64;
        if profile.page_hmac_offset.is_none() || !passed {
            profile.page_hmac_offset = Some(hmac_offset);
            profile.stored_page_hmac_hex = Some(hex::encode(slice));
        }
        let data = &bytes[..page_size as usize - reserve];

        // 候选 1：64 位 hex 主密钥直接使用（SQLCipher `PRAGMA key = "x'...'"`）。
        if let Some(master) = options.raw_master_key.as_deref() {
            let mut raw_key = [0_u8; 32];
            let take = master.len().min(32);
            raw_key[..take].copy_from_slice(&master[..take]);
            let key = page_key(algorithm, &raw_key, PAGE_NO_FIRST);
            let hmac = HmacKey::new(algorithm, &key).digest(data);
            let ok = constant_time_eq(&hmac[..stored_len], slice);
            attempts.push(Attempt {
                key_source: "raw-key-hex",
                kdf_iterations: 0,
                hmac_algorithm: algorithm.name(),
                derived_key_prefix_hex: hex::prefix(&key, 8),
                passed: ok,
                computed_hmac_hex: hex::encode(&hmac[..stored_len]),
                stored_hmac_hex: hex::encode(slice),
            });
            passed |= ok;
        }

        // 候选 2：口令 → PBKDF2-HMAC-<family>(passphrase, salt, iter) → 每页派生密钥。
        if let Some(passphrase) = options.passphrase.as_deref() {
            for iterations in &iterations_list {
                let derived = pbkdf2(
                    algorithm,
                    passphrase.as_bytes(),
                    &plan.salt,
                    *iterations,
                    32,
                );
                let mut raw_key = [0_u8; 32];
                raw_key.copy_from_slice(&derived[..32]);
                let key = page_key(algorithm, &raw_key, PAGE_NO_FIRST);
                let hmac = HmacKey::new(algorithm, &key).digest(data);
                let ok = constant_time_eq(&hmac[..stored_len], slice);
                attempts.push(Attempt {
                    key_source: "passphrase",
                    kdf_iterations: *iterations,
                    hmac_algorithm: algorithm.name(),
                    derived_key_prefix_hex: hex::prefix(&key, 8),
                    passed: ok,
                    computed_hmac_hex: hex::encode(&hmac[..stored_len]),
                    stored_hmac_hex: hex::encode(slice),
                });
                passed |= ok;
            }
        }
    }

    profile.page_read = Some((plan.page_offset, bytes.len(), true));
    profile.attempts = attempts;
    if passed {
        profile.key_check = KeyCheck::Passed;
        if profile.header_kind == HeaderKind::Unknown {
            profile.header_kind = HeaderKind::EncryptedSqliteLikely;
            profile.verdict_basis.push_str(
                " 此外第一页 HMAC 校验通过，说明结构字段虽不完全典型，但确为 SQLCipher 加密库。",
            );
        }
    } else {
        profile.key_check = KeyCheck::Failed;
        if !matches!(profile.header_kind, HeaderKind::Unknown) {
            profile.limitations.push(
                "第一页 HMAC 校验失败：口令/主密钥、salt、页大小、reserve 或 KDF 参数（迭代次数/\
                 PRF 家族）至少有一项与建库时不一致。本版本只做单页试校验，不做全量解密以确认。"
                    .to_string(),
            );
        }
    }
    profile.key_check
}

fn normalized_iterations(options: &Options) -> Vec<u32> {
    if options.kdf_iterations.is_empty() {
        vec![DEFAULT_KDF_ITER]
    } else {
        let mut list = options.kdf_iterations.clone();
        list.dedup();
        list
    }
}

fn normalized_algorithms(options: &Options) -> Vec<DigestKind> {
    if options.hmac_algorithms.is_empty() {
        vec![DEFAULT_HMAC]
    } else {
        let mut list = options.hmac_algorithms.clone();
        list.dedup();
        list
    }
}

/// SQLCipher 每页密钥派生（crypto_impl):
/// `raw_key(32) || pad(32 零, 仅 SHA-512 家族) ^ page_no(大端 u32 在低 4 字节)`
/// 再做一次 HMAC-<family>，输出 32 字节页密钥。第一页 `page_no = 1`。
fn page_key(algorithm: DigestKind, raw_key: &[u8; 32], page_no: u32) -> Vec<u8> {
    let mut block = [0_u8; 64];
    block[..32].copy_from_slice(raw_key);
    let mask_len = algorithm.output_len().min(block.len());
    let page_bytes = page_no.to_be_bytes();
    for (index, byte) in page_bytes.iter().enumerate() {
        // SQLCipher 把 page_no 与掩码块最后 4 字节异或。
        block[mask_len - 4 + index] ^= byte;
    }
    HmacKey::new(algorithm, raw_key).digest(&block[..mask_len])
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// 合成样例（只用于测试与离线样例；不内置任何真实口令/密钥）
// ---------------------------------------------------------------------------

/// 合成 SQLCipher 4 样例的参数。
#[derive(Clone, Debug)]
pub struct SyntheticParams {
    pub passphrase: String,
    pub salt: [u8; 16],
    pub page_size: u16,
    pub reserve: u8,
    pub kdf_iter: u32,
    /// 允许构造非法页大小等破坏性样例。
    pub raw_page_size: Option<u16>,
    pub payload_fraction: u8,
    pub file_change_counter: u32,
    pub pages: usize,
}

impl Default for SyntheticParams {
    fn default() -> Self {
        Self {
            passphrase: "synthetic-test-passphrase".to_string(),
            salt: *b"SQLCipherSynth01",
            page_size: 1024,
            reserve: DEFAULT_RESERVE,
            kdf_iter: DEFAULT_KDF_ITER,
            raw_page_size: None,
            payload_fraction: 64,
            file_change_counter: 1,
            pages: 2,
        }
    }
}

/// 确定性伪随机流（SplitMix64），在样例里冒充 AES-CBC 密文。
fn fill_pseudo_random(seed: u64, out: &mut [u8]) {
    let mut state = seed;
    for chunk in out.chunks_mut(8) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let bytes = z.to_be_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// 构造一个"结构上合法"的 SQLCipher 4 样例。
///
/// 布局与 SQLCipher 4 一致：salt 占第一页 `[0..16]`，随后是 4 字节头
/// `[16..20]`，密文区为 `[20 .. pageSize-reserve)`，页尾 reserve 区最后
/// `64` 字节是本页 HMAC-SHA512。所有页的 HMAC 都用给定口令**真实计算**；
/// 密文部分用确定性伪随机流代替（本插件不实现 AES，见 limitations）。
pub fn build_synthetic(params: &SyntheticParams) -> Vec<u8> {
    let page_size = usize::from(params.page_size);
    let reserve = usize::from(params.reserve);
    let hmac_len = DEFAULT_HMAC.output_len();
    let mut file = Vec::with_capacity(page_size * params.pages);
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&params.salt);
    let raw_page_size = params.raw_page_size.unwrap_or(params.page_size);
    header.extend_from_slice(&raw_page_size.to_be_bytes());
    // SQLCipher 4 的版本字节取 SQLite 合法值 1/2（4.x 默认写 1、读 1）。
    header.push(1); // 写版本
    header.push(1); // 读版本
    header.push(params.reserve);
    header.push(params.payload_fraction);
    header.push(1); // 文件格式读版本
    header.push(1); // 文件格式写版本
    header.extend_from_slice(&params.file_change_counter.to_be_bytes());
    file.extend_from_slice(&header);
    let mut body = vec![0_u8; page_size - header.len()];
    fill_pseudo_random(0x5eed_0001, &mut body);
    file.extend_from_slice(&body);
    for page_index in 1..params.pages {
        let mut page = vec![0_u8; page_size];
        fill_pseudo_random(0x5eed_0100 + page_index as u64, &mut page);
        file.extend_from_slice(&page);
    }

    // 密钥链：PBKDF2 → 32 字节 raw key → 每页派生密钥 → 页 HMAC。
    let raw = pbkdf2(
        DEFAULT_HMAC,
        params.passphrase.as_bytes(),
        &params.salt,
        params.kdf_iter,
        32,
    );
    let mut raw_key = [0_u8; 32];
    raw_key.copy_from_slice(&raw[..32]);
    let data_end = page_size - reserve;
    for page_index in 0..params.pages {
        let page_no = PAGE_NO_FIRST + page_index as u32;
        let key = page_key(DEFAULT_HMAC, &raw_key, page_no);
        let start = page_index * page_size;
        let mac = HmacKey::new(DEFAULT_HMAC, &key).digest(&file[start..start + data_end]);
        let stored = reserve.min(hmac_len);
        let mac_start = start + page_size - stored;
        file[mac_start..start + page_size].copy_from_slice(&mac[..stored]);
    }
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_of(bytes: &[u8]) -> Profile {
        parse_header(bytes, bytes.len() as u64, &Options::profile_only())
    }

    #[test]
    fn plaintext_sqlite_header_is_detected_and_stops() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SQLITE_PLAINTEXT_MAGIC);
        bytes.extend_from_slice(&1024_u16.to_be_bytes());
        bytes.extend_from_slice(&[1, 1, 0, 64, 1, 1]);
        bytes.extend_from_slice(&7_u32.to_be_bytes());
        bytes.resize(1024, 0);
        let profile = profile_of(&bytes);
        assert_eq!(profile.header_kind, HeaderKind::PlaintextSqlite);
        assert_eq!(profile.key_check, KeyCheck::NotAttempted);
        assert!(profile.salt_hex.is_none());
        assert!(profile.checks.is_empty(), "明文库不应继续做加密参数检查");
        assert_eq!(profile.page_size, Some(1024));
        assert_eq!(profile.file_change_counter, Some(7));
        assert!(page_plan(&profile, &Options::profile_only()).is_none());
    }

    #[test]
    fn empty_and_three_byte_files_are_unknown_without_panic() {
        let empty = profile_of(&[]);
        assert_eq!(empty.header_kind, HeaderKind::Unknown);
        assert_eq!(empty.window_len, 0);
        assert!(empty
            .limitations
            .iter()
            .any(|item| item.contains("短于 16 字节")));

        let three = profile_of(&[0xde, 0xad, 0xbe]);
        assert_eq!(three.header_kind, HeaderKind::Unknown);
        assert_eq!(three.file_len, 3);
        assert_eq!(three.salt_hex, None);
        assert_eq!(three.page_size, None);
        assert_eq!(three.key_check, KeyCheck::NotAttempted);
    }

    #[test]
    fn partial_sqlite_magic_is_not_plaintext() {
        // 只有 13 字节 "SQLite format"：不是完整魔数，也不足 28 字节。
        let profile = profile_of(b"SQLite format");
        assert_eq!(profile.header_kind, HeaderKind::Unknown);
    }

    #[test]
    fn illegal_page_size_is_unknown_and_does_not_read_further() {
        let mut params = SyntheticParams::default();
        params.raw_page_size = Some(1000); // 不是 512 的二次幂
        let bytes = build_synthetic(&params);
        let profile = profile_of(&bytes);
        assert_eq!(profile.header_kind, HeaderKind::Unknown);
        assert_eq!(profile.page_size_raw, Some(1000));
        assert_eq!(profile.page_size, None);
        assert!(profile.page_read.is_none());
        assert!(profile.verdict_basis.contains("非法"));
        // 合法的覆盖参数仍可让调用方继续（头部被破坏时的显式救济路径）。
        let mut options = Options::profile_only();
        options.page_size_override = Some(1024);
        let recovered = parse_header(&bytes, bytes.len() as u64, &options);
        assert_eq!(recovered.header_kind, HeaderKind::EncryptedSqliteLikely);
        assert_eq!(recovered.page_size, Some(1024));
    }

    #[test]
    fn page_size_one_means_65536_and_bad_overrides_rejected() {
        assert_eq!(valid_page_size(1), Some(65_536));
        assert_eq!(valid_page_size(512), Some(512));
        assert_eq!(valid_page_size(1024), Some(1024));
        assert_eq!(valid_page_size(4096), Some(4096));
        assert_eq!(valid_page_size(0), None);
        assert_eq!(valid_page_size(256), None);
        assert_eq!(valid_page_size(1000), None);
        assert_eq!(valid_page_size(12_345), None);

        let mut options = Options::profile_only();
        options.page_size_override = Some(1000);
        let bytes = build_synthetic(&SyntheticParams::default());
        let profile = parse_header(&bytes, bytes.len() as u64, &options);
        assert_eq!(profile.header_kind, HeaderKind::Unknown);
        assert!(profile.verdict_basis.contains("覆盖的页大小"));
    }

    #[test]
    fn synthetic_sqlcipher4_without_key_is_likely() {
        let bytes = build_synthetic(&SyntheticParams::default());
        let profile = profile_of(&bytes);
        assert_eq!(profile.header_kind, HeaderKind::EncryptedSqliteLikely);
        assert_eq!(
            profile.salt_hex.as_deref(),
            Some("53514c43697068657253796e74683031")
        );
        assert_eq!(profile.page_size, Some(1024));
        assert_eq!(profile.reserve_size, Some(48));
        assert_eq!(profile.kdf_iter, DEFAULT_KDF_ITER);
        assert_eq!(profile.hmac_algorithm, "SHA512");
        assert_eq!(profile.file_change_counter, Some(1));
        assert_eq!(profile.key_check, KeyCheck::NotAttempted);
        assert!(profile.checks.iter().all(|item| item.passed));
        for check in &profile.checks {
            assert!(check.field.contains("offset") || check.field.starts_with("fileLen"));
        }
    }

    #[test]
    fn correct_passphrase_passes_and_wrong_one_fails() {
        let params = SyntheticParams::default();
        let bytes = build_synthetic(&params);
        let mut options = Options::profile_only();
        options.passphrase = Some(params.passphrase.clone());
        let mut profile = parse_header(&bytes, bytes.len() as u64, &options);
        let plan = page_plan(&profile, &options).expect("plan");
        assert_eq!(plan.read_len, 1024);
        assert_eq!(plan.hmac_offset, 1024 - 48);
        let page = &bytes[..1024];
        let outcome = verify_page(
            &mut profile,
            &options,
            &plan,
            PageBytes {
                page,
                requested: plan.read_len,
            },
        );
        assert_eq!(outcome, KeyCheck::Passed);
        assert_eq!(profile.attempts.len(), 1);
        assert_eq!(profile.attempts[0].kdf_iterations, DEFAULT_KDF_ITER);
        assert_eq!(profile.attempts[0].hmac_algorithm, "SHA512");

        let mut wrong = Options::profile_only();
        wrong.passphrase = Some("definitely-not-the-passphrase".to_string());
        let mut wrong_profile = parse_header(&bytes, bytes.len() as u64, &wrong);
        let wrong_plan = page_plan(&wrong_profile, &wrong).expect("plan");
        let outcome = verify_page(
            &mut wrong_profile,
            &wrong,
            &wrong_plan,
            PageBytes {
                page,
                requested: wrong_plan.read_len,
            },
        );
        assert_eq!(outcome, KeyCheck::Failed);
        assert!(wrong_profile
            .limitations
            .iter()
            .any(|item| item.contains("HMAC 校验失败")));
    }

    #[test]
    fn truncated_first_page_reports_failure_not_panic() {
        let params = SyntheticParams::default();
        let bytes = build_synthetic(&params);
        let mut options = Options::profile_only();
        options.passphrase = Some(params.passphrase.clone());
        let mut profile = parse_header(&bytes, bytes.len() as u64, &options);
        let plan = page_plan(&profile, &options).expect("plan");
        let short = &bytes[..100];
        let outcome = verify_page(
            &mut profile,
            &options,
            &plan,
            PageBytes {
                page: short,
                requested: plan.read_len,
            },
        );
        assert_eq!(outcome, KeyCheck::Failed);
        assert!(profile
            .limitations
            .iter()
            .any(|item| item.contains("读取不完整")));
    }

    #[test]
    fn reserve_too_small_for_sha512_is_reported() {
        let mut params = SyntheticParams::default();
        params.page_size = 512;
        params.reserve = 16;
        let bytes = build_synthetic(&params);
        let mut options = Options::profile_only();
        options.passphrase = Some(params.passphrase.clone());
        let profile = parse_header(&bytes, bytes.len() as u64, &options);
        assert_eq!(profile.reserve_size, Some(16));
        // 16 字节 reserve 低于 SQLCipher 4 的合法区间（32..=64），头部判定不成立，
        // 不应进入单页 HMAC 校验，更不能把它当作可通过的布局。
        assert!(profile
            .checks
            .iter()
            .any(|check| check.name == "reserve_size_range" && !check.passed));
        assert!(page_plan(&profile, &options).is_none());
    }

    #[test]
    fn raw_master_key_matches_sqlcipher_constructor() {
        // 与 SQLCipher `sqlite3_key(c, key, 32)` 一致：64 hex → 32 字节主密钥。
        let params = SyntheticParams::default();
        let bytes = build_synthetic(&params);
        let raw = pbkdf2(
            DEFAULT_HMAC,
            params.passphrase.as_bytes(),
            &params.salt,
            params.kdf_iter,
            32,
        );
        let mut options = Options::profile_only();
        options.raw_master_key = Some(raw.clone());
        let mut profile = parse_header(&bytes, bytes.len() as u64, &options);
        let plan = page_plan(&profile, &options).expect("plan");
        let outcome = verify_page(
            &mut profile,
            &options,
            &plan,
            PageBytes {
                page: &bytes[..1024],
                requested: 1024,
            },
        );
        assert_eq!(outcome, KeyCheck::Passed);
    }

    #[test]
    fn random_garbage_with_valid_page_size_is_unknown() {
        let mut bytes = vec![0x41_u8; 512];
        // 合法页大小 4096，但其余字段是填塞值。
        bytes[16] = 0x10;
        bytes[17] = 0x00;
        bytes[18] = 0x41;
        bytes[19] = 0x41;
        bytes[20] = 0x41;
        bytes[21] = 0x41;
        let profile = profile_of(&bytes);
        assert_eq!(profile.header_kind, HeaderKind::Unknown);
        assert!(profile.verdict_basis.contains("payload_fraction"));
    }

    #[test]
    fn page_plan_requires_key_and_likely_layout() {
        let bytes = build_synthetic(&SyntheticParams::default());
        let profile = profile_of(&bytes);
        assert!(page_plan(&profile, &Options::profile_only()).is_none());
        let mut options = Options::profile_only();
        options.page_offset = 4096;
        options.passphrase = Some("x".to_string());
        let plan = page_plan(&profile, &options).expect("plan");
        assert_eq!(plan.page_offset, 4096);
        assert_eq!(plan.hmac_offset, 4096 + 1024 - 48);
    }
}
