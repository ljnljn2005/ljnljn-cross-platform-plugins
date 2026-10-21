//! `file_analyzer` 实现：通过 SDK 只读逻辑句柄读取文件，套用
//! [`crate::profile`] 的纯解析逻辑，再映射成 LPP v1 结果。
//!
//! 硬约束（SDK）：
//! * 插件拿不到检材真实路径，只用 `File::read(offset, len)`；
//! * 读文件必须给上限（这里只读前 [`HEADER_WINDOW`] 字节，加一次页读取）；
//! * 每条 artifact 都带 `source.*` 属性和取证依据 `sqlcipher.*` 属性。

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, File, FileAnalyzer, Finding, LogLevel, Result, Severity,
    Value,
};

use crate::hex;
use crate::profile::{
    page_plan, parse_header, verify_page, HeaderKind, KeyCheck, Options, PageBytes, Profile,
    HEADER_WINDOW,
};

/// analyzer 名，必须与 plugin.toml 的 `analyzer` 完全一致。
pub const ANALYZER_NAME: &str = "ljnljn.sqlcipher-profile";

/// 属性命名空间。
pub const NS: &str = "sqlcipher";

/// 文件分析器。
#[derive(Default)]
pub struct SqlCipherHeaderProfile {
    options: Options,
}

impl SqlCipherHeaderProfile {
    /// 用给定参数构造（测试与调用方显式指定口令/偏移时使用）。
    pub fn with_options(options: Options) -> Self {
        Self { options }
    }

    /// 默认：不带任何密钥，只做结构指纹与参数画像。
    pub fn profile_only() -> Self {
        Self {
            options: Options::profile_only(),
        }
    }
}

impl FileAnalyzer for SqlCipherHeaderProfile {
    fn analyzer(&self) -> &str {
        ANALYZER_NAME
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let size = file.size();
        let window_len = usize::try_from(size.min(HEADER_WINDOW as u64)).unwrap_or(0);
        file.context()
            .check_cancelled()
            .inspect_err(|error| {
                file.context().log(
                    LogLevel::Debug,
                    &format!("sqlcipher header profile cancelled before read: {error}"),
                )
            })?;
        // 单次有界读取：文件前 4096 字节（SDK 会把长度夹到文件尾）。
        let window = file.read(0, window_len)?;
        let mut profile = parse_header(&window, size, &self.options);
        add_standard_limitations(&mut profile, file);

        // 可选步骤：提供密钥时做第一页 HMAC 试校验（只读一页）。
        let mut page_note = None;
        if let Some(plan) = page_plan(&profile, &self.options) {
            file.context().check_cancelled()?;
            let page = file.read(plan.page_offset, plan.read_len)?;
            page_note = Some((plan.page_offset, plan.read_len, page.len()));
            verify_page(
                &mut profile,
                &self.options,
                &plan,
                PageBytes {
                    page: &page,
                    requested: plan.read_len,
                },
            );
        }

        Ok(build_result(file, &profile, page_note))
    }
}

fn add_standard_limitations(profile: &mut Profile, file: &File) {
    if profile.window_len < usize::try_from(file.size()).unwrap_or(usize::MAX) {
        profile.limitations.push(format!(
            "只读取了文件前 {} 字节（文件共 {} 字节）：不覆盖后续页、WAL/journal 或自由块。",
            profile.window_len,
            file.size()
        ));
    }
    profile.limitations.push(
        "本版本不做实际解密：不解 AES-CBC 页，不读取表结构/记录，也不处理 WAL/journal。"
            .to_string(),
    );
    profile.limitations.push(
        "不提供密钥时只能做结构级判定（encrypted-sqlite-likely），不能证明可解密。"
            .to_string(),
    );
    profile.limitations.push(
        "宿主 LPP v1 没有单文件分析器的自定义参数通道，口令/主密钥/页偏移默认取插件内置默认值\
         （不带密钥、页偏移 0）；需要试校验时由调用方用 SqlCipherHeaderProfile::with_options \
         显式提供。"
            .to_string(),
    );
    profile.limitations.push(
        "支持的 HMAC/PRF 家族为 SHA512（SQLCipher 4 默认）与 SHA256；不含 SHA1（SQLCipher 3 默认）\
         与 AES-256-CBC 明文校验。"
            .to_string(),
    );
    profile.limitations.push(
        "位于检材文件系统内的 SQLite 文件应先用其它插件/内置文件系统提取为单文件，本分析器只处理\
         逻辑文件句柄。"
            .to_string(),
    );
}

fn build_result(file: &File, profile: &Profile, page_note: Option<(u64, usize, usize)>) -> AnalysisResult {
    let mut out = AnalysisResult::default();
    out.summary = Some(summary_text(profile));
    out.artifacts.push(profile_artifact(file, profile));
    for check in &profile.checks {
        out.artifacts.push(structural_check_artifact(file, profile, check));
    }
    for attempt in &profile.attempts {
        out.artifacts.push(attempt_artifact(file, profile, attempt));
    }
    if profile.header_kind == HeaderKind::PlaintextSqlite {
        out.artifacts.push(plaintext_artifact(file, profile));
    }
    if let Some((offset, requested, got)) = page_note {
        out.artifacts.push(page_read_artifact(file, profile, offset, requested, got));
    }
    if profile.header_kind == HeaderKind::EncryptedSqliteLikely && profile.key_check == KeyCheck::NotAttempted {
        out.findings.push(Finding {
            severity: Severity::Info,
            title: "疑似 SQLCipher 加密数据库（未校验密钥）".to_string(),
            description: format!(
                "文件头符合 SQLCipher 4 布局：salt={}，pageSize={}，reserve={}。\
                 未提供密钥，未做 HMAC 试校验；如需确认可解密性，请以显式参数重跑。",
                profile.salt_hex.as_deref().unwrap_or(""),
                profile.page_size.map(|size| size.to_string()).unwrap_or_default(),
                profile.reserve_size.map(|size| size.to_string()).unwrap_or_default(),
            ),
            attributes: source_attributes(file),
        });
    }
    out
}

fn summary_text(profile: &Profile) -> String {
    let mut parts = Vec::new();
    parts.push(format!("文件长度 {}", profile.file_len));
    parts.push(format!("headerKind={}", profile.header_kind.as_str()));
    if let Some(salt) = &profile.salt_hex {
        parts.push(format!("salt={salt}"));
    }
    if let Some(size) = profile.page_size {
        parts.push(format!("pageSize={size}"));
    }
    if let Some(reserve) = profile.reserve_size {
        parts.push(format!("reserveSize={reserve}"));
    }
    parts.push(format!("kdfIter={}", profile.kdf_iter));
    parts.push(format!("hmac={}", profile.hmac_algorithm));
    if let Some(counter) = profile.file_change_counter {
        parts.push(format!("fileChangeCounter={counter}"));
    }
    parts.push(format!("keyCheck={}", profile.key_check.as_str()));
    format!(
        "SQLCipher 文件头画像：{}；判定依据：{}",
        parts.join(", "),
        profile.verdict_basis
    )
}

fn source_attributes(file: &File) -> Attributes {
    let mut attributes = Attributes::new();
    attributes.insert("source.path", file.name());
    attributes.insert("source.file_id", file.id());
    attributes.insert("source.size", file.size());
    attributes.insert("source.mime", file.mime());
    attributes.insert(format!("{NS}.source"), "lovelycarve.file_analyzer");
    attributes.insert(format!("{NS}.analyzer"), ANALYZER_NAME);
    attributes
}

fn header_kind_value(profile: &Profile) -> Value {
    Value::from(profile.header_kind.as_str())
}

fn profile_artifact(file: &File, profile: &Profile) -> Artifact {
    let mut attributes = source_attributes(file);
    attributes.insert("sqlcipher.filePath", file.name());
    attributes.insert("sqlcipher.fileLength", profile.file_len);
    attributes.insert("sqlcipher.headerKind", header_kind_value(profile));
    attributes.insert_optional("sqlcipher.saltHex", profile.salt_hex.clone());
    attributes.insert_optional("sqlcipher.pageSize", profile.page_size.map(u64::from));
    attributes.insert_optional(
        "sqlcipher.pageSizeRaw",
        profile.page_size_raw.map(u64::from),
    );
    attributes.insert_optional("sqlcipher.reserveSize", profile.reserve_size.map(u64::from));
    attributes.insert("sqlcipher.kdfIter", u64::from(profile.kdf_iter));
    attributes.insert("sqlcipher.hmacAlgorithm", profile.hmac_algorithm);
    attributes.insert_optional(
        "sqlcipher.fileChangeCounter",
        profile.file_change_counter.map(u64::from),
    );
    attributes.insert_optional(
        "sqlcipher.writeVersion",
        profile.write_version.map(u64::from),
    );
    attributes.insert_optional(
        "sqlcipher.readVersion",
        profile.read_version.map(u64::from),
    );
    attributes.insert_optional(
        "sqlcipher.payloadFraction",
        profile.payload_fraction.map(u64::from),
    );
    attributes.insert_optional(
        "sqlcipher.fileFormatRead",
        profile.file_format_read.map(u64::from),
    );
    attributes.insert_optional(
        "sqlcipher.fileFormatWrite",
        profile.file_format_write.map(u64::from),
    );
    attributes.insert("sqlcipher.keyCheck", profile.key_check.as_str());
    attributes.insert(
        "sqlcipher.verdictBasis",
        profile.verdict_basis.clone(),
    );
    attributes.insert(
        "sqlcipher.evidence",
        Value::Array(evidence_lines(profile).into_iter().map(Value::from).collect()),
    );
    attributes.insert(
        "sqlcipher.limitations",
        Value::Array(
            profile
                .limitations
                .iter()
                .cloned()
                .map(Value::from)
                .collect(),
        ),
    );
    attributes.insert("sqlcipher.checksPassed", passed_count(profile));
    attributes.insert("sqlcipher.checksTotal", profile.checks.len() as u64);
    Artifact {
        artifact_type: format!("{NS}.profile"),
        title: format!("SQLCipher 文件头画像（{}）", profile.header_kind.as_str()),
        value: Some(Value::from(profile.salt_hex.as_deref().unwrap_or(""))),
        attributes,
    }
}

fn passed_count(profile: &Profile) -> u64 {
    profile.checks.iter().filter(|item| item.passed).count() as u64
}

/// `evidence` 字段：读取偏移与字节区间。
fn evidence_lines(profile: &Profile) -> Vec<String> {
    let mut lines = vec![format!(
        "read(0, {}): 0x00000000..0x{:08x} header window ({} bytes read, fileLen={})",
        HEADER_WINDOW,
        profile.window_len,
        profile.window_len,
        profile.file_len
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
    if let Some((offset, len, ok)) = profile.page_read {
        lines.push(format!(
            "read({offset}, {len}): 第一页，实读 {len} 字节，完整={ok}"
        ));
    }
    lines
}

fn structural_check_artifact(
    file: &File,
    profile: &Profile,
    check: &crate::profile::Check,
) -> Artifact {
    let mut attributes = source_attributes(file);
    attributes.insert("sqlcipher.check", check.name);
    attributes.insert("sqlcipher.passed", check.passed);
    attributes.insert("sqlcipher.field", check.field.clone());
    attributes.insert("sqlcipher.observed", check.observed.clone());
    attributes.insert("sqlcipher.expected", check.expected.clone());
    attributes.insert("sqlcipher.headerKind", header_kind_value(profile));
    attributes.insert("sqlcipher.verification", "header-field-compare");
    Artifact {
        artifact_type: format!("{NS}.header_check"),
        title: format!(
            "结构检查 {}（{}）",
            check.name,
            if check.passed { "通过" } else { "不通过" }
        ),
        value: Some(Value::from(check.observed.clone())),
        attributes,
    }
}

fn attempt_artifact(file: &File, profile: &Profile, attempt: &crate::profile::Attempt) -> Artifact {
    let mut attributes = source_attributes(file);
    attributes.insert("sqlcipher.keySource", attempt.key_source);
    attributes.insert("sqlcipher.kdfIterations", u64::from(attempt.kdf_iterations));
    attributes.insert("sqlcipher.hmacAlgorithm", attempt.hmac_algorithm);
    attributes.insert(
        "sqlcipher.derivedKeyPrefixHex",
        attempt.derived_key_prefix_hex.clone(),
    );
    attributes.insert("sqlcipher.passed", attempt.passed);
    attributes.insert("sqlcipher.computedHmacHex", attempt.computed_hmac_hex.clone());
    attributes.insert("sqlcipher.storedHmacHex", attempt.stored_hmac_hex.clone());
    attributes.insert("sqlcipher.headerKind", header_kind_value(profile));
    attributes.insert(
        "sqlcipher.verification",
        "pbkdf2-hmac-first-page-digest-compare (only the 64-byte digest is compared; no plaintext recovered)",
    );
    Artifact {
        artifact_type: format!("{NS}.key_attempt"),
        title: format!(
            "首库页 HMAC 试校验 {}（{}）",
            attempt.key_source,
            if attempt.passed { "通过" } else { "不通过" }
        ),
        value: Some(Value::from(attempt.computed_hmac_hex.clone())),
        attributes,
    }
}

fn plaintext_artifact(file: &File, profile: &Profile) -> Artifact {
    let mut attributes = source_attributes(file);
    attributes.insert(
        "sqlcipher.magic",
        hex::encode(crate::profile::SQLITE_PLAINTEXT_MAGIC),
    );
    attributes.insert("sqlcipher.magicOffset", "0x00000000..0x00000010");
    attributes.insert("sqlcipher.headerKind", header_kind_value(profile));
    attributes.insert("sqlcipher.verification", "magic-bytes-0x00..0x10");
    Artifact {
        artifact_type: format!("{NS}.plaintext_sqlite"),
        title: "明文 SQLite 文件头（非加密库，已停止加密参数推断）".to_string(),
        value: Some(Value::from("SQLite format 3")),
        attributes,
    }
}

fn page_read_artifact(
    file: &File,
    profile: &Profile,
    offset: u64,
    requested: usize,
    got: usize,
) -> Artifact {
    let mut attributes = source_attributes(file);
    attributes.insert("sqlcipher.pageOffset", offset);
    attributes.insert("sqlcipher.requested", requested as u64);
    attributes.insert("sqlcipher.received", got as u64);
    attributes.insert("sqlcipher.headerKind", header_kind_value(profile));
    Artifact {
        artifact_type: format!("{NS}.page_read"),
        title: "第一页读取记录".to_string(),
        value: Some(Value::from(format!("{got}/{requested}"))),
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{build_synthetic, SyntheticParams, DEFAULT_KDF_ITER};

    fn artifact_of<'a>(result: &'a AnalysisResult, kind: &str) -> Option<&'a Artifact> {
        result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == format!("{NS}.{kind}"))
    }

    #[test]
    fn analyzer_name_matches_manifest_and_identity() {
        let analyzer = SqlCipherHeaderProfile::profile_only();
        assert_eq!(analyzer.analyzer(), ANALYZER_NAME);
        assert_eq!(ANALYZER_NAME, "ljnljn.sqlcipher-profile");
        // 与 plugin.toml / lib.rs 的 Plugin::new id 对齐
        assert_eq!(crate::PLUGIN_ID, "org.ljnljn.sqlcipher-profile");
    }

    #[test]
    fn source_identity_is_present_on_every_artifact() {
        let bytes = build_synthetic(&SyntheticParams::default());
        let (result, _) = crate::test_support::analyze_bytes("account.db", &bytes);
        assert!(!result.artifacts.is_empty());
        for artifact in &result.artifacts {
            assert_eq!(
                artifact
                    .attributes
                    .get("source.path")
                    .and_then(Value::as_str),
                Some("account.db"),
                "{} 缺少 source.path",
                artifact.artifact_type
            );
            assert_eq!(
                artifact
                    .attributes
                    .get("sqlcipher.analyzer")
                    .and_then(Value::as_str),
                Some(ANALYZER_NAME)
            );
            assert!(artifact.artifact_type.starts_with("sqlcipher."));
        }
    }

    #[test]
    fn profile_artifact_exposes_all_required_fields() {
        let bytes = build_synthetic(&SyntheticParams::default());
        let (result, _) = crate::test_support::analyze_bytes("account.db", &bytes);
        let artifact = artifact_of(&result, "profile").expect("profile artifact");
        let attributes = &artifact.attributes;
        assert_eq!(
            attributes.get("sqlcipher.filePath").and_then(Value::as_str),
            Some("account.db")
        );
        assert_eq!(
            attributes.get("sqlcipher.fileLength").and_then(Value::as_u64),
            Some(bytes.len() as u64)
        );
        assert_eq!(
            attributes.get("sqlcipher.headerKind").and_then(Value::as_str),
            Some("encrypted-sqlite-likely")
        );
        assert_eq!(
            attributes.get("sqlcipher.pageSize").and_then(Value::as_u64),
            Some(1024)
        );
        assert_eq!(
            attributes.get("sqlcipher.reserveSize").and_then(Value::as_u64),
            Some(48)
        );
        assert_eq!(
            attributes.get("sqlcipher.kdfIter").and_then(Value::as_u64),
            Some(u64::from(DEFAULT_KDF_ITER))
        );
        assert_eq!(
            attributes.get("sqlcipher.hmacAlgorithm").and_then(Value::as_str),
            Some("SHA512")
        );
        assert_eq!(
            attributes.get("sqlcipher.fileChangeCounter").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            attributes.get("sqlcipher.keyCheck").and_then(Value::as_str),
            Some("not-attempted")
        );
        let evidence = attributes.get("sqlcipher.evidence").and_then(Value::as_array).expect("evidence");
        assert!(evidence.iter().any(|item| item.as_str().unwrap_or("").contains("0x00000000..0x00000010")));
        assert!(attributes.contains_key("sqlcipher.limitations"));
        // 明文字段没有 salt 时 profile artifact 也必须有 salt 属性键
        assert!(attributes.contains_key("sqlcipher.saltHex"));
    }

    #[test]
    fn plaintext_and_unknown_paths_render_without_key_attempts() {
        let mut plain = Vec::new();
        plain.extend_from_slice(b"SQLite format 3\0");
        plain.extend_from_slice(&4096_u16.to_be_bytes());
        plain.resize(4096, 0);
        let (result, _) = crate::test_support::analyze_bytes("plain.db", &plain);
        let profile_artifact = artifact_of(&result, "profile").expect("profile");
        assert_eq!(
            profile_artifact
                .attributes
                .get("sqlcipher.headerKind")
                .and_then(Value::as_str),
            Some("plaintext-sqlite")
        );
        assert!(artifact_of(&result, "plaintext_sqlite").is_some());
        assert_eq!(
            result
                .artifacts
                .iter()
                .filter(|artifact| artifact.artifact_type == format!("{NS}.header_check"))
                .count(),
            0
        );

        let (result, _) = crate::test_support::analyze_bytes("empty.db", &[]);
        let profile_artifact = artifact_of(&result, "profile").expect("profile");
        assert_eq!(
            profile_artifact
                .attributes
                .get("sqlcipher.headerKind")
                .and_then(Value::as_str),
            Some("unknown")
        );
        assert!(result.summary.as_deref().unwrap_or("").contains("unknown"));
        assert!(!result.artifacts.is_empty(), "空文件也要给出可追溯的画像记录");

        let (result, _) = crate::test_support::analyze_bytes("tiny.db", &[0xde, 0xad, 0xbe]);
        let profile_artifact = artifact_of(&result, "profile").expect("profile");
        assert_eq!(
            profile_artifact
                .attributes
                .get("sqlcipher.fileLength")
                .and_then(Value::as_u64),
            Some(3)
        );
    }
}
