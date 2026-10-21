//! EWF/E01 段级头部元数据最小解析器（纯解析部分，不依赖宿主）。
//!
//! 布局依据公开 EWF1 结构（libewf `ewf_file_header.h` / `ewf_section.h` /
//! `ewf_volume.h`）：
//! * 文件头固定 13 字节：0..8 为签名 `EVF\x09\x0d\x0a\xff\x00`，字节 8 为
//!   fields_start（0x01），字节 9..11 为段号（u16 小端，1 起算），
//!   字节 11..13 为 fields_end（原样记录）；
//! * 文件头之后紧跟 76 字节节段描述符：0..16 类型（NUL 结尾 ASCII）、
//!   16..24 next 偏移（绝对、u64 小端）、24..32 节段长度（含描述符自身）、
//!   32..72 填充、72..76 adler32(0..72)；
//! * EWF1 volume 节段内容 1052 字节：0 media_type、4..8 number_of_chunks、
//!   8..12 sectors_per_chunk、12..16 bytes_per_sector、16..24 number_of_sectors、
//!   24..36 CHS、36 media_flags、52 compression_level、64..80 集合标识、
//!   1048..1052 adler32(0..1048)。
//!
//! 覆盖范围：签名、EWF1 文件头字段、段号与扩展名序号比对、首枚节段
//! `headerLength`、有界节段链遍历、EWF1 volume 候选值；EWF2/Ex01 只识别并记录
//! 32 字节文件头，明确不解析其 v2 节段/volume/disk 布局。
//!
//! 明确不做：chunk 表遍历、数据解压、哈希重算、逻辑卷大小计算、分区层解析。

use sha2::{Digest, Sha256};

/// 公共 EWF 文件签名（EWF1/EWF2/Ex01 相同，8 字节）。
pub const SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
/// EWF1 文件头长度：签名 8 + fields_start 1 + 段号 2 + fields_end 2。
pub const EWF1_FILE_HEADER_SIZE: u64 = 13;
/// EWF2/Ex01 文件头长度：签名 8 + 主/次版本 2 + 压缩方法 2 + 段号 4 + 集合标识 16。
pub const EWF2_FILE_HEADER_SIZE: u64 = 32;
/// EWF1 节段描述符固定长度。
pub const SECTION_DESCRIPTOR_SIZE: u64 = 76;
/// EWF1 首枚节段描述符的绝对偏移（紧随 13 字节文件头）。
pub const FIRST_SECTION_OFFSET: u64 = EWF1_FILE_HEADER_SIZE;
/// EWF1 volume 节段内容长度。
pub const EWF1_VOLUME_BODY_SIZE: u64 = 1052;
/// 节段链读取窗口上限（有界读取；超出后停止并在 warnings 说明）。
pub const SECTION_WINDOW_CAP: u64 = 64 * 1024;
/// 单次解析最多检查的节段描述符数量。
pub const MAX_SECTIONS: usize = 64;
/// 头部区截断摘要（hex）的最大字节数。
pub const HEADER_HEX_CAP: usize = 256;
/// 表节段类型（用于 containsTableSection 标记）。
const TABLE_SECTIONS: &[&str] = &["table", "table2"];

/// EWF 格式。字段布局只实现 EWF1；EWF2/Ex01 仅识别文件头。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EwfFormat {
    /// EWF1（EnCase E01 一类，13 字节文件头）。
    Ewf1,
    /// EWF2（32 字节 v2 文件头，v2 节段布局未实现）。
    Ewf2,
    /// Ex01（32 字节 v2 文件头，v2 节段布局未实现）。
    Ex01,
}

impl EwfFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ewf1 => "EWF1",
            Self::Ewf2 => "EWF2",
            Self::Ex01 => "Ex01",
        }
    }

    /// 展示用格式类别。
    pub fn kind(self) -> &'static str {
        match self {
            Self::Ewf1 => "encase-ewf1",
            Self::Ewf2 => "ewf2",
            Self::Ex01 => "ex01",
        }
    }
}

/// 所有结果共用的限制说明（每条都带来源/边界）。
pub fn standard_limitations() -> Vec<String> {
    vec![
        "EWF1 文件头固定 13 字节：字节 0..8 为签名 EVF\\x09\\x0d\\x0a\\xff\\x00，字节 8 为 \
fields_start（0x01），字节 9..11 为段号（u16 小端，1 起算），字节 11..13 为 fields_end\
（原样记录，不强制取值）。其他厂商写法或损坏的头部布局可能不同，本插件不做启发式猜测。"
            .to_string(),
        "首枚节段描述符固定在文件头之后（绝对偏移 13），长度 76 字节：0..16 类型（NUL 结尾 ASCII）、\
16..24 next 偏移（绝对、u64 小端）、24..32 节段长度（含描述符自身）、72..76 adler32(0..72)。"
            .to_string(),
        "headerLength 取自首枚节段描述符字节 24..32；该值是首枚节段（通常是 header）的长度，\
不是 13 字节文件头长度。为 0、小于 76 或越过文件末尾只记录 errors，不静默置零。"
            .to_string(),
        "节段链在文件头之后 64 KiB 的有界读取窗口内遍历，最多检查 64 枚描述符；\
窗口之外停止并在 warnings/limitations 说明。不做 chunk 表遍历、数据解压与哈希重算。"
            .to_string(),
        "EWF1 volume 节段内容 1052 字节：0 media_type、4..8 number_of_chunks、\
8..12 sectors_per_chunk、12..16 bytes_per_sector、16..24 number_of_sectors、\
24..36 CHS、36 media_flags（1 字节）、52 compression_level（1 字节）、64..80 集合标识、\
1048..1052 adler32(0..1048)。内容不足时对应字段为 null 并记录 notes。"
            .to_string(),
        "EWF1 标准节段中没有 disk；disk 节段属于 EWF2/Ex01 布局，本插件不把 disk 当作 volume \
解析，其候选值置 null 并记录原因。"
            .to_string(),
        "EWF2/Ex01 使用 32 字节文件头（8 字节签名、主/次版本、2 字节压缩方法、4 字节段号、\
16 字节集合标识）；本插件只识别并记录这些文件头字段，不解析其后的 v2 节段描述符、\
volume/disk 节段，候选值一律 null。"
            .to_string(),
        "sectors_per_chunk 与 number_of_sectors 保持镜像原始记录值，不做“扇区→字节”换算；\
media_size_bytes = number_of_sectors × bytes_per_sector 仅是推导值，并在 notes 标注。"
            .to_string(),
        "volume 节段尾部的 adler32 只在内容完整 1052 字节时比对，结论写入 notes；\
文件头/节段描述符的校验只做展示性比对，不因校验失败中止解析。"
            .to_string(),
        "segmentCountContiguous 由单个段文件无法确定：输出 null；多段连续性需上层把同名的 \
E01/E02…/Ex01 逐个调度后比对段号。"
            .to_string(),
        "扩展名序号只识别 E01..E99 与 Ex01..Ex99；EAA/EAB 等字母序号扩展名不在本次范围，\
遇到时按“无法比对扩展名序号”处理并写入 limitations。"
            .to_string(),
        "单段文件头没有 isLastSegment 字段；最后一段需由 done/next 节段链判定。\
本插件只记录有界窗口内的 doneSectionPresent，不推断 isLastSegment（输出 null）。"
            .to_string(),
        "插件运行时只有宿主授予的只读逻辑文件句柄（id / name / size / read），拿不到真实路径；\
path 字段即该句柄的 name，目录输入需由宿主按扩展名与段号逐个调度文件。"
            .to_string(),
    ]
}

/// 文件头字节 8 的含义（EWF1 是 fields_start，EWF2/Ex01 是 major_version）。
pub fn format_id_kind(byte: u8) -> &'static str {
    match byte {
        0x01 => "ewf1-fields-start",
        0x02 => "ewf2-major-version",
        _ => "unknown",
    }
}

fn extension_text(name: &str) -> Option<&str> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.rsplit_once('.').map(|(_, extension)| extension)
}

/// 从扩展名解析段号序号：`E01`/`e01` → 1、`E02` → 2、`Ex01`/`ex01` → 1。
///
/// 只接受 EWF 段文件的两字母前缀（E/L 与 Ex），返回 None 表示不是可识别的
/// EWF 段扩展名（含 `.E00`、`.E100`、`.txt` 等）。
pub fn extension_number(name: &str) -> Option<u64> {
    let extension = extension_text(name)?;
    let lower = extension.to_ascii_lowercase();
    let digits = if lower.len() == 3 && lower.starts_with('e') {
        &lower[1..]
    } else if lower.len() == 4 && lower.starts_with("ex") {
        &lower[2..]
    } else {
        return None;
    };
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number: u64 = digits.parse().ok()?;
    (number >= 1).then_some(number)
}

/// 扩展名是否为 `.Ex01` 形式（EWF2/Ex01 家族）。
pub fn extension_is_ex01(name: &str) -> bool {
    extension_text(name)
        .map(|extension| extension.eq_ignore_ascii_case("ex01"))
        .unwrap_or(false)
}

/// 头部区布局（偏移均为绝对文件偏移）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderLayout {
    /// 文件头起始偏移（固定 0）。
    pub header_offset: u64,
    /// 该格式要求的文件头长度（EWF1 13 / EWF2 32）。
    pub header_size: u64,
    /// 实际可覆盖的文件头结束位置（文件短于头部时按文件长度截断）。
    pub header_end: u64,
    /// 文件头之后第一枚节段描述符的偏移（EWF1 为 13）。
    pub section_offset: u64,
    /// 首枚 76 字节节段描述符是否完整落在文件内。
    pub section_fits: bool,
}

/// 计算头部区布局。
pub fn header_layout(file_size: u64, header_size: u64) -> HeaderLayout {
    let header_end = header_size.min(file_size);
    let section_fits = header_size
        .checked_add(SECTION_DESCRIPTOR_SIZE)
        .is_some_and(|end| end <= file_size);
    HeaderLayout {
        header_offset: 0,
        header_size,
        header_end,
        section_offset: header_size,
        section_fits,
    }
}

/// 解析后的文件头字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub signature_len: usize,
    pub layout: HeaderLayout,
    pub format: Option<EwfFormat>,
    /// 字节 8：EWF1 的 fields_start 或 EWF2/Ex01 的 major_version。
    pub format_id: Option<u8>,
    pub segment_number: Option<u64>,
    pub fields_start: Option<u8>,
    pub fields_end: Option<[u8; 2]>,
    pub major_version: Option<u8>,
    pub minor_version: Option<u8>,
    pub compression_method: Option<u16>,
    pub set_identifier: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// 在 `head` 起始处校验 8 字节 EVF 签名并解析文件头。
///
/// 返回 None 表示偏移 0 处没有完整签名；签名完整但字段截断时仍返回
/// [`FileHeader`]，并在 `errors` 中说明。
pub fn parse_file_header(name: &str, head: &[u8], file_size: u64) -> Option<FileHeader> {
    if head.len() < SIGNATURE.len() || &head[..SIGNATURE.len()] != SIGNATURE {
        return None;
    }
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let format_id = head.get(8).copied();
    let (header_size, format) = match format_id {
        Some(0x01) => (EWF1_FILE_HEADER_SIZE, Some(EwfFormat::Ewf1)),
        Some(0x02) => {
            let format = if extension_is_ex01(name) {
                EwfFormat::Ex01
            } else {
                EwfFormat::Ewf2
            };
            (EWF2_FILE_HEADER_SIZE, Some(format))
        }
        Some(other) => {
            errors.push(format!(
                "文件头字节 8 = 0x{other:02x}，既不是 EWF1 的 fields_start(0x01)，\
也不是 EWF2/Ex01 的 major_version(0x02)；格式无法判定"
            ));
            (EWF1_FILE_HEADER_SIZE, None)
        }
        None => {
            errors.push(
                "文件头在字节 8 处被截断，缺少 fields_start / major_version 字段".to_string(),
            );
            (EWF1_FILE_HEADER_SIZE, None)
        }
    };
    let mut layout = header_layout(file_size, header_size);
    if format != Some(EwfFormat::Ewf1) {
        // v2 节段描述符布局未实现，不能声称首枚 76 字节描述符可用。
        layout.section_fits = false;
    }

    let mut fields_start = None;
    let mut fields_end = None;
    let mut major_version = None;
    let mut minor_version = None;
    let mut compression_method = None;
    let mut set_identifier = None;
    let mut segment_number = None;

    match format {
        Some(EwfFormat::Ewf1) => {
            fields_start = head.get(8).copied();
            segment_number = le_u16_at(head, 9).map(u64::from);
            if segment_number.is_none() {
                errors.push("段号字段缺失：EWF1 文件头不足 11 字节".to_string());
            } else if segment_number == Some(0) {
                errors.push("段号字段为 0；EWF1 段号从 1 起算，无法与扩展名序号比对".to_string());
            }
            if head.len() >= 13 {
                fields_end = Some([head[11], head[12]]);
                if head[11] == 0 && head[12] == 0 {
                    warnings
                        .push("fields_end 为 0x0000；本插件不强制该字段取值，原样记录".to_string());
                }
            } else {
                errors.push("fields_end 缺失：EWF1 文件头不足 13 字节".to_string());
            }
        }
        Some(format @ (EwfFormat::Ewf2 | EwfFormat::Ex01)) => {
            major_version = head.get(8).copied();
            minor_version = head.get(9).copied();
            compression_method = le_u16_at(head, 10);
            segment_number = le_u32_at(head, 12).map(u64::from);
            if head.len() >= EWF2_FILE_HEADER_SIZE as usize {
                set_identifier = Some(hex_lower(&head[16..32]));
            }
            warnings.push(format!(
                "{} 文件头按 32 字节 v2 布局读取；其后的 v2 节段描述符与 volume/disk 布局\
不在本插件实现范围内",
                format.as_str()
            ));
        }
        None => {}
    }

    Some(FileHeader {
        signature_len: SIGNATURE.len(),
        layout,
        format,
        format_id,
        segment_number,
        fields_start,
        fields_end,
        major_version,
        minor_version,
        compression_method,
        set_identifier,
        errors,
        warnings,
    })
}

/// 头部区之后第一枚节段描述符（76 字节）的关键字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionDescriptor {
    /// 描述符自身的绝对偏移。
    pub offset: u64,
    /// 节段类型：最长 16 字节的以 0 结尾的 ASCII 串（可能为空）。
    pub section_type: String,
    /// 下一枚节段描述符的绝对偏移（0 表示链结束）。
    pub next_offset: u64,
    /// 节段长度（含描述符自身），即需求中的 headerLength。
    pub length: u64,
    /// 节段内容起始的绝对偏移（描述符之后）。
    pub body_offset: u64,
    /// 节段内容长度（`length - 76`，长度非法时为 0）。
    pub body_length: u64,
    /// 描述符尾部 adler32 是否与字节 0..72 一致；记录值为 0 时为 None。
    pub checksum_ok: Option<bool>,
}

/// 节段链扫描结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SectionScan {
    pub sections: Vec<SectionDescriptor>,
    pub volume: Option<(SectionDescriptor, Vec<u8>)>,
    pub disk: Option<SectionDescriptor>,
    pub contains_table: bool,
    pub done_present: bool,
    pub chain_limited: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// 在“文件头之后”的有界窗口内遍历 EWF1 节段链。
///
/// `window` 从绝对偏移 [`FIRST_SECTION_OFFSET`] 开始；所有越界/截断都只记录
/// 到 `errors`/`warnings`，不会 panic。
pub fn scan_sections(window: &[u8], file_size: u64) -> SectionScan {
    let mut scan = SectionScan::default();
    let window_len = window.len() as u64;
    if window_len < SECTION_DESCRIPTOR_SIZE {
        scan.errors.push(format!(
            "文件头之后没有完整的节段描述符：需要 {SECTION_DESCRIPTOR_SIZE} 字节，\
实际 {window_len} 字节（文件长度 {file_size}）"
        ));
        return scan;
    }

    let mut rel: u64 = 0;
    let mut hit_section_cap = false;
    while scan.sections.len() < MAX_SECTIONS {
        let abs = FIRST_SECTION_OFFSET.saturating_add(rel);
        if rel.saturating_add(SECTION_DESCRIPTOR_SIZE) > window_len {
            scan.chain_limited = true;
            scan.warnings.push(format!(
                "节段链在偏移 {abs} 处超出 {SECTION_WINDOW_CAP} 字节有界读取窗口，未继续遍历"
            ));
            break;
        }
        if abs.saturating_add(SECTION_DESCRIPTOR_SIZE) > file_size {
            scan.errors.push(format!(
                "节段描述符越界：偏移 {abs} 处需要 {SECTION_DESCRIPTOR_SIZE} 字节，\
文件长度 {file_size}"
            ));
            break;
        }

        let start = rel as usize;
        let descriptor = &window[start..start + SECTION_DESCRIPTOR_SIZE as usize];
        let section_type = descriptor_type(descriptor);
        let next_offset = le_u64_at(descriptor, 16).unwrap_or(0);
        let length = le_u64_at(descriptor, 24).unwrap_or(0);
        let stored_checksum = le_u32_at(descriptor, 72);
        let checksum_ok = stored_checksum.and_then(|stored| {
            if stored == 0 {
                None
            } else {
                Some(stored == adler32(&descriptor[..72]))
            }
        });
        match checksum_ok {
            Some(true) => scan.warnings.push(format!(
                "节段描述符 `{section_type}`（偏移 {abs}）adler32 自检通过"
            )),
            Some(false) => scan.warnings.push(format!(
                "节段描述符 `{section_type}`（偏移 {abs}）adler32 不一致，字段仍按原值记录"
            )),
            None => {}
        }

        let body_length = length.saturating_sub(SECTION_DESCRIPTOR_SIZE);
        let section = SectionDescriptor {
            offset: abs,
            section_type: section_type.clone(),
            next_offset,
            length,
            body_offset: abs.saturating_add(SECTION_DESCRIPTOR_SIZE),
            body_length,
            checksum_ok,
        };
        let kind = section_type.to_ascii_lowercase();
        scan.sections.push(section.clone());

        let length_valid = length >= SECTION_DESCRIPTOR_SIZE;
        let end = abs.checked_add(length);
        let bounds_valid = length_valid && end.is_some_and(|end| end <= file_size);
        if length == 0 {
            scan.errors.push(format!(
                "节段 `{section_type}`（偏移 {abs}）长度为 0，按规范非法"
            ));
        } else if length < SECTION_DESCRIPTOR_SIZE {
            scan.errors.push(format!(
                "节段 `{section_type}`（偏移 {abs}）长度 {length} 小于描述符长度 \
{SECTION_DESCRIPTOR_SIZE}"
            ));
        } else if let Some(end) = end {
            if end > file_size {
                scan.errors.push(format!(
                    "节段 `{section_type}`（偏移 {abs}）越界：结束位置 {end} 超过文件长度 \
{file_size}"
                ));
            }
        } else {
            scan.errors.push(format!(
                "节段 `{section_type}`（偏移 {abs}）长度 {length} 与偏移相加溢出 u64"
            ));
        }

        if bounds_valid {
            if kind == "volume" {
                if scan.volume.is_none() {
                    scan.volume = read_volume_body(&section, window, rel, window_len);
                }
            } else if kind == "disk" && scan.disk.is_none() {
                scan.disk = Some(section.clone());
            }
            if TABLE_SECTIONS.contains(&kind.as_str()) {
                scan.contains_table = true;
            }
            if kind == "done" {
                scan.done_present = true;
            }
        }

        if length == 0 || !bounds_valid {
            break;
        }
        if next_offset == 0 {
            break;
        }
        if next_offset <= abs {
            scan.errors.push(format!(
                "节段 `{section_type}` 的 next 偏移 {next_offset} 未前进（当前 {abs}），\
节段链无法遍历"
            ));
            break;
        }
        if let Some(end) = end {
            if next_offset < end {
                scan.errors.push(format!(
                    "节段 `{section_type}` 的 next 偏移 {next_offset} 落在本节段内容内\
（结束位置 {end}），节段链无法可靠遍历"
                ));
                break;
            }
        }
        let Some(next_rel) = next_offset.checked_sub(FIRST_SECTION_OFFSET) else {
            scan.errors.push(format!(
                "节段 `{section_type}` 的 next 偏移 {next_offset} 小于首枚描述符偏移 \
{FIRST_SECTION_OFFSET}"
            ));
            break;
        };
        if next_rel <= rel {
            scan.errors.push(format!(
                "节段 `{section_type}` 的 next 偏移 {next_offset} 指向自身或之前，节段链无法遍历"
            ));
            break;
        }
        if next_rel.saturating_add(SECTION_DESCRIPTOR_SIZE) > window_len {
            scan.chain_limited = true;
            scan.warnings.push(format!(
                "下一枚节段描述符偏移 {next_offset} 超出有界读取窗口，未继续遍历"
            ));
            break;
        }
        rel = next_rel;
        if scan.sections.len() >= MAX_SECTIONS {
            hit_section_cap = true;
        }
    }

    if hit_section_cap {
        scan.chain_limited = true;
        scan.warnings.push(format!(
            "节段链达到单次解析上限 {MAX_SECTIONS} 枚描述符，未继续遍历"
        ));
    }
    scan
}

/// 从窗口内截取 volume 节段内容（最多 1052 字节）。
///
/// 内容完全不在窗口内时返回空内容（由 `volume_info` 记录为候选值 null，
/// 避免把“窗口截断”误报成“没有 volume 节段”）。
fn read_volume_body(
    section: &SectionDescriptor,
    window: &[u8],
    rel: u64,
    window_len: u64,
) -> Option<(SectionDescriptor, Vec<u8>)> {
    let content_start = rel.saturating_add(SECTION_DESCRIPTOR_SIZE);
    let available = window_len.saturating_sub(content_start);
    let want = section
        .body_length
        .min(EWF1_VOLUME_BODY_SIZE)
        .min(available);
    let start = content_start as usize;
    let end = start.saturating_add(want as usize);
    if end > window.len() {
        return Some((section.clone(), Vec::new()));
    }
    Some((section.clone(), window[start..end].to_vec()))
}

/// 节段类型名（最多 16 字节，遇 0 截断）。
pub fn descriptor_type(descriptor: &[u8]) -> String {
    let field = descriptor.get(..16).unwrap_or(descriptor);
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    field[..end]
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

/// 部分签名匹配：返回偏移 0 起已匹配的签名字节数（至少 3 才返回）。
pub fn partial_signature_match(head: &[u8]) -> Option<usize> {
    let mut matched = 0;
    while matched < head.len() && matched < SIGNATURE.len() && head[matched] == SIGNATURE[matched] {
        matched += 1;
    }
    (matched >= 3).then_some(matched)
}

/// 卷头候选值。所有数值保持镜像原始精度与原始单位，不猜测单位。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeInfo {
    pub section_type: Option<String>,
    pub section_offset: Option<u64>,
    pub media_type: Option<u8>,
    pub number_of_chunks: Option<u64>,
    pub sectors_per_chunk: Option<u64>,
    pub sector_size: Option<u64>,
    pub sector_count: Option<u64>,
    /// volume 节段字节 36 的 media_flags（1 字节，原样记录）。
    pub media_flags: Option<u8>,
    /// volume 节段字节 52 的 compression_level（0=无压缩、1=fast/good、2=best）。
    pub compression_level: Option<u8>,
    /// `number_of_sectors × bytes_per_sector`，仅在两个原始字段都存在时给出。
    pub media_size_bytes: Option<u64>,
    /// compression_level 的文本解释；字段缺失时为 null。
    pub compression: Option<String>,
    pub checksum_ok: Option<bool>,
    pub notes: Vec<String>,
}

/// 仅对 EWF1 解析 volume 节段；EWF2/Ex01、disk 与缺失节段一律置 null 并写 notes。
pub fn volume_info(
    format: Option<EwfFormat>,
    section: Option<&SectionDescriptor>,
    body: &[u8],
) -> VolumeInfo {
    let mut info = VolumeInfo::default();
    match format {
        Some(EwfFormat::Ewf1) => {}
        Some(other) => {
            info.notes.push(format!(
                "{} 的 v2 节段/卷节段布局不在本次可核实范围，卷头候选值置 null\
（仅记录 32 字节文件头字段）",
                other.as_str()
            ));
            return info;
        }
        None => {
            info.notes
                .push("格式未识别（非 EWF1），卷头候选值置 null".to_string());
            return info;
        }
    }
    let Some(section) = section else {
        info.notes
            .push("文件头之后的有界窗口内没有找到 volume 节段，卷头候选值置 null".to_string());
        return info;
    };
    info.section_type = Some(section.section_type.clone());
    info.section_offset = Some(section.offset);
    let kind = section.section_type.to_ascii_lowercase();
    if kind == "disk" {
        info.notes.push(
            "EWF1 标准节段中没有 disk；disk 属于 EWF2/Ex01 布局，本插件不解析 disk 候选值"
                .to_string(),
        );
        return info;
    }
    if kind != "volume" {
        info.notes.push(format!(
            "节段 `{}` 不是 volume，卷头候选值置 null",
            section.section_type
        ));
        return info;
    }
    if body.is_empty() {
        info.notes
            .push("volume 节段内容为空或超出有界读取窗口，卷头候选值置 null".to_string());
        return info;
    }

    // 公开 EWF1 volume 结构：media_type(0)、number_of_chunks(4..8)、
    // sectors_per_chunk(8..12)、bytes_per_sector(12..16)、number_of_sectors(16..24)、
    // CHS(24..36)、media_flags(36)、compression_level(52)，尾部 1048..1052 为 adler32。
    info.media_type = body.first().copied();
    info.number_of_chunks = le_u32_at(body, 4).map(u64::from);
    info.sectors_per_chunk = le_u32_at(body, 8).map(u64::from);
    info.sector_size = le_u32_at(body, 12).map(u64::from);
    info.sector_count = le_u64_at(body, 16);
    info.media_flags = body.get(36).copied();
    info.compression_level = body.get(52).copied();
    info.compression = info.compression_level.map(|level| match level {
        0x00 => "none (0x00)".to_string(),
        0x01 => "fast/good (0x01)".to_string(),
        0x02 => "best (0x02)".to_string(),
        other => format!("unknown compression level (0x{other:02x})"),
    });

    if body.len() < EWF1_VOLUME_BODY_SIZE as usize {
        info.notes.push(format!(
            "volume 节段只读到 {} 字节（完整长度 1052），缺失字段与尾部校验置 null",
            body.len()
        ));
    } else {
        let stored = le_u32_at(body, 1048).unwrap_or(0);
        let computed = adler32(&body[..1048]);
        info.checksum_ok = Some(stored == computed);
        if stored == computed {
            info.notes
                .push(format!("volume 节段 adler32 自检通过（{computed:#010x}）"));
        } else {
            info.notes.push(format!(
                "volume 节段 adler32 不一致：记录 {stored:#010x}，本地 {computed:#010x}"
            ));
        }
    }

    match info.compression_level {
        Some(level @ 0x00..=0x02) => info.notes.push(format!(
            "compression_level 0x{level:02x} 按 libewf 公开结构解释为 {}；\
本插件不读取 header 节段的压缩数据，未做解压验证",
            info.compression.as_deref().unwrap_or("unknown")
        )),
        Some(level) => info.notes.push(format!(
            "compression_level 0x{level:02x} 不在 libewf 公开取值（0x00/0x01/0x02）内，\
原样记录为 unknown"
        )),
        None => info
            .notes
            .push("volume 节段不足 53 字节，compression_level 置 null".to_string()),
    }

    match (info.sector_count, info.sector_size) {
        (Some(count), Some(size)) => {
            info.media_size_bytes = Some(count.saturating_mul(size));
            info.notes.push(
                "media_size_bytes 由 number_of_sectors × bytes_per_sector 直接相乘得到\
（推导值，非镜像记录字段）"
                    .to_string(),
            );
        }
        _ => {
            info.notes.push(
                "number_of_sectors 或 bytes_per_sector 缺失，media_size_bytes 置 null".to_string(),
            );
        }
    }
    info
}

/// 一行段的完整解析结果（对应需求里的“每段”输出字段）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRecord {
    pub path: String,
    pub file_size: u64,
    pub signature_ok: bool,
    pub signature_len: Option<usize>,
    pub format: Option<EwfFormat>,
    pub format_kind: Option<&'static str>,
    pub format_id: Option<u8>,
    pub fields_start: Option<u8>,
    pub fields_end: Option<[u8; 2]>,
    pub major_version: Option<u8>,
    pub minor_version: Option<u8>,
    pub compression_method: Option<u16>,
    pub set_identifier: Option<String>,
    pub segment_number: Option<u64>,
    pub extension_number: Option<u64>,
    pub extension_number_match: Option<bool>,
    pub header_length: Option<u64>,
    pub header_offset: u64,
    pub header_end: u64,
    pub header_sha256: Option<String>,
    pub header_hex: String,
    pub header_truncated: bool,
    pub section_offset: Option<u64>,
    pub section_type: Option<String>,
    pub section_next_offset: Option<u64>,
    pub section_fits: bool,
    pub section_count: usize,
    pub section_chain_limited: bool,
    pub contains_table_section: bool,
    pub done_section_present: bool,
    pub volume: VolumeInfo,
    pub segment_count_contiguous: Option<u64>,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
    pub warnings: Vec<String>,
}

impl SegmentRecord {
    fn blank(name: &str, file_size: u64, extension_number: Option<u64>) -> Self {
        Self {
            path: name.to_string(),
            file_size,
            signature_ok: false,
            signature_len: None,
            format: None,
            format_kind: None,
            format_id: None,
            fields_start: None,
            fields_end: None,
            major_version: None,
            minor_version: None,
            compression_method: None,
            set_identifier: None,
            segment_number: None,
            extension_number,
            extension_number_match: None,
            header_length: None,
            header_offset: 0,
            header_end: 0,
            header_sha256: None,
            header_hex: String::new(),
            header_truncated: false,
            section_offset: None,
            section_type: None,
            section_next_offset: None,
            section_fits: false,
            section_count: 0,
            section_chain_limited: false,
            contains_table_section: false,
            done_section_present: false,
            volume: VolumeInfo::default(),
            segment_count_contiguous: None,
            errors: Vec::new(),
            limitations: standard_limitations(),
            warnings: Vec::new(),
        }
    }

    fn fill_header(&mut self, header: &FileHeader, head: &[u8]) {
        self.signature_ok = true;
        self.signature_len = Some(header.signature_len);
        self.format = header.format;
        self.format_kind = header.format.map(EwfFormat::kind);
        self.format_id = header.format_id;
        self.fields_start = header.fields_start;
        self.fields_end = header.fields_end;
        self.major_version = header.major_version;
        self.minor_version = header.minor_version;
        self.compression_method = header.compression_method;
        self.set_identifier = header.set_identifier.clone();
        self.segment_number = header.segment_number;
        self.header_offset = header.layout.header_offset;
        self.header_end = header.layout.header_end;
        self.errors.extend(header.errors.iter().cloned());
        self.warnings.extend(header.warnings.iter().cloned());

        let readonly_header = header.layout.header_size.min(head.len() as u64);
        self.header_truncated = header.layout.header_end < header.layout.header_size
            || readonly_header < header.layout.header_size;
        if self.header_truncated {
            self.errors.push(format!(
                "文件头被截断：需要 {} 字节，实际可读 {} 字节（文件长度 {}）",
                header.layout.header_size,
                readonly_header.min(self.file_size),
                self.file_size
            ));
        }

        let header_len = (header.layout.header_end as usize).min(head.len());
        self.header_hex = hex_lower(&head[..header_len.min(HEADER_HEX_CAP)]);
        if header_len > 0 && header_len == header.layout.header_size as usize {
            let digest = Sha256::digest(&head[..header_len]);
            self.header_sha256 = Some(hex_lower(&digest));
        }
    }

    fn check_extension(&mut self, name: &str) {
        if let Some(extension) = self.extension_number {
            match self.segment_number {
                Some(number) => {
                    let matched = number == extension;
                    self.extension_number_match = Some(matched);
                    if !matched {
                        self.errors.push(format!(
                            "段号不一致：文件头段号 {number}，文件名扩展名序号 {extension}"
                        ));
                    }
                }
                None => self
                    .errors
                    .push("段号字段缺失，无法与扩展名序号比对".to_string()),
            }
        } else {
            self.limitations.push(format!(
                "文件扩展名不是可识别的 EWF 段扩展名（E01../Ex01），无法做扩展名序号比对：{}",
                self.path
            ));
        }
        if extension_is_ex01(name) && self.format == Some(EwfFormat::Ewf1) {
            self.errors.push(
                "扩展名为 Ex01，但文件头是 EWF1（fields_start=0x01）布局；v2 布局才属于 Ex01"
                    .to_string(),
            );
        }
    }
}

/// 解析入口：调用方按偏移读取 `head`（文件起始，建议 512 字节）与
/// `sections`（从 [`FIRST_SECTION_OFFSET`] 开始的有界窗口，建议 64 KiB）。
///
/// 返回值不含宿主依赖；所有读取都经过长度检查，不会 panic。
pub fn parse_segment(name: &str, file_size: u64, head: &[u8], sections: &[u8]) -> SegmentRecord {
    let extension_number = extension_number(name);
    let mut record = SegmentRecord::blank(name, file_size, extension_number);

    if file_size == 0 {
        record
            .errors
            .push("文件长度为 0，无法读取 EVF 签名".to_string());
        record
            .limitations
            .push("空文件：签名、段号与文件头都无法解析".to_string());
        return record;
    }

    let Some(header) = parse_file_header(name, head, file_size) else {
        match partial_signature_match(head) {
            Some(matched) => {
                record.errors.push(format!(
                    "EVF 签名不完整：偏移 0 处只匹配到 {matched}/8 字节签名 {}",
                    hex_lower(&SIGNATURE[..matched])
                ));
                record.limitations.push(format!(
                    "文件含部分签名字节（{matched}/8），不构成 EWF 段文件；格式、段号与文件头均无法解析"
                ));
            }
            None => {
                record.errors.push(
                    "未找到 EVF 签名（EVF\\x09\\x0d\\x0a\\xff\\x00），不是 EWF 段文件".to_string(),
                );
                record
                    .limitations
                    .push("非 EWF 文件：未做任何格式猜测，也未读取卷头".to_string());
            }
        }
        if extension_number.is_some() {
            record
                .errors
                .push("扩展名像 EWF 段文件，但文件头签名无效".to_string());
        }
        return record;
    };

    record.fill_header(&header, head);
    record.check_extension(name);

    match record.format {
        Some(EwfFormat::Ewf1) => {
            record.section_offset = Some(FIRST_SECTION_OFFSET);
            let scan = scan_sections(sections, file_size);
            record.section_count = scan.sections.len();
            record.contains_table_section = scan.contains_table;
            record.done_section_present = scan.done_present;
            record.section_chain_limited = scan.chain_limited;
            record.errors.extend(scan.errors.iter().cloned());
            record.warnings.extend(scan.warnings.iter().cloned());
            record.section_fits = header.layout.section_fits && !scan.sections.is_empty();

            if let Some(first) = scan.sections.first() {
                record.section_type = Some(first.section_type.clone());
                record.section_next_offset = Some(first.next_offset);
                record.header_length = Some(first.length);
            }

            let (volume_section, volume_body) = match &scan.volume {
                Some((section, body)) => (Some(section), body.as_slice()),
                None => (scan.disk.as_ref(), &[][..]),
            };
            record.volume = volume_info(record.format, volume_section, volume_body);
            if scan.volume.is_none() {
                record.limitations.push(format!(
                    "在文件头之后 {SECTION_WINDOW_CAP} 字节窗口内未找到 EWF1 volume 节段，\
卷头候选值置 null"
                ));
            }
            if scan.chain_limited {
                record.limitations.push(
                    "节段链超出有界读取窗口或达到单次解析上限，未继续遍历；\
table/done 标记与 volume 查找可能不完整"
                        .to_string(),
                );
            }
        }
        Some(other) => {
            // EWF2/Ex01：只记录 32 字节文件头，明确不解析 v2 节段布局。
            record.limitations.push(format!(
                "检测到 {} 文件头（32 字节 v2 布局；v2 文件头本身不区分 EWF2 与 Ex01，\
格式名按扩展名判定）；其后使用 v2 节段描述符与 volume/disk 布局，本插件未实现，\
节段与卷头候选值全部置 null",
                other.as_str()
            ));
            record.volume = volume_info(record.format, None, &[]);
            record.section_fits = false;
            record.section_offset = None;
        }
        None => {
            record.volume = volume_info(None, None, &[]);
            record.section_fits = false;
        }
    }

    record.segment_count_contiguous = None;
    record.limitations.push(format!(
        "段文件 `{}` 单独分析：segmentCountContiguous 记为 null，连续段数需由上层把同名的 \
E01/E02…/Ex01 逐个调度后比对段号",
        record.path
    ));
    record
}

/// 小写 hex。
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

/// adler32（用于节段描述符/volume 节段的自检展示，不做强制校验）。
pub fn adler32(bytes: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// 小端 u16；越界返回 None。
pub fn le_u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// 小端 u32；越界返回 None。
pub fn le_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(slice);
    Some(u32::from_le_bytes(buffer))
}

/// 小端 u64；越界返回 None。
pub fn le_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(slice);
    Some(u64::from_le_bytes(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_numbers_cover_encase_and_ex01_and_reject_others() {
        assert_eq!(extension_number("disk.E01"), Some(1));
        assert_eq!(extension_number("disk.e02"), Some(2));
        assert_eq!(extension_number("C:\\cases\\disk.E10"), Some(10));
        assert_eq!(extension_number("disk.Ex01"), Some(1));
        assert_eq!(extension_number("disk.ex10"), Some(10));
        assert_eq!(extension_number("disk.E00"), None);
        assert_eq!(extension_number("disk.E100"), None);
        assert_eq!(extension_number("disk.txt"), None);
        assert_eq!(extension_number("disk"), None);
        assert!(extension_is_ex01("x.Ex01"));
        assert!(!extension_is_ex01("x.E01"));
    }

    #[test]
    fn header_layout_is_13_for_ewf1_and_truncates_short_files() {
        let long = header_layout(1_470, EWF1_FILE_HEADER_SIZE);
        assert_eq!(long.header_end, 13);
        assert_eq!(long.section_offset, 13);
        assert!(long.section_fits);
        let short = header_layout(10, EWF1_FILE_HEADER_SIZE);
        assert_eq!(short.header_end, 10);
        assert!(!short.section_fits);
        let v2 = header_layout(1_470, EWF2_FILE_HEADER_SIZE);
        assert_eq!(v2.header_end, 32);
        assert_eq!(v2.section_offset, 32);
    }

    #[test]
    fn descriptor_type_stops_at_nul_and_escapes_binary() {
        let mut descriptor = [0u8; 76];
        descriptor[..6].copy_from_slice(b"volume");
        assert_eq!(descriptor_type(&descriptor), "volume");
        let mut binary = [0xffu8; 76];
        binary[16] = 0;
        assert_eq!(descriptor_type(&binary), "................");
        assert_eq!(descriptor_type(&[]), "");
    }

    #[test]
    fn little_endian_helpers_reject_short_slices() {
        assert_eq!(le_u16_at(&[0x01, 0x00], 0), Some(1));
        assert_eq!(le_u16_at(&[0x01], 0), None);
        assert_eq!(le_u32_at(&[0x40, 0x00, 0x00, 0x00], 0), Some(64));
        assert_eq!(le_u32_at(&[0x40, 0x00, 0x00], 0), None);
        assert_eq!(le_u64_at(&2048u64.to_le_bytes(), 0), Some(2048));
        assert_eq!(le_u64_at(&[0u8; 7], 0), None);
        assert_eq!(le_u16_at(&[0u8; 4], 3), None);
    }

    #[test]
    fn adler32_matches_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"abc"), 0x024d0127);
    }

    #[test]
    fn missing_volume_and_disk_are_reported_without_values() {
        let missing = volume_info(Some(EwfFormat::Ewf1), None, &[]);
        assert!(missing.sectors_per_chunk.is_none());
        assert!(missing.notes.iter().any(|note| note.contains("没有找到")));

        let disk = SectionDescriptor {
            offset: 13,
            section_type: "disk".to_string(),
            next_offset: 0,
            length: SECTION_DESCRIPTOR_SIZE,
            body_offset: 13 + SECTION_DESCRIPTOR_SIZE,
            body_length: 0,
            checksum_ok: None,
        };
        let unsupported = volume_info(Some(EwfFormat::Ewf1), Some(&disk), &[]);
        assert!(unsupported.sectors_per_chunk.is_none());
        assert!(unsupported.notes.iter().any(|note| note.contains("disk")));
    }

    #[test]
    fn partial_signature_counts_only_leading_bytes() {
        assert_eq!(partial_signature_match(b"EVF"), Some(3));
        assert_eq!(partial_signature_match(b"EVF\x09\x0d"), Some(5));
        assert_eq!(partial_signature_match(b"PK\x03\x04"), None);
    }
}
