//! 只读 ZIP 容器读取（xlsx / xlsm 是 ZIP 包）。
//!
//! 设计要点：
//! - 只接受 STORED(0) 与 DEFLATE(8) 两种压缩方式，其他方式（zstd、bzip2、加密）
//!   明确报错，不静默跳过；
//! - 读条目时按“有界分块读取 + 解压后长度上限 + CRC32 校验”，不把整包解压进内存
//!   （zip 炸弹防护）；
//! - 拒绝 `..` / 绝对路径条目（zip-slip）；插件也不会把任何条目写回文件系统。

use flate2::read::DeflateDecoder;
use std::io::Read;

use crate::error::DedupError;

const EOCD_SIG: u32 = 0x0605_4b50;
const EOCD64_LOCATOR_SIG: u32 = 0x0706_4b50;
const EOCD64_SIG: u32 = 0x0606_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;
const EOCD_LEN: usize = 22;
const EOCD64_LOCATOR_LEN: usize = 20;
const EOCD64_LEN: usize = 56;
const CENTRAL_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
const MAX_COMMENT: usize = 0xffff;
/// 每次从 Blob 读取的压缩数据窗口。
pub const STREAM_CHUNK: usize = 64 * 1024;
/// 中央目录结束记录的预扫描窗口（规范允许最多 16 字节注释探测）。
pub const EOCD_TAIL_WINDOW: usize = 64 * 1024;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// 中央目录一项。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipEntry {
    /// 包内路径，已把 `\` 统一为 `/`。
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_offset: u64,
}

impl ZipEntry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x0001 != 0
    }
}

/// 压缩数据的只读来源：宿主 `File`/`EvidenceVolume` 的有界读取，或测试用的内存切片。
pub trait Blob {
    fn len(&self) -> u64;
    /// 读取 `[offset, offset+len)`；允许在数据末尾被截短。
    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, DedupError>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Blob for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, DedupError> {
        let start = usize::try_from(offset)
            .map_err(|_| DedupError::new("zip.offset", "偏移超出可寻址范围"))?
            .min(<[u8]>::len(self));
        let end = start.saturating_add(len).min(<[u8]>::len(self));
        Ok(self[start..end].to_vec())
    }
}

impl Blob for Vec<u8> {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, DedupError> {
        self.as_slice().read_at(offset, len)
    }
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// 签名 `PK\x03\x04`（普通包）/ `PK\x05\x06`（空包）/ `PK\x07\x08`（spanned 片段）。
fn looks_like_zip(head: &[u8]) -> bool {
    matches!(
        head.get(..4).map(|b| le_u32(b, 0)),
        Some(Some(LOCAL_SIG)) | Some(Some(EOCD_SIG)) | Some(Some(0x0807_4b50))
    )
}

/// 包内名称统一分隔符并拒绝向上越级、绝对路径、控制字符；不可安全表示时返回 `None`。
pub fn sanitize_entry_name(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 4096 || raw.chars().any(char::is_control) {
        return None;
    }
    let unified = raw.replace('\\', "/");
    if unified.starts_with('/') {
        return None;
    }
    if unified.split('/').any(|segment| segment == "..") {
        return None;
    }
    Some(unified)
}

/// 由内存字节解析出 ZIP 包索引（不含目录条目）。
pub fn read_entries(data: &[u8]) -> Result<Vec<ZipEntry>, DedupError> {
    read_entries_from(data)
}

/// 由任意 [`Blob`] 解析出 ZIP 包索引（不含目录条目）。
pub fn read_entries_from<B: Blob + ?Sized>(blob: &B) -> Result<Vec<ZipEntry>, DedupError> {
    let total = blob.len();
    if total < EOCD_LEN as u64 {
        return Err(DedupError::new(
            "zip.too_short",
            format!("长度 {total} 小于 ZIP 最小长度 {EOCD_LEN}"),
        ));
    }
    let head = blob.read_at(0, 4)?;
    if !looks_like_zip(&head) {
        return Err(DedupError::new(
            "zip.not_zip",
            "文件头不是 PK\\x03\\x04 / PK\\x05\\x06 / PK\\x07\\x08",
        ));
    }

    // 1) 从尾部搜索 EOCD：先看 64 KiB 窗口，再按规范上限（注释 65535 字节）回退。
    let tail_len = (MAX_COMMENT as u64 + EOCD_LEN as u64).min(total) as usize;
    let tail_start = total - tail_len as u64;
    let tail = blob.read_at(tail_start, tail_len)?;
    let Some(eocd_offset) = find_eocd(&tail) else {
        return Err(DedupError::new(
            "zip.not_zip",
            "未找到中央目录结束记录（可能被截断或不是 ZIP 包）",
        ));
    };
    let eocd = &tail[eocd_offset..];
    // 偏移 10 是“中央目录条目总数”，规范定义为 2 字节；若按 4 字节读取会把
    // 紧随其后的 CD 大小并入计数，导致所有正常包被误判为超限。
    let mut entry_total = le_u16(eocd, 10).unwrap_or(0) as u64;
    let mut cd_size = le_u32(eocd, 12).unwrap_or(0) as u64;
    let mut cd_offset = le_u32(eocd, 16).unwrap_or(0) as u64;
    let absolute_eocd = tail_start + eocd_offset as u64;

    // 2) ZIP64：字段取满或存在 ZIP64 结束记录定位器时改读 ZIP64 结束记录。
    if absolute_eocd >= EOCD64_LOCATOR_LEN as u64 {
        let locator_at = absolute_eocd - EOCD64_LOCATOR_LEN as u64;
        let locator = blob.read_at(locator_at, EOCD64_LOCATOR_LEN)?;
        if le_u32(&locator, 0) == Some(EOCD64_LOCATOR_SIG) {
            let eocd64_at = le_u64(&locator, 8).unwrap_or(u64::MAX);
            if eocd64_at.saturating_add(EOCD64_LEN as u64) <= total {
                let record = blob.read_at(eocd64_at, EOCD64_LEN)?;
                if le_u32(&record, 0) == Some(EOCD64_SIG) {
                    entry_total = le_u64(&record, 32).unwrap_or(entry_total);
                    cd_size = le_u64(&record, 40).unwrap_or(cd_size);
                    cd_offset = le_u64(&record, 48).unwrap_or(cd_offset);
                }
            }
        }
    }

    // 3) 中央目录位置与条目数上限。
    if cd_offset.saturating_add(cd_size) > total {
        return Err(DedupError::new(
            "zip.corrupt",
            format!("中央目录越界：offset={cd_offset} size={cd_size} total={total}"),
        ));
    }
    if entry_total > crate::limits::MAX_ZIP_ENTRIES {
        return Err(DedupError::resource(format!(
            "ZIP 条目数 {entry_total} 超过上限 {}",
            crate::limits::MAX_ZIP_ENTRIES
        )));
    }

    // 4) 流式遍历中央目录。
    let mut entries = Vec::new();
    let mut position = cd_offset;
    let cd_end = cd_offset + cd_size;
    while position + CENTRAL_LEN as u64 <= cd_end {
        let header = blob.read_at(position, CENTRAL_LEN)?;
        if header.len() < CENTRAL_LEN || le_u32(&header, 0) != Some(CENTRAL_SIG) {
            return Err(DedupError::new(
                "zip.corrupt",
                format!("中央目录项签名错误 @{position}"),
            ));
        }
        let name_len = le_u16(&header, 28).unwrap_or(0) as usize;
        let extra_len = le_u16(&header, 30).unwrap_or(0) as usize;
        let comment_len = le_u16(&header, 32).unwrap_or(0) as usize;
        let variable = blob.read_at(position + CENTRAL_LEN as u64, name_len + extra_len)?;
        let raw_name = if variable.len() >= name_len {
            String::from_utf8_lossy(&variable[..name_len]).into_owned()
        } else {
            String::new()
        };
        let mut entry = ZipEntry {
            name: raw_name,
            method: le_u16(&header, 10).unwrap_or(0),
            flags: le_u16(&header, 8).unwrap_or(0),
            crc32: le_u32(&header, 16).unwrap_or(0),
            compressed_size: le_u32(&header, 20).unwrap_or(0) as u64,
            uncompressed_size: le_u32(&header, 24).unwrap_or(0) as u64,
            local_offset: le_u32(&header, 42).unwrap_or(0) as u64,
        };
        apply_zip64_extra(variable.get(name_len..).unwrap_or(&[]), &mut entry);
        if let Some(name) = sanitize_entry_name(&entry.name) {
            entry.name = name;
            if !entry.is_dir() {
                entries.push(entry);
            }
        } else {
            return Err(DedupError::new(
                "zip.unsafe_name",
                "包内存在不可安全表示的路径条目，已拒绝整包",
            ));
        }
        position = position
            .saturating_add(CENTRAL_LEN as u64)
            .saturating_add(name_len as u64)
            .saturating_add(extra_len as u64)
            .saturating_add(comment_len as u64);
    }
    Ok(entries)
}

fn find_eocd(tail: &[u8]) -> Option<usize> {
    let mut limit = tail.len();
    while limit >= EOCD_LEN {
        let found = tail[..limit]
            .windows(4)
            .rposition(|window| le_u32(window, 0) == Some(EOCD_SIG))?;
        let comment_len = le_u16(tail, found + 20).unwrap_or(0) as usize;
        if found + EOCD_LEN + comment_len <= tail.len() {
            return Some(found);
        }
        limit = found;
    }
    None
}

fn apply_zip64_extra(extra: &[u8], entry: &mut ZipEntry) {
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let id = le_u16(extra, at).unwrap_or(0);
        let size = le_u16(extra, at + 2).unwrap_or(0) as usize;
        let body_start = at + 4;
        let Some(body) = extra.get(body_start..body_start + size) else {
            return;
        };
        if id == 0x0001 {
            let mut cursor = 0usize;
            if entry.uncompressed_size == 0xffff_ffff {
                if let Some(value) = le_u64(body, cursor) {
                    entry.uncompressed_size = value;
                    cursor += 8;
                }
            }
            if entry.compressed_size == 0xffff_ffff {
                if let Some(value) = le_u64(body, cursor) {
                    entry.compressed_size = value;
                    cursor += 8;
                }
            }
            if entry.local_offset == 0xffff_ffff {
                if let Some(value) = le_u64(body, cursor) {
                    entry.local_offset = value;
                }
            }
            return;
        }
        at = body_start + size;
    }
}

/// 流式解压一个条目：分块读取压入数据、边解压边累计，超过 `max_bytes` 立即失败，
/// 结束后校验解压长度与 CRC32。
pub fn read_entry(
    blob: &(impl Blob + ?Sized),
    entry: &ZipEntry,
    max_bytes: u64,
) -> Result<Vec<u8>, DedupError> {
    let mut output = Vec::new();
    let limit = max_bytes.saturating_add(1);
    read_entry_into(blob, entry, limit, |chunk| {
        output.extend_from_slice(chunk);
        Ok(())
    })?;
    if output.len() as u64 > max_bytes {
        return Err(DedupError::resource(format!(
            "条目 {} 解压后超过上限 {max_bytes} 字节",
            entry.name
        )));
    }
    verify_entry(entry, &output)?;
    Ok(output)
}

fn verify_entry(entry: &ZipEntry, output: &[u8]) -> Result<(), DedupError> {
    if output.len() as u64 != entry.uncompressed_size {
        return Err(DedupError::new(
            "zip.corrupt",
            format!(
                "条目 {} 解压长度 {} 与目录声明 {} 不符",
                entry.name,
                output.len(),
                entry.uncompressed_size
            ),
        ));
    }
    let actual = crc32fast::hash(output);
    if actual != entry.crc32 {
        return Err(DedupError::new(
            "zip.crc",
            format!(
                "条目 {} CRC32 {actual:08x} 与目录声明 {:08x} 不符（数据损坏）",
                entry.name, entry.crc32
            ),
        ));
    }
    Ok(())
}

/// 把 [`Blob`] 的一个区间适配成 `std::io::Read`，供 DEFLATE 单流式解压使用。
///
/// 压缩数据不能被任意切成独立的 deflate 流（块边界只在压缩流内部有效），
/// 所以这里只提供一个按需拉动压缩字节的读取器，而不是每块新建解码器。
struct RangeReader<'a, B: Blob + ?Sized> {
    blob: &'a B,
    position: u64,
    end: u64,
}

impl<B: Blob + ?Sized> Read for RangeReader<'_, B> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.position >= self.end {
            return Ok(0);
        }
        let want = (self.end - self.position)
            .min(buffer.len() as u64)
            .min(STREAM_CHUNK as u64) as usize;
        let chunk = self
            .blob
            .read_at(self.position, want)
            .map_err(|error| std::io::Error::other(format!("读取压缩数据失败：{error}")))?;
        let copied = chunk.len().min(buffer.len());
        buffer[..copied].copy_from_slice(&chunk[..copied]);
        self.position += copied as u64;
        Ok(copied)
    }
}

/// 逐块解压，把解压后的数据交给 `sink`；`max_bytes` 是解压后字节上限（含）。
pub fn read_entry_into(
    blob: &(impl Blob + ?Sized),
    entry: &ZipEntry,
    max_bytes: u64,
    mut sink: impl FnMut(&[u8]) -> Result<(), DedupError>,
) -> Result<(), DedupError> {
    if entry.is_encrypted() {
        return Err(DedupError::new(
            "zip.encrypted",
            format!("条目 {} 被加密，按不执行/不绕过的原则跳过分析", entry.name),
        ));
    }
    let local = blob.read_at(entry.local_offset, LOCAL_LEN)?;
    if local.len() < LOCAL_LEN || le_u32(&local, 0) != Some(LOCAL_SIG) {
        return Err(DedupError::new(
            "zip.corrupt",
            format!("条目 {} 本地头签名错误", entry.name),
        ));
    }
    let local_name_len = le_u16(&local, 26).unwrap_or(0) as usize;
    let local_extra_len = le_u16(&local, 28).unwrap_or(0) as usize;
    let data_start = entry
        .local_offset
        .saturating_add(LOCAL_LEN as u64)
        .saturating_add(local_name_len as u64)
        .saturating_add(local_extra_len as u64);
    let data_end = data_start.saturating_add(entry.compressed_size);
    if data_end > blob.len() {
        return Err(DedupError::new(
            "zip.short_read",
            format!("条目 {} 压缩数据被截断", entry.name),
        ));
    }

    match entry.method {
        METHOD_STORED => {
            let mut produced_total = 0u64;
            let mut position = data_start;
            while position < data_end {
                let want = (data_end - position).min(STREAM_CHUNK as u64) as usize;
                let chunk = blob.read_at(position, want)?;
                if chunk.is_empty() {
                    return Err(DedupError::new(
                        "zip.short_read",
                        format!("条目 {} 压缩数据读取提前结束", entry.name),
                    ));
                }
                position += chunk.len() as u64;
                produced_total = produced_total.saturating_add(chunk.len() as u64);
                if produced_total > max_bytes {
                    return Err(DedupError::resource(format!(
                        "条目 {} 解压后超过上限 {max_bytes} 字节",
                        entry.name
                    )));
                }
                sink(&chunk)?;
            }
        }
        METHOD_DEFLATE => {
            let source = RangeReader {
                blob,
                position: data_start,
                end: data_end,
            };
            // 整个入口是一个 deflate 流：只创建一次解码器，按需从 Blob 拉取压缩字节。
            let mut decoder = DeflateDecoder::new(source);
            let mut buffer = [0u8; 32 * 1024];
            let mut produced_total = 0u64;
            loop {
                let read = decoder.read(&mut buffer).map_err(|error| {
                    DedupError::new(
                        "zip.deflate",
                        format!("条目 {} 解压失败：{error}", entry.name),
                    )
                })?;
                if read == 0 {
                    break;
                }
                produced_total = produced_total.saturating_add(read as u64);
                if produced_total > max_bytes {
                    return Err(DedupError::resource(format!(
                        "条目 {} 解压后超过上限 {max_bytes} 字节",
                        entry.name
                    )));
                }
                sink(&buffer[..read])?;
            }
        }
        other => {
            return Err(DedupError::new(
                "zip.method",
                format!("条目 {} 使用了不支持的压缩方式 {other}", entry.name),
            ))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_sanitizing_rejects_traversal_and_absolute_paths() {
        assert_eq!(
            sanitize_entry_name("xl/worksheets/sheet1.xml").as_deref(),
            Some("xl/worksheets/sheet1.xml")
        );
        assert_eq!(
            sanitize_entry_name("xl\\worksheets\\sheet1.xml").as_deref(),
            Some("xl/worksheets/sheet1.xml")
        );
        assert_eq!(sanitize_entry_name("../evil.xml"), None);
        assert_eq!(sanitize_entry_name("/etc/passwd"), None);
        assert_eq!(sanitize_entry_name("xl/../../evil.xml"), None);
        assert_eq!(sanitize_entry_name(""), None);
        assert_eq!(sanitize_entry_name("xl/a\u{0}b.xml"), None);
    }

    #[test]
    fn non_zip_bytes_are_rejected_with_a_reason() {
        let error = read_entries(b"not a zip at all").expect_err("must fail");
        assert_eq!(error.code, "zip.too_short");
        let mut long = vec![0u8; 200];
        long[..4].copy_from_slice(b"PK\x03\x04");
        let error = read_entries(&long).expect_err("no central directory");
        assert_eq!(error.code, "zip.not_zip");
    }

    #[test]
    fn deflate_entries_larger_than_one_chunk_round_trip() {
        // 伪随机内容保证压缩后仍超过 STREAM_CHUNK，覆盖跨块解压路径。
        let mut seed = 0x1234_5678u32;
        let data: Vec<u8> = (0..300_000)
            .map(|_| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (seed >> 24) as u8
            })
            .collect();
        let bytes = crate::fixtures::zip_bytes(
            &[("large.bin".to_owned(), data.clone())],
            crate::fixtures::ZipOptions {
                deflate: true,
                corrupt_crc_entry: None,
            },
        );
        let entries = read_entries(&bytes).expect("central directory");
        assert!(entries[0].compressed_size > STREAM_CHUNK as u64);
        let output = read_entry(&bytes, &entries[0], 1_000_000).expect("inflate");
        assert_eq!(output, data);
    }
}
