//! 抓包读取层（首版范围：**classic pcap**）。
//!
//! * 只通过 [`ByteSource`]（`FileSource` / `MemorySource`）按需读取，包载荷
//!   缓冲上限见 [`SCAN_CHUNK`]，大文件不会整份进内存；
//! * 支持 4 种 pcap 魔数（大小端 × 微秒/纳秒）。时间戳 = `ts_sec +
//!   ts_frac/1e6(或 1e9)`。文件头偏移 8 的 32 位字段在 pcap 2.4 里是保留字段
//!   （旧规范写作 `thiszone`，回绕后可能带出无意义的巨大值），**不参与 epoch
//!   换算**：记录时间戳本身就按 Unix epoch 记录；该值只作为元数据原样记录，
//!   便于复核；
//! * 每条记录都记录是否为乱序（时间戳小于此前最大值）；乱序记录保留原始
//!   时间戳值，只在上层统计前排序；
//! * 截断、结构损坏、只有文件头没有包、未知魔数都**报错返回**，不静默给空结果。
//!
//! 未覆盖：pcapng（Section/Interface/Enhanced Packet Block、`if_tsresol`、
//! `if_tsoffset`）。pcapng 文件会得到明确的 `unsupported_capture_format`
//! 错误码，而不是被当成 pcap 解析。

use crate::error::{
    AnalyzeError, AnalyzeResult, E_CORRUPT_PACKET, E_IO, E_NO_TIMESTAMP, E_TRUNCATED_CAPTURE,
    E_UNSUPPORTED_FORMAT,
};
use crate::options::TimeSource;

/// 单个包记录缓冲上限（一条记录最多这么多字节）。
pub const SCAN_CHUNK: usize = 256 * 1024;

/// 一次读取访问的结果（区分"数据不足"与"宿主错误"）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Chunk {
    /// 读到的字节（可能少于请求，末尾即文件末尾）。
    Data(Vec<u8>),
    /// 到达文件末尾。
    Eof,
    /// 宿主读取失败（取消、资源上限等）。
    Error(String),
}

/// 只读、可随机访问的字节来源。
pub trait ByteSource {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, len: usize) -> Chunk;
}

/// 内存字节（单元测试与合成样例）。
pub struct MemorySource<'a> {
    bytes: &'a [u8],
}

impl<'a> MemorySource<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl ByteSource for MemorySource<'_> {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, len: usize) -> Chunk {
        let Ok(start) = usize::try_from(offset) else {
            return Chunk::Eof;
        };
        if start >= self.bytes.len() {
            return Chunk::Eof;
        }
        let end = start.saturating_add(len).min(self.bytes.len());
        Chunk::Data(self.bytes[start..end].to_vec())
    }
}

/// 通过 SDK `File::read` 读取的只读来源。`read` 为注入的闭包，便于在没有
/// 宿主的环境里对同一解析器做单元测试。
pub struct FileSource<'a> {
    size: u64,
    read: &'a dyn Fn(u64, usize) -> Result<Vec<u8>, String>,
}

impl<'a> FileSource<'a> {
    pub fn new(size: u64, read: &'a dyn Fn(u64, usize) -> Result<Vec<u8>, String>) -> Self {
        Self { size, read }
    }
}

impl ByteSource for FileSource<'_> {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, len: usize) -> Chunk {
        if offset >= self.size {
            return Chunk::Eof;
        }
        let wanted = (len as u64).min(self.size - offset) as usize;
        if wanted == 0 {
            return Chunk::Eof;
        }
        match (self.read)(offset, wanted) {
            Ok(bytes) if bytes.is_empty() => Chunk::Eof,
            Ok(bytes) => Chunk::Data(bytes),
            Err(message) => Chunk::Error(message),
        }
    }
}

/// 读取"必须前 n 字节"的辅助：不足即抛出对应错误码。
#[allow(dead_code)]
fn need(
    source: &dyn ByteSource,
    offset: u64,
    len: usize,
    code: &'static str,
) -> AnalyzeResult<Vec<u8>> {
    match source.read_at(offset, len) {
        Chunk::Data(bytes) if bytes.len() >= len => Ok(bytes),
        Chunk::Data(bytes) => Err(AnalyzeError::new(
            code,
            format!(
                "文件在偏移 {offset} 处提前结束（需要 {len} 字节，实际 {} 字节）",
                bytes.len()
            ),
        )),
        Chunk::Eof => Err(AnalyzeError::new(
            code,
            format!("文件在偏移 {offset} 处提前结束（需要 {len} 字节）"),
        )),
        Chunk::Error(message) => Err(AnalyzeError::new(E_IO, message)),
    }
}

/// 一条解析出的链路层帧（时间戳已换算为 epoch 秒）。
#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    /// 记录在抓包文件中的槽位号（0 起，按文件顺序）。
    pub slot: u64,
    /// 记录起始的文件偏移。
    pub offset: u64,
    /// 时间戳（epoch 秒）。
    pub epoch: f64,
    /// 原始 32 位秒、32 位小数部分。
    pub raw_ts: (u32, u32),
    /// 时间戳来源。
    pub source: TimeSource,
    /// 链路类型（pcap 头里的 network 字段）。
    pub linktype: u32,
    /// 链路载荷（不含填充）。
    pub payload: Vec<u8>,
    /// 是否为乱序记录（原值保留，上层排序）。
    pub out_of_order: bool,
}

/// 抓包级元数据。
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureInfo {
    pub format: &'static str,
    pub linktype: u32,
    /// 时间戳来源。
    pub time_source: TimeSource,
    /// 时间基准描述（如 "pcap.header raw*1/1000000s, reserved_field_ignored"）。
    pub timebase: String,
    /// 文件头偏移 8 的 32 位原始字段（pcap 2.4 保留字段；旧规范写作
    /// `thiszone`）。**仅记录，不参与 epoch 换算**。
    pub reserved_field: u32,
    /// 文件头里的 snaplen。
    pub snaplen: u32,
    /// 是否为纳秒精度魔数。
    pub nanoseconds: bool,
}

impl CaptureInfo {
    pub fn source_label(&self) -> &'static str {
        self.time_source.as_str()
    }
}

/// 一次遍历的统计。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanStats {
    /// 已读取的包记录总数。
    pub records: u64,
    /// 回调给访问者的帧数。
    pub frames: u64,
    /// 乱序帧数。
    pub out_of_order: u64,
}

/// 时间戳换算模型：`epoch = ts_sec + ts_frac / den`（不加任何文件头偏移）。
///
/// 注意 classic pcap 的 `ts_usec/ts_nsec` 是**独立的 32 位字段**，不是
/// `ts_sec` 的低位；绝不能拼成 `(ts_sec << 32) | frac` 再整体除以 1e6。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TsResolution {
    pub den: u64,
    pub source: TimeSource,
}

impl TsResolution {
    /// 由文件头精度（微秒或纳秒魔数）计算。
    pub fn from_header(nanoseconds: bool) -> Self {
        Self {
            den: if nanoseconds { 1_000_000_000 } else { 1_000_000 },
            source: TimeSource::PcapHeader,
        }
    }

    /// 精确换算：秒部分与小数部分分别处理，避免大 epoch 的浮点精度损失。
    pub fn to_epoch(&self, ts_sec: u32, ts_frac: u32) -> f64 {
        f64::from(ts_sec) + f64::from(ts_frac) / self.den as f64
    }

    pub fn describe(&self) -> String {
        format!(
            "{} epoch=ts_sec+ts_frac/{}s, reserved_field_ignored",
            self.source.as_str(),
            self.den
        )
    }
}

/// 帧接收器：解析器每读到一个包记录就回调一次。
pub trait FrameVisitor {
    fn on_frame(&mut self, frame: &Frame) -> AnalyzeResult<()>;
    /// 每 4096 条记录回调一次，让上层检查取消标志。
    fn checkpoint(&mut self) -> AnalyzeResult<()> {
        Ok(())
    }
}

/// 遍历 classic pcap 文件。
pub fn scan(
    source: &dyn ByteSource,
    visitor: &mut dyn FrameVisitor,
) -> AnalyzeResult<(CaptureInfo, ScanStats)> {
    let head = match source.read_at(0, 24) {
        Chunk::Data(bytes) if bytes.len() == 24 => bytes,
        Chunk::Data(bytes) => {
            if bytes.len() >= 4 && bytes[..4] == [0x0A, 0x0D, 0x0D, 0x0A] {
                return Err(pcapng_unsupported());
            }
            return Err(AnalyzeError::new(
                E_UNSUPPORTED_FORMAT,
                format!("文件不足 24 字节的 pcap 文件头（实际 {} 字节）", bytes.len()),
            ));
        }
        Chunk::Eof => {
            return Err(AnalyzeError::new(
                E_UNSUPPORTED_FORMAT,
                "空文件，不是 pcap 抓包",
            ))
        }
        Chunk::Error(message) => return Err(AnalyzeError::new(E_IO, message)),
    };
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if magic == 0x0A0D_0D0A {
        return Err(pcapng_unsupported());
    }
    let (big_endian, nanoseconds) = match magic {
        0xA1B2_C3D4 => (true, false),
        0xD4C3_B2A1 => (false, false),
        0xA1B2_3C4D => (true, true),
        0x4D3C_B2A1 => (false, true),
        _ => {
            return Err(AnalyzeError::new(
                E_UNSUPPORTED_FORMAT,
                format!("未知抓包魔数 0x{magic:08x}：不是 classic pcap"),
            ))
        }
    };
    let read16 = |bytes: &[u8], at: usize| {
        let pair = [bytes[at], bytes[at + 1]];
        if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        }
    };
    let read32 = |bytes: &[u8], at: usize| {
        let quad = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        if big_endian {
            u32::from_be_bytes(quad)
        } else {
            u32::from_le_bytes(quad)
        }
    };
    let version_major = read16(&head, 4);
    let version_minor = read16(&head, 6);
    // 偏移 8 的 32 位字段：pcap 2.4 保留字段（旧文档称 thiszone），
    // 不参与时间换算，只原样记录。
    let reserved_field = read32(&head, 8);
    let snaplen = read32(&head, 16);
    let linktype = read32(&head, 20) & 0x0FFF_FFFF;
    if version_major != 2 {
        return Err(AnalyzeError::new(
            E_UNSUPPORTED_FORMAT,
            format!("未知 pcap 版本 {version_major}.{version_minor}"),
        ));
    }
    let resolution = TsResolution::from_header(nanoseconds);
    let info = CaptureInfo {
        format: "pcap",
        linktype,
        time_source: resolution.source,
        timebase: resolution.describe(),
        reserved_field,
        snaplen,
        nanoseconds,
    };
    let mut stats = ScanStats::default();
    let mut offset: u64 = 24;
    let mut slot: u64 = 0;
    let mut max_epoch = f64::NEG_INFINITY;
    loop {
        if slot % 4096 == 0 {
            visitor.checkpoint()?;
        }
        let record_header = match source.read_at(offset, 16) {
            Chunk::Data(bytes) if bytes.len() == 16 => bytes,
            Chunk::Data(bytes) if !bytes.is_empty() => {
                return Err(AnalyzeError::new(
                    E_TRUNCATED_CAPTURE,
                    format!("包记录头被截断（只有 {} 字节）", bytes.len()),
                )
                .at(slot, offset));
            }
            Chunk::Data(_) | Chunk::Eof => break,
            Chunk::Error(message) => return Err(AnalyzeError::new(E_IO, message)),
        };
        let ts_sec = read32(&record_header, 0);
        let ts_frac = read32(&record_header, 4);
        let incl_len = read32(&record_header, 8);
        let orig_len = read32(&record_header, 12);
        if slot == 0 && ts_sec == 0 && ts_frac == 0 && incl_len == 0 && orig_len == 0 {
            // 全零记录通常是文件头之后被清零/损坏的填充。
            return Err(AnalyzeError::new(
                E_NO_TIMESTAMP,
                "首个包记录全为 0，无法恢复任何合法时间戳",
            )
            .at(slot, offset));
        }
        if incl_len > SCAN_CHUNK as u32 {
            return Err(AnalyzeError::new(
                E_CORRUPT_PACKET,
                format!("包记录 incl_len={incl_len} 超出单条上限 {SCAN_CHUNK}"),
            )
            .at(slot, offset));
        }
        if orig_len < incl_len {
            return Err(AnalyzeError::new(
                E_CORRUPT_PACKET,
                format!("包记录 orig_len={orig_len} < incl_len={incl_len}"),
            )
            .at(slot, offset));
        }
        let data_offset = offset + 16;
        let available = source.size().saturating_sub(data_offset);
        if u64::from(incl_len) > available {
            return Err(AnalyzeError::new(
                E_TRUNCATED_CAPTURE,
                format!("包记录声明 {incl_len} 字节，但文件只剩 {available} 字节"),
            )
            .at(slot, data_offset));
        }
        let payload = read_packet_body(source, data_offset, incl_len as usize)?;
        let epoch = resolution.to_epoch(ts_sec, ts_frac);
        let out_of_order = epoch < max_epoch;
        if out_of_order {
            stats.out_of_order += 1;
        } else {
            max_epoch = epoch;
        }
        stats.records += 1;
        visitor.on_frame(&Frame {
            slot,
            offset,
            epoch,
            raw_ts: (ts_sec, ts_frac),
            source: resolution.source,
            linktype,
            payload,
            out_of_order,
        })?;
        stats.frames += 1;
        offset = data_offset + u64::from(incl_len);
        slot += 1;
    }
    if stats.records == 0 {
        return Err(AnalyzeError::new(
            E_NO_TIMESTAMP,
            "pcap 只有文件头，没有任何包记录，无法获得合法时间戳",
        ));
    }
    Ok((info, stats))
}

fn pcapng_unsupported() -> AnalyzeError {
    AnalyzeError::new(
        E_UNSUPPORTED_FORMAT,
        "首版不支持 pcapng（Section/Interface/Enhanced Packet Block 与 if_tsresol 换算）；请先转换为 classic pcap",
    )
}

/// 分块读取包载荷，避免一次性大块读入。
fn read_packet_body(
    source: &dyn ByteSource,
    offset: u64,
    len: usize,
) -> AnalyzeResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(len);
    while buffer.len() < len {
        let want = (len - buffer.len()).min(SCAN_CHUNK);
        let at = offset + buffer.len() as u64;
        match source.read_at(at, want) {
            Chunk::Data(bytes) if !bytes.is_empty() => buffer.extend_from_slice(&bytes),
            Chunk::Data(_) | Chunk::Eof => {
                return Err(AnalyzeError::new(E_TRUNCATED_CAPTURE, "包载荷读取不完整"));
            }
            Chunk::Error(message) => return Err(AnalyzeError::new(E_IO, message)),
        }
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Collect {
        frames: Vec<Frame>,
    }

    impl FrameVisitor for Collect {
        fn on_frame(&mut self, frame: &Frame) -> AnalyzeResult<()> {
            self.frames.push(frame.clone());
            Ok(())
        }
    }

    /// 经典 pcap：小端、以太网；`packets` 为 (ts_sec, ts_frac, payload)。
    /// `reserved_field` 写入文件头偏移 8 的保留字段。
    pub(crate) fn build_pcap(
        packets: &[(u32, u32, Vec<u8>)],
        reserved_field: u32,
        nano: bool,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let magic = if nano { 0xA1B2_3C4D_u32 } else { 0xA1B2_C3D4 };
        bytes.extend_from_slice(&magic.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&reserved_field.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        for (sec, frac, payload) in packets {
            bytes.extend_from_slice(&sec.to_le_bytes());
            bytes.extend_from_slice(&frac.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(payload);
        }
        bytes
    }

    #[test]
    fn pcap_header_timestamp_and_reserved_field_handling() {
        // 保留字段塞一个"非零/疑似时区"的值，验证不参与 epoch 换算。
        let bytes = build_pcap(&[(1_700_000_000, 250_000, vec![1, 2, 3])], 28_800, false);
        let mut collect = Collect { frames: Vec::new() };
        let (info, stats) = scan(&MemorySource::new(&bytes), &mut collect).expect("pcap 解析");
        assert_eq!(info.format, "pcap");
        assert_eq!(info.linktype, 1);
        assert_eq!(info.reserved_field, 28_800);
        assert!(info.timebase.contains("reserved_field_ignored"));
        assert_eq!(stats.records, 1);
        assert_eq!(collect.frames.len(), 1);
        let frame = &collect.frames[0];
        // 只按 ts_sec + ts_frac/1e6 换算，不加 28800 秒。
        assert!((frame.epoch - 1_700_000_000.25).abs() < 1e-9, "epoch={}", frame.epoch);
        assert_eq!(frame.raw_ts, (1_700_000_000, 250_000));
        assert_eq!(frame.payload, vec![1, 2, 3]);
        assert!(!frame.out_of_order);
        assert_eq!(frame.slot, 0);
        assert_eq!(frame.offset, 24);
    }

    #[test]
    fn max_u32_reserved_field_does_not_shift_timestamps() {
        // old thiszone 回绕后可能出现 0xFFFFFFFF；不得因此把时间推到 22 世纪。
        let bytes = build_pcap(&[(1, 0, vec![0])], u32::MAX, false);
        let mut collect = Collect { frames: Vec::new() };
        scan(&MemorySource::new(&bytes), &mut collect).expect("pcap 解析");
        assert_eq!(collect.frames[0].epoch, 1.0);
        assert_eq!(collect.frames[0].raw_ts, (1, 0));
    }

    #[test]
    fn pcap_nanosecond_magic_is_scaled_by_1e9() {
        let bytes = build_pcap(&[(10, 123_456_789, vec![0])], 0, true);
        let mut collect = Collect { frames: Vec::new() };
        let (info, _) = scan(&MemorySource::new(&bytes), &mut collect).expect("纳秒 pcap 解析");
        assert!(info.nanoseconds);
        assert!((collect.frames[0].epoch - 10.123_456_789).abs() < 1e-9);
    }

    #[test]
    fn big_endian_files_are_supported() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xA1B2_C3D4_u32.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&0i32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&65535u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&500_000u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let mut collect = Collect { frames: Vec::new() };
        scan(&MemorySource::new(&bytes), &mut collect).expect("大端 pcap 解析");
        assert!((collect.frames[0].epoch - 7.5).abs() < 1e-9);
    }

    #[test]
    fn pcap_out_of_order_records_are_flagged_but_keep_raw_values() {
        let bytes = build_pcap(&[(100, 0, vec![1]), (90, 0, vec![2]), (95, 0, vec![3])], 0, false);
        let mut collect = Collect { frames: Vec::new() };
        let (_, stats) = scan(&MemorySource::new(&bytes), &mut collect).expect("乱序 pcap 解析");
        assert_eq!(stats.out_of_order, 2);
        assert_eq!(collect.frames[0].epoch, 100.0);
        assert_eq!(collect.frames[1].raw_ts.0, 90);
        assert!(collect.frames[1].out_of_order);
        assert!(collect.frames[2].out_of_order);
    }

    #[test]
    fn truncated_pcap_is_reported_not_silently_empty() {
        let mut bytes = build_pcap(&[(1, 0, vec![1, 2, 3, 4])], 0, false);
        bytes.truncate(bytes.len() - 2);
        let mut collect = Collect { frames: Vec::new() };
        let error = scan(&MemorySource::new(&bytes), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_TRUNCATED_CAPTURE);
        assert_eq!(error.record_index, Some(0));

        let header_only = build_pcap(&[], 0, false);
        let error = scan(&MemorySource::new(&header_only), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_NO_TIMESTAMP);

        let mut partial_record = build_pcap(&[(1, 0, vec![1, 2, 3, 4])], 0, false);
        partial_record.truncate(24 + 8);
        let error = scan(&MemorySource::new(&partial_record), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_TRUNCATED_CAPTURE);
    }

    #[test]
    fn unknown_magic_and_pcapng_are_rejected_explicitly() {
        let mut collect = Collect { frames: Vec::new() };
        let error =
            scan(&MemorySource::new(b"GET / HTTP/1.1\r\n\r\n++++++++"), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_UNSUPPORTED_FORMAT);

        // pcapng 的 Section Header Block 魔数。
        let mut pcapng = vec![0x0A, 0x0D, 0x0D, 0x0A];
        pcapng.extend_from_slice(&[0x1C, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A]);
        pcapng.extend_from_slice(&[0u8; 32]);
        let error = scan(&MemorySource::new(&pcapng), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_UNSUPPORTED_FORMAT);
        assert!(error.message.contains("pcapng"), "{}", error.message);

        let error = scan(&MemorySource::new(&[]), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_UNSUPPORTED_FORMAT);
    }

    #[test]
    fn oversized_or_inconsistent_record_lengths_are_corrupt() {
        let mut bytes = build_pcap(&[(1, 0, vec![1, 2, 3, 4])], 0, false);
        // incl_len 超出单条上限。
        let huge = (SCAN_CHUNK as u32 + 4).to_le_bytes();
        bytes[24 + 8..24 + 12].copy_from_slice(&huge);
        let mut collect = Collect { frames: Vec::new() };
        let error = scan(&MemorySource::new(&bytes), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_CORRUPT_PACKET);

        // orig_len < incl_len。
        let mut bytes = build_pcap(&[(1, 0, vec![1, 2, 3, 4])], 0, false);
        bytes[24 + 12..24 + 16].copy_from_slice(&1u32.to_le_bytes());
        let error = scan(&MemorySource::new(&bytes), &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_CORRUPT_PACKET);
    }

    #[test]
    fn host_read_errors_propagate() {
        let failing = |_offset: u64, _len: usize| Err("CANCELLED: 已取消".to_string());
        let source = FileSource::new(1024, &failing);
        let mut collect = Collect { frames: Vec::new() };
        let error = scan(&source, &mut collect).expect_err("应报错");
        assert_eq!(error.code, E_IO);
        assert!(error.message.contains("CANCELLED"));
    }

    #[test]
    fn file_source_reads_through_the_injected_closure() {
        let bytes = build_pcap(&[(5, 0, vec![9, 8, 7])], 0, false);
        let len = bytes.len() as u64;
        let reader = |offset: u64, want: usize| {
            let start = (offset as usize).min(bytes.len());
            let end = (start + want).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        };
        let source = FileSource::new(len, &reader);
        let mut collect = Collect { frames: Vec::new() };
        scan(&source, &mut collect).expect("FileSource 解析");
        assert_eq!(collect.frames[0].payload, vec![9, 8, 7]);
    }
}
