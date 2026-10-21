//! 宿主句柄 → 纯解析层 [`Blob`] 的只读桥接。
//!
//! 插件拿不到检材真实路径，只能通过 `File` / `EvidenceVolume` 的有界读取访问数据。
//! 这里遵守宿主限制：单次读取不超过 4 MiB（`MAX_HOST_READ`），文件大小先查
//! `stat` 再按块读；不存在、非文件、损坏与超限分别返回不同 `code`。

use lovelycarve_plugin::{Error, EvidenceVolume, File, Result, MAX_HOST_READ};

use crate::error::DedupError;
use crate::zipread::Blob;

/// 把解析层错误映射成宿主错误（`RESOURCE_LIMIT` 保留，便于宿主按超限处理）。
pub fn host_error(error: DedupError) -> Error {
    Error::new(error.code, error.message)
}

/// 宿主 `File`（FileAnalyzer 传入的单文件句柄）。
pub struct FileBlob<'a> {
    file: &'a File,
}

impl<'a> FileBlob<'a> {
    pub fn new(file: &'a File) -> Self {
        Self { file }
    }
}

impl Blob for FileBlob<'_> {
    fn len(&self) -> u64 {
        self.file.size()
    }

    fn read_at(&self, offset: u64, len: usize) -> std::result::Result<Vec<u8>, DedupError> {
        let mut output = Vec::with_capacity(len.min(MAX_HOST_READ));
        let mut position = offset;
        let end = offset.saturating_add(len as u64).min(self.file.size());
        while position < end {
            let want = usize::try_from((end - position).min(MAX_HOST_READ as u64)).unwrap_or(0);
            if want == 0 {
                break;
            }
            let chunk = self
                .file
                .read(position, want)
                .map_err(|error| DedupError::new("host.read", format!("读取失败：{error}")))?;
            if chunk.is_empty() {
                break;
            }
            position += chunk.len() as u64;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }
}

/// 证据卷内的一个文件句柄。
pub struct VolumeBlob<'a> {
    volume: &'a EvidenceVolume,
    path: String,
    size: u64,
}

impl<'a> VolumeBlob<'a> {
    /// 不存在/非文件返回 `Ok(None)`（调用方应优雅跳过）。
    pub fn open(volume: &'a EvidenceVolume, path: &str) -> Result<Option<Self>> {
        let Some(node) = volume.stat(path)? else {
            return Ok(None);
        };
        if !node.is_file() {
            return Ok(None);
        }
        Ok(Some(Self {
            volume,
            path: path.to_owned(),
            size: node.size,
        }))
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Blob for VolumeBlob<'_> {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, len: usize) -> std::result::Result<Vec<u8>, DedupError> {
        let end = offset.saturating_add(len as u64).min(self.size);
        if end <= offset {
            return Ok(Vec::new());
        }
        let length = end - offset;
        let mut output = Vec::with_capacity(usize::try_from(length).unwrap_or(0).min(MAX_HOST_READ));
        let mut position = offset;
        while position < end {
            let want = (end - position).min(MAX_HOST_READ as u64);
            let chunk = self
                .volume
                .read(&self.path, position, Some(want))
                .map_err(|error| DedupError::new("host.read", format!("读取失败：{error}")))?;
            if chunk.is_empty() {
                break;
            }
            position += chunk.len() as u64;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_errors_keep_their_codes() {
        let error = host_error(DedupError::resource("太大"));
        assert_eq!(error.code, "RESOURCE_LIMIT");
        let error = host_error(DedupError::new("zip.crc", "校验失败"));
        assert_eq!(error.code, "zip.crc");
        assert_eq!(error.message, "校验失败");
    }
}
