//! Host handle → [`Blob`] read-only adapter.

use lovelycarve_plugin::FileRef;

use crate::error::DedupError;
use crate::zipread::Blob;

/// A bounded read-only view of a host file handle. `FileRef::read_at` clamps
/// at the end of the file and splits host reads at the protocol limit, so a
/// single call never requests more than the host allows.
pub struct FileBlob<'a> {
    file: &'a FileRef,
}

impl<'a> FileBlob<'a> {
    pub fn new(file: &'a FileRef) -> Self {
        Self { file }
    }
}

impl Blob for FileBlob<'_> {
    fn len(&self) -> u64 {
        self.file.size()
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, DedupError> {
        self.file
            .read_at(offset, len)
            .map_err(|error| DedupError::new("host.read", format!("读取失败：{}", error.message)))
    }
}
