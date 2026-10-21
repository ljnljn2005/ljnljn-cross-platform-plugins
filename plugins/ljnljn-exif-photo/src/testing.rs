//! 测试支持 API：把内部的纯解析函数与合成样例构造器按 `pub mod testing` 暴露，
//! 供集成测试（`tests/`）与外部验证脚本复用。
//!
//! 这些接口只做内存解析，不接触证据句柄，也不改变生产路径的行为；
//! LovelyCarve 宿主不会调用它们。

pub use crate::container::{parse_xmp, scan_jpeg, scan_png};
pub use crate::exif::{Ifd, TiffBlock};
pub use crate::fields::{self, signed_decimal, timestamp_shape, TimestampShape};
pub use crate::fixtures::{crc32, ExifSample, Entry, JpegSample, Layout, PngSample};
pub use crate::format::{sniff, ExtensionKind, RealFormat};
pub use crate::record::{accumulate, parse_file, Outcome, PhotoRecord, RunSummary};
pub use crate::sha256::Sha256;

/// Appends one JPEG marker segment (marker + big-endian length + payload).
pub fn push_segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    crate::fixtures::push_segment(out, marker, payload);
}

/// Builds the JPEG+GPS synthetic sample used by the documented test matrix.
pub fn jpeg_with_gps() -> (Vec<u8>, Option<u32>, Option<Layout>) {
    JpegSample {
        exif: Some(ExifSample::with_gps()),
        with_app0: true,
        with_scan: true,
        ..JpegSample::default()
    }
    .build()
}

/// Builds the JPEG sample without GPS.
pub fn jpeg_without_gps() -> (Vec<u8>, Option<u32>, Option<Layout>) {
    JpegSample {
        exif: Some(ExifSample::without_gps()),
        with_scan: true,
        ..JpegSample::default()
    }
    .build()
}

/// Builds the PNG `eXIf` sample (little-endian TIFF inside a `tEXt`+`eXIf` PNG).
pub fn png_with_exif() -> (Vec<u8>, Option<u32>, Option<Layout>) {
    let mut sample = ExifSample::with_gps();
    sample.little_endian = true;
    PngSample {
        width: 640,
        height: 480,
        exif: Some(sample),
        texts: vec![("Software".to_owned(), "SyntheticCam 1.0".to_owned())],
        ..PngSample::default()
    }
    .build()
}

/// A JPEG truncated in the middle of its APP1 payload.
pub fn truncated_jpeg() -> Vec<u8> {
    let (bytes, _, _) = jpeg_with_gps();
    let cut = bytes.len() / 3;
    bytes[..cut].to_vec()
}

/// Plain text renamed to `.jpg`.
pub fn text_disguised_as_jpeg() -> Vec<u8> {
    b"this is not a photo, just text\n".repeat(8)
}
