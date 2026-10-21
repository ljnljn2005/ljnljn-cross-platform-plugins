//! Pure input dispatch: one logical input (a selected file, a view file, or a
//! zip member) becomes an [`Accumulator`] update. This module is intentionally
//! free of the LovelyCarve SDK so the same code paths run in unit tests.

use crate::dedup::Accumulator;
use crate::limits::MAX_MEMBER_BYTES;
use crate::parse::{head_looks_like_zip, workbook_shape, zip_members, InputFile, InputSet, Link};
use crate::zipread::{read_entries_from, read_entry, Blob};

/// Parse one logical input: a direct xlsx/xlsm, or a zip containing
/// xlsx/xlsm members. Every rejection is recorded with a stable code.
pub fn parse_input<B: Blob + ?Sized>(
    accumulator: &mut Accumulator,
    link: Link,
    display: &str,
    blob: &B,
) {
    let total = blob.len();
    if total == 0 {
        accumulator.reject(link, display, "empty_file", "文件长度为 0");
        return;
    }
    let head = match blob.read_at(0, 8) {
        Ok(head) => head,
        Err(error) => {
            accumulator.reject(link, display, error.code, error.message);
            return;
        }
    };
    if !head_looks_like_zip(&head) {
        accumulator.reject(
            link,
            display,
            "not_zip_container",
            "不是 ZIP 容器（xlsx/xlsm 本质上是 ZIP），可能是 .xls/.csv/.txt 或损坏文件",
        );
        return;
    }
    if !workbook_shape(blob) {
        // It is a zip: expand only the xlsx/xlsm members.
        let members = match zip_members(blob) {
            Ok(members) => members,
            Err(error) => {
                accumulator.reject(link, display, error.code, error.message);
                return;
            }
        };
        if members.is_empty() {
            accumulator.reject(
                link,
                display,
                "zip.no_spreadsheet",
                "ZIP 内没有 .xlsx/.xlsm 成员（已忽略 __MACOSX 与临时文件）",
            );
            return;
        }
        let entries = match read_entries_from(blob) {
            Ok(entries) => entries,
            Err(error) => {
                accumulator.reject(link, display, error.code, error.message);
                return;
            }
        };
        let mut set = InputSet::new();
        for member in members {
            if !set.admit(&InputFile::evidence("zip", &member)) {
                continue;
            }
            let Some(entry) = entries.iter().find(|entry| entry.name == member) else {
                continue;
            };
            let bytes = match read_entry(blob, entry, MAX_MEMBER_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    accumulator.reject(
                        link.clone(),
                        format!("{display}::{member}"),
                        error.code,
                        error.message,
                    );
                    continue;
                }
            };
            analyze_package(
                accumulator,
                link.clone(),
                &format!("{display}::{member}"),
                &bytes,
            );
        }
        return;
    }
    analyze_package(accumulator, link, display, blob);
}

fn analyze_package<B: Blob + ?Sized>(
    accumulator: &mut Accumulator,
    link: Link,
    display: &str,
    blob: &B,
) {
    match crate::parse::load_workbook(blob) {
        Ok(workbook) => accumulator.analyze_workbook(link, display, blob, &workbook),
        Err(error) => accumulator.reject(link, display, error.code, error.message),
    }
}
