//! 解析层单元测试：合成 JPEG（含/不含 GPS）、PNG eXIf、截断、伪装文本、
//! 多段 EXIF、循环引用，以及“字段值 + 偏移定位”的交叉校验。
//!
//! 全部样例在内存里合成（见 `crate::fixtures`），不读写真实检材。

use ljnljn_kb_exif_photo_metadata_8ffbc036::exif::{self, reason, Ifd};
use ljnljn_kb_exif_photo_metadata_8ffbc036::testing::fields::{self, signed_decimal, TimestampShape};
use ljnljn_kb_exif_photo_metadata_8ffbc036::testing::{
    accumulate, parse_file, push_segment, Entry, ExifSample, JpegSample, Outcome, PhotoRecord,
    PngSample, RealFormat, RunSummary, Sha256,
};

fn photo(outcome: Outcome) -> Box<PhotoRecord> {
    match outcome {
        Outcome::Photo(record) => record,
        other => panic!("expected a parsed photo, got {other:?}"),
    }
}

#[test]
fn jpeg_with_gps_yields_expected_fields_and_offsets() {
    let sample = JpegSample {
        exif: Some(ExifSample::with_gps()),
        with_app0: true,
        with_scan: true,
        ..JpegSample::default()
    };
    let (bytes, first_payload, layout) = sample.build();
    let layout = layout.expect("layout of the first EXIF block");
    let record = photo(parse_file("DCIM/Camera/IMG_0001.jpg", &bytes));

    assert_eq!(record.format, RealFormat::Jpeg);
    assert!(record.exif_present);
    assert!(record.has_gps());
    assert_eq!(record.size, bytes.len() as u64);
    assert_eq!(record.sha256, Sha256::digest_hex(&bytes));

    let fields = &record.fields;
    let datetime = fields.datetime_original.as_ref().expect("DateTimeOriginal");
    assert_eq!(datetime.raw, "2023:08:15 10:30:00");
    // OffsetTimeOriginal is recorded verbatim and never applied.
    assert_eq!(datetime.offset_time.as_deref(), Some("+08:00"));
    assert_eq!(datetime.precision, "second");
    assert_eq!(fields.make.as_ref().unwrap().value, "TestMake");
    assert_eq!(fields.model.as_ref().unwrap().value, "ModelX-100");
    assert_eq!(fields.lens_model.as_ref().unwrap().value, "EF24-70mm f/2.8L");
    assert_eq!(fields.image_width.as_ref().unwrap().0, 4032);
    assert_eq!(fields.image_height.as_ref().unwrap().0, 3024);
    assert_eq!(fields.orientation.as_ref().unwrap().0, 6);

    let latitude = fields.latitude.as_ref().expect("latitude");
    assert_eq!(latitude.reference.as_deref(), Some("S"));
    assert_eq!(latitude.degrees, 37.0);
    assert_eq!(latitude.minutes, 49.0);
    assert_eq!(latitude.seconds, 22.87);
    // 37 + 49/60 + 22.87/3600, negative because Ref is S.
    assert!((latitude.decimal - -37.823_019_444).abs() < 1e-6, "{}", latitude.decimal);
    let longitude = fields.longitude.as_ref().expect("longitude");
    assert_eq!(longitude.reference.as_deref(), Some("E"));
    assert!((longitude.decimal - 144.962_702_777_8).abs() < 1e-6);
    let altitude = fields.altitude.as_ref().expect("altitude");
    assert_eq!(altitude.reference.as_deref(), Some("0"));
    assert!((altitude.signed_meters - 12.34).abs() < 1e-9);

    // Offsets: TIFF base = payload + 6 ("Exif\0\0"), values from the layout map.
    let block = record.exif_block.as_ref().expect("exif block");
    assert_eq!(block.carrier, "jpeg-app1");
    assert_eq!(block.container_offset, first_payload.expect("payload offset"));
    assert_eq!(block.tiff_offset, first_payload.unwrap() + 6);
    assert_eq!(block.block.byte_order, "big-endian");
    let expected_datetime_offset = u64::from(block.tiff_offset) + u64::from(layout.value_offsets[&0x9003]);
    assert_eq!(datetime.origin.file_offset, expected_datetime_offset);
    assert_eq!(datetime.origin.ifd, Ifd::Exif);
    // The recorded offset really points at the ASCII value in the file.
    let start = datetime.origin.file_offset as usize;
    assert_eq!(&bytes[start..start + 19], b"2023:08:15 10:30:00");
    let lat_offset = u64::from(block.tiff_offset) + u64::from(layout.value_offsets[&0x0002]);
    assert_eq!(latitude.origin.file_offset, lat_offset);
    // RATIONAL triple occupies 24 bytes at that offset.
    assert_eq!(latitude.origin.length, 24);
    assert_eq!(record.fields.missing(), Vec::<&str>::new());
    assert_eq!(fields.skipped, Vec::<String>::new());
}

#[test]
fn jpeg_without_gps_reports_missing_gps_fields() {
    let sample = JpegSample {
        exif: Some(ExifSample::without_gps()),
        with_scan: true,
        ..JpegSample::default()
    };
    let (bytes, _, _) = sample.build();
    let record = photo(parse_file("DCIM/Camera/IMG_0002.JPG", &bytes));
    assert!(record.exif_present);
    assert!(!record.has_gps());
    assert_eq!(
        record.fields.datetime_original.as_ref().unwrap().raw,
        "2020:01:02 03:04:05"
    );
    assert_eq!(record.fields.datetime_original.as_ref().unwrap().offset_time, None);
    assert_eq!(record.exif_block.as_ref().unwrap().block.byte_order, "little-endian");
    let missing = record.fields.missing();
    assert!(missing.contains(&"gps_latitude"));
    assert!(missing.contains(&"gps_longitude"));
    assert!(missing.contains(&"gps_altitude"));
    assert!(missing.contains(&"lens_model") == false, "lens present: {missing:?}");
}

#[test]
fn jpeg_without_exif_yields_empty_fields() {
    let sample = JpegSample {
        with_app0: true,
        with_scan: true,
        ..JpegSample::default()
    };
    let (bytes, _, _) = sample.build();
    let record = photo(parse_file("DCIM/Camera/plain.jpg", &bytes));
    assert!(!record.exif_present);
    assert_eq!(record.reason, "no_exif");
    assert!(!record.has_gps());
    assert_eq!(record.fields.make, None);
    assert_eq!(record.fields.missing().len(), fields::REQUIRED_FIELDS.len());
}

#[test]
fn png_exif_text_and_xmp_are_read_with_offsets() {
    let mut sample = ExifSample::with_gps();
    // PNG eXIf blocks are typically little-endian; exercise that branch.
    sample.little_endian = true;
    let png = PngSample {
        width: 640,
        height: 480,
        exif: Some(sample),
        texts: vec![
            ("Software".to_owned(), "SyntheticCam 1.0".to_owned()),
            (
                "XML:com.adobe.xmp".to_owned(),
                "<x:xmpmeta><xmp:CreatorTool>Synth</xmp:CreatorTool>\
                 <xmp:CreateDate>2024-02-03T04:05:06</xmp:CreateDate></x:xmpmeta>"
                    .to_owned(),
            ),
        ],
        extra_chunks: Vec::new(),
        truncate_to: None,
    };
    let (bytes, exif_offset, layout) = png.build();
    let exif_offset = exif_offset.expect("eXIf offset");
    let layout = layout.expect("layout");
    let record = photo(parse_file("Pictures/shot.png", &bytes));
    assert_eq!(record.format, RealFormat::Png);
    let block = record.exif_block.as_ref().expect("eXIf block");
    assert_eq!(block.carrier, "png-exif");
    assert_eq!(block.container_offset, exif_offset);
    // eXIf carries the TIFF header directly, so both offsets coincide.
    assert_eq!(block.tiff_offset, exif_offset);
    assert_eq!(record.fields.png_dimensions, Some((640, 480)));
    assert_eq!(record.fields.image_width.as_ref().unwrap().0, 4032);
    let datetime = record.fields.datetime_original.as_ref().expect("timestamp");
    assert_eq!(
        datetime.origin.file_offset,
        u64::from(exif_offset) + u64::from(layout.value_offsets[&0x9003])
    );
    let start = datetime.origin.file_offset as usize;
    assert_eq!(&bytes[start..start + 19], b"2023:08:15 10:30:00");
    // Text chunks: keyword/value plus the chunk offset.
    let software = record
        .png_texts
        .iter()
        .find(|text| text.key == "Software")
        .expect("tEXt Software");
    assert_eq!(software.value, "SyntheticCam 1.0");
    let chunk_start = software.offset as usize - 8;
    assert_eq!(&bytes[chunk_start + 4..chunk_start + 8], b"tEXt");
    // XMP fields come from the XML:com.adobe.xmp iTXt/tEXt chunk.
    let xmp = record.xmp.as_ref().expect("xmp packet");
    assert_eq!(xmp.creator_tool.as_deref(), Some("Synth"));
    assert_eq!(xmp.date_created.as_deref(), Some("2024-02-03T04:05:06"));
    // The XMP chunk is not reported as a plain text field.
    assert!(!record.png_texts.iter().any(|text| text.key.starts_with("XML:")));
}

#[test]
fn truncated_files_are_rejected_with_reasons() {
    let sample = JpegSample {
        exif: Some(ExifSample::with_gps()),
        with_scan: true,
        ..JpegSample::default()
    };
    let (bytes, _, _) = sample.build();
    // Cut inside the APP1 payload: the segment length exceeds the file.
    let cut = bytes.len() / 3;
    match parse_file("DCIM/Camera/cut.jpg", &bytes[..cut]) {
        Outcome::Rejected(error) => {
            assert_eq!(error.reason, reason::TRUNCATED);
            assert!(error.message.contains("超出文件长"), "{}", error.message);
        }
        other => panic!("expected rejection, got {other:?}"),
    }
    // A 3-byte JPEG prefix is still a JPEG but too short to hold a segment.
    match parse_file("x.jpg", &bytes[..2]) {
        Outcome::Rejected(error) => assert_eq!(error.reason, reason::TRUNCATED),
        other => panic!("expected rejection, got {other:?}"),
    }
    // A valid EXIF segment does not excuse a missing SOS/EOI: the segment
    // table ends at EOF and the file must still be rejected.
    let (no_scan, _, _) = JpegSample {
        exif: Some(ExifSample::with_gps()),
        ..JpegSample::default()
    }
    .build();
    match parse_file("DCIM/Camera/noscan.jpg", &no_scan) {
        Outcome::Rejected(error) => assert_eq!(error.reason, reason::TRUNCATED),
        other => panic!("expected rejection, got {other:?}"),
    }
    // Cutting only the trailing EOI leaves the SOS header intact, so the
    // entropy-data check must reject it as truncated.
    match parse_file("DCIM/Camera/noeoi.jpg", &bytes[..bytes.len() - 2]) {
        Outcome::Rejected(error) => assert_eq!(error.reason, reason::TRUNCATED),
        other => panic!("expected rejection, got {other:?}"),
    }
    // Truncating the IFD itself (inside a structurally valid segment) is caught
    // by the TIFF reader as an out-of-bounds directory.
    let (mut tiff, _) = ExifSample::with_gps().build();
    tiff.truncate(tiff.len() - 8);
    assert!(exif::parse_tiff(&tiff, false).is_err());
    let mut header_only = vec![0u8; 8];
    header_only[..2].copy_from_slice(b"MM");
    header_only[2..4].copy_from_slice(&42u16.to_be_bytes());
    header_only[4..8].copy_from_slice(&0xFFFFu32.to_be_bytes());
    let error = exif::parse_tiff(&header_only, false).expect_err("IFD0 out of bounds");
    assert_eq!(error.reason, reason::IFD_OUT_OF_BOUNDS);
}

#[test]
fn png_truncated_is_rejected() {
    let png = PngSample {
        width: 8,
        height: 8,
        exif: Some(ExifSample::with_gps()),
        ..PngSample::default()
    };
    let (bytes, _, _) = png.build();
    match parse_file("Pictures/cut.png", &bytes[..bytes.len() - 6]) {
        Outcome::Rejected(error) => assert_eq!(error.reason, reason::TRUNCATED),
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn text_disguised_as_jpeg_is_not_a_photo() {
    let text = b"This is a plain text file renamed to .jpg\n".repeat(4);
    match parse_file("DCIM/Camera/fake.jpg", &text) {
        Outcome::NotPhoto { format, detail } => {
            assert_eq!(format, RealFormat::Unknown);
            assert!(detail.contains("文件头"), "{detail}");
        }
        other => panic!("expected NotPhoto, got {other:?}"),
    }
    // Extension outside the photo list never reaches the parser.
    assert_eq!(parse_file("a/notes.txt", &text), Outcome::NotCandidate);
    // PNG content behind a .jpg name is accepted and flagged, per "real format".
    let png = PngSample {
        width: 4,
        height: 4,
        ..PngSample::default()
    }
    .build()
    .0;
    let record = photo(parse_file("DCIM/Camera/mislabeled.jpg", &png));
    assert_eq!(record.format, RealFormat::Png);
    assert!(record.extension_mismatch);
    assert!(record
        .warnings
        .iter()
        .any(|warning| warning.contains("真实格式 PNG")));
}

#[test]
fn multiple_exif_segments_use_the_first_valid_one() {
    let mut second = ExifSample::without_gps();
    second.ifd0[0] = Entry::Ascii(0x010F, "SecondSegment".to_owned());
    let (bytes, _, layout) = JpegSample {
        exif: Some(ExifSample::with_gps()),
        extra_exif: vec![second],
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    let layout = layout.expect("layout");
    let record = photo(parse_file("DCIM/Camera/two.jpg", &bytes));
    assert_eq!(record.fields.make.as_ref().unwrap().value, "TestMake");
    assert_eq!(record.exif_candidates, 2);
    assert!(record
        .skipped_exif
        .iter()
        .any(|item| item.contains("未被采用") || item.contains("未采用")));
    assert!(
        record.exif_block.as_ref().unwrap().container_offset
            < record.exif_block.as_ref().unwrap().container_offset
                + u32::from(layout.value_offsets[&0x010F])
                + 4096
    );
}

#[test]
fn broken_first_exif_falls_back_to_the_next_segment() {
    // First APP1 carries a bad TIFF magic; the second one is valid.
    let mut out = vec![0xFF, 0xD8];
    let mut bad = b"Exif\0\0".to_vec();
    bad.extend_from_slice(b"II\x2a\x00\x08\x00\x00\x00"); // truncated: no IFD0
    push_segment(&mut out, 0xE1, &bad);
    let (good_tiff, _) = ExifSample::without_gps().build();
    let mut good = b"Exif\0\0".to_vec();
    good.extend_from_slice(&good_tiff);
    push_segment(&mut out, 0xE1, &good);
    out.extend_from_slice(&[0xFF, 0xD9]);
    let record = photo(parse_file("DCIM/Camera/fallback.jpg", &out));
    assert_eq!(record.exif_candidates, 2);
    assert_eq!(record.fields.model.as_ref().unwrap().value, "NoGps1");
    assert!(!record.skipped_exif.is_empty());
}

#[test]
fn cyclic_ifd_is_rejected() {
    let mut sample = ExifSample::without_gps();
    sample.ifd1 = Some(vec![Entry::Ascii(0x010F, "IFD1".to_owned())]);
    sample.cycle = true;
    let (bytes, _, _) = JpegSample {
        exif: Some(sample),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    match parse_file("DCIM/Camera/loop.jpg", &bytes) {
        Outcome::Rejected(error) => assert_eq!(error.reason, reason::IFD_CYCLE),
        other => panic!("expected cycle rejection, got {other:?}"),
    }
}

#[test]
fn coordinate_sign_comes_only_from_the_reference() {
    // D + M/60 + S/3600: 37 + 49/60 + 22.70/3600 = 37.8229722…
    assert!((signed_decimal(37.0, 49.0, 22.70, Some("S")) + 37.822_972_222).abs() < 1e-6);
    // 37 + 49/60 + 22.87/3600 = 37.8230194…
    assert!((signed_decimal(37.0, 49.0, 22.87, Some("N")) - 37.823_019_444).abs() < 1e-6);
    // 144 + 57/60 + 45.73/3600 = 144.9627027…
    assert!((signed_decimal(144.0, 57.0, 45.73, Some("W")) + 144.962_702_777_8).abs() < 1e-6);
    // Negative stored minutes must not flip the sign on their own.
    assert!((signed_decimal(-37.0, -49.0, -22.87, Some("N")) - 37.823_019_444).abs() < 1e-6);
    assert!((signed_decimal(-37.0, -49.0, -22.87, Some("S")) + 37.823_019_444).abs() < 1e-6);
    // No reference: positive value, flagged as defaulted.
    assert_eq!(signed_decimal(1.0, 30.0, 0.0, None), 1.5);
}

#[test]
fn missing_gps_reference_keeps_the_magnitude_and_reports_it() {
    let mut sample = ExifSample::with_gps();
    let gps = sample.gps_ifd.as_mut().unwrap();
    gps.retain(|entry| entry.tag() != 0x0001); // drop GPSLatitudeRef
    let (bytes, _, _) = JpegSample {
        exif: Some(sample),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    let record = photo(parse_file("DCIM/Camera/noref.jpg", &bytes));
    let latitude = record.fields.latitude.as_ref().expect("latitude");
    assert!(latitude.ref_defaulted);
    assert!(latitude.decimal > 0.0);
    assert!(record.fields.missing().contains(&"gps_latitude_ref"));
}

#[test]
fn timestamp_shapes_are_classified_without_guessing() {
    assert_eq!(
        fields::timestamp_shape("2023:08:15 10:30:00"),
        TimestampShape::Full
    );
    assert_eq!(
        fields::timestamp_shape("2023:08:15"),
        TimestampShape::DateOnly
    );
    assert_eq!(
        fields::timestamp_shape("0000:00:00 00:00:00"),
        TimestampShape::Blank
    );
    assert_eq!(
        fields::timestamp_shape("2023-08-15T10:30:00"),
        TimestampShape::Full
    );
    assert_eq!(
        fields::timestamp_shape("garbage"),
        TimestampShape::Malformed
    );
    // Date-only values are kept as-is with their own precision marker.
    let mut sample = ExifSample::without_gps();
    sample.exif_ifd = Some(vec![Entry::Ascii(0x9003, "2021:12:31".to_owned())]);
    let (bytes, _, _) = JpegSample {
        exif: Some(sample),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    let record = photo(parse_file("d.jpg", &bytes));
    let datetime = record.fields.datetime_original.expect("timestamp");
    assert_eq!(datetime.raw, "2021:12:31");
    assert_eq!(datetime.precision, "date-only");
}

#[test]
fn out_of_bounds_sub_ifd_rejects_the_whole_file() {
    let mut sample = ExifSample::without_gps();
    // Point IFD0.exif_ifd at 0x7fff_ff00 (far past the block end).
    sample.ifd0.push(Entry::Long(0x8769, vec![0x7fff_ff00]));
    let (tiff, _) = sample.build();
    let error = exif::parse_tiff(&tiff, false).expect_err("exif ifd out of bounds");
    assert_eq!(error.reason, reason::IFD_OUT_OF_BOUNDS);
    assert_eq!(error.ifd, Some(Ifd::Exif));
    // Through the container the whole photo is rejected, no half-parsed record.
    let (bytes, _, _) = JpegSample {
        exif: Some(sample),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    match parse_file("DCIM/Camera/badifd.jpg", &bytes) {
        Outcome::Rejected(error) => {
            assert_eq!(error.reason, reason::IFD_OUT_OF_BOUNDS);
            assert!(error.message.contains("ExifIFD"), "{}", error.message);
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn invalid_single_tag_is_skipped_without_losing_the_file() {
    let mut sample = ExifSample::without_gps();
    // Orientation outside 1..8 plus a zero-count RATIONAL GPS latitude.
    sample.ifd0.retain(|entry| entry.tag() != 0x0112);
    sample.ifd0.push(Entry::Short(0x0112, vec![99]));
    sample.gps_ifd = Some(vec![
        Entry::Ascii(0x0001, "N".to_owned()),
        Entry::Rational(0x0002, Vec::new()),
    ]);
    let (bytes, _, _) = JpegSample {
        exif: Some(sample),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    let record = photo(parse_file("weird.jpg", &bytes));
    assert!(record.exif_present);
    assert!(record.fields.orientation.is_none());
    assert!(record.fields.latitude.is_none());
    assert!(record
        .warnings
        .iter()
        .any(|warning| warning.contains("Orientation")));
    assert!(record
        .warnings
        .iter()
        .any(|warning| warning.contains("数量为 0")));
}

#[test]
fn heic_and_heif_are_identified_but_not_parsed() {
    let mut heic = vec![0, 0, 0, 0x18];
    heic.extend_from_slice(b"ftypheic");
    heic.extend_from_slice(&[0, 0, 0, 0]);
    heic.extend_from_slice(b"mif1heic");
    heic.extend_from_slice(&[0u8; 32]);
    let record = photo(parse_file("DCIM/Camera/IMG_0003.HEIC", &heic));
    assert_eq!(record.format, RealFormat::Heic);
    assert!(!record.exif_present);
    assert_eq!(record.reason, "heif_not_parsed");
    assert!(record.fields.missing().contains(&"datetime_original"));
}

#[test]
fn run_summary_counts_every_category() {
    let mut summary = RunSummary::default();
    let (with_gps, _, _) = JpegSample {
        exif: Some(ExifSample::with_gps()),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    let (no_gps, _, _) = JpegSample {
        exif: Some(ExifSample::without_gps()),
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    let (plain, _, _) = JpegSample {
        with_scan: true,
        ..JpegSample::default()
    }
    .build();
    accumulate(&mut summary, &parse_file("a.jpg", &with_gps));
    accumulate(&mut summary, &parse_file("b.jpg", &no_gps));
    accumulate(&mut summary, &parse_file("c.jpg", &plain));
    accumulate(&mut summary, &parse_file("d.jpg", &plain[..plain.len() / 2]));
    accumulate(&mut summary, &parse_file("e.jpg", b"not an image"));
    summary.finish();
    assert_eq!(summary.total, 5);
    assert_eq!(summary.with_exif, 2);
    assert_eq!(summary.with_gps, 1);
    assert_eq!(summary.without_gps, 4);
    assert_eq!(summary.without_exif, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.excluded_non_image, 1);
    assert!(summary.text.contains("文件数 5"), "{}", summary.text);
    assert!(summary.text.contains("含 GPS 1"), "{}", summary.text);
    assert!(summary.reasons.contains(&("not_image".to_owned(), 1)));
    assert!(summary.reasons.contains(&(reason::TRUNCATED.to_owned(), 1)));
}
