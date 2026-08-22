use super::*;
use crate::file::NtfsFile;
use crate::indexes::NtfsFileNameIndex;
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsStandardInformation;
use core::num::NonZeroU64;
use fsmnt_parser_core::io::FsReadSeek;
use fsmnt_testkit::Cursor;

/// Byte position of the synthetic FILE record inside the image.
/// Chosen well clear of the 512-byte boot sector.
const RECORD_POSITION: u64 = 4096;

/// Size of the synthetic FILE record (matches the boot sector's
/// `clusters_per_mft_record = -10` => 2^10 = 1024 bytes).
const RECORD_SIZE: usize = 1024;

/// Offset of the first attribute within the synthetic FILE record,
/// placed just after the 16-byte header + 6-byte update sequence array.
const FIRST_ATTRIBUTE_OFFSET: usize = 56;

/// Builds a minimal valid 512-byte NTFS boot sector that `Ntfs::new`
/// accepts: NTFS OEM ID, 512-byte sectors, 1 sector/cluster
/// (`cluster_size` = 512), 1 KiB MFT records, and the 0x55AA signature.
fn make_boot_sector() -> [u8; 512] {
    let mut bs = [0u8; 512];
    bs[3..11].copy_from_slice(b"NTFS    "); // OEM ID (offset 0x03)
    bs[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
    bs[0x0D] = 1; // sectors_per_cluster => cluster_size 512
    bs[0x28..0x30].copy_from_slice(&8192u64.to_le_bytes()); // total_sectors
    bs[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn (>0)
    bs[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn (>0)
    bs[0x40] = 0xF6; // clusters_per_mft_record = -10 => 1024-byte records
    bs[0x48..0x50].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes()); // serial
    bs[510] = 0x55;
    bs[511] = 0xAA;
    bs
}

/// Builds a 1 KiB FILE record whose first attribute starts at
/// `FIRST_ATTRIBUTE_OFFSET` and is initialised from `attr`. The update
/// sequence array is laid out so `Record::fixup` succeeds (the two
/// per-sector USN slots at offsets 510 and 1022 carry the USN before
/// fixup, and the array supplies their fixed-up values afterwards).
fn make_file_record(attr: &[u8]) -> Vec<u8> {
    let mut rec = vec![0u8; RECORD_SIZE];
    // RecordHeader: "FILE" signature.
    rec[0..4].copy_from_slice(b"FILE");
    // update_sequence_offset = 0x30 (offset 4).
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    // update_sequence_count = 3 (1 USN + 2 array entries) (offset 6).
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    // Update sequence array at 0x30: USN, then two fixup values.
    let usn = 0x0001u16;
    rec[0x30..0x32].copy_from_slice(&usn.to_le_bytes()); // USN
    rec[0x32..0x34].copy_from_slice(&0xAAAAu16.to_le_bytes()); // sector 0 value
    rec[0x34..0x36].copy_from_slice(&0xBBBBu16.to_le_bytes()); // sector 1 value
    // Per-sector USN slots must equal the USN for fixup to validate.
    rec[510..512].copy_from_slice(&usn.to_le_bytes());
    rec[1022..1024].copy_from_slice(&usn.to_le_bytes());

    // FileRecordHeader fields (after the 16-byte RecordHeader).
    rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number
    rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
    // first_attribute_offset (offset 20).
    rec[20..22].copy_from_slice(&u16::try_from(FIRST_ATTRIBUTE_OFFSET).expect("test value fits u16").to_le_bytes());
    rec[22..24].copy_from_slice(&1u16.to_le_bytes()); // flags (IN_USE)
    rec[24..28].copy_from_slice(&u32::try_from(RECORD_SIZE).expect("test value fits u32").to_le_bytes()); // data_size
    rec[28..32].copy_from_slice(&u32::try_from(RECORD_SIZE).expect("test value fits u32").to_le_bytes()); // allocated_size

    rec[FIRST_ATTRIBUTE_OFFSET..FIRST_ATTRIBUTE_OFFSET + attr.len()].copy_from_slice(attr);
    rec
}

/// Assembles a full in-memory NTFS image: boot sector, padding, and a
/// single FILE record at `RECORD_POSITION`.
fn make_image(attr: &[u8]) -> Cursor<Vec<u8>> {
    let mut data = vec![0u8; usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE];
    data[0..512].copy_from_slice(&make_boot_sector());
    let record = make_file_record(attr);
    data[usize::try_from(RECORD_POSITION).expect("test value fits usize")..usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE]
        .copy_from_slice(&record);
    Cursor::new(data)
}

/// A resident `$DATA` attribute (type 0x80) whose value is `value`,
/// with the given attribute `flags` and an attribute `name`
/// (UTF-16 code points, 2 bytes each). Layout follows
/// `NtfsResidentAttributeHeader`.
fn resident_attribute(value: &[u8], flags: u16, name_utf16: &[u16]) -> Vec<u8> {
    let header = 24usize; // resident header rounded up to 8 bytes
    let name_offset = header;
    let name_bytes = name_utf16.len() * 2;
    let value_offset = name_offset + name_bytes;
    let attribute_length = value_offset + value.len();

    let mut attr = vec![0u8; attribute_length];
    attr[0..4].copy_from_slice(&NtfsAttributeType::Data.as_u32().to_le_bytes()); // ty
    attr[4..8].copy_from_slice(&u32::try_from(attribute_length).expect("test value fits u32").to_le_bytes()); // length
    attr[8] = 0; // is_non_resident = 0 (resident)
    attr[9] = u8::try_from(name_utf16.len()).expect("test value fits u8"); // name_length (chars)
    attr[10..12].copy_from_slice(&u16::try_from(name_offset).expect("test value fits u16").to_le_bytes()); // name_offset
    attr[12..14].copy_from_slice(&flags.to_le_bytes()); // flags
    attr[14..16].copy_from_slice(&7u16.to_le_bytes()); // instance
    attr[16..20].copy_from_slice(&u32::try_from(value.len()).expect("test value fits u32").to_le_bytes()); // value_length
    attr[20..22].copy_from_slice(&u16::try_from(value_offset).expect("test value fits u16").to_le_bytes()); // value_offset
    attr[22] = 0; // indexed_flag
    for (i, cp) in name_utf16.iter().enumerate() {
        attr[name_offset + i * 2..name_offset + i * 2 + 2].copy_from_slice(&cp.to_le_bytes());
    }
    attr[value_offset..value_offset + value.len()].copy_from_slice(value);
    attr
}

/// A non-resident `$DATA` attribute (type 0x80). The data runs region
/// (between `data_runs_offset` and `attribute_length`) carries `runs`.
fn non_resident_attribute(
    runs: &[u8],
    flags: u16,
    compression_unit_exponent: u8,
    data_size: u64,
    initialized_size: u64,
) -> Vec<u8> {
    let header = 64usize; // size_of NtfsNonResidentAttributeHeader (packed)
    let data_runs_offset = header;
    let attribute_length = data_runs_offset + runs.len();

    let mut attr = vec![0u8; attribute_length];
    attr[0..4].copy_from_slice(&NtfsAttributeType::Data.as_u32().to_le_bytes()); // ty
    attr[4..8].copy_from_slice(&u32::try_from(attribute_length).expect("test value fits u32").to_le_bytes()); // length
    attr[8] = 1; // is_non_resident = 1
    attr[9] = 0; // name_length
    attr[10..12].copy_from_slice(&0u16.to_le_bytes()); // name_offset
    attr[12..14].copy_from_slice(&flags.to_le_bytes()); // flags
    attr[14..16].copy_from_slice(&7u16.to_le_bytes()); // instance
    // lowest_vcn @16 (8), highest_vcn @24 (8): leave zero.
    attr[32..34].copy_from_slice(&u16::try_from(data_runs_offset).expect("test value fits u16").to_le_bytes()); // data_runs_offset
    attr[34] = compression_unit_exponent; // compression_unit_exponent
    attr[40..48].copy_from_slice(&0u64.to_le_bytes()); // allocated_size
    attr[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
    attr[56..64].copy_from_slice(&initialized_size.to_le_bytes()); // initialized_size
    attr[data_runs_offset..attribute_length].copy_from_slice(runs);
    attr
}

/// Construct an `Ntfs` plus a `NtfsFile` over the synthetic image.
/// The caller holds the returned tuple so the borrows stay alive.
fn open(attr: &[u8]) -> (Ntfs, Cursor<Vec<u8>>) {
    let mut fs = make_image(attr);
    let ntfs = Ntfs::new(&mut fs).unwrap();
    (ntfs, fs)
}

fn file<'n>(ntfs: &'n Ntfs, fs: &mut Cursor<Vec<u8>>) -> NtfsFile<'n> {
    NtfsFile::new(ntfs, fs, NonZeroU64::new(RECORD_POSITION).unwrap(), 0).unwrap()
}

/// Builds an image with the attribute placed at a custom `offset`
/// within the FILE record (rather than `FIRST_ATTRIBUTE_OFFSET`), so
/// tests can drive a chosen `remaining_length` for boundary checks.
fn open_at(offset: usize, attr: &[u8]) -> (Ntfs, Cursor<Vec<u8>>) {
    let mut record = make_file_record(&[]);
    record[20..22].copy_from_slice(&u16::try_from(offset).expect("test value fits u16").to_le_bytes()); // first_attribute_offset
    record[offset..offset + attr.len()].copy_from_slice(attr);
    // Restore the per-sector update-sequence slots in case the attribute
    // overlapped them, so the FILE record still passes USA fixup.
    let usn = 0x0001u16;
    record[510..512].copy_from_slice(&usn.to_le_bytes());
    record[1022..1024].copy_from_slice(&usn.to_le_bytes());
    let mut data = vec![0u8; usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE];
    data[0..512].copy_from_slice(&make_boot_sector());
    data[usize::try_from(RECORD_POSITION).expect("test value fits usize")..usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE]
        .copy_from_slice(&record);
    (
        Ntfs::new(&mut Cursor::new(data.clone())).unwrap(),
        Cursor::new(data),
    )
}

/// As [`make_image`] but fills the cluster region targeted by a data run
/// (`fill_lcn` * `cluster_size`) with `fill_length` bytes of `fill_byte`, so
/// non-resident reads observe known initialized data.
fn open_with_cluster_data(
    attr: &[u8],
    fill_lcn: u64,
    fill_length: usize,
    fill_byte: u8,
) -> (Ntfs, Cursor<Vec<u8>>) {
    let mut data = vec![0u8; usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE];
    data[0..512].copy_from_slice(&make_boot_sector());
    let record = make_file_record(attr);
    data[usize::try_from(RECORD_POSITION).expect("test value fits usize")..usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE]
        .copy_from_slice(&record);
    let fill_start = usize::try_from(fill_lcn * 512 ).expect("test value fits usize");
    for b in &mut data[fill_start..fill_start + fill_length] {
        *b = fill_byte;
    }
    (
        Ntfs::new(&mut Cursor::new(data.clone())).unwrap(),
        Cursor::new(data),
    )
}

#[test]
fn synthetic_resident_attribute_accessors() {
    let value = b"hello";
    let name = [u16::from(b'A'), u16::from(b'D'), u16::from(b'S')]; // "ADS"
    let attr_bytes = resident_attribute(value, NtfsAttributeFlags::COMPRESSED.bits(), &name);
    let attr_len = u32::try_from(attr_bytes.len()).expect("test value fits u32");
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

    // attribute_length reads the on-disk length field (line 252/253):
    // distinct from 0/1 and from offset arithmetic mutations.
    assert_eq!(attr.attribute_length(), attr_len);
    assert!(attr_len > 1);
    // ty (line 446/447).
    assert_eq!(attr.ty().unwrap(), NtfsAttributeType::Data);
    // ensure_ty (line 257/258): matching type Ok, mismatch Err.
    assert!(attr.ensure_ty(NtfsAttributeType::Data).is_ok());
    assert!(attr.ensure_ty(NtfsAttributeType::FileName).is_err());
    // flags (line 271): COMPRESSED set.
    assert_eq!(attr.flags(), NtfsAttributeFlags::COMPRESSED);
    assert!(attr.is_compressed()); // line 605
    // instance (line 279): on-disk value 7, distinct from 0/1.
    assert_eq!(attr.instance(), 7);
    // is_resident (line 286/288): true for resident.
    assert!(attr.is_resident());
    // name (lines 296/302) and name_offset/name_length (310/320/322).
    assert_eq!(attr.name_length(), 6); // 3 chars * 2 bytes
    let parsed_name = attr.name().unwrap();
    assert_eq!(parsed_name.to_string_lossy(), "ADS");
    // offset (line 373): the offset we constructed at.
    assert_eq!(attr.offset(), FIRST_ATTRIBUTE_OFFSET);
    // resident_value_length / resident_value_offset reflected by value.
    assert_eq!(
        attr.value_length(),
        u64::try_from(value.len()).expect("test value length fits u64")
    ); // line 596
    let resident = attr.resident_value().unwrap();
    assert_eq!(resident.data(), value);
    // compression_unit_exponent is None for resident (line 613).
    assert_eq!(attr.compression_unit_exponent(), None);
    assert_eq!(attr.compression_unit_size(&ntfs), None);
}

#[test]
fn synthetic_resident_no_name_and_no_flags() {
    // name_offset 0 / name_length 0 => empty name (line 296 boundary).
    let attr_bytes = resident_attribute(b"xyz", 0, &[]);
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

    assert_eq!(attr.name_length(), 0);
    assert!(attr.name().unwrap().is_empty());
    assert!(!attr.is_compressed());
    assert_eq!(attr.flags(), NtfsAttributeFlags::empty());
}

#[test]
fn synthetic_name_length_zero_with_bad_offset_short_circuits() {
    // name() returns empty when EITHER name_offset or name_length is 0
    // (line 296 `||`). Here name_length == 0 but name_offset is set
    // OUT OF RANGE: the `||` short-circuits to Ok(empty). An `&&`
    // mutation (or `name_length == 0` -> `!= 0`) would instead fall
    // through to validate_name_sizes and surface an offset error.
    let mut attr_bytes = resident_attribute(b"v", 0, &[]);
    let attr_len = u16::try_from(attr_bytes.len()).expect("test value fits u16");
    attr_bytes[9] = 0; // name_length (chars) = 0
    attr_bytes[10..12].copy_from_slice(&(attr_len + 8).to_le_bytes()); // bad name_offset
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(attr.name_length(), 0);
    assert!(attr.name_offset() >= u16::try_from(attr.attribute_length()).expect("test value fits u16"));
    assert!(attr.name().expect("empty name, no validation").is_empty());
}

#[test]
fn synthetic_name_offset_zero_short_circuits() {
    // name_offset == 0 short-circuits to empty (line 296). With a
    // non-zero name_length and name_offset 0, the genuine `== 0` returns
    // Ok(empty); flipping it to `!= 0` would read a non-empty name from
    // the attribute header bytes instead.
    let mut attr_bytes = resident_attribute(b"vv", 0, &[]);
    attr_bytes[9] = 1; // name_length (chars) = 1 (=> 2 bytes)
    attr_bytes[10..12].copy_from_slice(&0u16.to_le_bytes()); // name_offset = 0
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(attr.name_offset(), 0);
    assert_eq!(attr.name_length(), 2);
    assert!(attr.name().expect("empty name").is_empty());
}

#[test]
fn synthetic_non_resident_attribute_accessors() {
    // A simple single data run: header byte 0x21 (1 length byte, 1
    // offset byte), length 0x05 clusters, LCN offset 0x02, terminator.
    let runs = [0x21u8, 0x05, 0x02, 0x00];
    let data_size = 2560u64; // 5 clusters * 512
    let initialized_size = 2048u64;
    let attr_bytes = non_resident_attribute(&runs, 0, 4, data_size, initialized_size);
    let attr_len = u32::try_from(attr_bytes.len()).expect("test value fits u32");
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

    assert!(!attr.is_resident());
    assert_eq!(attr.attribute_length(), attr_len);
    // value_length for non-resident == data_size (line 596 / 355).
    assert_eq!(attr.value_length(), data_size);
    // compression_unit_exponent reads on-disk exponent 4 (line 613/618/620).
    assert_eq!(attr.compression_unit_exponent(), Some(4));
    // compression_unit_size = (1 << 4) * cluster_size(512) = 8192 (line 629).
    assert_eq!(attr.compression_unit_size(&ntfs), Some(16 * 512));
    // The non-resident value parses (exercises data_runs_offset,
    // data_size, initialized_size accessors: lines 341/342/356/362/368).
    let nrv = attr.non_resident_value().unwrap();
    assert_eq!(nrv.len(), data_size);
}

#[test]
fn synthetic_compression_unit_exponent_zero_is_none() {
    // exponent 0 => None (line 620 boundary: `> 0`).
    let runs = [0x00u8];
    let attr_bytes = non_resident_attribute(&runs, 0, 0, 512, 512);
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(attr.compression_unit_exponent(), None);
    assert_eq!(attr.compression_unit_size(&ntfs), None);
}

#[test]
fn synthetic_non_resident_initialized_size_governs_read() {
    // data_size = 1024 (2 clusters), initialized_size = 512 (1 cluster).
    // The data run maps LCN 2 (byte 1024) for 2 clusters; the first
    // cluster is filled with 0xAB. A read of all 1024 bytes returns the
    // 0xAB-initialised first half and zeros beyond initialized_size.
    // Mutating non_resident_value_initialized_size to 0/1 (or its offset
    // arithmetic) shrinks the initialised region and zeros the bytes we
    // assert as 0xAB.
    let runs = [0x21u8, 0x02, 0x02, 0x00]; // 2 clusters at LCN 2
    let data_size = 1024u64;
    let initialized_size = 512u64;
    let attr_bytes = non_resident_attribute(&runs, 0, 0, data_size, initialized_size);
    // Fill BOTH on-disk clusters (bytes 1024..2048) with 0xAB so any
    // bytes read back as zero must come from the initialized_size cap,
    // not from empty disk. An offset-arithmetic mutation of
    // non_resident_value_initialized_size (`+`->`-`) reads the field
    // from the wrong location, yielding a huge value clamped to
    // data_size (1024) and exposing the 0xAB data past offset 512.
    let (ntfs, mut fs) = open_with_cluster_data(&attr_bytes, 2, 1024, 0xAB);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

    let mut value = attr.value(&mut fs).unwrap();
    let mut buf = [0u8; 1024];
    value.read_exact(&mut fs, &mut buf).unwrap();
    // Bytes inside the initialized region are the genuine 0xAB data.
    assert_eq!(buf[0], 0xAB);
    assert_eq!(buf[256], 0xAB);
    assert_eq!(buf[511], 0xAB);
    // Bytes beyond initialized_size (512) read back as zero even though
    // the disk holds 0xAB there.
    assert_eq!(buf[512], 0x00);
    assert_eq!(buf[1023], 0x00);
}

#[cfg(feature = "compression")]
#[test]
fn synthetic_compressed_attribute_decompresses_through_owned_value() {
    let original: Vec<u8> = (0..400_u16)
        .map(|value| u8::try_from(value % 31).expect("test byte fits u8"))
        .collect();
    let header = u16::try_from((original.len() - 1) & 0x0FFF)
        .expect("test chunk length fits u16")
        | (0b011 << 12);
    let mut encoded = header.to_le_bytes().to_vec();
    encoded.extend_from_slice(&original);

    // One allocated cluster at LCN 2 followed by seven sparse clusters is
    // one compressed eight-cluster unit (exponent 3).
    let runs = [0x11, 0x01, 0x02, 0x01, 0x07, 0x00];
    let data_size = u64::try_from(original.len()).unwrap();
    let attribute = non_resident_attribute(
        &runs,
        NtfsAttributeFlags::COMPRESSED.bits(),
        3,
        data_size,
        data_size,
    );
    let (ntfs, mut fs) = open(&attribute);
    let data_offset = 2 * 512;
    fs.get_mut()[data_offset..data_offset + encoded.len()].copy_from_slice(&encoded);
    let file = file(&ntfs, &mut fs);
    let attribute = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

    let value = attribute.value(&mut fs).unwrap();
    assert!(matches!(
        &value,
        NtfsAttributeValue::CompressedNonResident(_)
    ));
    let mut value = value.into_owned(&mut fs).unwrap();
    let mut output = vec![0_u8; original.len()];
    assert_eq!(value.read_at(&mut fs, 0, &mut output).unwrap(), original.len());
    assert_eq!(output, original);
}

#[cfg(not(feature = "compression"))]
#[test]
fn synthetic_compressed_attribute_requires_the_feature() {
    let runs = [0x11, 0x01, 0x02, 0x01, 0x07, 0x00];
    let attribute = non_resident_attribute(
        &runs,
        NtfsAttributeFlags::COMPRESSED.bits(),
        3,
        400,
        400,
    );
    let (ntfs, mut fs) = open(&attribute);
    let file = file(&ntfs, &mut fs);
    let attribute = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

    assert!(matches!(
        attribute.value(&mut fs),
        Err(NtfsError::CompressedAttributeNotSupported)
    ));
}

/// Extracts the `expected`/`actual` fields of an `InvalidAttributeLength`.
fn invalid_length_fields(err: &NtfsError) -> (usize, usize) {
    match err {
        NtfsError::InvalidAttributeLength {
            expected, actual, ..
        } => (*expected, *actual),
        other => panic!("expected InvalidAttributeLength, got {other:?}"),
    }
}

#[test]
fn synthetic_validate_attribute_length_too_short_fires_header_check() {
    // remaining_length(16) < ATTRIBUTE_HEADER_SIZE(16) is false at the
    // boundary, so the header check (line 461) is skipped and the
    // type-min check (line 493) fires instead: the error reports
    // expected = RESIDENT_ATTRIBUTE_MIN_SIZE (23), not 16. A `<= ` or
    // `==` mutation of line 461 would fire the header check, reporting
    // expected = 16.
    let mut attr = vec![0u8; 16];
    attr[0..4].copy_from_slice(&NtfsAttributeType::Data.as_u32().to_le_bytes());
    attr[4..8].copy_from_slice(&16u32.to_le_bytes()); // attribute_length = 16
    attr[8] = 0; // resident
    let offset = RECORD_SIZE - 16; // remaining_length == 16
    let (ntfs, mut fs) = open_at(offset, &attr);
    let file = file(&ntfs, &mut fs);
    let err = NtfsAttribute::new(&file, offset, None).unwrap_err();
    let (expected, _) = invalid_length_fields(&err);
    assert_eq!(expected, RESIDENT_ATTRIBUTE_MIN_SIZE);
}

#[test]
fn synthetic_validate_attribute_length_at_header_size_fires_type_min() {
    // attribute_length(16) < ATTRIBUTE_HEADER_SIZE(16) is false at the
    // boundary (line 470), so validation proceeds to the type-min check
    // (line 493) reporting expected = 23. A `<=`/`==` mutation of line
    // 470 would fire the header check, reporting expected = 16.
    let mut attr_bytes = resident_attribute(b"abcdefgh", 0, &[]);
    attr_bytes[4..8].copy_from_slice(&16u32.to_le_bytes()); // attribute_length = 16
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let err = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap_err();
    let (expected, actual) = invalid_length_fields(&err);
    assert_eq!(expected, RESIDENT_ATTRIBUTE_MIN_SIZE);
    assert_eq!(actual, 16);
}

#[test]
fn synthetic_validate_attribute_length_equal_to_remaining_passes() {
    // attribute_length(968) > remaining_length(968) is false at the
    // boundary (line 478), so the attribute is accepted. A `>=`
    // mutation would reject it.
    let remaining = RECORD_SIZE - FIRST_ATTRIBUTE_OFFSET; // 968
    let mut attr = vec![0u8; remaining];
    attr[0..4].copy_from_slice(&NtfsAttributeType::Data.as_u32().to_le_bytes());
    attr[4..8].copy_from_slice(&u32::try_from(remaining).expect("test value fits u32").to_le_bytes()); // == remaining
    attr[8] = 0; // resident
    attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // value_offset
    let (ntfs, mut fs) = open_at(FIRST_ATTRIBUTE_OFFSET, &attr);
    let file = file(&ntfs, &mut fs);
    let parsed = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(
        usize::try_from(parsed.attribute_length()).expect("test attribute length fits usize"),
        remaining
    );
}

#[test]
fn synthetic_validate_attribute_length_exceeds_remaining_rejected() {
    // attribute_length(969) > remaining_length(968) => Err (line 478),
    // reporting expected = attribute_length, actual = remaining.
    let remaining = RECORD_SIZE - FIRST_ATTRIBUTE_OFFSET; // 968
    let mut attr_bytes = resident_attribute(b"a", 0, &[]);
    attr_bytes[4..8].copy_from_slice(&u32::try_from(remaining + 1 ).expect("test value fits u32").to_le_bytes());
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let err = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap_err();
    let (expected, actual) = invalid_length_fields(&err);
    assert_eq!(expected, remaining + 1);
    assert_eq!(actual, remaining);
}

#[test]
fn synthetic_validate_attribute_length_below_type_min_rejected() {
    // attribute_length(18) < RESIDENT_ATTRIBUTE_MIN_SIZE(23) => Err
    // (line 493), reporting expected = 23.
    let mut attr_bytes = resident_attribute(b"abcd", 0, &[]);
    attr_bytes[4..8].copy_from_slice(&18u32.to_le_bytes()); // 16 <= 18 < 23
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let err = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap_err();
    let (expected, actual) = invalid_length_fields(&err);
    assert_eq!(expected, RESIDENT_ATTRIBUTE_MIN_SIZE);
    assert_eq!(actual, 18);
}

#[test]
fn synthetic_validate_attribute_length_accepts_exact_min() {
    // attribute_length exactly == RESIDENT_ATTRIBUTE_MIN_SIZE (23) is
    // NOT below it, so validation passes (line 493 `<` boundary). A
    // `<=` mutation would reject the attribute.
    let mut attr_bytes = resident_attribute(b"a", 0, &[]); // 25 bytes
    attr_bytes[4..8].copy_from_slice(&u32::try_from(RESIDENT_ATTRIBUTE_MIN_SIZE).expect("test value fits u32").to_le_bytes());
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let parsed = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(
        usize::try_from(parsed.attribute_length()).expect("test attribute length fits usize"),
        RESIDENT_ATTRIBUTE_MIN_SIZE
    );
}

#[test]
fn synthetic_validate_name_sizes_rejects_bad_offset() {
    // name_offset >= attribute_length => InvalidAttributeNameOffset
    // (line 506 / 515). Build a resident attr then corrupt name_offset.
    let name = [u16::from(b'X')];
    let mut attr_bytes = resident_attribute(b"v", 0, &name);
    let attr_len = u16::try_from(attr_bytes.len()).expect("test value fits u16");
    // name_offset field at byte 10..12; set it past the attribute.
    attr_bytes[10..12].copy_from_slice(&(attr_len + 10).to_le_bytes());
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    let err = attr.name().unwrap_err();
    assert!(matches!(err, NtfsError::InvalidAttributeNameOffset { .. }));
}

#[test]
fn synthetic_validate_name_sizes_rejects_bad_length() {
    // name_offset valid but name_offset + name_length > attribute_length
    // => InvalidAttributeNameLength (line 514/515).
    let name = [u16::from(b'X'), u16::from(b'Y')];
    let mut attr_bytes = resident_attribute(b"v", 0, &name);
    // Inflate name_length (chars) at byte 9 so end exceeds the attribute.
    attr_bytes[9] = 200;
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    let err = attr.name().unwrap_err();
    assert!(matches!(err, NtfsError::InvalidAttributeNameLength { .. }));
}

#[test]
fn synthetic_validate_name_sizes_end_equal_to_length_passes() {
    // With an empty value, the name occupies the tail of the attribute:
    // name_offset + name_length == attribute_length. `end > attr_len` is
    // false at the boundary (line 515), so the name parses. A `>=`
    // mutation would reject it.
    let name = [u16::from(b'Z')];
    let attr_bytes = resident_attribute(b"", 0, &name); // 24 + 2 = 26 bytes
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(usize::from(attr.name_offset()) + attr.name_length(), 26);
    assert_eq!(attr.attribute_length(), 26);
    assert_eq!(attr.name().unwrap().to_string_lossy(), "Z");
}

#[test]
fn synthetic_validate_resident_value_sizes_rejects_bad_offset() {
    // resident_value_offset > attribute_length => Err (line 533).
    let mut attr_bytes = resident_attribute(b"vv", 0, &[]);
    let attr_len = u16::try_from(attr_bytes.len()).expect("test value fits u16");
    // value_offset field at byte 20..22.
    attr_bytes[20..22].copy_from_slice(&(attr_len + 4).to_le_bytes());
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    let err = attr.resident_value().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidResidentAttributeValueOffset { .. }
    ));
}

#[test]
fn synthetic_validate_resident_value_sizes_rejects_bad_length() {
    // value_offset + value_length > attribute_length => Err (line 551).
    let mut attr_bytes = resident_attribute(b"vv", 0, &[]);
    // value_length field at byte 16..20; inflate it.
    attr_bytes[16..20].copy_from_slice(&500u32.to_le_bytes());
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    let err = attr.resident_value().unwrap_err();
    assert!(matches!(
        err,
        NtfsError::InvalidResidentAttributeValueLength { .. }
    ));
}

#[test]
fn synthetic_validate_resident_value_offset_equal_to_length_passes() {
    // An empty-value resident attribute has value_offset ==
    // attribute_length (both 24). `value_offset > attr_len` is false at
    // the boundary (line 533), so resident_value succeeds with an empty
    // slice. A `>=` mutation would reject it.
    let attr_bytes = resident_attribute(b"", 0, &[]); // 24 bytes, value_offset 24
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    assert_eq!(attr.attribute_length(), 24);
    let value = attr.resident_value().unwrap();
    assert_eq!(value.data().len(), 0);
}

#[test]
fn synthetic_resident_structured_value_rejects_non_resident() {
    // resident_structured_value on a non-resident attr => Err
    // (line 396 `!is_resident`). Use $STANDARD_INFORMATION type so the
    // ensure_ty check passes first.
    let runs = [0x00u8];
    let mut attr_bytes = non_resident_attribute(&runs, 0, 0, 512, 512);
    attr_bytes[0..4]
        .copy_from_slice(&NtfsAttributeType::StandardInformation.as_u32().to_le_bytes());
    let (ntfs, mut fs) = open(&attr_bytes);
    let file = file(&ntfs, &mut fs);
    let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
    let err = attr
        .resident_structured_value::<NtfsStandardInformation>()
        .unwrap_err();
    assert!(matches!(
        err,
        NtfsError::UnexpectedNonResidentAttribute { .. }
    ));
}

#[test]
fn synthetic_raw_iterator_yields_attribute_then_end() {
    // NtfsAttributesRaw::next walks attributes and stops at the End
    // marker (lines 882/883/887). Two resident attributes back to back
    // followed by the End marker. The iterator advances by
    // `items_range.start += attribute_length` (line 883) and reads the
    // 4-byte type window via `end = start + size_of::<u32>()` (line 888).
    // The first attribute is large enough (value 250 bytes) that the
    // second begins past offset 256: an `items_range.start *=` mutation
    // (883) or an `end = start *` mutation (888) would compute an
    // out-of-range window for the second attribute and yield only one
    // item, so we assert exactly two attributes are returned in
    // ascending offset order.
    let big_value = [b'x'; 250];
    let attr0 = resident_attribute(&big_value, 0, &[]);
    let attr1 = resident_attribute(b"more", 0, &[]);
    let off1 = FIRST_ATTRIBUTE_OFFSET + attr0.len();
    assert!(off1 > 256, "second attribute must start past offset 256");
    let mut buf = attr0.clone();
    buf.extend_from_slice(&attr1);
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // End marker
    let (ntfs, mut fs) = open(&buf);
    let file = file(&ntfs, &mut fs);

    let mut iter = file.attributes_raw();
    let first = iter.next().expect("first attribute").expect("valid");
    assert_eq!(first.ty().unwrap(), NtfsAttributeType::Data);
    assert_eq!(first.offset(), FIRST_ATTRIBUTE_OFFSET);
    assert_eq!(
        usize::try_from(first.attribute_length()).expect("test attribute length fits usize"),
        attr0.len()
    );
    // The iterator advanced by exactly attribute_length to the second
    // attribute (not a multiplied offset).
    let second = iter.next().expect("second attribute").expect("valid");
    assert_eq!(second.offset(), off1);
    assert_eq!(
        usize::try_from(second.attribute_length()).expect("test attribute length fits usize"),
        attr1.len()
    );
    // After both attributes the End marker stops iteration.
    assert!(iter.next().is_none());
}

#[test]
fn synthetic_attributes_iterator_yields_item() {
    // NtfsAttributes::next (line 679) and try_next (line 773) yield the
    // single resident attribute. NtfsAttributesAttached::next (line 812)
    // wraps it as an Iterator.
    let attr_bytes = resident_attribute(b"abc", 0, &[]);
    let mut buf = attr_bytes.clone();
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let (ntfs, mut fs) = open(&buf);
    let file = file(&ntfs, &mut fs);

    let mut attached = file.attributes().attach(&mut fs);
    let item = attached.next().expect("one item").expect("valid");
    let attribute = item.to_attribute().unwrap();
    assert_eq!(attribute.ty().unwrap(), NtfsAttributeType::Data);
    assert!(attached.next().is_none());
}

#[cfg(feature = "arbitrary")]
#[test]
fn synthetic_attribute_type_arbitrary_index_wraps() {
    // The arbitrary impl indexes `variants[index % len]` (line 208).
    // `% len` keeps the index in range; `+ len` or `/ len` would panic
    // or pick the wrong element. Verify the modulo selects correctly
    // for indices spanning more than one full wrap.
    let variants = [
        NtfsAttributeType::StandardInformation,
        NtfsAttributeType::AttributeList,
        NtfsAttributeType::FileName,
        NtfsAttributeType::ObjectId,
        NtfsAttributeType::SecurityDescriptor,
        NtfsAttributeType::VolumeName,
        NtfsAttributeType::VolumeInformation,
        NtfsAttributeType::Data,
        NtfsAttributeType::IndexRoot,
        NtfsAttributeType::IndexAllocation,
        NtfsAttributeType::Bitmap,
        NtfsAttributeType::ReparsePoint,
        NtfsAttributeType::EAInformation,
        NtfsAttributeType::EA,
        NtfsAttributeType::PropertySet,
        NtfsAttributeType::LoggedUtilityStream,
        NtfsAttributeType::End,
    ];
    let len = variants.len();
    // Feed several byte patterns; for each, derive the same `usize`
    // the impl decodes and assert the chosen variant matches
    // `variants[index % len]`. A `+ len` mutation would index out of
    // bounds (panic) for indices producing `index + len >= len`, and a
    // `/ len` mutation would pick a different variant. Large patterns
    // (all-0xFF) drive `index` well above `len`.
    let patterns: [&[u8]; 4] = [
        &[0x00; 16],
        &[0xFF; 16],
        &[0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for raw in patterns {
        let index: usize = arbitrary::Unstructured::new(raw).arbitrary().unwrap();
        let mut u = arbitrary::Unstructured::new(raw);
        let ty = <NtfsAttributeType as arbitrary::Arbitrary>::arbitrary(&mut u).unwrap();
        assert_eq!(ty, variants[index % len]);
    }
    // At least one pattern must produce index >= len so the `% len`
    // versus `+ len` / `/ len` distinction is observable.
    let big: usize = arbitrary::Unstructured::new([0xFFu8; 16].as_slice())
        .arbitrary()
        .unwrap();
    assert!(big >= len);
}

#[test]
fn attribute_flags_display_renders_bits() {
    // Display::fmt forwards to the inner flags storage (line 68): a
    // non-empty flag set renders a non-empty string. The
    // `Ok(Default::default())` mutant writes nothing, producing "".
    let flags = NtfsAttributeFlags::COMPRESSED | NtfsAttributeFlags::SPARSE;
    let rendered = alloc::format!("{flags}");
    assert!(!rendered.is_empty(), "rendered: {rendered:?}");
    assert!(rendered.contains("COMPRESSED"), "rendered: {rendered:?}");
    assert!(rendered.contains("SPARSE"), "rendered: {rendered:?}");
}

#[test]
fn test_empty_data_attribute() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "empty-file".
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry =
        NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "empty-file")
            .unwrap()
            .unwrap();
    let empty_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let data_attribute_item = empty_file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();
    assert_eq!(data_attribute.value_length(), 0);

    let mut data_attribute_value = data_attribute.value(&mut testfs1).unwrap();
    assert!(data_attribute_value.is_empty());

    let mut buf = [0u8; 5];
    let bytes_read = data_attribute_value.read(&mut testfs1, &mut buf).unwrap();
    assert_eq!(bytes_read, 0);
}

#[test]
fn test_zero_bytes_file() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "edge-cases" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry =
        NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
            .unwrap()
            .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Find the zero-bytes file.
    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut edge_cases_finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(
        &mut edge_cases_finder,
        &ntfs,
        &mut testfs1,
        "zero-bytes.bin",
    )
    .unwrap()
    .unwrap();
    let zero_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let data_attribute_item = zero_file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();
    assert_eq!(data_attribute.value_length(), 0);
}

#[test]
fn test_cluster_boundary_file() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "edge-cases" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry =
        NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
            .unwrap()
            .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Find the cluster-boundary file (512 bytes = 1 cluster).
    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut edge_cases_finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(
        &mut edge_cases_finder,
        &ntfs,
        &mut testfs1,
        "cluster-boundary.bin",
    )
    .unwrap()
    .unwrap();
    let cluster_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let data_attribute_item = cluster_file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();
    // 512 bytes = exactly one cluster
    assert_eq!(data_attribute.value_length(), 512);

    // Read and verify we can read all 512 bytes (content is random from /dev/urandom)
    let mut data_value = data_attribute.value(&mut testfs1).unwrap();
    let mut buf = vec![0u8; 512];
    let bytes_read = data_value.read(&mut testfs1, &mut buf).unwrap();
    assert_eq!(bytes_read, 512);
}
