//! Synthetic NTFS image construction for tests.
//!
//! Builds a self-consistent in-memory NTFS volume (boot sector + a
//! single FILE record placed at a known cluster) so that
//! [`NtfsFile::new`] can load and parse a record without a real
//! filesystem image. Records carry hand-built resident attributes.

use alloc::vec;
use alloc::vec::Vec;
use fsmnt_testkit::Cursor;

use crate::attribute::NtfsAttributeType;
use crate::ntfs::Ntfs;

use super::NtfsFile;

pub(crate) const SECTOR_SIZE: usize = 512;
pub(crate) const RECORD_SIZE: usize = 1024;
/// LCN where the synthetic FILE record lives (cluster size == sector size == 512,
/// so this is byte offset 8 * 512 = 4096).
pub(crate) const RECORD_LCN: u64 = 8;
pub(crate) const RECORD_POSITION: u64 = RECORD_LCN * 512;

/// Builds a 512-byte NTFS boot sector with `sector_size=512`,
/// `sectors_per_cluster=1`, 1024-byte file records, and a small volume.
pub(crate) fn boot_sector() -> [u8; SECTOR_SIZE] {
    let mut bs = [0u8; SECTOR_SIZE];
    bs[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    bs[3..11].copy_from_slice(b"NTFS    "); // OEM ID
    bs[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
    bs[0x0D] = 1; // sectors per cluster
    bs[0x28..0x30].copy_from_slice(&4096u64.to_le_bytes()); // total sectors
    bs[0x30..0x38].copy_from_slice(&2u64.to_le_bytes()); // MFT LCN (byte 1024)
    bs[0x38..0x40].copy_from_slice(&64u64.to_le_bytes()); // MFT mirror LCN (byte 32768)
    bs[0x40] = 0xF6; // clusters_per_mft_record = -10 => 2^10 = 1024-byte records
    bs[0x48..0x50].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes()); // serial
    bs[510] = 0x55;
    bs[511] = 0xAA;
    bs
}

/// A resident attribute to embed in a synthetic FILE record.
pub(crate) struct ResidentAttr {
    pub ty: NtfsAttributeType,
    pub instance: u16,
    pub name: &'static str,
    pub value: Vec<u8>,
}

/// Encodes one resident attribute (header + optional name + value).
fn encode_resident(attr: &ResidentAttr) -> Vec<u8> {
    let name_utf16: Vec<u8> = attr
        .name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let name_offset = 24usize; // resident header is 24 bytes
    let value_offset = name_offset + name_utf16.len();
    // 8-byte align the total length.
    let unpadded = value_offset + attr.value.len();
    let length = unpadded.div_ceil(8) * 8;

    let mut buf = vec![0u8; length];
    buf[0..4].copy_from_slice(&attr.ty.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(
        &u32::try_from(length)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    buf[8] = 0; // is_non_resident = 0 (resident)
    buf[9] = u8::try_from(attr.name.encode_utf16().count()).expect("test value fits u8"); // name_length (code points)
    buf[10..12].copy_from_slice(
        &u16::try_from(name_offset)
            .expect("test value fits u16")
            .to_le_bytes(),
    );
    buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
    buf[14..16].copy_from_slice(&attr.instance.to_le_bytes());
    // Resident-specific:
    buf[16..20].copy_from_slice(
        &u32::try_from(attr.value.len())
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // value_length
    buf[20..22].copy_from_slice(
        &u16::try_from(value_offset)
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // value_offset
    buf[22] = 0; // indexed_flag
    buf[name_offset..name_offset + name_utf16.len()].copy_from_slice(&name_utf16);
    buf[value_offset..value_offset + attr.value.len()].copy_from_slice(&attr.value);
    buf
}

/// Builds a complete 1024-byte FILE record carrying the supplied
/// resident attributes, then applies a valid Update Sequence Array
/// so [`crate::record::Record::fixup`] succeeds.
///
/// `flags` are the [`super::NtfsFileFlags`] bits; `seq` the sequence
/// number; `hard_links` the hard-link count.
pub(crate) fn file_record(
    flags: u16,
    seq: u16,
    hard_links: u16,
    attrs: &[ResidentAttr],
) -> [u8; RECORD_SIZE] {
    let mut rec = [0u8; RECORD_SIZE];

    // --- FILE record header ---
    rec[0..4].copy_from_slice(b"FILE");
    let usa_offset = 0x30u16; // update sequence array offset
    rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    // update_sequence_count = 1 (USN) + 2 fixup entries (two 512-byte sectors).
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    rec[8..16].copy_from_slice(&0u64.to_le_bytes()); // logfile sequence number

    rec[16..18].copy_from_slice(&seq.to_le_bytes()); // sequence_number
    rec[18..20].copy_from_slice(&hard_links.to_le_bytes()); // hard_link_count
    let first_attr_offset = 0x38u16;
    rec[20..22].copy_from_slice(&first_attr_offset.to_le_bytes()); // first_attribute_offset
    rec[22..24].copy_from_slice(&flags.to_le_bytes()); // flags

    // --- attributes (start at first_attr_offset) ---
    let mut off = usize::from(first_attr_offset);
    for attr in attrs {
        let encoded = encode_resident(attr);
        rec[off..off + encoded.len()].copy_from_slice(&encoded);
        off += encoded.len();
    }
    // End marker.
    rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let used = off + 8;

    // data_size (used) and allocated_size (whole record).
    rec[24..28].copy_from_slice(
        &u32::try_from(used)
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // data_size
    rec[28..32].copy_from_slice(
        &u32::try_from(RECORD_SIZE)
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // allocated_size

    // --- Update Sequence Array fixup ---
    // USN value (0x0001) followed by the two real bytes per sector.
    let usn: u16 = 0x0001;
    let usa = usize::from(usa_offset);
    rec[usa..usa + 2].copy_from_slice(&usn.to_le_bytes()); // USN
    // Save the genuine sector-end bytes into the array, then stamp the USN
    // into the last 2 bytes of each sector so fixup validates and restores.
    for (i, sector_end) in [SECTOR_SIZE - 2, 2 * SECTOR_SIZE - 2]
        .into_iter()
        .enumerate()
    {
        let real = [rec[sector_end], rec[sector_end + 1]];
        let entry = usa + 2 + i * 2;
        rec[entry..entry + 2].copy_from_slice(&real);
        rec[sector_end..sector_end + 2].copy_from_slice(&usn.to_le_bytes());
    }
    rec
}

/// Builds a `$FILE_NAME` attribute value with the given parent record
/// number, namespace byte, and UTF-16 name. Header layout matches
/// `FileNameHeader` (66-byte header, then the name).
pub(crate) fn file_name_value(
    parent_record: u64,
    parent_sequence: u16,
    namespace: u8,
    is_directory: bool,
    name: &str,
) -> Vec<u8> {
    let name_utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut v = vec![0u8; 66 + name_utf16.len()];
    // parent_directory_reference: record (48-bit) | (seq << 48)
    let parent_ref = (parent_record & 0xFFFF_FFFF_FFFF) | (u64::from(parent_sequence) << 48);
    v[0..8].copy_from_slice(&parent_ref.to_le_bytes());
    // file_attributes at offset 56 (8+32+8+8).
    let file_attributes: u32 = if is_directory { 0x1000_0000 } else { 0x20 };
    v[56..60].copy_from_slice(&file_attributes.to_le_bytes());
    v[64] = u8::try_from(name.encode_utf16().count()).expect("test value fits u8"); // name_length (code points)
    v[65] = namespace;
    v[66..66 + name_utf16.len()].copy_from_slice(&name_utf16);
    v
}

/// Builds a `$I30` `$INDEX_ROOT` attribute value holding a single
/// `FILE_NAME` entry for `child` (record number, name, directory flag),
/// followed by the empty `LAST_ENTRY` terminator. The index is "small"
/// (no `$INDEX_ALLOCATION`).
pub(crate) fn index_root_i30_value(
    child_record: u64,
    child_is_directory: bool,
    child_name: &str,
) -> Vec<u8> {
    // FILE_NAME key for the entry.
    let key = file_name_value(5, 1, 1, child_is_directory, child_name);
    let entry_header = 16usize;
    let entry1_len = (entry_header + key.len()).div_ceil(8) * 8;
    let term_len = 16usize; // LAST_ENTRY terminator (header only)

    let node_header = 16usize;
    let entries_offset = node_header; // entries start right after node header
    let index_size = entries_offset + entry1_len + term_len; // used bytes in node
    let allocated_size = index_size;

    let mut v = vec![0u8; 16 + index_size];
    // IndexRootHeader.
    v[0..4].copy_from_slice(&NtfsAttributeType::FileName.as_u32().to_le_bytes()); // ty
    v[4..8].copy_from_slice(&0x01u32.to_le_bytes()); // collation_rule
    v[8..12].copy_from_slice(&4096u32.to_le_bytes()); // index_record_size
    v[12] = 1; // clusters_per_index_record
    // IndexNodeHeader (at offset 16).
    let n = 16usize;
    v[n..n + 4].copy_from_slice(
        &u32::try_from(entries_offset)
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // entries_offset
    v[n + 4..n + 8].copy_from_slice(
        &u32::try_from(index_size)
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // index_size
    v[n + 8..n + 12].copy_from_slice(
        &u32::try_from(allocated_size)
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // allocated_size
    v[n + 12] = 0; // flags (small index)

    // Entry 1 (real FILE_NAME entry) at offset 16 + entries_offset.
    let e1 = 16 + entries_offset;
    let file_ref = (child_record & 0xFFFF_FFFF_FFFF) | (1u64 << 48);
    v[e1..e1 + 8].copy_from_slice(&file_ref.to_le_bytes()); // file reference
    v[e1 + 8..e1 + 10].copy_from_slice(
        &u16::try_from(entry1_len)
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // index_entry_length
    v[e1 + 10..e1 + 12].copy_from_slice(
        &u16::try_from(key.len())
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // key_length
    v[e1 + 12] = 0; // flags
    v[e1 + entry_header..e1 + entry_header + key.len()].copy_from_slice(&key);

    // Terminator entry (LAST_ENTRY, no key).
    let e2 = e1 + entry1_len;
    v[e2 + 8..e2 + 10].copy_from_slice(
        &u16::try_from(term_len)
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // index_entry_length
    v[e2 + 10..e2 + 12].copy_from_slice(&0u16.to_le_bytes()); // key_length
    v[e2 + 12] = 0x02; // flags = LAST_ENTRY
    v
}

/// Builds a directory FILE record (`IS_DIRECTORY`) carrying a `$I30`
/// `$INDEX_ROOT` attribute with a single child entry.
pub(crate) fn directory_record(
    child_record: u64,
    child_is_directory: bool,
    child_name: &str,
) -> [u8; RECORD_SIZE] {
    let index_root = index_root_i30_value(child_record, child_is_directory, child_name);
    let attrs = [ResidentAttr {
        ty: NtfsAttributeType::IndexRoot,
        instance: 0,
        name: "$I30",
        value: index_root,
    }];
    file_record(0x0003, 1, 1, &attrs) // IN_USE | IS_DIRECTORY
}

/// Loads a synthetic FILE record into an [`Ntfs`] + [`NtfsFile`] pair.
///
/// Returns a leaked `Ntfs` reference so the returned file can outlive
/// the call; acceptable in test code.
pub(crate) fn load(record: &[u8; RECORD_SIZE], record_number: u64) -> (Ntfs, Cursor<Vec<u8>>) {
    let mut image =
        vec![0u8; usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE];
    image[..SECTOR_SIZE].copy_from_slice(&boot_sector());
    image[usize::try_from(RECORD_POSITION).expect("test value fits usize")
        ..usize::try_from(RECORD_POSITION).expect("test value fits usize") + RECORD_SIZE]
        .copy_from_slice(record);
    let mut cursor = Cursor::new(image);
    let ntfs = Ntfs::new(&mut cursor).unwrap();
    let _ = record_number;
    (ntfs, cursor)
}

/// Encodes one non-resident attribute carrying a single data run that
/// maps `cluster_count` clusters starting at absolute `start_lcn`.
fn encode_non_resident(
    ty: NtfsAttributeType,
    start_lcn: u64,
    cluster_count: u64,
    data_size: u64,
) -> Vec<u8> {
    let header_size = 64usize; // NtfsNonResidentAttributeHeader size
    // Single data run: header byte = (vcn_len << 4) | cc_len, then
    // cluster_count bytes (LE) then vcn bytes (signed LE), then 0 terminator.
    let cc_bytes = start_lcn_bytes(cluster_count);
    let vcn_bytes = start_lcn_bytes(start_lcn);
    let mut data_run = Vec::new();
    data_run.push(
        (u8::try_from(vcn_bytes.len()).expect("test value fits u8") << 4)
            | u8::try_from(cc_bytes.len()).expect("test value fits u8"),
    );
    data_run.extend_from_slice(&cc_bytes);
    data_run.extend_from_slice(&vcn_bytes);
    data_run.push(0); // terminator

    let data_runs_offset = header_size;
    let unpadded = data_runs_offset + data_run.len();
    let length = unpadded.div_ceil(8) * 8;

    let mut buf = vec![0u8; length];
    buf[0..4].copy_from_slice(&ty.as_u32().to_le_bytes());
    buf[4..8].copy_from_slice(
        &u32::try_from(length)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    buf[8] = 1; // is_non_resident = 1
    buf[9] = 0; // name_length
    buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // name_offset
    buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
    buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // instance
    // Non-resident header fields (start at offset 16):
    buf[16..24].copy_from_slice(&0u64.to_le_bytes()); // lowest_vcn
    let highest_vcn = cluster_count.saturating_sub(1);
    buf[24..32].copy_from_slice(&highest_vcn.to_le_bytes()); // highest_vcn
    buf[32..34].copy_from_slice(
        &u16::try_from(data_runs_offset)
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // data_runs_offset
    buf[34] = 0; // compression_unit_exponent
    // reserved [35..40]
    let allocated = cluster_count * 512; // cluster size == sector size
    buf[40..48].copy_from_slice(&allocated.to_le_bytes()); // allocated_size
    buf[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
    buf[56..64].copy_from_slice(&data_size.to_le_bytes()); // initialized_size
    buf[data_runs_offset..data_runs_offset + data_run.len()].copy_from_slice(&data_run);
    buf
}

/// Minimal little-endian byte encoding of a value (at least 1 byte).
fn start_lcn_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
        bytes.pop();
    }
    bytes
}

/// Builds a $MFT record (record 0) whose non-resident $DATA attribute
/// maps `record_count` 1024-byte records starting at the MFT LCN (2).
fn mft_record(record_count: u64) -> [u8; RECORD_SIZE] {
    let mft_lcn = 2u64;
    let clusters = record_count * (1024 / 512);
    let data_size = record_count * 1024;
    let data_attr = encode_non_resident(NtfsAttributeType::Data, mft_lcn, clusters, data_size);

    let mut rec = [0u8; RECORD_SIZE];
    rec[0..4].copy_from_slice(b"FILE");
    let usa_offset = 0x30u16;
    rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number
    rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
    let first_attr_offset = 0x38u16;
    rec[20..22].copy_from_slice(&first_attr_offset.to_le_bytes());
    rec[22..24].copy_from_slice(&0x0001u16.to_le_bytes()); // IN_USE

    let mut off = usize::from(first_attr_offset);
    rec[off..off + data_attr.len()].copy_from_slice(&data_attr);
    off += data_attr.len();
    rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let used = off + 8;
    rec[24..28].copy_from_slice(
        &u32::try_from(used)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    rec[28..32].copy_from_slice(
        &u32::try_from(RECORD_SIZE)
            .expect("test value fits u32")
            .to_le_bytes(),
    );

    apply_fixup(&mut rec, usa_offset);
    rec
}

/// Applies a valid Update Sequence Array to a 1024-byte record.
fn apply_fixup(rec: &mut [u8; RECORD_SIZE], usa_offset: u16) {
    let usn: u16 = 0x0001;
    let usa = usize::from(usa_offset);
    rec[usa..usa + 2].copy_from_slice(&usn.to_le_bytes());
    for (i, sector_end) in [SECTOR_SIZE - 2, 2 * SECTOR_SIZE - 2]
        .into_iter()
        .enumerate()
    {
        let real = [rec[sector_end], rec[sector_end + 1]];
        let entry = usa + 2 + i * 2;
        rec[entry..entry + 2].copy_from_slice(&real);
        rec[sector_end..sector_end + 2].copy_from_slice(&usn.to_le_bytes());
    }
}

/// Builds a full NTFS image with a working $MFT spanning `records.len()`
/// records (record 0 is generated as $MFT; the caller-supplied records
/// fill slots 1..). The MFT lives at LCN 2 and the mirror at LCN 4.
///
/// Returns the image bytes. Use [`Ntfs::new`] then `ntfs.file(fs, n)`.
pub(crate) fn mft_image(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
    let record_count = u64::try_from(records.len() + 1).expect("test record count fits in u64");
    let mft_lcn = 2u64;
    let mft_byte = mft_lcn * 512;
    let mirror_lcn = 64u64;
    let mirror_byte = mirror_lcn * 512;

    // Image must cover the boot sector, the mirror region, and all MFT records.
    let mft_region_end = mft_byte + record_count * 1024;
    let mirror_region_end = mirror_byte + 4 * 1024;
    let size =
        usize::try_from(mft_region_end.max(mirror_region_end)).expect("test value fits usize");
    let mut image = vec![0u8; size];
    image[..SECTOR_SIZE].copy_from_slice(&boot_sector());

    // Record 0 = $MFT.
    let mft = mft_record(record_count);
    let base = usize::try_from(mft_byte).expect("test value fits usize");
    image[base..base + RECORD_SIZE].copy_from_slice(&mft);
    // Records 1.. = caller-supplied.
    for (i, rec) in records.iter().enumerate() {
        let pos = base + (i + 1) * RECORD_SIZE;
        image[pos..pos + RECORD_SIZE].copy_from_slice(rec);
    }
    image
}

/// Number of `u16` entries in the `$UpCase` table.
const UPCASE_ENTRY_COUNT: usize = 65536;
/// Size of the `$UpCase` table in bytes.
const UPCASE_BYTES: usize = UPCASE_ENTRY_COUNT * 2;

/// Builds an NTFS image with a working `$MFT` (records 0..=10) where
/// record 10 is `$UpCase` with a non-resident `$DATA` mapping an identity
/// uppercase table. `records` fill slots 1..=9. Enables
/// [`Ntfs::read_upcase_table`] in tests so case-insensitive comparisons work.
pub(crate) fn mft_image_with_upcase(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
    assert!(
        records.len() <= 9,
        "records fill slots 1..=9 (record 10 is $UpCase)"
    );
    let mft_lcn = 2u64;
    let mft_byte = usize::try_from(mft_lcn).expect("test value fits usize") * SECTOR_SIZE;
    let record_count = 11u64; // records 0..=10

    // Identity upcase table lives well past the MFT and mirror regions.
    let upcase_lcn = 256u64; // byte 131072
    let upcase_byte = usize::try_from(upcase_lcn).expect("test value fits usize") * SECTOR_SIZE;
    let upcase_bytes = u64::try_from(UPCASE_BYTES).expect("test upcase table size fits in u64");
    let upcase_clusters = upcase_bytes.div_ceil(512);

    let size = upcase_byte + UPCASE_BYTES;
    let mut image = vec![0u8; size];
    image[..SECTOR_SIZE].copy_from_slice(&boot_sector());

    // Record 0 = $MFT spanning 11 records.
    image[mft_byte..mft_byte + RECORD_SIZE].copy_from_slice(&mft_record(record_count));
    // Records 1..=9 = caller-supplied (zero-filled if absent; those slots
    // will fail to parse but build/test code only touches the ones it opens).
    for (i, rec) in records.iter().enumerate() {
        let pos = mft_byte + (i + 1) * RECORD_SIZE;
        image[pos..pos + RECORD_SIZE].copy_from_slice(rec);
    }
    // Fill any unused slots 1..=9 with a minimal valid in-use FILE record so
    // ntfs.file() for those numbers (if ever opened) does not error.
    for slot in (records.len() + 1)..=9 {
        let pos = mft_byte + slot * RECORD_SIZE;
        image[pos..pos + RECORD_SIZE].copy_from_slice(&file_record(0x0001, 1, 1, &[]));
    }

    // Record 10 = $UpCase with non-resident $DATA of exactly UPCASE_BYTES.
    let data_attr = encode_non_resident(
        NtfsAttributeType::Data,
        upcase_lcn,
        upcase_clusters,
        upcase_bytes,
    );
    let mut upcase_rec = [0u8; RECORD_SIZE];
    upcase_rec[0..4].copy_from_slice(b"FILE");
    let usa_offset = 0x30u16;
    upcase_rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    upcase_rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    upcase_rec[16..18].copy_from_slice(&1u16.to_le_bytes());
    upcase_rec[18..20].copy_from_slice(&1u16.to_le_bytes());
    let first_attr_offset = 0x38u16;
    upcase_rec[20..22].copy_from_slice(&first_attr_offset.to_le_bytes());
    upcase_rec[22..24].copy_from_slice(&0x0001u16.to_le_bytes());
    let mut off = usize::from(first_attr_offset);
    upcase_rec[off..off + data_attr.len()].copy_from_slice(&data_attr);
    off += data_attr.len();
    upcase_rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let used = off + 8;
    upcase_rec[24..28].copy_from_slice(
        &u32::try_from(used)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    upcase_rec[28..32].copy_from_slice(
        &u32::try_from(RECORD_SIZE)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    apply_fixup(&mut upcase_rec, usa_offset);
    let r10 = mft_byte + 10 * RECORD_SIZE;
    image[r10..r10 + RECORD_SIZE].copy_from_slice(&upcase_rec);

    // Identity uppercase table: uppercase[i] == i for every code unit.
    for i in 0..UPCASE_ENTRY_COUNT {
        let b = upcase_byte + i * 2;
        image[b..b + 2]
            .copy_from_slice(&u16::try_from(i).expect("test value fits u16").to_le_bytes());
    }
    image
}

/// Builds an `Ntfs`, loads the record at `RECORD_POSITION`, and returns
/// the resulting `NtfsFile`. Panics on parse failure.
pub(crate) fn open_file<'n>(
    ntfs: &'n Ntfs,
    cursor: &mut Cursor<Vec<u8>>,
    record_number: u64,
) -> NtfsFile<'n> {
    use core::num::NonZeroU64;
    NtfsFile::new(
        ntfs,
        cursor,
        NonZeroU64::new(RECORD_POSITION).unwrap(),
        record_number,
    )
    .unwrap()
}
