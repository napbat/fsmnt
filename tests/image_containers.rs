//! Public-API coverage for decoded disk-image containers.

use std::io::{Read, Seek, SeekFrom, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use fsmnt::device::{
    DetectedBootSector, DeviceReader, Disk, DiskLayout, FilesystemDriver, ImageFormat, ImageReader,
};
use fsmnt::{
    FsEntry, FsError, FsMetadata, FsResult, ImageOpenOptions, OpenImageError, TargetFilesystem,
    open_image, open_image_with_options,
};

const EWF_CHUNK_SIZE: usize = 32_768;
const EWF1_SIGNATURE: [u8; 8] = [b'E', b'V', b'F', 0x09, 0x0d, 0x0a, 0xff, 0x00];
const EWF_DESCRIPTOR_SIZE: usize = 76;
const EWF_TABLE_DESCRIPTOR_OFFSET: u64 = 183;
const EWF_SECTORS_DESCRIPTOR_OFFSET: u64 = 287;
const EWF_SECTORS_DATA_OFFSET: u64 = 363;
const SECTOR_SIZE: usize = 512;
const MARKER_OFFSET: usize = 100;

struct EmptyFilesystem;

impl TargetFilesystem for EmptyFilesystem {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        Err(FsError::NotFound(path.to_string()))
    }

    fn try_exists(&mut self, _path: &str) -> FsResult<bool> {
        Ok(false)
    }

    fn try_is_dir(&mut self, _path: &str) -> FsResult<bool> {
        Ok(false)
    }

    fn try_is_file(&mut self, _path: &str) -> FsResult<bool> {
        Ok(false)
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        Err(FsError::NotFound(path.to_string()))
    }

    fn read_dir(&mut self, _path: &str) -> FsResult<Vec<FsEntry>> {
        Ok(Vec::new())
    }
}

struct InspectingNtfsDriver {
    marker: u8,
}

struct AcceptingImageDriver;

impl FilesystemDriver for AcceptingImageDriver {
    fn name(&self) -> &'static str {
        "accepting-image"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected.is_filesystem() || detected == DetectedBootSector::BitLocker
    }

    fn open(
        &self,
        _reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(EmptyFilesystem))
    }
}

impl FilesystemDriver for InspectingNtfsDriver {
    fn name(&self) -> &'static str {
        "inspecting-ntfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ntfs
    }

    fn open(
        &self,
        mut reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let mut sector = [0_u8; SECTOR_SIZE];
        reader
            .read_exact(&mut sector)
            .map_err(|error| FsError::Filesystem(error.to_string()))?;
        if sector[3..11] != *b"NTFS    " || sector[MARKER_OFFSET] != self.marker {
            return Err(FsError::Filesystem(
                "driver did not receive decoded image bytes".to_string(),
            ));
        }
        Ok(Box::new(EmptyFilesystem))
    }
}

fn registry(marker: u8) -> fsmnt::device::DriverRegistry {
    let mut registry = fsmnt::device::DriverRegistry::new();
    registry.register(Box::new(InspectingNtfsDriver { marker }));
    registry
}

fn accepting_registry() -> fsmnt::device::DriverRegistry {
    let mut registry = fsmnt::device::DriverRegistry::new();
    registry.register(Box::new(AcceptingImageDriver));
    registry
}

fn ntfs_media(filesystem_offset: usize, marker: u8) -> Vec<u8> {
    let mut media = vec![0_u8; EWF_CHUNK_SIZE];
    let sector = &mut media[filesystem_offset..filesystem_offset + SECTOR_SIZE];
    sector[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 8;
    sector[MARKER_OFFSET] = marker;
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
    media
}

fn synthetic_ewf(media: &[u8]) -> std::io::Result<Vec<u8>> {
    if media.len() > EWF_CHUNK_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "synthetic EWF media exceeds one chunk",
        ));
    }

    let mut chunk = media.to_vec();
    chunk.resize(EWF_CHUNK_SIZE, 0);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&chunk)?;
    let compressed = encoder.finish()?;
    let compressed_length = u64::try_from(compressed.len())
        .map_err(|_| std::io::Error::other("compressed chunk length exceeds u64"))?;

    // Minimal one-chunk EWF v1 layout. The selected reader accepts zeroed
    // descriptor checksum fields in this synthetic integration fixture.
    let done_descriptor_offset = EWF_SECTORS_DATA_OFFSET + compressed_length;

    let mut image = Vec::new();
    image.extend_from_slice(&ewf_header());
    image.extend_from_slice(&descriptor(b"volume", EWF_TABLE_DESCRIPTOR_OFFSET, 170));

    let mut volume = [0_u8; 94];
    volume[0..4].copy_from_slice(&1_u32.to_le_bytes());
    volume[4..8].copy_from_slice(&1_u32.to_le_bytes());
    volume[8..12].copy_from_slice(&64_u32.to_le_bytes());
    volume[12..16].copy_from_slice(&512_u32.to_le_bytes());
    volume[16..24].copy_from_slice(&64_u64.to_le_bytes());
    image.extend_from_slice(&volume);

    image.extend_from_slice(&descriptor(b"table", EWF_SECTORS_DESCRIPTOR_OFFSET, 104));
    let mut table_header = [0_u8; 24];
    table_header[0..4].copy_from_slice(&1_u32.to_le_bytes());
    table_header[8..16].copy_from_slice(&EWF_SECTORS_DATA_OFFSET.to_le_bytes());
    image.extend_from_slice(&table_header);
    image.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

    image.extend_from_slice(&descriptor(
        b"sectors",
        done_descriptor_offset,
        u64::try_from(EWF_DESCRIPTOR_SIZE).expect("descriptor size fits u64") + compressed_length,
    ));
    image.extend_from_slice(&compressed);
    image.extend_from_slice(&descriptor(
        b"done",
        0,
        u64::try_from(EWF_DESCRIPTOR_SIZE).expect("descriptor size fits u64"),
    ));
    Ok(image)
}

fn ewf_header() -> [u8; 13] {
    let mut header = [0_u8; 13];
    header[0..8].copy_from_slice(&EWF1_SIGNATURE);
    header[8] = 1;
    header[9..11].copy_from_slice(&1_u16.to_le_bytes());
    header
}

fn descriptor(section_type: &[u8], next: u64, size: u64) -> [u8; 76] {
    let mut descriptor = [0_u8; 76];
    descriptor[..section_type.len()].copy_from_slice(section_type);
    descriptor[16..24].copy_from_slice(&next.to_le_bytes());
    descriptor[24..32].copy_from_slice(&size.to_le_bytes());
    descriptor
}

#[test]
fn raw_images_still_follow_the_filesystem_driver_path() {
    const MARKER: u8 = 0xa5;
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("volume.img");
    std::fs::write(&path, ntfs_media(0, MARKER)).expect("write raw image");

    let opened = open_image(&path, &registry(MARKER)).expect("open raw image");

    assert_eq!(opened.format, ImageFormat::Raw);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, 32_768);
}

#[test]
fn decoded_media_offsets_have_a_typed_error() {
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("volume.img");
    std::fs::write(&path, ntfs_media(0, 0x11)).expect("write raw image");
    let options = ImageOpenOptions::new().with_offset(32_768);

    let error = open_image_with_options(&path, &registry(0x11), options)
        .err()
        .expect("end offset must fail");

    assert!(matches!(
        error,
        OpenImageError::OffsetOutOfRange {
            offset: 32_768,
            size_bytes: 32_768,
            ..
        }
    ));
}

#[test]
fn ewf_images_decode_before_detection_and_driver_dispatch() {
    const MARKER: u8 = 0x5a;
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("evidence.E01");
    let image = synthetic_ewf(&ntfs_media(0, MARKER)).expect("build EWF image");
    std::fs::write(&path, image).expect("write EWF image");

    let opened = open_image(&path, &registry(MARKER)).expect("open EWF image");

    assert_eq!(opened.format, ImageFormat::Ewf);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, 32_768);
}

#[test]
fn ewf_offsets_address_decoded_logical_media() {
    const FILESYSTEM_OFFSET: usize = 4096;
    const MARKER: u8 = 0x3c;
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("partitioned.E01");
    let image = synthetic_ewf(&ntfs_media(FILESYSTEM_OFFSET, MARKER)).expect("build EWF image");
    std::fs::write(&path, image).expect("write EWF image");
    let offset = u64::try_from(FILESYSTEM_OFFSET).expect("filesystem offset fits u64");
    let options = ImageOpenOptions::new().with_offset(offset);

    let opened = open_image_with_options(&path, &registry(MARKER), options)
        .expect("open filesystem within EWF image");

    assert_eq!(opened.format, ImageFormat::Ewf);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, 32_768 - offset);
}

#[test]
fn invalid_e01_is_reported_as_an_ewf_error() {
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("broken.E01");
    std::fs::write(&path, b"not EWF!").expect("write invalid EWF image");

    let error = ImageReader::open(&path)
        .err()
        .expect("invalid EWF must fail");

    assert_eq!(error.path(), path);
    assert!(error.to_string().contains("EWF"));
}

const MIB: usize = 1024 * 1024;
const MIB_U32: u32 = 1024 * 1024;
const MIB_U64: u64 = 1024 * 1024;
const VHD_DYNAMIC_HEADER_OFFSET: usize = 512;
const VHD_BAT_OFFSET: usize = 1536;
const VHD_BLOCK_OFFSET: usize = 2048;
const VHD_PAYLOAD_OFFSET: usize = VHD_BLOCK_OFFSET + SECTOR_SIZE;

#[derive(Clone, Copy)]
enum VhdDiskKind {
    Fixed,
    Dynamic,
    Differencing,
}

impl VhdDiskKind {
    const fn code(self) -> u32 {
        match self {
            Self::Fixed => 2,
            Self::Dynamic => 3,
            Self::Differencing => 4,
        }
    }

    const fn data_offset(self) -> u64 {
        match self {
            Self::Fixed => u64::MAX,
            Self::Dynamic | Self::Differencing => 512,
        }
    }
}

fn synthetic_fixed_vhd(media: &[u8], unique_id: [u8; 16]) -> Vec<u8> {
    let mut image = media.to_vec();
    image.extend_from_slice(&vhd_footer(VhdDiskKind::Fixed, media.len(), unique_id));
    image
}

fn synthetic_sparse_vhd(
    kind: VhdDiskKind,
    media: Option<&[u8]>,
    unique_id: [u8; 16],
    parent_unique_id: [u8; 16],
    parent_name: &str,
) -> Vec<u8> {
    assert!(matches!(
        kind,
        VhdDiskKind::Dynamic | VhdDiskKind::Differencing
    ));
    let virtual_size = media.map_or(EWF_CHUNK_SIZE, <[u8]>::len);
    let footer = vhd_footer(kind, virtual_size, unique_id);
    let trailing_footer_offset = if media.is_some() {
        VHD_PAYLOAD_OFFSET + MIB
    } else {
        VHD_BLOCK_OFFSET
    };
    let mut image = vec![0_u8; trailing_footer_offset + SECTOR_SIZE];
    image[..SECTOR_SIZE].copy_from_slice(&footer);
    let header = vhd_dynamic_header(parent_unique_id, parent_name);
    image[VHD_DYNAMIC_HEADER_OFFSET..VHD_DYNAMIC_HEADER_OFFSET + header.len()]
        .copy_from_slice(&header);
    let bat_entry = if media.is_some() {
        u32::try_from(VHD_BLOCK_OFFSET / SECTOR_SIZE).expect("VHD BAT sector fits u32")
    } else {
        u32::MAX
    };
    put_u32_be(&mut image, VHD_BAT_OFFSET, bat_entry);
    if let Some(media) = media {
        let sectors = media.len().div_ceil(SECTOR_SIZE);
        for sector in 0..sectors {
            image[VHD_BLOCK_OFFSET + sector / 8] |=
                0x80_u8 >> u8::try_from(sector % 8).expect("bitmap bit fits u8");
        }
        image[VHD_PAYLOAD_OFFSET..VHD_PAYLOAD_OFFSET + media.len()].copy_from_slice(media);
    }
    image[trailing_footer_offset..].copy_from_slice(&footer);
    image
}

fn vhd_footer(kind: VhdDiskKind, virtual_size: usize, unique_id: [u8; 16]) -> [u8; 512] {
    let mut footer = [0_u8; 512];
    footer[..8].copy_from_slice(b"conectix");
    put_u32_be(&mut footer, 8, 2);
    put_u32_be(&mut footer, 12, 0x0001_0000);
    put_u64_be(&mut footer, 16, kind.data_offset());
    footer[28..32].copy_from_slice(b"fsmn");
    put_u32_be(&mut footer, 32, 0x0001_0000);
    footer[36..40].copy_from_slice(b"Wi2k");
    let size = u64::try_from(virtual_size).expect("test virtual size fits u64");
    put_u64_be(&mut footer, 40, size);
    put_u64_be(&mut footer, 48, size);
    put_u32_be(&mut footer, 56, 0x0001_0101);
    put_u32_be(&mut footer, 60, kind.code());
    footer[68..84].copy_from_slice(&unique_id);
    finish_vhd_checksum(&mut footer, 64);
    footer
}

fn vhd_dynamic_header(parent_unique_id: [u8; 16], parent_name: &str) -> [u8; 1024] {
    let mut header = [0_u8; 1024];
    header[..8].copy_from_slice(b"cxsparse");
    put_u64_be(&mut header, 8, u64::MAX);
    put_u64_be(
        &mut header,
        16,
        u64::try_from(VHD_BAT_OFFSET).expect("VHD BAT offset fits u64"),
    );
    put_u32_be(&mut header, 24, 0x0001_0000);
    put_u32_be(&mut header, 28, 1);
    put_u32_be(&mut header, 32, MIB_U32);
    header[40..56].copy_from_slice(&parent_unique_id);
    for (index, unit) in parent_name.encode_utf16().take(256).enumerate() {
        let offset = 64 + index * 2;
        header[offset..offset + 2].copy_from_slice(&unit.to_be_bytes());
    }
    finish_vhd_checksum(&mut header, 36);
    header
}

fn finish_vhd_checksum(bytes: &mut [u8], checksum_offset: usize) {
    bytes[checksum_offset..checksum_offset + 4].fill(0);
    let checksum = !bytes
        .iter()
        .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
    put_u32_be(bytes, checksum_offset, checksum);
}

const BAT_REGION_GUID: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const METADATA_REGION_GUID: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];
const FILE_PARAMETERS_GUID: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const VIRTUAL_DISK_SIZE_GUID: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const VIRTUAL_DISK_ID_GUID: [u8; 16] = [
    0xab, 0x12, 0xca, 0xbe, 0xe6, 0xb2, 0x23, 0x45, 0x93, 0xef, 0xc3, 0x09, 0xe0, 0x00, 0xc7, 0x46,
];
const LOGICAL_SECTOR_SIZE_GUID: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];
const PHYSICAL_SECTOR_SIZE_GUID: [u8; 16] = [
    0xc7, 0x48, 0xa3, 0xcd, 0x5d, 0x44, 0x71, 0x44, 0x9c, 0xc9, 0xe9, 0x88, 0x52, 0x51, 0xc5, 0x56,
];
const PARENT_LOCATOR_GUID: [u8; 16] = [
    0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c,
];
const VHDX_LOCATOR_TYPE_GUID: [u8; 16] = [
    0xb7, 0xef, 0x4a, 0xb0, 0x9e, 0xd1, 0x81, 0x4a, 0xb7, 0x89, 0x25, 0xb8, 0xe9, 0x44, 0x59, 0x13,
];

#[derive(Clone, Copy)]
enum VhdxPayload<'a> {
    FullyPresent(&'a [u8]),
    ParentOnly,
    PartiallyPresent(&'a [u8]),
}

fn synthetic_vhdx(
    payload: VhdxPayload<'_>,
    data_write_guid: [u8; 16],
    parent: Option<([u8; 16], &str)>,
) -> Vec<u8> {
    let file_mib = match payload {
        VhdxPayload::ParentOnly => 4,
        VhdxPayload::FullyPresent(_) => 5,
        VhdxPayload::PartiallyPresent(_) => 6,
    };
    let mut image = vec![0_u8; file_mib * MIB];
    image[..8].copy_from_slice(b"vhdxfile");
    let header1 = vhdx_header(1, data_write_guid);
    let header2 = vhdx_header(2, data_write_guid);
    image[64 * 1024..64 * 1024 + header1.len()].copy_from_slice(&header1);
    image[128 * 1024..128 * 1024 + header2.len()].copy_from_slice(&header2);
    let regions = vhdx_region_table();
    image[192 * 1024..192 * 1024 + regions.len()].copy_from_slice(&regions);
    image[256 * 1024..256 * 1024 + regions.len()].copy_from_slice(&regions);
    let metadata = vhdx_metadata(parent);
    image[2 * MIB..3 * MIB].copy_from_slice(&metadata);

    match payload {
        VhdxPayload::FullyPresent(media) => {
            put_u64_le(&mut image, 3 * MIB, (4_u64 << 20) | 6);
            image[4 * MIB..4 * MIB + media.len()].copy_from_slice(media);
        }
        VhdxPayload::ParentOnly => {}
        VhdxPayload::PartiallyPresent(media) => {
            put_u64_le(&mut image, 3 * MIB, (4_u64 << 20) | 7);
            let bitmap_entry = 3 * MIB + 4096 * 8;
            put_u64_le(&mut image, bitmap_entry, (5_u64 << 20) | 6);
            image[4 * MIB..4 * MIB + media.len()].copy_from_slice(media);
            image[5 * MIB] = 1;
        }
    }
    image
}

fn vhdx_header(sequence: u64, data_write_guid: [u8; 16]) -> [u8; 4096] {
    let mut header = [0_u8; 4096];
    header[..4].copy_from_slice(b"head");
    put_u64_le(&mut header, 8, sequence);
    header[16..32].fill(0x51);
    header[32..48].copy_from_slice(&data_write_guid);
    put_u16_le(&mut header, 66, 1);
    put_u32_le(&mut header, 68, MIB_U32);
    put_u64_le(&mut header, 72, MIB_U64);
    finish_crc32c(&mut header, 4);
    header
}

fn vhdx_region_table() -> Vec<u8> {
    let mut table = vec![0_u8; 64 * 1024];
    table[..4].copy_from_slice(b"regi");
    put_u32_le(&mut table, 8, 2);
    table[16..32].copy_from_slice(&BAT_REGION_GUID);
    put_u64_le(&mut table, 32, 3 * MIB_U64);
    put_u32_le(&mut table, 40, MIB_U32);
    put_u32_le(&mut table, 44, 1);
    table[48..64].copy_from_slice(&METADATA_REGION_GUID);
    put_u64_le(&mut table, 64, 2 * MIB_U64);
    put_u32_le(&mut table, 72, MIB_U32);
    put_u32_le(&mut table, 76, 1);
    finish_crc32c(&mut table, 4);
    table
}

fn vhdx_metadata(parent: Option<([u8; 16], &str)>) -> Vec<u8> {
    let has_parent = parent.is_some();
    let mut file_parameters = vec![0_u8; 8];
    put_u32_le(&mut file_parameters, 0, MIB_U32);
    put_u32_le(&mut file_parameters, 4, if has_parent { 2 } else { 0 });
    let virtual_size = u64::try_from(EWF_CHUNK_SIZE)
        .expect("test virtual size fits u64")
        .to_le_bytes()
        .to_vec();
    let logical_sector_size = 512_u32.to_le_bytes().to_vec();
    let physical_sector_size = logical_sector_size.clone();
    let mut items = vec![
        (FILE_PARAMETERS_GUID, file_parameters),
        (VIRTUAL_DISK_SIZE_GUID, virtual_size),
        (VIRTUAL_DISK_ID_GUID, vec![0x44; 16]),
        (LOGICAL_SECTOR_SIZE_GUID, logical_sector_size),
        (PHYSICAL_SECTOR_SIZE_GUID, physical_sector_size),
    ];
    if let Some((linkage, name)) = parent {
        items.push((PARENT_LOCATOR_GUID, vhdx_parent_locator(linkage, name)));
    }

    let mut metadata = vec![0_u8; MIB];
    metadata[..8].copy_from_slice(b"metadata");
    put_u16_le(
        &mut metadata,
        10,
        u16::try_from(items.len()).expect("metadata item count fits u16"),
    );
    let mut item_offset = 64 * 1024;
    for (index, (guid, value)) in items.into_iter().enumerate() {
        let entry = 32 + index * 32;
        metadata[entry..entry + 16].copy_from_slice(&guid);
        put_u32_le(
            &mut metadata,
            entry + 16,
            u32::try_from(item_offset).expect("metadata offset fits u32"),
        );
        put_u32_le(
            &mut metadata,
            entry + 20,
            u32::try_from(value.len()).expect("metadata length fits u32"),
        );
        let flags = if matches!(guid, FILE_PARAMETERS_GUID | PARENT_LOCATOR_GUID) {
            4
        } else {
            6
        };
        put_u32_le(&mut metadata, entry + 24, flags);
        metadata[item_offset..item_offset + value.len()].copy_from_slice(&value);
        item_offset += value.len();
    }
    metadata
}

fn vhdx_parent_locator(linkage: [u8; 16], parent_name: &str) -> Vec<u8> {
    let pairs = [
        (
            utf16_le("parent_linkage"),
            utf16_le(&format!("{{{}}}", format_guid(linkage))),
        ),
        (utf16_le("relative_path"), utf16_le(parent_name)),
    ];
    let table_end = 20 + pairs.len() * 12;
    let string_bytes = pairs
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum::<usize>();
    let mut locator = vec![0_u8; table_end + string_bytes];
    locator[..16].copy_from_slice(&VHDX_LOCATOR_TYPE_GUID);
    put_u16_le(
        &mut locator,
        18,
        u16::try_from(pairs.len()).expect("locator pair count fits u16"),
    );
    let mut string_offset = table_end;
    for (index, (key, value)) in pairs.into_iter().enumerate() {
        let entry = 20 + index * 12;
        put_u32_le(
            &mut locator,
            entry,
            u32::try_from(string_offset).expect("locator key offset fits u32"),
        );
        put_u16_le(
            &mut locator,
            entry + 8,
            u16::try_from(key.len()).expect("locator key length fits u16"),
        );
        locator[string_offset..string_offset + key.len()].copy_from_slice(&key);
        string_offset += key.len();
        put_u32_le(
            &mut locator,
            entry + 4,
            u32::try_from(string_offset).expect("locator value offset fits u32"),
        );
        put_u16_le(
            &mut locator,
            entry + 10,
            u16::try_from(value.len()).expect("locator value length fits u16"),
        );
        locator[string_offset..string_offset + value.len()].copy_from_slice(&value);
        string_offset += value.len();
    }
    locator
}

fn utf16_le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn format_guid(guid: [u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
        u16::from_le_bytes([guid[4], guid[5]]),
        u16::from_le_bytes([guid[6], guid[7]]),
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

fn finish_crc32c(bytes: &mut [u8], checksum_offset: usize) {
    bytes[checksum_offset..checksum_offset + 4].fill(0);
    put_u32_le(bytes, checksum_offset, crc32c::crc32c(bytes));
}

fn put_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64_be(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn fixed_and_dynamic_vhd_images_expose_virtual_media() {
    const FIXED_MARKER: u8 = 0x21;
    const DYNAMIC_MARKER: u8 = 0x43;
    let directory = tempfile::tempdir().expect("temporary VHD directory");
    let fixed = directory.path().join("fixed.vhd");
    let dynamic = directory.path().join("dynamic.vhd");
    std::fs::write(
        &fixed,
        synthetic_fixed_vhd(&ntfs_media(0, FIXED_MARKER), [0x10; 16]),
    )
    .expect("write fixed VHD");
    std::fs::write(
        &dynamic,
        synthetic_sparse_vhd(
            VhdDiskKind::Dynamic,
            Some(&ntfs_media(0, DYNAMIC_MARKER)),
            [0x20; 16],
            [0; 16],
            "",
        ),
    )
    .expect("write dynamic VHD");

    for (path, marker) in [(fixed, FIXED_MARKER), (dynamic, DYNAMIC_MARKER)] {
        let opened = open_image(&path, &registry(marker)).expect("open VHD image");
        assert_eq!(opened.format, ImageFormat::Vhd);
        assert_eq!(opened.detected, DetectedBootSector::Ntfs);
        assert_eq!(opened.size_bytes, 32_768);
    }
}

#[test]
fn differencing_vhd_resolves_its_parent_by_name() {
    const PARENT_MARKER: u8 = 0x65;
    const CHILD_MARKER: u8 = 0x76;
    const PARENT_ID: [u8; 16] = [0x31; 16];
    let directory = tempfile::tempdir().expect("temporary differencing VHD directory");
    let parent = directory.path().join("parent.vhd");
    let child = directory.path().join("unallocated.avhd");
    let partial_child = directory.path().join("partial.avhd");
    let mut parent_media = ntfs_media(0, PARENT_MARKER);
    parent_media[SECTOR_SIZE + 9] = 0x87;
    std::fs::write(&parent, synthetic_fixed_vhd(&parent_media, PARENT_ID))
        .expect("write parent VHD");
    std::fs::write(
        &child,
        synthetic_sparse_vhd(
            VhdDiskKind::Differencing,
            None,
            [0x32; 16],
            PARENT_ID,
            "parent.vhd",
        ),
    )
    .expect("write child VHD");
    let child_media = ntfs_media(0, CHILD_MARKER);
    let mut partial_image = synthetic_sparse_vhd(
        VhdDiskKind::Differencing,
        Some(&child_media),
        [0x33; 16],
        PARENT_ID,
        "parent.vhd",
    );
    partial_image[VHD_BLOCK_OFFSET..VHD_PAYLOAD_OFFSET].fill(0);
    partial_image[VHD_BLOCK_OFFSET] = 0x80;
    std::fs::write(&partial_child, partial_image).expect("write partial child VHD");

    let opened = open_image(&child, &registry(PARENT_MARKER)).expect("open differencing VHD");
    assert_eq!(opened.format, ImageFormat::Vhd);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);

    let opened =
        open_image(&partial_child, &registry(CHILD_MARKER)).expect("open partial VHD chain");
    assert_eq!(opened.format, ImageFormat::Vhd);
    let mut image = ImageReader::open(&partial_child).expect("open partial VHD reader");
    let mut sectors = [0_u8; SECTOR_SIZE * 2];
    image
        .read_exact(&mut sectors)
        .expect("read partial VHD sectors");
    assert_eq!(sectors[MARKER_OFFSET], CHILD_MARKER);
    assert_eq!(sectors[SECTOR_SIZE + 9], 0x87);
}

#[test]
fn fully_present_vhdx_exposes_virtual_media() {
    const MARKER: u8 = 0x87;
    let directory = tempfile::tempdir().expect("temporary VHDX directory");
    let path = directory.path().join("disk.vhdx");
    let media = ntfs_media(0, MARKER);
    std::fs::write(
        &path,
        synthetic_vhdx(VhdxPayload::FullyPresent(&media), [0x61; 16], None),
    )
    .expect("write VHDX");

    let opened = open_image(&path, &registry(MARKER)).expect("open VHDX image");
    assert_eq!(opened.format, ImageFormat::Vhdx);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, 32_768);
}

#[test]
fn avhdx_uses_sector_bitmap_and_parent_fallback() {
    const PARENT_MARKER: u8 = 0xa1;
    const CHILD_MARKER: u8 = 0xb2;
    const PARENT_GUID: [u8; 16] = [0x71; 16];
    let directory = tempfile::tempdir().expect("temporary AVHDX directory");
    let parent_path = directory.path().join("parent.vhdx");
    let child_path = directory.path().join("checkpoint.avhdx");
    let mut parent_media = ntfs_media(0, PARENT_MARKER);
    parent_media[SECTOR_SIZE + 7] = 0xc3;
    let child_media = ntfs_media(0, CHILD_MARKER);
    std::fs::write(
        &parent_path,
        synthetic_vhdx(VhdxPayload::FullyPresent(&parent_media), PARENT_GUID, None),
    )
    .expect("write parent VHDX");
    std::fs::write(
        &child_path,
        synthetic_vhdx(
            VhdxPayload::PartiallyPresent(&child_media),
            [0x72; 16],
            Some((PARENT_GUID, "parent.vhdx")),
        ),
    )
    .expect("write AVHDX");

    let opened = open_image(&child_path, &registry(CHILD_MARKER)).expect("open AVHDX chain");
    assert_eq!(opened.format, ImageFormat::Vhdx);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);

    let mut image = ImageReader::open(&child_path).expect("open AVHDX reader");
    let mut sectors = [0_u8; SECTOR_SIZE * 2];
    image.read_exact(&mut sectors).expect("read AVHDX sectors");
    assert_eq!(sectors[MARKER_OFFSET], CHILD_MARKER);
    assert_eq!(sectors[SECTOR_SIZE + 7], 0xc3);
    image.seek(SeekFrom::End(-1)).expect("seek within AVHDX");
    assert_eq!(
        image.stream_position().expect("query AVHDX position"),
        32_767
    );
}

#[test]
fn parent_only_avhdx_inherits_unallocated_blocks() {
    const MARKER: u8 = 0xd4;
    const PARENT_GUID: [u8; 16] = [0x81; 16];
    let directory = tempfile::tempdir().expect("temporary parent-only AVHDX directory");
    let parent_path = directory.path().join("base.vhdx");
    let child_path = directory.path().join("checkpoint.avhdx");
    let parent_media = ntfs_media(0, MARKER);
    std::fs::write(
        &parent_path,
        synthetic_vhdx(VhdxPayload::FullyPresent(&parent_media), PARENT_GUID, None),
    )
    .expect("write base VHDX");
    std::fs::write(
        &child_path,
        synthetic_vhdx(
            VhdxPayload::ParentOnly,
            [0x82; 16],
            Some((PARENT_GUID, "base.vhdx")),
        ),
    )
    .expect("write parent-only AVHDX");

    let opened = open_image(&child_path, &registry(MARKER)).expect("open inherited AVHDX");
    assert_eq!(opened.format, ImageFormat::Vhdx);
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
}

#[test]
fn configured_hyper_v_directory_opens_every_vhdx_layer_read_only() {
    let Some(directory) = std::env::var_os("FSMNT_VHDX_DIRECTORY") else {
        return;
    };
    let mut paths = std::fs::read_dir(&directory)
        .expect("read configured Hyper-V directory")
        .map(|entry| entry.expect("read Hyper-V directory entry").path())
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("vhdx")
                        || extension.eq_ignore_ascii_case("avhdx")
                })
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert!(!paths.is_empty(), "configured directory has no VHDX layers");
    for path in paths {
        let mut image = ImageReader::open(&path)
            .unwrap_or_else(|error| panic!("failed to open {}: {error}", path.display()));
        assert_eq!(image.format(), ImageFormat::Vhdx);
        assert!(!image.is_empty());
        let sector_size = u64::try_from(SECTOR_SIZE).expect("sector size fits u64");
        let length = image.len();
        let sample_offsets = [
            0,
            (length / 3 / sector_size) * sector_size,
            (length / 2 / sector_size) * sector_size,
            length.saturating_sub(sector_size),
        ];
        for offset in sample_offsets {
            image
                .seek(SeekFrom::Start(offset))
                .unwrap_or_else(|error| panic!("failed to seek {}: {error}", path.display()));
            let mut sector = [0_u8; SECTOR_SIZE];
            image
                .read_exact(&mut sector)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        }

        let reader = ImageReader::open(&path)
            .unwrap_or_else(|error| panic!("failed to reopen {}: {error}", path.display()));
        let mut disk = Disk::new(reader)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        assert!(matches!(disk.layout(), DiskLayout::Gpt { .. }));
        let sector_size = disk.sector_size();
        let mut selected = None;
        for index in 0..disk.partition_count() {
            let entry = disk.gpt_partition(index).unwrap_or_else(|error| {
                panic!("failed to read GPT entry in {}: {error}", path.display())
            });
            if entry.is_empty() {
                continue;
            }
            let offset = entry.start_offset(sector_size);
            let detected = disk.detect_boot_sector_at(offset).unwrap_or_else(|error| {
                panic!(
                    "failed to inspect a partition in {}: {error}",
                    path.display()
                )
            });
            if detected.is_filesystem() || detected == DetectedBootSector::BitLocker {
                selected = Some((offset, detected));
                break;
            }
        }
        let (offset, detected) = selected.unwrap_or_else(|| {
            panic!(
                "no supported filesystem partition found in {}",
                path.display()
            )
        });
        let options = ImageOpenOptions::new().with_offset(offset);
        let opened = open_image_with_options(&path, &accepting_registry(), options).unwrap_or_else(
            |error| panic!("failed to open {} at {offset}: {error}", path.display()),
        );
        assert_eq!(opened.format, ImageFormat::Vhdx);
        assert_eq!(opened.detected, detected);
    }
}
