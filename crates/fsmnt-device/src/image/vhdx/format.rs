//! Structural parsing for VHDX headers, regions, metadata, and parent locators.

use super::VhdxError;

pub(super) const MIB: u64 = 1024 * 1024;
pub(super) const HEADER_REGION_SIZE: usize = 1024 * 1024;
pub(super) const LOG_SECTOR_SIZE: usize = 4096;
const HEADER_SIZE: usize = 4096;
const REGION_TABLE_SIZE: usize = 64 * 1024;
const REGION_TABLE1_OFFSET: usize = 192 * 1024;
const REGION_TABLE2_OFFSET: usize = 256 * 1024;
const MAX_REGION_ENTRIES: usize = 2047;
const MAX_METADATA_ENTRIES: usize = 2047;
const MAX_METADATA_REGION_SIZE: usize = 16 * 1024 * 1024;
const MAX_VIRTUAL_SIZE: u64 = 64 * 1024 * 1024 * 1024 * 1024;

pub(super) type Guid = [u8; 16];

const BAT_REGION_GUID: Guid = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const METADATA_REGION_GUID: Guid = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];
const FILE_PARAMETERS_GUID: Guid = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const VIRTUAL_DISK_SIZE_GUID: Guid = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const VIRTUAL_DISK_ID_GUID: Guid = [
    0xab, 0x12, 0xca, 0xbe, 0xe6, 0xb2, 0x23, 0x45, 0x93, 0xef, 0xc3, 0x09, 0xe0, 0x00, 0xc7, 0x46,
];
const LOGICAL_SECTOR_SIZE_GUID: Guid = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];
const PHYSICAL_SECTOR_SIZE_GUID: Guid = [
    0xc7, 0x48, 0xa3, 0xcd, 0x5d, 0x44, 0x71, 0x44, 0x9c, 0xc9, 0xe9, 0x88, 0x52, 0x51, 0xc5, 0x56,
];
const PARENT_LOCATOR_GUID: Guid = [
    0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c,
];
const VHDX_LOCATOR_TYPE_GUID: Guid = [
    0xb7, 0xef, 0x4a, 0xb0, 0x9e, 0xd1, 0x81, 0x4a, 0xb7, 0x89, 0x25, 0xb8, 0xe9, 0x44, 0x59, 0x13,
];

#[derive(Clone, Debug)]
pub(super) struct Header {
    pub(super) data_write_guid: Guid,
    pub(super) log_guid: Guid,
    pub(super) log_length: u32,
    pub(super) log_offset: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Region {
    pub(super) offset: u64,
    pub(super) length: u32,
}

impl Region {
    fn end(self) -> Result<u64, VhdxError> {
        self.offset
            .checked_add(u64::from(self.length))
            .ok_or(VhdxError::OutOfBounds)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Regions {
    pub(super) bat: Region,
    pub(super) metadata: Region,
}

#[derive(Clone, Debug)]
pub(super) struct Metadata {
    pub(super) block_size: u32,
    pub(super) has_parent: bool,
    pub(super) virtual_disk_size: u64,
    pub(super) logical_sector_size: u32,
    pub(super) parent: Option<ParentLocator>,
}

#[derive(Clone, Debug)]
pub(super) struct ParentLocator {
    pub(super) expected_parent_guids: Vec<Guid>,
    pub(super) paths: Vec<ParentPath>,
}

#[derive(Clone, Debug)]
pub(super) struct ParentPath {
    pub(super) kind: ParentPathKind,
    pub(super) value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentPathKind {
    Relative,
    Volume,
    Absolute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataItemKind {
    FileParameters,
    VirtualDiskSize,
    VirtualDiskId,
    LogicalSectorSize,
    PhysicalSectorSize,
    ParentLocator,
    Unknown,
}

impl MetadataItemKind {
    const fn from_guid(guid: Guid) -> Self {
        match guid {
            FILE_PARAMETERS_GUID => Self::FileParameters,
            VIRTUAL_DISK_SIZE_GUID => Self::VirtualDiskSize,
            VIRTUAL_DISK_ID_GUID => Self::VirtualDiskId,
            LOGICAL_SECTOR_SIZE_GUID => Self::LogicalSectorSize,
            PHYSICAL_SECTOR_SIZE_GUID => Self::PhysicalSectorSize,
            PARENT_LOCATOR_GUID => Self::ParentLocator,
            _ => Self::Unknown,
        }
    }

    const fn expected_flags(self) -> Option<u32> {
        match self {
            Self::FileParameters | Self::ParentLocator => Some(0x4),
            Self::VirtualDiskSize
            | Self::VirtualDiskId
            | Self::LogicalSectorSize
            | Self::PhysicalSectorSize => Some(0x6),
            Self::Unknown => None,
        }
    }
}

#[derive(Default)]
struct MetadataFields {
    block_size: Option<u32>,
    has_parent: bool,
    virtual_disk_size: Option<u64>,
    has_virtual_disk_id: bool,
    logical_sector_size: Option<u32>,
    physical_sector_size: Option<u32>,
    parent: Option<ParentLocator>,
}

pub(super) fn parse_active_header(prefix: &[u8]) -> Result<Header, VhdxError> {
    if prefix.len() < HEADER_REGION_SIZE || prefix[..8] != *b"vhdxfile" {
        return Err(VhdxError::Invalid("missing VHDX file signature"));
    }
    let first = parse_header(&prefix[64 * 1024..64 * 1024 + HEADER_SIZE]);
    let second = parse_header(&prefix[128 * 1024..128 * 1024 + HEADER_SIZE]);
    match (first, second) {
        (Ok((first, first_sequence)), Ok((second, second_sequence))) => {
            if first_sequence == second_sequence {
                return Err(VhdxError::Invalid(
                    "both VHDX headers have the same sequence number",
                ));
            }
            if first_sequence > second_sequence {
                Ok(first)
            } else {
                Ok(second)
            }
        }
        (Ok((header, _)), Err(_)) | (Err(_), Ok((header, _))) => Ok(header),
        (Err(first), Err(_)) => Err(first),
    }
}

fn parse_header(bytes: &[u8]) -> Result<(Header, u64), VhdxError> {
    if bytes.len() != HEADER_SIZE || bytes[..4] != *b"head" {
        return Err(VhdxError::Invalid("invalid VHDX header signature"));
    }
    validate_crc32c(bytes, 4, "VHDX header")?;
    let sequence = le_u64(bytes, 8);
    if sequence == 0 {
        return Err(VhdxError::Invalid("VHDX header sequence is zero"));
    }
    let log_guid = guid_at(bytes, 48);
    if (log_guid != [0_u8; 16] && le_u16(bytes, 64) != 0) || le_u16(bytes, 66) != 1 {
        return Err(VhdxError::Invalid("unsupported VHDX header version"));
    }
    let log_length = le_u32(bytes, 68);
    let log_offset = le_u64(bytes, 72);
    if log_length != 0
        && (!u64::from(log_length).is_multiple_of(MIB) || !log_offset.is_multiple_of(MIB))
    {
        return Err(VhdxError::Invalid(
            "VHDX log offset or length is not 1 MiB-aligned",
        ));
    }
    Ok((
        Header {
            data_write_guid: guid_at(bytes, 32),
            log_guid,
            log_length,
            log_offset,
        },
        sequence,
    ))
}

pub(super) fn parse_regions(
    prefix: &[u8],
    effective_file_length: u64,
) -> Result<Regions, VhdxError> {
    parse_region_table(
        &prefix[REGION_TABLE1_OFFSET..REGION_TABLE1_OFFSET + REGION_TABLE_SIZE],
        effective_file_length,
    )
    .or_else(|_| {
        parse_region_table(
            &prefix[REGION_TABLE2_OFFSET..REGION_TABLE2_OFFSET + REGION_TABLE_SIZE],
            effective_file_length,
        )
    })
}

fn parse_region_table(bytes: &[u8], effective_file_length: u64) -> Result<Regions, VhdxError> {
    if bytes.len() != REGION_TABLE_SIZE || bytes[..4] != *b"regi" {
        return Err(VhdxError::Invalid("invalid VHDX region-table signature"));
    }
    validate_crc32c(bytes, 4, "VHDX region table")?;
    if le_u32(bytes, 12) != 0 {
        return Err(VhdxError::Invalid(
            "VHDX region-table reserved field is nonzero",
        ));
    }
    let entry_count = usize::try_from(le_u32(bytes, 8)).map_err(|_| VhdxError::OutOfBounds)?;
    if entry_count > MAX_REGION_ENTRIES {
        return Err(VhdxError::Invalid("too many VHDX region-table entries"));
    }
    let mut bat = None;
    let mut metadata = None;
    for index in 0..entry_count {
        let offset = 16 + index * 32;
        let guid = guid_at(bytes, offset);
        let region = Region {
            offset: le_u64(bytes, offset + 16),
            length: le_u32(bytes, offset + 24),
        };
        let flags = le_u32(bytes, offset + 28);
        if flags & !1 != 0 {
            return Err(VhdxError::Invalid(
                "reserved VHDX region-table flags are set",
            ));
        }
        validate_region(region, effective_file_length)?;
        match guid {
            BAT_REGION_GUID if bat.replace(region).is_some() => {
                return Err(VhdxError::Invalid("duplicate VHDX BAT region"));
            }
            METADATA_REGION_GUID if metadata.replace(region).is_some() => {
                return Err(VhdxError::Invalid("duplicate VHDX metadata region"));
            }
            BAT_REGION_GUID | METADATA_REGION_GUID => {}
            _ if flags & 1 != 0 => {
                return Err(VhdxError::InvalidDetail(format!(
                    "unknown required VHDX region {}",
                    format_guid(guid)
                )));
            }
            _ => {}
        }
    }
    let regions = Regions {
        bat: bat.ok_or(VhdxError::Invalid("VHDX BAT region is missing"))?,
        metadata: metadata.ok_or(VhdxError::Invalid("VHDX metadata region is missing"))?,
    };
    if regions_overlap(regions.bat, regions.metadata)? {
        return Err(VhdxError::Invalid("VHDX regions overlap"));
    }
    Ok(regions)
}

fn validate_region(region: Region, file_length: u64) -> Result<(), VhdxError> {
    let end = region.end()?;
    if region.offset < MIB
        || region.length == 0
        || !region.offset.is_multiple_of(MIB)
        || !u64::from(region.length).is_multiple_of(MIB)
        || end > file_length
    {
        return Err(VhdxError::OutOfBounds);
    }
    Ok(())
}

pub(super) fn validate_layout(
    header: &Header,
    regions: Regions,
    physical_file_length: u64,
) -> Result<(), VhdxError> {
    if header.log_length == 0 {
        return Ok(());
    }
    let log = Region {
        offset: header.log_offset,
        length: header.log_length,
    };
    validate_region(log, physical_file_length)?;
    if regions_overlap(log, regions.bat)? || regions_overlap(log, regions.metadata)? {
        return Err(VhdxError::Invalid("VHDX log and region overlap"));
    }
    Ok(())
}

fn regions_overlap(first: Region, second: Region) -> Result<bool, VhdxError> {
    Ok(first.offset < second.end()? && second.offset < first.end()?)
}

pub(super) fn parse_metadata(bytes: &[u8]) -> Result<Metadata, VhdxError> {
    if bytes.len() > MAX_METADATA_REGION_SIZE {
        return Err(VhdxError::Invalid("VHDX metadata region is too large"));
    }
    if bytes.len() < 32 || bytes[..8] != *b"metadata" {
        return Err(VhdxError::Invalid("invalid VHDX metadata-table signature"));
    }
    if bytes[8..10] != [0_u8; 2] || bytes[12..32].iter().any(|byte| *byte != 0) {
        return Err(VhdxError::Invalid(
            "VHDX metadata-table reserved fields are nonzero",
        ));
    }
    let entry_count = usize::from(le_u16(bytes, 10));
    let table_end = 32_usize
        .checked_add(entry_count.checked_mul(32).ok_or(VhdxError::OutOfBounds)?)
        .ok_or(VhdxError::OutOfBounds)?;
    if entry_count > MAX_METADATA_ENTRIES || table_end > bytes.len() {
        return Err(VhdxError::Invalid("invalid VHDX metadata entry count"));
    }

    let mut fields = MetadataFields::default();
    let mut seen_guids = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let entry_offset = 32 + index * 32;
        let guid = guid_at(bytes, entry_offset);
        let kind = MetadataItemKind::from_guid(guid);
        if seen_guids.contains(&guid) {
            return Err(VhdxError::Invalid(
                "VHDX metadata table contains a duplicate item",
            ));
        }
        seen_guids.push(guid);
        let item_offset = usize::try_from(le_u32(bytes, entry_offset + 16))
            .map_err(|_| VhdxError::OutOfBounds)?;
        let item_length = usize::try_from(le_u32(bytes, entry_offset + 20))
            .map_err(|_| VhdxError::OutOfBounds)?;
        let flags = le_u32(bytes, entry_offset + 24);
        if flags & !0x7 != 0 || le_u32(bytes, entry_offset + 28) != 0 {
            return Err(VhdxError::Invalid("reserved VHDX metadata flags are set"));
        }
        if kind
            .expected_flags()
            .is_some_and(|expected| flags != expected)
        {
            return Err(VhdxError::Invalid(
                "known VHDX metadata item has invalid flags",
            ));
        }
        if flags & 0x4 != 0 && kind == MetadataItemKind::Unknown {
            return Err(VhdxError::InvalidDetail(format!(
                "unknown required VHDX metadata item {}",
                format_guid(guid)
            )));
        }
        let item_end = item_offset
            .checked_add(item_length)
            .ok_or(VhdxError::OutOfBounds)?;
        if item_offset < table_end || item_end > bytes.len() {
            return Err(VhdxError::OutOfBounds);
        }
        parse_metadata_item(kind, &bytes[item_offset..item_end], &mut fields)?;
    }
    finish_metadata(fields)
}

fn parse_metadata_item(
    kind: MetadataItemKind,
    item: &[u8],
    fields: &mut MetadataFields,
) -> Result<(), VhdxError> {
    let expected_length = match kind {
        MetadataItemKind::FileParameters | MetadataItemKind::VirtualDiskSize => Some(8),
        MetadataItemKind::VirtualDiskId => Some(16),
        MetadataItemKind::LogicalSectorSize | MetadataItemKind::PhysicalSectorSize => Some(4),
        MetadataItemKind::ParentLocator | MetadataItemKind::Unknown => None,
    };
    if expected_length.is_some_and(|expected| item.len() != expected)
        || (kind == MetadataItemKind::ParentLocator && item.is_empty())
    {
        return Err(VhdxError::Invalid(
            "known VHDX metadata item has an invalid length",
        ));
    }
    match kind {
        MetadataItemKind::FileParameters => {
            fields.block_size = Some(le_u32(item, 0));
            let parameters = le_u32(item, 4);
            if parameters & !0x3 != 0 {
                return Err(VhdxError::Invalid(
                    "reserved VHDX FileParameters bits are set",
                ));
            }
            fields.has_parent = parameters & 2 != 0;
        }
        MetadataItemKind::VirtualDiskSize => fields.virtual_disk_size = Some(le_u64(item, 0)),
        MetadataItemKind::VirtualDiskId => fields.has_virtual_disk_id = true,
        MetadataItemKind::LogicalSectorSize => fields.logical_sector_size = Some(le_u32(item, 0)),
        MetadataItemKind::PhysicalSectorSize => {
            fields.physical_sector_size = Some(le_u32(item, 0));
        }
        MetadataItemKind::ParentLocator => fields.parent = Some(parse_parent_locator(item)?),
        MetadataItemKind::Unknown => {}
    }
    Ok(())
}

fn finish_metadata(fields: MetadataFields) -> Result<Metadata, VhdxError> {
    let block_size = fields.block_size.ok_or(VhdxError::Invalid(
        "VHDX FileParameters metadata is missing",
    ))?;
    if !(1024 * 1024..=256 * 1024 * 1024).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(VhdxError::Invalid("invalid VHDX payload block size"));
    }
    let virtual_disk_size = fields.virtual_disk_size.ok_or(VhdxError::Invalid(
        "VHDX VirtualDiskSize metadata is missing",
    ))?;
    let logical_sector_size = fields.logical_sector_size.ok_or(VhdxError::Invalid(
        "VHDX LogicalSectorSize metadata is missing",
    ))?;
    let physical_sector_size = fields.physical_sector_size.ok_or(VhdxError::Invalid(
        "VHDX PhysicalSectorSize metadata is missing",
    ))?;
    if !fields.has_virtual_disk_id {
        return Err(VhdxError::Invalid("VHDX VirtualDiskId metadata is missing"));
    }
    if !matches!(logical_sector_size, 512 | 4096)
        || !matches!(physical_sector_size, 512 | 4096)
        || virtual_disk_size == 0
        || virtual_disk_size > MAX_VIRTUAL_SIZE
        || !virtual_disk_size.is_multiple_of(u64::from(logical_sector_size))
    {
        return Err(VhdxError::Invalid("invalid VHDX virtual-disk geometry"));
    }
    if fields.has_parent && fields.parent.is_none() {
        return Err(VhdxError::Invalid(
            "differencing VHDX has no parent locator",
        ));
    }
    Ok(Metadata {
        block_size,
        has_parent: fields.has_parent,
        virtual_disk_size,
        logical_sector_size,
        parent: fields.parent,
    })
}

fn parse_parent_locator(bytes: &[u8]) -> Result<ParentLocator, VhdxError> {
    if bytes.len() < 20 || guid_at(bytes, 0) != VHDX_LOCATOR_TYPE_GUID {
        return Err(VhdxError::Invalid("unsupported VHDX parent-locator type"));
    }
    if le_u16(bytes, 16) != 0 {
        return Err(VhdxError::Invalid(
            "VHDX parent-locator reserved field is nonzero",
        ));
    }
    let entry_count = usize::from(le_u16(bytes, 18));
    let table_end = 20_usize
        .checked_add(entry_count.checked_mul(12).ok_or(VhdxError::OutOfBounds)?)
        .ok_or(VhdxError::OutOfBounds)?;
    if table_end > bytes.len() {
        return Err(VhdxError::OutOfBounds);
    }

    let mut expected_parent_guids = Vec::new();
    let mut paths = Vec::new();
    let mut keys = Vec::new();
    for index in 0..entry_count {
        let entry = 20 + index * 12;
        let key_offset =
            usize::try_from(le_u32(bytes, entry)).map_err(|_| VhdxError::OutOfBounds)?;
        let value_offset =
            usize::try_from(le_u32(bytes, entry + 4)).map_err(|_| VhdxError::OutOfBounds)?;
        let key_length = usize::from(le_u16(bytes, entry + 8));
        let value_length = usize::from(le_u16(bytes, entry + 10));
        if key_length == 0 {
            return Err(VhdxError::Invalid("VHDX parent-locator key is empty"));
        }
        if key_offset < table_end || value_offset < table_end {
            return Err(VhdxError::Invalid(
                "VHDX parent-locator string overlaps its entry table",
            ));
        }
        let key = decode_utf16_range(bytes, key_offset, key_length)?;
        if keys.contains(&key) {
            return Err(VhdxError::Invalid(
                "VHDX parent-locator contains a duplicate key",
            ));
        }
        keys.push(key.clone());
        let value = decode_utf16_range(bytes, value_offset, value_length)?;
        match key.as_str() {
            "parent_linkage" | "parent_linkage2" => {
                let guid = parse_guid(&value)?;
                if !expected_parent_guids.contains(&guid) {
                    expected_parent_guids.push(guid);
                }
            }
            "relative_path" => paths.push(ParentPath {
                kind: ParentPathKind::Relative,
                value,
            }),
            "volume_path" => paths.push(ParentPath {
                kind: ParentPathKind::Volume,
                value,
            }),
            "absolute_win32_path" => paths.push(ParentPath {
                kind: ParentPathKind::Absolute,
                value,
            }),
            _ => {}
        }
    }
    if expected_parent_guids.is_empty() {
        return Err(VhdxError::Invalid(
            "VHDX parent locator has no parent linkage",
        ));
    }
    Ok(ParentLocator {
        expected_parent_guids,
        paths,
    })
}

fn decode_utf16_range(bytes: &[u8], offset: usize, length: usize) -> Result<String, VhdxError> {
    let end = offset.checked_add(length).ok_or(VhdxError::OutOfBounds)?;
    if length == 0 {
        return Ok(String::new());
    }
    if !length.is_multiple_of(2) || end > bytes.len() {
        return Err(VhdxError::Invalid("invalid UTF-16 VHDX metadata string"));
    }
    char::decode_utf16(
        bytes[offset..end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    )
    .collect::<Result<String, _>>()
    .map_err(|_| VhdxError::Invalid("invalid UTF-16 VHDX metadata string"))
}

fn parse_guid(value: &str) -> Result<Guid, VhdxError> {
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    let groups: Vec<_> = value.split('-').collect();
    if groups.len() != 5
        || groups[0].len() != 8
        || groups[1].len() != 4
        || groups[2].len() != 4
        || groups[3].len() != 4
        || groups[4].len() != 12
    {
        return Err(VhdxError::Invalid("invalid VHDX parent-linkage GUID"));
    }
    let first = u32::from_str_radix(groups[0], 16)
        .map_err(|_| VhdxError::Invalid("invalid VHDX parent-linkage GUID"))?;
    let second = u16::from_str_radix(groups[1], 16)
        .map_err(|_| VhdxError::Invalid("invalid VHDX parent-linkage GUID"))?;
    let third = u16::from_str_radix(groups[2], 16)
        .map_err(|_| VhdxError::Invalid("invalid VHDX parent-linkage GUID"))?;
    let tail = format!("{}{}", groups[3], groups[4]);
    let mut guid = [0_u8; 16];
    guid[..4].copy_from_slice(&first.to_le_bytes());
    guid[4..6].copy_from_slice(&second.to_le_bytes());
    guid[6..8].copy_from_slice(&third.to_le_bytes());
    for (index, pair) in tail.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| VhdxError::Invalid("invalid VHDX parent-linkage GUID"))?;
        guid[8 + index] = u8::from_str_radix(pair, 16)
            .map_err(|_| VhdxError::Invalid("invalid VHDX parent-linkage GUID"))?;
    }
    Ok(guid)
}

pub(super) fn validate_bat_capacity(region: Region, metadata: &Metadata) -> Result<(), VhdxError> {
    let payload_count = metadata
        .virtual_disk_size
        .div_ceil(u64::from(metadata.block_size));
    let chunk_ratio = chunk_ratio(metadata)?;
    let payload_entry_count = payload_count
        .checked_add(payload_count.saturating_sub(1) / chunk_ratio)
        .ok_or(VhdxError::OutOfBounds)?;
    let entry_count = if metadata.has_parent {
        payload_count
            .div_ceil(chunk_ratio)
            .checked_mul(chunk_ratio + 1)
            .ok_or(VhdxError::OutOfBounds)?
    } else {
        payload_entry_count
    };
    let required_bytes = entry_count.checked_mul(8).ok_or(VhdxError::OutOfBounds)?;
    if required_bytes > u64::from(region.length) {
        return Err(VhdxError::Invalid(
            "VHDX BAT region is too small for the virtual disk",
        ));
    }
    Ok(())
}

pub(super) fn chunk_ratio(metadata: &Metadata) -> Result<u64, VhdxError> {
    let numerator = (1_u64 << 23)
        .checked_mul(u64::from(metadata.logical_sector_size))
        .ok_or(VhdxError::OutOfBounds)?;
    let ratio = numerator / u64::from(metadata.block_size);
    if ratio == 0 {
        return Err(VhdxError::Invalid("VHDX chunk ratio is zero"));
    }
    Ok(ratio)
}

fn validate_crc32c(
    bytes: &[u8],
    checksum_offset: usize,
    structure: &'static str,
) -> Result<(), VhdxError> {
    let stored = le_u32(bytes, checksum_offset);
    let mut protected = bytes.to_vec();
    protected[checksum_offset..checksum_offset + 4].fill(0);
    if crc32c::crc32c(&protected) != stored {
        return Err(VhdxError::InvalidChecksum { structure });
    }
    Ok(())
}

pub(super) fn guid_at(bytes: &[u8], offset: usize) -> Guid {
    let mut guid = [0_u8; 16];
    guid.copy_from_slice(&bytes[offset..offset + 16]);
    guid
}

pub(super) fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(super) fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(super) fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub(super) fn format_guid(guid: Guid) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_parent_linkage_guid_into_vhdx_byte_order() {
        let guid = parse_guid("{b04aefb7-d19e-4a81-b789-25b8e9445913}").unwrap();
        assert_eq!(guid, VHDX_LOCATOR_TYPE_GUID);
    }

    #[test]
    fn formats_vhdx_guid_byte_order() {
        assert_eq!(
            format_guid(VHDX_LOCATOR_TYPE_GUID),
            "b04aefb7-d19e-4a81-b789-25b8e9445913"
        );
    }
}
