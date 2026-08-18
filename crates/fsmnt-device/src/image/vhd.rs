//! Native, bounded-memory reader for the legacy Microsoft VHD format.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tracing::debug;

use super::container::ImageContainer;
use super::format::ImageFormat;
use super::util::{has_extension as path_has_extension, seek_position};

const SECTOR_SIZE: u64 = 512;
const FOOTER_SIZE: usize = 512;
const DYNAMIC_HEADER_SIZE: usize = 1024;
const BAT_UNALLOCATED: u32 = u32::MAX;
const PARENT_CHAIN_LIMIT: usize = 32;
const MAX_BLOCK_SIZE: u32 = 256 * 1024 * 1024;
const MAX_BAT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PARENT_LOCATOR_BYTES: u32 = 64 * 1024;
const MAX_VIRTUAL_SIZE: u64 = 2 * 1024 * 1024 * 1024 * 1024;

pub(super) fn has_extension(path: &Path) -> bool {
    path_has_extension(path, &["vhd", "avhd"])
}

#[derive(Debug, thiserror::Error)]
pub(super) enum VhdError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid VHD footer: {0}")]
    InvalidFooter(&'static str),
    #[error("invalid VHD dynamic header: {0}")]
    InvalidDynamicHeader(&'static str),
    #[error("invalid VHD {structure} checksum")]
    InvalidChecksum { structure: &'static str },
    #[error("unsupported VHD disk type {0}")]
    UnsupportedDiskType(u32),
    #[error("VHD structure offset or length is outside the container")]
    OutOfBounds,
    #[error("VHD parent chain exceeds {PARENT_CHAIN_LIMIT} layers")]
    ParentChainTooDeep,
    #[error("VHD parent chain contains a cycle at {0}")]
    ParentCycle(PathBuf),
    #[error("VHD differencing parent could not be resolved: {0}")]
    ParentNotFound(String),
    #[error("VHD parent identifier does not match the child")]
    ParentIdentifierMismatch,
}

impl From<VhdError> for io::Error {
    fn from(error: VhdError) -> Self {
        match error {
            VhdError::Io(error) => error,
            VhdError::ParentNotFound(_) => io::Error::new(io::ErrorKind::NotFound, error),
            VhdError::OutOfBounds => io::Error::new(io::ErrorKind::UnexpectedEof, error),
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiskType {
    Fixed,
    Dynamic,
    Differencing,
}

#[derive(Clone, Debug)]
struct Footer {
    data_offset: u64,
    current_size: u64,
    disk_type: DiskType,
    unique_id: [u8; 16],
}

struct DynamicState {
    block_size: u64,
    bitmap_size: u64,
    bat: Vec<VhdBatEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VhdBatEntry {
    Unallocated,
    Allocated { file_offset: u64 },
}

struct DynamicHeader {
    table_offset: u64,
    max_table_entries: u32,
    block_size: u32,
    parent_unique_id: [u8; 16],
    parent_name: String,
    locators: Vec<ParentLocator>,
}

struct ParentLocator {
    platform_code: [u8; 4],
    data_space: u32,
    data_length: u32,
    data_offset: u64,
}

/// Streaming decoded-media view of a fixed, dynamic, or differencing VHD.
pub(super) struct VhdReader {
    file: File,
    position: u64,
    length: u64,
    unique_id: [u8; 16],
    dynamic: Option<DynamicState>,
    parent: Option<Box<Self>>,
}

impl VhdReader {
    pub(super) fn open(path: &Path) -> Result<Self, VhdError> {
        Self::open_layer(path, PARENT_CHAIN_LIMIT, &HashSet::new())
    }

    fn open_layer(
        path: &Path,
        depth_remaining: usize,
        ancestors: &HashSet<PathBuf>,
    ) -> Result<Self, VhdError> {
        if depth_remaining == 0 {
            return Err(VhdError::ParentChainTooDeep);
        }
        let canonical_path = std::fs::canonicalize(path)?;
        if ancestors.contains(&canonical_path) {
            return Err(VhdError::ParentCycle(canonical_path));
        }
        let mut next_ancestors = ancestors.clone();
        next_ancestors.insert(canonical_path.clone());

        let mut file = File::open(&canonical_path)?;
        let file_length = file.metadata()?.len();
        let footer = load_footer(&mut file, file_length)?;
        let length = footer.current_size;

        match footer.disk_type {
            DiskType::Fixed => {
                let required = length
                    .checked_add(u64::try_from(FOOTER_SIZE).map_err(|_| VhdError::OutOfBounds)?)
                    .ok_or(VhdError::OutOfBounds)?;
                if required > file_length {
                    return Err(VhdError::OutOfBounds);
                }
                Ok(Self {
                    file,
                    position: 0,
                    length,
                    unique_id: footer.unique_id,
                    dynamic: None,
                    parent: None,
                })
            }
            DiskType::Dynamic | DiskType::Differencing => {
                let header = load_dynamic_header(&mut file, &footer, file_length)?;
                let dynamic = load_dynamic_state(&mut file, &header, length, file_length)?;
                let parent = if footer.disk_type == DiskType::Differencing {
                    Some(Box::new(resolve_parent(
                        &mut file,
                        &canonical_path,
                        &header,
                        length,
                        depth_remaining,
                        &next_ancestors,
                    )?))
                } else {
                    None
                };
                Ok(Self {
                    file,
                    position: 0,
                    length,
                    unique_id: footer.unique_id,
                    dynamic: Some(dynamic),
                    parent,
                })
            }
        }
    }

    fn read_virtual_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), VhdError> {
        let length = u64::try_from(buffer.len()).map_err(|_| VhdError::OutOfBounds)?;
        let end = offset.checked_add(length).ok_or(VhdError::OutOfBounds)?;
        if end > self.length {
            return Err(VhdError::OutOfBounds);
        }
        if self.dynamic.is_none() {
            return read_exact_at(&mut self.file, offset, buffer).map_err(VhdError::Io);
        }

        let mut virtual_offset = offset;
        let mut written = 0;
        while written < buffer.len() {
            let block_size = self
                .dynamic
                .as_ref()
                .ok_or(VhdError::InvalidDynamicHeader("missing dynamic state"))?
                .block_size;
            let block_index =
                usize::try_from(virtual_offset / block_size).map_err(|_| VhdError::OutOfBounds)?;
            let offset_in_block = virtual_offset % block_size;
            let block_remaining = block_size - offset_in_block;
            let output_remaining = buffer.len() - written;
            let chunk_length = output_remaining
                .min(usize::try_from(block_remaining).map_or(usize::MAX, std::convert::identity));
            self.read_dynamic_block(
                block_index,
                offset_in_block,
                virtual_offset,
                &mut buffer[written..written + chunk_length],
            )?;
            let advanced = u64::try_from(chunk_length).map_err(|_| VhdError::OutOfBounds)?;
            virtual_offset = virtual_offset
                .checked_add(advanced)
                .ok_or(VhdError::OutOfBounds)?;
            written += chunk_length;
        }
        Ok(())
    }

    fn read_dynamic_block(
        &mut self,
        block_index: usize,
        offset_in_block: u64,
        virtual_offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), VhdError> {
        let (entry, bitmap_size) = {
            let dynamic = self
                .dynamic
                .as_ref()
                .ok_or(VhdError::InvalidDynamicHeader("missing dynamic state"))?;
            let entry = *dynamic.bat.get(block_index).ok_or(VhdError::OutOfBounds)?;
            (entry, dynamic.bitmap_size)
        };
        let block_file_offset = match entry {
            VhdBatEntry::Unallocated => {
                return self.read_parent_or_zero(virtual_offset, buffer);
            }
            VhdBatEntry::Allocated { file_offset } => file_offset,
        };
        let bitmap_length = usize::try_from(bitmap_size).map_err(|_| VhdError::OutOfBounds)?;
        let mut bitmap = vec![0_u8; bitmap_length];
        read_exact_at(&mut self.file, block_file_offset, &mut bitmap)?;

        let mut block_offset = offset_in_block;
        let mut logical_offset = virtual_offset;
        let mut written = 0;
        while written < buffer.len() {
            let sector_in_block = block_offset / SECTOR_SIZE;
            let offset_in_sector = block_offset % SECTOR_SIZE;
            let sector_remaining = SECTOR_SIZE - offset_in_sector;
            let chunk_length = (buffer.len() - written)
                .min(usize::try_from(sector_remaining).map_or(usize::MAX, std::convert::identity));
            let bitmap_byte =
                usize::try_from(sector_in_block / 8).map_err(|_| VhdError::OutOfBounds)?;
            let bitmap_bit =
                u8::try_from(sector_in_block % 8).map_err(|_| VhdError::OutOfBounds)?;
            let present = bitmap
                .get(bitmap_byte)
                .is_some_and(|byte| byte & (0x80_u8 >> bitmap_bit) != 0);
            let destination = &mut buffer[written..written + chunk_length];
            if present {
                let file_offset = block_file_offset
                    .checked_add(bitmap_size)
                    .and_then(|value| value.checked_add(block_offset))
                    .ok_or(VhdError::OutOfBounds)?;
                read_exact_at(&mut self.file, file_offset, destination)?;
            } else {
                self.read_parent_or_zero(logical_offset, destination)?;
            }

            let advanced = u64::try_from(chunk_length).map_err(|_| VhdError::OutOfBounds)?;
            block_offset = block_offset
                .checked_add(advanced)
                .ok_or(VhdError::OutOfBounds)?;
            logical_offset = logical_offset
                .checked_add(advanced)
                .ok_or(VhdError::OutOfBounds)?;
            written += chunk_length;
        }
        Ok(())
    }

    fn read_parent_or_zero(
        &mut self,
        virtual_offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), VhdError> {
        if let Some(parent) = &mut self.parent {
            parent.read_virtual_at(virtual_offset, buffer)
        } else {
            buffer.fill(0);
            Ok(())
        }
    }
}

impl Read for VhdReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let remaining = self.length - self.position;
        let count = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.read_virtual_at(self.position, &mut buffer[..count])
            .map_err(io::Error::from)?;
        self.position += u64::try_from(count)
            .map_err(|_| io::Error::other("VHD read length does not fit u64"))?;
        Ok(count)
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = seek_position(self.position, self.length, position)?;
        Ok(self.position)
    }
}

impl ImageContainer for VhdReader {
    fn format(&self) -> ImageFormat {
        ImageFormat::Vhd
    }

    fn len(&self) -> u64 {
        self.length
    }
}

pub(super) fn has_footer_signature(file: &mut File, length: u64) -> io::Result<bool> {
    let footer_size = u64::try_from(FOOTER_SIZE)
        .map_err(|_| io::Error::other("VHD footer size does not fit u64"))?;
    if length < footer_size {
        return Ok(false);
    }
    let mut signature = [0_u8; 8];
    read_exact_at(file, length - footer_size, &mut signature)?;
    Ok(signature == *b"conectix")
}

fn load_footer(file: &mut File, file_length: u64) -> Result<Footer, VhdError> {
    let footer_size = u64::try_from(FOOTER_SIZE).map_err(|_| VhdError::OutOfBounds)?;
    if file_length < footer_size {
        return Err(VhdError::InvalidFooter(
            "container is shorter than 512 bytes",
        ));
    }
    let mut trailing = [0_u8; FOOTER_SIZE];
    read_exact_at(file, file_length - footer_size, &mut trailing)?;
    match parse_footer(&trailing) {
        Ok(footer) => Ok(footer),
        Err(trailing_error) => {
            let mut leading = [0_u8; FOOTER_SIZE];
            read_exact_at(file, 0, &mut leading)?;
            if leading[..8] == *b"conectix" {
                let footer = parse_footer(&leading)?;
                if footer.disk_type == DiskType::Fixed {
                    return Err(trailing_error);
                }
                Ok(footer)
            } else {
                Err(trailing_error)
            }
        }
    }
}

fn parse_footer(bytes: &[u8; FOOTER_SIZE]) -> Result<Footer, VhdError> {
    if bytes[..8] != *b"conectix" {
        return Err(VhdError::InvalidFooter("missing conectix cookie"));
    }
    if be_u32(bytes, 12) != 0x0001_0000 {
        return Err(VhdError::InvalidFooter("unsupported format version"));
    }
    let features = be_u32(bytes, 8);
    if features & 2 == 0 || features & !3 != 0 {
        return Err(VhdError::InvalidFooter("invalid feature flags"));
    }
    validate_ones_complement_checksum(bytes, 64, "footer")?;
    let current_size = be_u64(bytes, 48);
    if current_size == 0
        || current_size > MAX_VIRTUAL_SIZE
        || !current_size.is_multiple_of(SECTOR_SIZE)
    {
        return Err(VhdError::InvalidFooter(
            "current size is unsupported or not sector-aligned",
        ));
    }
    let disk_type = match be_u32(bytes, 60) {
        2 => DiskType::Fixed,
        3 => DiskType::Dynamic,
        4 => DiskType::Differencing,
        value => return Err(VhdError::UnsupportedDiskType(value)),
    };
    let data_offset = be_u64(bytes, 16);
    if disk_type == DiskType::Fixed && data_offset != u64::MAX {
        return Err(VhdError::InvalidFooter(
            "fixed VHD has a dynamic-header offset",
        ));
    }
    let mut unique_id = [0_u8; 16];
    unique_id.copy_from_slice(&bytes[68..84]);
    Ok(Footer {
        data_offset,
        current_size,
        disk_type,
        unique_id,
    })
}

fn load_dynamic_header(
    file: &mut File,
    footer: &Footer,
    file_length: u64,
) -> Result<DynamicHeader, VhdError> {
    let header_size = u64::try_from(DYNAMIC_HEADER_SIZE).map_err(|_| VhdError::OutOfBounds)?;
    let header_end = footer
        .data_offset
        .checked_add(header_size)
        .ok_or(VhdError::OutOfBounds)?;
    if footer.data_offset == u64::MAX || header_end > file_length {
        return Err(VhdError::InvalidDynamicHeader(
            "dynamic header offset is outside the container",
        ));
    }
    let mut bytes = [0_u8; DYNAMIC_HEADER_SIZE];
    read_exact_at(file, footer.data_offset, &mut bytes)?;
    parse_dynamic_header(&bytes)
}

fn parse_dynamic_header(bytes: &[u8; DYNAMIC_HEADER_SIZE]) -> Result<DynamicHeader, VhdError> {
    if bytes[..8] != *b"cxsparse" {
        return Err(VhdError::InvalidDynamicHeader("missing cxsparse cookie"));
    }
    if be_u64(bytes, 8) != u64::MAX {
        return Err(VhdError::InvalidDynamicHeader(
            "dynamic-header data offset is not reserved",
        ));
    }
    if be_u32(bytes, 24) != 0x0001_0000 {
        return Err(VhdError::InvalidDynamicHeader(
            "unsupported dynamic-header version",
        ));
    }
    validate_ones_complement_checksum(bytes, 36, "dynamic header")?;
    let table_offset = be_u64(bytes, 16);
    if !table_offset.is_multiple_of(SECTOR_SIZE) {
        return Err(VhdError::InvalidDynamicHeader(
            "BAT offset is not sector-aligned",
        ));
    }
    let max_table_entries = be_u32(bytes, 28);
    let block_size = be_u32(bytes, 32);
    if block_size < u32::try_from(SECTOR_SIZE).map_err(|_| VhdError::OutOfBounds)?
        || block_size > MAX_BLOCK_SIZE
        || !block_size.is_power_of_two()
    {
        return Err(VhdError::InvalidDynamicHeader("block size is invalid"));
    }
    let mut parent_unique_id = [0_u8; 16];
    parent_unique_id.copy_from_slice(&bytes[40..56]);
    let parent_name = decode_utf16_be(&bytes[64..576])?;
    let mut locators = Vec::new();
    for index in 0..8 {
        let offset = 576 + index * 24;
        let mut platform_code = [0_u8; 4];
        platform_code.copy_from_slice(&bytes[offset..offset + 4]);
        let data_space = be_u32(bytes, offset + 4);
        let data_length = be_u32(bytes, offset + 8);
        let data_offset = be_u64(bytes, offset + 16);
        if data_length != 0 {
            locators.push(ParentLocator {
                platform_code,
                data_space,
                data_length,
                data_offset,
            });
        }
    }
    Ok(DynamicHeader {
        table_offset,
        max_table_entries,
        block_size,
        parent_unique_id,
        parent_name,
        locators,
    })
}

fn load_dynamic_state(
    file: &mut File,
    header: &DynamicHeader,
    virtual_size: u64,
    file_length: u64,
) -> Result<DynamicState, VhdError> {
    let block_size = u64::from(header.block_size);
    let required_entries = virtual_size.div_ceil(block_size);
    if required_entries > u64::from(header.max_table_entries) {
        return Err(VhdError::InvalidDynamicHeader(
            "BAT has too few entries for the virtual disk",
        ));
    }
    let entry_count = usize::try_from(required_entries).map_err(|_| VhdError::OutOfBounds)?;
    let bat_length = entry_count.checked_mul(4).ok_or(VhdError::OutOfBounds)?;
    if bat_length > MAX_BAT_BYTES {
        return Err(VhdError::InvalidDynamicHeader(
            "BAT exceeds the supported in-memory limit",
        ));
    }
    let bat_length_u64 = u64::try_from(bat_length).map_err(|_| VhdError::OutOfBounds)?;
    let bat_end = header
        .table_offset
        .checked_add(bat_length_u64)
        .ok_or(VhdError::OutOfBounds)?;
    if bat_end > file_length {
        return Err(VhdError::OutOfBounds);
    }
    let mut bat_bytes = vec![0_u8; bat_length];
    read_exact_at(file, header.table_offset, &mut bat_bytes)?;
    let mut bat = Vec::with_capacity(entry_count);
    for entry in bat_bytes.chunks_exact(4) {
        let raw = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let parsed = if raw == BAT_UNALLOCATED {
            VhdBatEntry::Unallocated
        } else {
            VhdBatEntry::Allocated {
                file_offset: u64::from(raw)
                    .checked_mul(SECTOR_SIZE)
                    .ok_or(VhdError::OutOfBounds)?,
            }
        };
        bat.push(parsed);
    }

    let sectors_per_block = block_size / SECTOR_SIZE;
    let bitmap_bytes = sectors_per_block.div_ceil(8);
    let bitmap_size = bitmap_bytes.div_ceil(SECTOR_SIZE) * SECTOR_SIZE;
    let data_end = file_length
        .checked_sub(u64::try_from(FOOTER_SIZE).map_err(|_| VhdError::OutOfBounds)?)
        .ok_or(VhdError::OutOfBounds)?;
    for block_start in bat.iter().filter_map(|entry| match entry {
        VhdBatEntry::Unallocated => None,
        VhdBatEntry::Allocated { file_offset } => Some(*file_offset),
    }) {
        let block_end = block_start
            .checked_add(bitmap_size)
            .and_then(|value| value.checked_add(block_size))
            .ok_or(VhdError::OutOfBounds)?;
        if block_end > data_end {
            return Err(VhdError::OutOfBounds);
        }
    }
    Ok(DynamicState {
        block_size,
        bitmap_size,
        bat,
    })
}

fn resolve_parent(
    file: &mut File,
    child_path: &Path,
    header: &DynamicHeader,
    child_size: u64,
    depth_remaining: usize,
    ancestors: &HashSet<PathBuf>,
) -> Result<VhdReader, VhdError> {
    let candidates = parent_candidates(file, child_path, header)?;
    let mut failures = Vec::new();
    for candidate in candidates {
        match VhdReader::open_layer(&candidate, depth_remaining - 1, ancestors) {
            Ok(parent)
                if parent.unique_id == header.parent_unique_id && parent.length == child_size =>
            {
                debug!(
                    path = %candidate.display(),
                    depth = PARENT_CHAIN_LIMIT - depth_remaining + 1,
                    "resolved a VHD differencing parent"
                );
                return Ok(parent);
            }
            Ok(_) => failures.push(format!(
                "{}: identifier or virtual size does not match",
                candidate.display()
            )),
            Err(error) => failures.push(format!("{}: {error}", candidate.display())),
        }
    }
    if failures.is_empty() {
        return Err(VhdError::ParentIdentifierMismatch);
    }
    Err(VhdError::ParentNotFound(failures.join("; ")))
}

fn parent_candidates(
    file: &mut File,
    child_path: &Path,
    header: &DynamicHeader,
) -> Result<Vec<PathBuf>, VhdError> {
    let child_directory = child_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let file_length = file.metadata()?.len();
    let mut relative = Vec::new();
    let mut absolute = Vec::new();

    for locator in &header.locators {
        let allocated = u64::from(locator.data_space)
            .checked_mul(SECTOR_SIZE)
            .ok_or(VhdError::OutOfBounds)?;
        if u64::from(locator.data_length) > allocated {
            return Err(VhdError::InvalidDynamicHeader(
                "parent locator exceeds its allocated space",
            ));
        }
        if locator.data_length > MAX_PARENT_LOCATOR_BYTES {
            return Err(VhdError::InvalidDynamicHeader(
                "parent locator path is too large",
            ));
        }
        let end = locator
            .data_offset
            .checked_add(u64::from(locator.data_length))
            .ok_or(VhdError::OutOfBounds)?;
        if end > file_length {
            return Err(VhdError::OutOfBounds);
        }
        let length = usize::try_from(locator.data_length).map_err(|_| VhdError::OutOfBounds)?;
        let mut bytes = vec![0_u8; length];
        read_exact_at(file, locator.data_offset, &mut bytes)?;
        match &locator.platform_code {
            b"W2ru" => relative.push(decode_utf16_le(&bytes)?),
            b"W2ku" => absolute.push(decode_utf16_le(&bytes)?),
            b"Wi2r" => relative.push(decode_legacy_path(&bytes)),
            b"Wi2k" => absolute.push(decode_legacy_path(&bytes)),
            _ => {}
        }
    }

    let mut candidates = Vec::new();
    for value in relative {
        push_path_candidate(
            &mut candidates,
            child_directory.join(portable_locator_path(&value)),
        );
        push_sibling_candidate(&mut candidates, &child_directory, &value);
    }
    for value in absolute {
        push_path_candidate(&mut candidates, portable_locator_path(&value));
        push_sibling_candidate(&mut candidates, &child_directory, &value);
    }
    if !header.parent_name.is_empty() {
        push_path_candidate(
            &mut candidates,
            child_directory.join(portable_locator_path(&header.parent_name)),
        );
        push_sibling_candidate(&mut candidates, &child_directory, &header.parent_name);
    }
    Ok(candidates)
}

fn push_sibling_candidate(paths: &mut Vec<PathBuf>, directory: &Path, value: &str) {
    if let Some(file_name) = locator_file_name(value) {
        push_path_candidate(paths, directory.join(file_name));
    }
}

fn push_path_candidate(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.contains(&candidate) {
        paths.push(candidate);
    }
}

fn portable_locator_path(value: &str) -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(value)
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(value.replace('\\', "/"))
    }
}

fn locator_file_name(value: &str) -> Option<&str> {
    value
        .rsplit(['\\', '/'])
        .find(|component| !component.is_empty() && *component != "." && *component != "..")
}

fn decode_utf16_be(bytes: &[u8]) -> Result<String, VhdError> {
    decode_utf16(bytes, u16::from_be_bytes)
}

fn decode_utf16_le(bytes: &[u8]) -> Result<String, VhdError> {
    decode_utf16(bytes, u16::from_le_bytes)
}

fn decode_utf16(bytes: &[u8], decode: impl Fn([u8; 2]) -> u16) -> Result<String, VhdError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(VhdError::InvalidDynamicHeader(
            "UTF-16 parent path has an odd byte length",
        ));
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| decode([chunk[0], chunk[1]]))
        .take_while(|unit| *unit != 0);
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| VhdError::InvalidDynamicHeader("parent path is not valid UTF-16"))
}

fn decode_legacy_path(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn validate_ones_complement_checksum(
    bytes: &[u8],
    checksum_offset: usize,
    structure: &'static str,
) -> Result<(), VhdError> {
    let stored = be_u32(bytes, checksum_offset);
    let sum = bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| !(*index >= checksum_offset && *index < checksum_offset + 4))
        .fold(0_u32, |sum, (_, byte)| sum.wrapping_add(u32::from(*byte)));
    if stored != !sum {
        return Err(VhdError::InvalidChecksum { structure });
    }
    Ok(())
}

fn read_exact_at(file: &mut File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buffer)
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn be_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
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

#[cfg(test)]
mod tests {
    use super::*;

    fn footer_bytes(size: u64, disk_type: u32) -> [u8; FOOTER_SIZE] {
        let mut footer = [0_u8; FOOTER_SIZE];
        footer[..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2_u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
        footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        footer[40..48].copy_from_slice(&size.to_be_bytes());
        footer[48..56].copy_from_slice(&size.to_be_bytes());
        footer[60..64].copy_from_slice(&disk_type.to_be_bytes());
        let sum = footer
            .iter()
            .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
        footer
    }

    #[test]
    fn parses_a_valid_fixed_footer() {
        let footer = parse_footer(&footer_bytes(4096, 2)).unwrap();
        assert_eq!(footer.current_size, 4096);
        assert_eq!(footer.disk_type, DiskType::Fixed);
    }

    #[test]
    fn rejects_footer_checksum_damage() {
        let mut footer = footer_bytes(4096, 2);
        footer[100] ^= 1;
        assert!(matches!(
            parse_footer(&footer),
            Err(VhdError::InvalidChecksum {
                structure: "footer"
            })
        ));
    }

    #[test]
    fn decodes_parent_paths_in_both_vhd_encodings() {
        let little: Vec<u8> = "parent.vhd"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let big: Vec<u8> = "parent.vhd"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        assert_eq!(decode_utf16_le(&little).unwrap(), "parent.vhd");
        assert_eq!(decode_utf16_be(&big).unwrap(), "parent.vhd");
    }
}
