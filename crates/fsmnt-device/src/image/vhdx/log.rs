//! Read-only VHDX transaction-log replay into a bounded in-memory overlay.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::VhdxError;
use super::format::{Guid, Header, LOG_SECTOR_SIZE, MIB, guid_at, le_u32, le_u64};

const MAX_LOG_LENGTH: usize = 256 * 1024 * 1024;
const ENTRY_HEADER_SIZE: usize = 64;
const DESCRIPTOR_SIZE: usize = 32;
const FIRST_SECTOR_DESCRIPTOR_CAPACITY: usize = 126;
const OTHER_SECTOR_DESCRIPTOR_CAPACITY: usize = 128;

#[derive(Debug)]
enum OverlayRun {
    Data { offset: u64, bytes: Vec<u8> },
    Zero { offset: u64, length: u64 },
}

/// In-memory view of committed log writes, retained in replay order.
#[derive(Debug)]
pub(super) struct LogOverlay {
    runs: Vec<OverlayRun>,
    effective_file_length: u64,
}

impl LogOverlay {
    pub(super) const fn clean(file_length: u64) -> Self {
        Self {
            runs: Vec::new(),
            effective_file_length: file_length,
        }
    }

    pub(super) const fn effective_file_length(&self) -> u64 {
        self.effective_file_length
    }

    pub(super) fn patch(&self, buffer: &mut [u8], read_offset: u64) {
        if buffer.is_empty() {
            return;
        }
        let read_end = read_offset.saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        for run in &self.runs {
            match run {
                OverlayRun::Data { offset, bytes } => {
                    patch_data(buffer, read_offset, read_end, *offset, bytes);
                }
                OverlayRun::Zero { offset, length } => {
                    patch_zero(buffer, read_offset, read_end, *offset, *length);
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct EntryInfo {
    offset: usize,
    length: usize,
    tail: usize,
    sequence: u64,
    flushed_file_offset: u64,
    last_file_offset: u64,
}

pub(super) fn build_overlay(
    file: &mut File,
    header: &Header,
    file_length: u64,
) -> Result<LogOverlay, VhdxError> {
    if header.log_guid == [0_u8; 16] {
        return Ok(LogOverlay::clean(file_length));
    }
    if header.log_length == 0 {
        return Err(VhdxError::Invalid(
            "VHDX header has a log GUID but no log region",
        ));
    }
    let log_length = usize::try_from(header.log_length).map_err(|_| VhdxError::OutOfBounds)?;
    if log_length > MAX_LOG_LENGTH || !log_length.is_multiple_of(LOG_SECTOR_SIZE) {
        return Err(VhdxError::Invalid("invalid VHDX log length"));
    }
    let log_end = header
        .log_offset
        .checked_add(u64::from(header.log_length))
        .ok_or(VhdxError::OutOfBounds)?;
    if log_end > file_length {
        return Err(VhdxError::OutOfBounds);
    }
    let mut log = vec![0_u8; log_length];
    read_exact_at(file, header.log_offset, &mut log)?;

    let entries = scan_valid_entries(&log, header.log_guid);
    let active = find_active_sequence(&entries, log.len())
        .ok_or(VhdxError::Invalid("no valid active VHDX log sequence"))?;
    let head = active
        .last()
        .ok_or(VhdxError::Invalid("active VHDX log sequence is empty"))?;
    if file_length < head.flushed_file_offset {
        return Err(VhdxError::Invalid(
            "VHDX file is shorter than the active log's flushed length",
        ));
    }

    let mut runs = Vec::new();
    for entry in &active {
        append_entry_runs(&log, entry, &mut runs)?;
    }
    Ok(LogOverlay {
        runs,
        effective_file_length: file_length.max(head.last_file_offset),
    })
}

fn scan_valid_entries(log: &[u8], expected_guid: Guid) -> HashMap<usize, EntryInfo> {
    let mut entries = HashMap::new();
    for offset in (0..log.len()).step_by(LOG_SECTOR_SIZE) {
        if let Some(entry) = validate_entry(log, offset, expected_guid) {
            entries.insert(offset, entry);
        }
    }
    entries
}

fn validate_entry(log: &[u8], offset: usize, expected_guid: Guid) -> Option<EntryInfo> {
    if circular_range(log, offset, 4)? != b"loge" {
        return None;
    }
    let header = circular_bytes(log, offset, ENTRY_HEADER_SIZE)?;
    let entry_length = usize::try_from(le_u32(&header, 8)).ok()?;
    if entry_length < LOG_SECTOR_SIZE
        || entry_length > log.len()
        || !entry_length.is_multiple_of(LOG_SECTOR_SIZE)
    {
        return None;
    }
    let mut entry = circular_bytes(log, offset, entry_length)?;
    let stored_checksum = le_u32(&entry, 4);
    entry[4..8].fill(0);
    if crc32c::crc32c(&entry) != stored_checksum {
        return None;
    }
    if guid_at(&entry, 32) != expected_guid {
        return None;
    }
    let tail = usize::try_from(le_u32(&entry, 12)).ok()?;
    let sequence = le_u64(&entry, 16);
    let flushed_file_offset = le_u64(&entry, 48);
    let last_file_offset = le_u64(&entry, 56);
    if sequence == 0
        || tail >= log.len()
        || !tail.is_multiple_of(LOG_SECTOR_SIZE)
        || le_u32(&entry, 28) != 0
        || !flushed_file_offset.is_multiple_of(MIB)
        || !last_file_offset.is_multiple_of(MIB)
    {
        return None;
    }
    validate_descriptors(&entry, sequence)?;
    Some(EntryInfo {
        offset,
        length: entry_length,
        tail,
        sequence,
        flushed_file_offset,
        last_file_offset,
    })
}

fn validate_descriptors(entry: &[u8], sequence: u64) -> Option<()> {
    let descriptor_count = usize::try_from(le_u32(entry, 24)).ok()?;
    let descriptor_sectors = descriptor_sector_count(descriptor_count);
    let descriptor_bytes = descriptor_sectors.checked_mul(LOG_SECTOR_SIZE)?;
    if descriptor_bytes > entry.len() {
        return None;
    }
    let mut data_count = 0_usize;
    for index in 0..descriptor_count {
        let offset = descriptor_offset(index)?;
        let end = offset.checked_add(DESCRIPTOR_SIZE)?;
        let descriptor = entry.get(offset..end)?;
        if le_u64(descriptor, 24) != sequence {
            return None;
        }
        match &descriptor[..4] {
            b"desc" => {
                if !le_u64(descriptor, 16).is_multiple_of(u64::try_from(LOG_SECTOR_SIZE).ok()?) {
                    return None;
                }
                data_count = data_count.checked_add(1)?;
            }
            b"zero" => {
                let zero_length = le_u64(descriptor, 8);
                let file_offset = le_u64(descriptor, 16);
                let alignment = u64::try_from(LOG_SECTOR_SIZE).ok()?;
                if le_u32(descriptor, 4) != 0
                    || zero_length == 0
                    || !zero_length.is_multiple_of(alignment)
                    || !file_offset.is_multiple_of(alignment)
                    || file_offset.checked_add(zero_length).is_none()
                {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let required_length = descriptor_bytes.checked_add(data_count.checked_mul(LOG_SECTOR_SIZE)?)?;
    if required_length > entry.len() {
        return None;
    }
    for index in 0..data_count {
        let offset = descriptor_bytes.checked_add(index.checked_mul(LOG_SECTOR_SIZE)?)?;
        let sector = entry.get(offset..offset + LOG_SECTOR_SIZE)?;
        let high = u64::from(le_u32(sector, 4));
        let low = u64::from(le_u32(sector, LOG_SECTOR_SIZE - 4));
        if sector[..4] != *b"data" || (high << 32 | low) != sequence {
            return None;
        }
    }
    Some(())
}

fn find_active_sequence(
    entries: &HashMap<usize, EntryInfo>,
    log_length: usize,
) -> Option<Vec<EntryInfo>> {
    let mut best = None;
    let mut best_sequence = 0_u64;
    for start in entries.keys().copied() {
        let mut chain = Vec::new();
        let mut current = start;
        let mut previous_sequence: Option<u64> = None;
        for _ in 0..entries.len() {
            let Some(entry) = entries.get(&current) else {
                break;
            };
            if previous_sequence
                .is_some_and(|previous| previous.checked_add(1) != Some(entry.sequence))
                || chain.iter().any(|item: &EntryInfo| item.offset == current)
            {
                break;
            }
            chain.push(entry.clone());
            previous_sequence = Some(entry.sequence);

            if let Some(tail_index) = chain.iter().position(|item| item.offset == entry.tail)
                && entry.sequence > best_sequence
            {
                best_sequence = entry.sequence;
                best = Some(chain[tail_index..].to_vec());
            }
            let Some(next) = current.checked_add(entry.length) else {
                break;
            };
            current = next % log_length;
        }
    }
    best
}

fn append_entry_runs(
    log: &[u8],
    info: &EntryInfo,
    runs: &mut Vec<OverlayRun>,
) -> Result<(), VhdxError> {
    let entry = circular_bytes(log, info.offset, info.length).ok_or(VhdxError::OutOfBounds)?;
    let descriptor_count =
        usize::try_from(le_u32(&entry, 24)).map_err(|_| VhdxError::OutOfBounds)?;
    let data_offset = descriptor_sector_count(descriptor_count)
        .checked_mul(LOG_SECTOR_SIZE)
        .ok_or(VhdxError::OutOfBounds)?;
    let mut data_index = 0_usize;
    for index in 0..descriptor_count {
        let offset = descriptor_offset(index).ok_or(VhdxError::OutOfBounds)?;
        let descriptor = &entry[offset..offset + DESCRIPTOR_SIZE];
        match &descriptor[..4] {
            b"desc" => {
                let sector_offset = data_offset
                    .checked_add(
                        data_index
                            .checked_mul(LOG_SECTOR_SIZE)
                            .ok_or(VhdxError::OutOfBounds)?,
                    )
                    .ok_or(VhdxError::OutOfBounds)?;
                let sector = &entry[sector_offset..sector_offset + LOG_SECTOR_SIZE];
                let mut restored = vec![0_u8; LOG_SECTOR_SIZE];
                restored[..8].copy_from_slice(&descriptor[8..16]);
                restored[8..LOG_SECTOR_SIZE - 4].copy_from_slice(&sector[8..LOG_SECTOR_SIZE - 4]);
                restored[LOG_SECTOR_SIZE - 4..].copy_from_slice(&descriptor[4..8]);
                runs.push(OverlayRun::Data {
                    offset: le_u64(descriptor, 16),
                    bytes: restored,
                });
                data_index += 1;
            }
            b"zero" => runs.push(OverlayRun::Zero {
                offset: le_u64(descriptor, 16),
                length: le_u64(descriptor, 8),
            }),
            _ => {
                return Err(VhdxError::Invalid("invalid descriptor in active VHDX log"));
            }
        }
    }
    Ok(())
}

fn descriptor_sector_count(descriptor_count: usize) -> usize {
    if descriptor_count <= FIRST_SECTOR_DESCRIPTOR_CAPACITY {
        1
    } else {
        1 + (descriptor_count - FIRST_SECTOR_DESCRIPTOR_CAPACITY)
            .div_ceil(OTHER_SECTOR_DESCRIPTOR_CAPACITY)
    }
}

fn descriptor_offset(index: usize) -> Option<usize> {
    if index < FIRST_SECTOR_DESCRIPTOR_CAPACITY {
        ENTRY_HEADER_SIZE.checked_add(index.checked_mul(DESCRIPTOR_SIZE)?)
    } else {
        let remaining = index - FIRST_SECTOR_DESCRIPTOR_CAPACITY;
        let sector = 1 + remaining / OTHER_SECTOR_DESCRIPTOR_CAPACITY;
        sector
            .checked_mul(LOG_SECTOR_SIZE)?
            .checked_add((remaining % OTHER_SECTOR_DESCRIPTOR_CAPACITY) * DESCRIPTOR_SIZE)
    }
}

fn circular_range(log: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    let end = offset.checked_add(length)?;
    if end <= log.len() {
        log.get(offset..end)
    } else {
        None
    }
}

fn circular_bytes(log: &[u8], offset: usize, length: usize) -> Option<Vec<u8>> {
    if length > log.len() || offset >= log.len() {
        return None;
    }
    if let Some(bytes) = circular_range(log, offset, length) {
        return Some(bytes.to_vec());
    }
    let first_length = log.len() - offset;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&log[offset..]);
    bytes.extend_from_slice(&log[..length - first_length]);
    Some(bytes)
}

fn patch_data(buffer: &mut [u8], read_start: u64, read_end: u64, run_start: u64, bytes: &[u8]) {
    let run_end = run_start.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    let overlap_start = read_start.max(run_start);
    let overlap_end = read_end.min(run_end);
    if overlap_start >= overlap_end {
        return;
    }
    let destination = usize::try_from(overlap_start - read_start).unwrap_or(usize::MAX);
    let source = usize::try_from(overlap_start - run_start).unwrap_or(usize::MAX);
    let length = usize::try_from(overlap_end - overlap_start).unwrap_or(0);
    if destination != usize::MAX && source != usize::MAX {
        buffer[destination..destination + length].copy_from_slice(&bytes[source..source + length]);
    }
}

fn patch_zero(buffer: &mut [u8], read_start: u64, read_end: u64, run_start: u64, run_length: u64) {
    let run_end = run_start.saturating_add(run_length);
    let overlap_start = read_start.max(run_start);
    let overlap_end = read_end.min(run_end);
    if overlap_start >= overlap_end {
        return;
    }
    let destination = usize::try_from(overlap_start - read_start).unwrap_or(usize::MAX);
    let length = usize::try_from(overlap_end - overlap_start).unwrap_or(0);
    if destination != usize::MAX {
        buffer[destination..destination + length].fill(0);
    }
}

fn read_exact_at(file: &mut File, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_log_entry(log_guid: Guid, file_offset: u64) -> Vec<u8> {
        const ENTRY_LENGTH: usize = 2 * LOG_SECTOR_SIZE;
        const SEQUENCE: u64 = 7;
        let mut entry = vec![0_u8; ENTRY_LENGTH];
        entry[..4].copy_from_slice(b"loge");
        entry[8..12].copy_from_slice(
            &u32::try_from(ENTRY_LENGTH)
                .expect("log entry length fits u32")
                .to_le_bytes(),
        );
        entry[12..16].copy_from_slice(&0_u32.to_le_bytes());
        entry[16..24].copy_from_slice(&SEQUENCE.to_le_bytes());
        entry[24..28].copy_from_slice(&1_u32.to_le_bytes());
        entry[32..48].copy_from_slice(&log_guid);
        entry[48..56].copy_from_slice(&(8 * MIB).to_le_bytes());
        entry[56..64].copy_from_slice(&(8 * MIB).to_le_bytes());

        let descriptor = &mut entry[ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + DESCRIPTOR_SIZE];
        descriptor[..4].copy_from_slice(b"desc");
        descriptor[4..8].copy_from_slice(&[0xf1, 0xf2, 0xf3, 0xf4]);
        descriptor[8..16].copy_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);
        descriptor[16..24].copy_from_slice(&file_offset.to_le_bytes());
        descriptor[24..32].copy_from_slice(&SEQUENCE.to_le_bytes());

        let data = &mut entry[LOG_SECTOR_SIZE..2 * LOG_SECTOR_SIZE];
        data[..4].copy_from_slice(b"data");
        data[4..8].copy_from_slice(
            &u32::try_from(SEQUENCE >> 32)
                .expect("high sequence bits fit u32")
                .to_le_bytes(),
        );
        data[8..LOG_SECTOR_SIZE - 4].fill(0x5a);
        data[LOG_SECTOR_SIZE - 4..].copy_from_slice(
            &u32::try_from(SEQUENCE & u64::from(u32::MAX))
                .expect("low sequence bits fit u32")
                .to_le_bytes(),
        );
        let checksum = crc32c::crc32c(&entry);
        entry[4..8].copy_from_slice(&checksum.to_le_bytes());
        entry
    }

    #[test]
    fn calculates_descriptor_sector_boundaries() {
        assert_eq!(descriptor_sector_count(0), 1);
        assert_eq!(descriptor_sector_count(126), 1);
        assert_eq!(descriptor_sector_count(127), 2);
        assert_eq!(descriptor_sector_count(254), 2);
        assert_eq!(descriptor_sector_count(255), 3);
        assert_eq!(descriptor_offset(0), Some(64));
        assert_eq!(descriptor_offset(125), Some(4064));
        assert_eq!(descriptor_offset(126), Some(4096));
    }

    #[test]
    fn applies_runs_in_replay_order() {
        let overlay = LogOverlay {
            runs: vec![
                OverlayRun::Data {
                    offset: 4,
                    bytes: vec![1, 2, 3, 4],
                },
                OverlayRun::Zero {
                    offset: 6,
                    length: 2,
                },
            ],
            effective_file_length: 8,
        };
        let mut bytes = [9_u8; 8];
        overlay.patch(&mut bytes, 0);
        assert_eq!(bytes, [9, 9, 9, 9, 1, 2, 0, 0]);
    }

    #[test]
    fn validates_and_reconstructs_a_data_log_entry() {
        const FILE_OFFSET: u64 = 4 * MIB;
        let log_guid = [0x42; 16];
        let entry = data_log_entry(log_guid, FILE_OFFSET);
        let info = validate_entry(&entry, 0, log_guid).expect("valid log entry");
        let entries = scan_valid_entries(&entry, log_guid);
        let sequence = find_active_sequence(&entries, entry.len()).expect("active log sequence");
        assert_eq!(sequence.len(), 1);

        let mut runs = Vec::new();
        append_entry_runs(&entry, &info, &mut runs).expect("reconstruct log write");
        let overlay = LogOverlay {
            runs,
            effective_file_length: 8 * MIB,
        };
        let mut restored = vec![0_u8; LOG_SECTOR_SIZE];
        overlay.patch(&mut restored, FILE_OFFSET);
        assert_eq!(
            &restored[..8],
            &[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]
        );
        assert!(
            restored[8..LOG_SECTOR_SIZE - 4]
                .iter()
                .all(|byte| *byte == 0x5a)
        );
        assert_eq!(&restored[LOG_SECTOR_SIZE - 4..], &[0xf1, 0xf2, 0xf3, 0xf4]);
    }
}
