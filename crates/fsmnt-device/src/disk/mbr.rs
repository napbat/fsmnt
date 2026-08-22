//! Resolution of logical partitions from extended-MBR chains.

use std::collections::HashSet;

use nostdio::{Read, Seek, SeekFrom};
use tracing::debug;

use super::ResolvedMbrPartition;
use crate::{BOOT_SECTOR_SIZE, Mbr, MbrPartitionEntry};

/// Resolve primary data entries and every readable EBR chain.
pub(super) fn resolve_volumes<R: Read + Seek>(
    reader: &mut R,
    mbr: &Mbr,
    sector_size: u32,
) -> Vec<ResolvedMbrPartition> {
    let mut volumes = mbr
        .partitions
        .iter()
        .filter(|entry| is_data_entry(entry))
        .map(|entry| ResolvedMbrPartition {
            entry: *entry,
            start_lba: u64::from(entry.start_lba.get()),
            logical: false,
        })
        .collect::<Vec<_>>();

    for extended in mbr
        .partitions
        .iter()
        .filter(|entry| entry.is_extended() && entry.sector_count.get() != 0)
    {
        if let Err(error) = read_ebr_chain(reader, extended, sector_size, &mut volumes) {
            debug!(
                start_lba = extended.start_lba.get(),
                sectors = extended.sector_count.get(),
                error = %error,
                "could not finish an MBR extended-partition chain"
            );
        }
    }
    volumes
}

fn is_data_entry(entry: &MbrPartitionEntry) -> bool {
    !entry.is_empty()
        && !entry.is_gpt_protective()
        && !entry.is_extended()
        && entry.sector_count.get() != 0
}

/// Walk one extended partition's linked EBR records.
///
/// Each validated logical extent is appended immediately. If a later link
/// is corrupt, already resolved partitions remain available to forensic
/// callers while the structural failure is reported to the trace.
fn read_ebr_chain<R: Read + Seek>(
    reader: &mut R,
    extended: &MbrPartitionEntry,
    sector_size: u32,
    volumes: &mut Vec<ResolvedMbrPartition>,
) -> std::io::Result<()> {
    let base_lba = u64::from(extended.start_lba.get());
    let end_lba = base_lba
        .checked_add(u64::from(extended.sector_count.get()))
        .ok_or_else(|| invalid_mbr("extended partition end LBA overflowed"))?;
    let sector_bytes = usize::try_from(sector_size)
        .map_err(|_| invalid_mbr("logical sector size exceeds usize"))?;
    if sector_bytes < BOOT_SECTOR_SIZE {
        return Err(invalid_mbr("logical sector is smaller than an MBR"));
    }

    let mut visited = HashSet::new();
    let mut ebr_lba = base_lba;
    loop {
        if ebr_lba < base_lba || ebr_lba >= end_lba {
            return Err(invalid_mbr("EBR lies outside its extended partition"));
        }
        if !visited.insert(ebr_lba) {
            return Err(invalid_mbr("EBR chain contains a loop"));
        }
        // A hard cap also bounds memory on a malicious chain whose every
        // link is unique.
        if visited.len() > 4096 {
            return Err(invalid_mbr("EBR chain exceeds 4096 records"));
        }

        let byte_offset = ebr_lba
            .checked_mul(u64::from(sector_size))
            .ok_or_else(|| invalid_mbr("EBR byte offset overflowed"))?;
        reader.seek(SeekFrom::Start(byte_offset))?;
        let mut sector = vec![0_u8; sector_bytes];
        reader.read_exact(&mut sector)?;
        let ebr = Mbr::from_bytes(&sector)
            .filter(|table| table.is_valid())
            .ok_or_else(|| invalid_mbr("EBR signature is missing"))?;

        if let Some(entry) = ebr.partitions.iter().find(|entry| is_data_entry(entry)) {
            let start_lba = ebr_lba
                .checked_add(u64::from(entry.start_lba.get()))
                .ok_or_else(|| invalid_mbr("logical partition start LBA overflowed"))?;
            let partition_end = start_lba
                .checked_add(u64::from(entry.sector_count.get()))
                .ok_or_else(|| invalid_mbr("logical partition end LBA overflowed"))?;
            if start_lba < base_lba || partition_end > end_lba {
                return Err(invalid_mbr(
                    "logical partition lies outside its extended partition",
                ));
            }
            volumes.push(ResolvedMbrPartition {
                entry: *entry,
                start_lba,
                logical: true,
            });
        }

        let Some(link) = ebr
            .partitions
            .iter()
            .find(|entry| entry.is_extended() && entry.sector_count.get() != 0)
        else {
            return Ok(());
        };
        ebr_lba = base_lba
            .checked_add(u64::from(link.start_lba.get()))
            .ok_or_else(|| invalid_mbr("next EBR LBA overflowed"))?;
    }
}

fn invalid_mbr(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{Disk, DiskLayout};

    const SECTOR_SIZE: usize = 512;

    fn write_partition_entry(
        sector: &mut [u8],
        slot: usize,
        partition_type: u8,
        start_lba: u32,
        sector_count: u32,
    ) {
        let start = 446 + slot * 16;
        sector[start + 4] = partition_type;
        sector[start + 8..start + 12].copy_from_slice(&start_lba.to_le_bytes());
        sector[start + 12..start + 16].copy_from_slice(&sector_count.to_le_bytes());
    }

    fn finish_mbr(sector: &mut [u8]) {
        sector[510] = 0x55;
        sector[511] = 0xAA;
    }

    fn extended_mbr_image() -> Vec<u8> {
        let mut image = vec![0_u8; SECTOR_SIZE * 128];
        write_partition_entry(&mut image[..SECTOR_SIZE], 0, 0x4D, 8, 4);
        write_partition_entry(&mut image[..SECTOR_SIZE], 1, 0xB1, 12, 8);
        write_partition_entry(&mut image[..SECTOR_SIZE], 2, 0xB2, 20, 8);
        write_partition_entry(&mut image[..SECTOR_SIZE], 3, 0x85, 32, 64);
        finish_mbr(&mut image[..SECTOR_SIZE]);

        let first_ebr = 32 * SECTOR_SIZE;
        write_partition_entry(
            &mut image[first_ebr..first_ebr + SECTOR_SIZE],
            0,
            0xB1,
            1,
            8,
        );
        write_partition_entry(
            &mut image[first_ebr..first_ebr + SECTOR_SIZE],
            1,
            0x85,
            16,
            48,
        );
        finish_mbr(&mut image[first_ebr..first_ebr + SECTOR_SIZE]);

        let second_ebr = 48 * SECTOR_SIZE;
        write_partition_entry(
            &mut image[second_ebr..second_ebr + SECTOR_SIZE],
            0,
            0xB2,
            1,
            8,
        );
        finish_mbr(&mut image[second_ebr..second_ebr + SECTOR_SIZE]);
        image
    }

    #[test]
    fn extended_containers_are_replaced_by_their_logical_partitions() {
        let mut disk = Disk::new(Cursor::new(extended_mbr_image())).expect("open MBR image");
        assert!(matches!(disk.layout(), DiskLayout::Mbr { .. }));
        assert_eq!(disk.partition_count(), 4);

        let partitions = disk.resolved_mbr_partitions().collect::<Vec<_>>();
        assert_eq!(partitions.len(), 5);
        assert_eq!(
            partitions
                .iter()
                .map(|partition| partition.start_lba())
                .collect::<Vec<_>>(),
            [8, 12, 20, 33, 49]
        );
        assert_eq!(
            partitions
                .iter()
                .map(|partition| partition.entry().partition_type)
                .collect::<Vec<_>>(),
            [0x4D, 0xB1, 0xB2, 0xB1, 0xB2]
        );
        assert_eq!(
            partitions
                .iter()
                .map(|partition| partition.is_logical())
                .collect::<Vec<_>>(),
            [false, false, false, true, true]
        );
        assert!(
            partitions
                .iter()
                .all(|partition| !partition.entry().is_extended())
        );

        let mut reader = disk
            .resolved_mbr_partition_reader(4)
            .expect("second logical partition reader");
        assert_eq!(reader.stream_position().expect("partition position"), 0);
        assert_eq!(reader.size(), 8 * 512);
    }

    #[test]
    fn a_looping_chain_keeps_the_logical_extent_already_resolved() {
        let mut image = extended_mbr_image();
        let first_ebr = 32 * SECTOR_SIZE;
        write_partition_entry(
            &mut image[first_ebr..first_ebr + SECTOR_SIZE],
            1,
            0x85,
            0,
            64,
        );
        let disk = Disk::new(Cursor::new(image)).expect("open MBR image");

        assert_eq!(disk.partition_count(), 4);
        let partitions = disk.resolved_mbr_partitions().collect::<Vec<_>>();
        assert_eq!(partitions.len(), 4);
        assert_eq!(
            partitions.last().map(|partition| partition.start_lba()),
            Some(33)
        );
        assert!(
            partitions
                .last()
                .is_some_and(|partition| partition.is_logical())
        );
    }
}
