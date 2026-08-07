//! Logical-to-physical reads across Btrfs chunk profiles.

use fsmnt_parser_core::io::{Read, Seek, SeekFrom};

use super::Btrfs;
use crate::chunk::{MappedSegment, PhysicalLocation};
use crate::{BtrfsError, Result, raid56};

#[derive(Clone, Copy)]
enum MappingPurpose {
    Metadata { apply_remap: bool },
    Data,
}

impl<R: Read + Seek> Btrfs<R> {
    pub(crate) fn logical_replica_count(
        &mut self,
        logical: u64,
        apply_remap: bool,
    ) -> Result<usize> {
        let segment = self.map_segment(logical, 1, MappingPurpose::Metadata { apply_remap })?;
        replica_count(&segment, logical)
    }

    pub(crate) fn data_replica_count(&mut self, logical: u64) -> Result<usize> {
        let segment = self.map_segment(logical, 1, MappingPurpose::Data)?;
        replica_count(&segment, logical)
    }

    pub(crate) fn read_logical_exact_from_replica(
        &mut self,
        logical: u64,
        output: &mut [u8],
        preferred_replica: usize,
        apply_remap: bool,
    ) -> Result<()> {
        self.read_exact_from_replica(
            logical,
            output,
            preferred_replica,
            MappingPurpose::Metadata { apply_remap },
        )
    }

    pub(crate) fn read_data_logical_exact_from_replica(
        &mut self,
        logical: u64,
        output: &mut [u8],
        preferred_replica: usize,
    ) -> Result<()> {
        self.read_exact_from_replica(logical, output, preferred_replica, MappingPurpose::Data)
    }

    fn read_exact_from_replica(
        &mut self,
        mut logical: u64,
        mut output: &mut [u8],
        preferred_replica: usize,
        purpose: MappingPurpose,
    ) -> Result<()> {
        while !output.is_empty() {
            let segment = self.map_segment(logical, output.len(), purpose)?;
            if segment.length == 0 {
                return Err(BtrfsError::LogicalAddressUnmapped { logical });
            }
            let target = &mut output[..segment.length];
            self.read_mapped_segment(&segment, target, preferred_replica, logical)?;
            let consumed =
                u64::try_from(segment.length).map_err(|_| BtrfsError::IntegerOverflow)?;
            logical = logical
                .checked_add(consumed)
                .ok_or(BtrfsError::IntegerOverflow)?;
            output = &mut output[segment.length..];
        }
        Ok(())
    }

    fn map_segment(
        &mut self,
        logical: u64,
        requested: usize,
        purpose: MappingPurpose,
    ) -> Result<MappedSegment> {
        let source = self
            .chunks
            .iter()
            .find(|chunk| chunk.contains(logical))
            .ok_or(BtrfsError::LogicalAddressUnmapped { logical })?;
        let source_end = source
            .logical
            .checked_add(source.length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let source_remaining = source_end
            .checked_sub(logical)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let requested_u64 = u64::try_from(requested).map_err(|_| BtrfsError::IntegerOverflow)?;
        let mut maximum = usize::try_from(source_remaining.min(requested_u64))
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        let apply_remap = match purpose {
            MappingPurpose::Metadata { apply_remap } => apply_remap,
            MappingPurpose::Data => true,
        };
        let source_is_remapped = source.is_remapped();
        let mut mapped_logical = logical;
        if apply_remap && source_is_remapped {
            let translation = self.translate_remap(logical, maximum)?;
            mapped_logical = translation.logical;
            maximum = translation.length;
        }
        let target = self
            .chunks
            .iter()
            .find(|chunk| chunk.contains(mapped_logical))
            .cloned()
            .ok_or(BtrfsError::LogicalAddressUnmapped {
                logical: mapped_logical,
            })?;
        if matches!(purpose, MappingPurpose::Data)
            && self.superblock().has_raid_stripe_tree()
            && target.uses_raid_stripe_tree()
        {
            self.map_raid_stripe(&target, mapped_logical, maximum)
        } else {
            target.map(mapped_logical, maximum)
        }
    }

    fn read_mapped_segment(
        &mut self,
        segment: &MappedSegment,
        output: &mut [u8],
        preferred_replica: usize,
        logical: u64,
    ) -> Result<()> {
        if let Some(recovery) = &segment.raid56 {
            if preferred_replica == 0
                && let Some(location) = segment.locations.first()
                && self.read_physical_exact(*location, output).is_ok()
            {
                return Ok(());
            }
            let forced_missing = recovery.forced_missing(preferred_replica);
            return raid56::reconstruct_data(
                recovery.data_stripes,
                recovery.parity_stripes,
                recovery.target_data,
                forced_missing,
                output,
                |index, stripe_output| {
                    let location =
                        recovery
                            .stripes
                            .get(index)
                            .ok_or(BtrfsError::Raid56RecoveryFailed {
                                failures: recovery.parity_stripes.saturating_add(1),
                                parity_stripes: recovery.parity_stripes,
                            })?;
                    self.read_physical_exact(*location, stripe_output)
                },
            );
        }

        let location_count = segment.locations.len();
        if location_count == 0 {
            return Err(BtrfsError::LogicalAddressUnmapped { logical });
        }
        let mut last_error = None;
        for relative_index in 0..location_count {
            let location_index = preferred_replica
                .checked_add(relative_index)
                .ok_or(BtrfsError::IntegerOverflow)?
                % location_count;
            let location = segment.locations[location_index];
            match self.read_physical_exact(location, output) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(BtrfsError::LogicalAddressUnmapped { logical }))
    }

    fn read_physical_exact(&mut self, location: PhysicalLocation, output: &mut [u8]) -> Result<()> {
        let reader = self
            .device_reader_mut(location.device_id, &location.device_uuid)
            .ok_or(BtrfsError::MissingDevice {
                device_id: location.device_id,
            })?;
        reader.seek(SeekFrom::Start(location.offset))?;
        reader.read_exact(output)?;
        Ok(())
    }

    fn device_reader_mut(&mut self, device_id: u64, device_uuid: &[u8; 16]) -> Option<&mut R> {
        if self.primary.superblock.device_id() == device_id
            && self.primary.superblock.device_uuid() == device_uuid
        {
            return Some(&mut self.primary.reader);
        }
        self.additional
            .iter_mut()
            .find(|device| {
                device.superblock.device_id() == device_id
                    && device.superblock.device_uuid() == device_uuid
            })
            .map(|device| &mut device.reader)
    }
}

fn replica_count(segment: &MappedSegment, logical: u64) -> Result<usize> {
    let count = match &segment.raid56 {
        Some(recovery) => recovery.replica_count(),
        None => segment.locations.len(),
    };
    if count == 0 {
        return Err(BtrfsError::LogicalAddressUnmapped { logical });
    }
    Ok(count)
}
