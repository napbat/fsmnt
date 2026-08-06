use core::mem;

use alloc::vec::Vec;
use memoffset::{offset_of, span_of};

use crate::error::{NtfsError, Result};
use crate::types::NtfsPosition;

const NTFS_BLOCK_SIZE: usize = 512;

/// Minimum size required for a valid record header.
const MIN_RECORD_HEADER_SIZE: usize = mem::size_of::<RecordHeader>();

#[repr(C, packed)]
pub(crate) struct RecordHeader {
    signature: [u8; 4],
    update_sequence_offset: u16,
    update_sequence_count: u16,
    logfile_sequence_number: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct Record {
    data: Vec<u8>,
    position: NtfsPosition,
}

impl Record {
    pub(crate) fn new(data: Vec<u8>, position: NtfsPosition) -> Self {
        Self { data, position }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn fixup(&mut self) -> Result<()> {
        let update_sequence_number = self.update_sequence_number()?;
        let array_count = self.update_sequence_array_count()?;

        let mut array_position = self.update_sequence_array_start()? as usize;
        let array_end =
            self.update_sequence_offset()? as usize + self.update_sequence_size()? as usize;
        let sectors_end = array_count as usize * NTFS_BLOCK_SIZE;

        if array_end > self.data.len() || sectors_end > self.data.len() {
            return Err(NtfsError::UpdateSequenceArrayExceedsRecordSize {
                position: self.position,
                array_count,
                record_size: self.data.len(),
            });
        }

        // The Update Sequence Number (USN) is written to the last 2 bytes of each sector.
        let mut sector_position = NTFS_BLOCK_SIZE - mem::size_of::<u16>();

        while array_position < array_end {
            let array_position_end = array_position + mem::size_of::<u16>();
            let sector_position_end = sector_position + mem::size_of::<u16>();

            // The array contains the actual 2 bytes that need to be at `sector_position` after the fixup.
            let new_bytes: [u8; 2] = self.data[array_position..array_position_end]
                .try_into()
                .unwrap();

            // The current 2 bytes at `sector_position` before the fixup should equal the Update Sequence Number (USN).
            // Otherwise, this sector is corrupted.
            let bytes_to_update = &mut self.data[sector_position..sector_position_end];
            if bytes_to_update != update_sequence_number {
                return Err(NtfsError::UpdateSequenceNumberMismatch {
                    position: self.position + array_position,
                    expected: update_sequence_number,
                    actual: (&*bytes_to_update).try_into().unwrap(),
                });
            }

            // Perform the actual fixup.
            bytes_to_update.copy_from_slice(&new_bytes);

            // Advance to the next array entry and sector.
            array_position += mem::size_of::<u16>();
            sector_position += NTFS_BLOCK_SIZE;
        }

        Ok(())
    }

    pub(crate) fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub(crate) fn len(&self) -> u32 {
        // A record is never larger than a u32.
        // Usually, it shouldn't even exceed a u16, but our code could handle that.
        self.data.len() as u32
    }

    pub(crate) fn position(&self) -> NtfsPosition {
        self.position
    }

    /// Validates that the record data is large enough to contain the header.
    fn validate_header_size(&self) -> Result<()> {
        if self.data.len() < MIN_RECORD_HEADER_SIZE {
            return Err(NtfsError::RecordTooSmall {
                position: self.position,
                expected: MIN_RECORD_HEADER_SIZE,
                actual: self.data.len(),
            });
        }
        Ok(())
    }

    pub(crate) fn signature(&self) -> Result<[u8; 4]> {
        self.validate_header_size()?;
        Ok(self.data[span_of!(RecordHeader, signature)]
            .try_into()
            .unwrap())
    }

    fn update_sequence_array_count(&self) -> Result<u16> {
        self.validate_header_size()?;
        let start = offset_of!(RecordHeader, update_sequence_count);
        let update_sequence_count = u16::from_le_bytes(*self.data[start..].first_chunk().unwrap());

        // Subtract the Update Sequence Number (USN) element, so that only the number of array elements remains.
        update_sequence_count
            .checked_sub(1)
            .ok_or(NtfsError::InvalidUpdateSequenceCount {
                position: self.position,
                update_sequence_count,
            })
    }

    fn update_sequence_array_start(&self) -> Result<u16> {
        // The Update Sequence Number (USN) comes first and the array begins right after that.
        Ok(self.update_sequence_offset()? + mem::size_of::<u16>() as u16)
    }

    fn update_sequence_number(&self) -> Result<[u8; 2]> {
        let start = self.update_sequence_offset()? as usize;
        let end = start + mem::size_of::<u16>();
        self.data
            .get(start..end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(NtfsError::InvalidUpdateSequenceNumberRange {
                position: self.position,
                range: start..end,
                size: self.data.len(),
            })
    }

    fn update_sequence_offset(&self) -> Result<u16> {
        self.validate_header_size()?;
        let start = offset_of!(RecordHeader, update_sequence_offset);
        Ok(u16::from_le_bytes(
            *self.data[start..].first_chunk().unwrap(),
        ))
    }

    pub(crate) fn update_sequence_size(&self) -> Result<u32> {
        self.validate_header_size()?;
        let start = offset_of!(RecordHeader, update_sequence_count);
        let update_sequence_count = u16::from_le_bytes(*self.data[start..].first_chunk().unwrap());
        Ok(update_sequence_count as u32 * mem::size_of::<u16>() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USN: [u8; 2] = [0xAA, 0xBB];

    /// Builds a synthetic NTFS fixup-protected record.
    ///
    /// Layout: `num_sectors` sectors of 512 bytes each. The RecordHeader is
    /// at offset 0 (signature "FILE", update_sequence_offset, count). The
    /// Update Sequence Number is written at `usn_offset` and into the last
    /// two bytes of every sector. The fixup array (one 2-byte entry per
    /// sector) follows the USN; entry `i` holds the original bytes that
    /// belong at sector `i`'s tail.
    fn build_record(num_sectors: usize, usn_offset: usize, fixups: &[[u8; 2]]) -> Vec<u8> {
        assert_eq!(fixups.len(), num_sectors);
        let mut data = vec![0u8; num_sectors * NTFS_BLOCK_SIZE];
        data[0..4].copy_from_slice(b"FILE");
        // update_sequence_offset (u16) at offset 4.
        data[4..6].copy_from_slice(&(usn_offset as u16).to_le_bytes());
        // update_sequence_count (u16) at offset 6: array_count + 1 USN slot.
        data[6..8].copy_from_slice(&((num_sectors + 1) as u16).to_le_bytes());
        // USN value.
        data[usn_offset..usn_offset + 2].copy_from_slice(&USN);
        // Fixup array entries follow the USN.
        for (i, fixup) in fixups.iter().enumerate() {
            let entry = usn_offset + 2 + i * 2;
            data[entry..entry + 2].copy_from_slice(fixup);
        }
        // Each sector's last two bytes currently hold the USN (pre-fixup).
        for s in 0..num_sectors {
            let tail = s * NTFS_BLOCK_SIZE + NTFS_BLOCK_SIZE - 2;
            data[tail..tail + 2].copy_from_slice(&USN);
        }
        data
    }

    fn record(data: Vec<u8>) -> Record {
        Record::new(data, NtfsPosition::new(0x1000))
    }

    #[test]
    fn signature_returns_actual_bytes() {
        let rec = record(build_record(1, 48, &[[0x11, 0x22]]));
        assert_eq!(rec.signature().unwrap(), *b"FILE");
    }

    #[test]
    fn len_returns_actual_size() {
        let rec = record(build_record(2, 48, &[[0x11, 0x22], [0x33, 0x44]]));
        assert_eq!(rec.len(), 1024);
    }

    #[test]
    fn into_data_returns_buffer() {
        let data = build_record(1, 48, &[[0x11, 0x22]]);
        let expected = data.clone();
        let rec = record(data);
        assert_eq!(rec.into_data(), expected);
    }

    #[test]
    fn validate_header_size_rejects_too_small() {
        // 10 bytes < MIN_RECORD_HEADER_SIZE (16): signature() must error.
        let rec = record(vec![b'F', b'I', b'L', b'E', 0, 0, 0, 0, 0, 0]);
        assert!(rec.signature().is_err());
    }

    #[test]
    fn validate_header_size_accepts_exact_minimum() {
        // Exactly MIN_RECORD_HEADER_SIZE (16) bytes: signature() succeeds.
        let mut data = vec![0u8; MIN_RECORD_HEADER_SIZE];
        data[0..4].copy_from_slice(b"FILE");
        let rec = record(data);
        assert_eq!(rec.signature().unwrap(), *b"FILE");
    }

    #[test]
    fn update_sequence_size_scales_with_count() {
        // count = num_sectors + 1 = 4 -> size = 4 * 2 = 8.
        let rec = record(build_record(
            3,
            48,
            &[[0x11, 0x22], [0x33, 0x44], [0x55, 0x66]],
        ));
        assert_eq!(rec.update_sequence_size().unwrap(), 8);
    }

    #[test]
    fn fixup_applies_to_single_sector() {
        let mut rec = record(build_record(1, 48, &[[0x11, 0x22]]));
        rec.fixup().expect("valid fixup");
        let data = rec.into_data();
        // Sector 0 tail replaced with the array entry.
        assert_eq!(&data[510..512], &[0x11, 0x22]);
    }

    #[test]
    fn fixup_applies_to_all_sectors() {
        // Three sectors prove the loop advances array_position and
        // sector_position correctly for every sector.
        let mut rec = record(build_record(
            3,
            48,
            &[[0x11, 0x22], [0x33, 0x44], [0x55, 0x66]],
        ));
        rec.fixup().expect("valid fixup");
        let data = rec.into_data();
        assert_eq!(&data[510..512], &[0x11, 0x22]);
        assert_eq!(&data[1022..1024], &[0x33, 0x44]);
        assert_eq!(&data[1534..1536], &[0x55, 0x66]);
        // The USN must NOT remain at any sector tail.
        assert_ne!(&data[510..512], &USN);
        assert_ne!(&data[1022..1024], &USN);
        assert_ne!(&data[1534..1536], &USN);
    }

    #[test]
    fn fixup_uses_correct_usn_and_sector_offsets() {
        // Put a distinct value at offset 256 (where `512 / 2` would wrongly
        // look) so the `- size_of` -> `/ size_of` mutation triggers a
        // mismatch. The real sector tail at 510 still holds the USN.
        let mut data = build_record(1, 48, &[[0x11, 0x22]]);
        data[256..258].copy_from_slice(&[0x77, 0x88]); // != USN
        let mut rec = record(data);
        rec.fixup().expect("valid fixup with correct geometry");
        let data = rec.into_data();
        assert_eq!(&data[510..512], &[0x11, 0x22]);
    }

    #[test]
    fn fixup_detects_usn_mismatch() {
        // Corrupt sector 0's tail so it no longer matches the USN.
        let mut data = build_record(2, 48, &[[0x11, 0x22], [0x33, 0x44]]);
        data[510..512].copy_from_slice(&[0x00, 0x01]); // != USN
        let mut rec = record(data);
        let err = rec.fixup().expect_err("USN mismatch must be detected");
        assert!(
            matches!(err, NtfsError::UpdateSequenceNumberMismatch { .. }),
            "expected UpdateSequenceNumberMismatch, got {err:?}"
        );
    }

    #[test]
    fn fixup_rejects_record_smaller_than_sectors() {
        // count = 3 -> array_count = 2 -> sectors_end = 2 * 512 = 1024,
        // but the record is only 600 bytes. The guard must reject this
        // (rather than reading past the end).
        let mut data = build_record(2, 48, &[[0x11, 0x22], [0x33, 0x44]]);
        data.truncate(600);
        let mut rec = record(data);
        let err = rec
            .fixup()
            .expect_err("record too small for declared sectors must error");
        assert!(
            matches!(
                err,
                NtfsError::UpdateSequenceArrayExceedsRecordSize { array_count: 2, .. }
            ),
            "expected UpdateSequenceArrayExceedsRecordSize{{array_count:2}}, got {err:?}"
        );
    }

    #[test]
    fn fixup_rejects_array_end_beyond_record() {
        // usn_offset near the end so array_end (offset + size) exceeds the
        // (tiny) record, isolating the array_end guard with sectors_end
        // small. count = 2 -> size = 4. Place usn_offset so offset+4 > len.
        let mut data = build_record(1, 48, &[[0x11, 0x22]]);
        // Move usn_offset to 510: array_end = 510 + 4 = 514 > 512.
        data[4..6].copy_from_slice(&510u16.to_le_bytes());
        let mut rec = record(data);
        let err = rec.fixup().expect_err("array_end beyond record must error");
        assert!(
            matches!(err, NtfsError::UpdateSequenceArrayExceedsRecordSize { .. }),
            "expected UpdateSequenceArrayExceedsRecordSize, got {err:?}"
        );
    }

    #[test]
    fn fixup_accepts_array_end_exactly_at_record_end() {
        // array_end == data.len() must be accepted (the guard is strict `>`).
        // Build a 520-byte record (one sector + 8 trailing bytes) with the
        // USN region placed so the fixup array ends exactly at byte 520.
        // count = 2 -> update_sequence_size = 4 -> array_end = usn_offset + 4.
        let usn_offset = 516usize; // array_end = 516 + 4 = 520 == len.
        let mut data = vec![0u8; 520];
        data[0..4].copy_from_slice(b"FILE");
        data[4..6].copy_from_slice(&(usn_offset as u16).to_le_bytes());
        data[6..8].copy_from_slice(&2u16.to_le_bytes()); // count = 2 (1 sector)
        let usn = [0xAAu8, 0xBB];
        data[usn_offset..usn_offset + 2].copy_from_slice(&usn); // USN value
        data[usn_offset + 2..usn_offset + 4].copy_from_slice(&[0x11, 0x22]); // fixup
        data[510..512].copy_from_slice(&usn); // sector 0 tail holds the USN

        let mut rec = record(data);
        rec.fixup().expect("array_end == len is valid");
        let data = rec.into_data();
        // The fixup must have replaced the sector tail.
        assert_eq!(&data[510..512], &[0x11, 0x22]);
    }
}
