//! SDS entry types and iterators for the $Secure system file.

use alloc::vec::Vec;

use crate::attribute::NtfsAttributeItem;
use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::structured_values::NtfsSecurityDescriptor;
use crate::types::NtfsPosition;
use fs_common::io::FsReadSeek;

/// Size of the $SDS entry header (hash + `security_id` + `file_offset`
/// + `entry_size`).
pub(crate) const SDS_HEADER_SIZE: usize = 20;
const SDS_HEADER_SIZE_U64: u64 = 20;

/// Maximum allowed $SDS entry size. Real security descriptors are
/// typically <1KB. This limit prevents OOM from corrupt $SII entries
/// declaring multi-GB sizes.
pub(crate) const SDS_MAX_SIZE: usize = 256 * 1024;

/// Size of one $SDS block (primary or mirror region).
pub(crate) const SDS_BLOCK_SIZE: u64 = 0x40000; // 256 KiB

/// Size of a primary+mirror block pair.
pub(crate) const SDS_BLOCK_PAIR_SIZE: u64 = 0x80000; // 512 KiB

/// Alignment of $SDS entries within a block.
pub(crate) const SDS_ENTRY_ALIGNMENT: u64 = 16;

/// Rounds `value` up to the next multiple of `align`.
/// `align` must be a power of two.
pub(crate) const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Status of dual-copy mirror comparison for an `$SDS` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsSdsMirrorStatus {
    /// Mirror copy matches primary.
    Match,
    /// Mirror copy differs from primary.
    Mismatch,
    /// Mirror copy could not be read (beyond stream end).
    Unavailable,
}

/// A single entry from the `$SDS` stream of the `$Secure` system
/// file.
///
/// Each entry contains a security descriptor header (20 bytes)
/// followed by a self-relative security descriptor. Entries are
/// never deleted from `$SDS`, making this a complete history of
/// every security descriptor ever assigned on the volume.
///
/// The `'b` lifetime is tied to the caller-provided buffer passed
/// to [`NtfsSdsEntries::next`].
pub struct NtfsSdsEntry<'b> {
    pub(crate) data: &'b [u8],
    pub(crate) stream_offset: u64,
    pub(crate) mirror_status: NtfsSdsMirrorStatus,
    pub(crate) slack_before: u64,
}

impl<'b> NtfsSdsEntry<'b> {
    /// Security descriptor hash from the entry header.
    #[must_use]
    pub fn hash(&self) -> u32 {
        u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    /// Security ID from the entry header.
    #[must_use]
    pub fn security_id(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Self-referencing offset stored in the entry header.
    ///
    /// On a healthy volume, this equals
    /// [`stream_offset`](Self::stream_offset). A mismatch indicates
    /// the entry was moved or the stream is corrupt.
    #[must_use]
    pub fn sds_offset(&self) -> u64 {
        u64::from_le_bytes([
            self.data[8],
            self.data[9],
            self.data[10],
            self.data[11],
            self.data[12],
            self.data[13],
            self.data[14],
            self.data[15],
        ])
    }

    /// Total entry size from the header (header + descriptor +
    /// alignment padding).
    #[must_use]
    pub fn entry_size(&self) -> u32 {
        u32::from_le_bytes([self.data[16], self.data[17], self.data[18], self.data[19]])
    }

    /// Actual byte offset where this entry was read from the `$SDS`
    /// stream.
    #[must_use]
    pub fn stream_offset(&self) -> u64 {
        self.stream_offset
    }

    /// Result of comparing this entry's primary copy with its
    /// mirror copy.
    #[must_use]
    pub fn mirror_status(&self) -> NtfsSdsMirrorStatus {
        self.mirror_status
    }

    /// Number of bytes between the previous entry's aligned end and
    /// this entry.
    ///
    /// Zero for the first entry in a block. A nonzero value
    /// indicates inter-entry slack (padding beyond 16-byte alignment
    /// or gaps from deleted entries).
    #[must_use]
    pub fn slack_before(&self) -> u64 {
        self.slack_before
    }

    /// Raw bytes after the 20-byte header through the end of
    /// `entry_size`.
    ///
    /// This includes the security descriptor and any trailing
    /// alignment padding within the entry's allocated size.
    #[must_use]
    pub fn entry_payload(&self) -> &'b [u8] {
        &self.data[SDS_HEADER_SIZE..]
    }

    /// Parse the security descriptor from the entry payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor payload is truncated or contains
    /// invalid self-relative security descriptor offsets.
    pub fn descriptor(&self) -> Result<NtfsSecurityDescriptor<'b>> {
        let descriptor_data = &self.data[SDS_HEADER_SIZE..];
        let position = NtfsPosition::new(self.stream_offset + SDS_HEADER_SIZE_U64);
        NtfsSecurityDescriptor::from_bytes(descriptor_data, position)
    }
}

/// Summary statistics from a full `$SDS` stream walk.
#[derive(Debug, Clone)]
pub struct NtfsSdsStreamInfo {
    /// Number of valid entries parsed.
    pub total_entries: u64,
    /// Total inter-entry slack bytes across all entries.
    pub total_slack_bytes: u64,
    /// Bytes remaining after the last valid entry to end of stream.
    pub stream_tail_bytes: u64,
    /// Number of entries where the mirror copy was compared.
    pub mirror_checked: u64,
    /// Number of entries where the mirror copy differed.
    pub mirror_mismatches: u64,
    /// Number of entries where the mirror was beyond stream end.
    pub mirror_unavailable: u64,
}

/// Iterator over all entries in the `$SDS` stream of the `$Secure`
/// system file.
///
/// Walks primary blocks sequentially, skipping mirror regions. For
/// each entry, compares the primary copy with its mirror and reports
/// the result via [`NtfsSdsMirrorStatus`].
///
/// # Usage
///
/// ```ignore
/// let mut entries = ntfs_secure_sds_entries(&secure_file, &mut fs)?;
/// let mut buf = Vec::new();
/// while let Some(result) = entries.next(&mut fs, &mut buf) {
///     match result {
///         Ok(entry) => { /* process */ }
///         Err(e) => { eprintln!("corrupt entry: {e}"); }
///     }
/// }
/// // Stream tail = entries.stream_len() - entries.position()
/// ```
pub struct NtfsSdsEntries<'n, 'f> {
    sds_item: NtfsAttributeItem<'n, 'f>,
    pub(crate) stream_len: u64,
    current_offset: u64,
    prev_entry_end: u64,
    mirror_buf: Vec<u8>,
}

impl<'n, 'f> NtfsSdsEntries<'n, 'f> {
    pub(crate) fn new(sds_item: NtfsAttributeItem<'n, 'f>, stream_len: u64) -> Self {
        Self {
            sds_item,
            stream_len,
            current_offset: 0,
            prev_entry_end: 0,
            mirror_buf: Vec::new(),
        }
    }

    /// Total length of the `$SDS` stream in bytes.
    #[must_use]
    pub fn stream_len(&self) -> u64 {
        self.stream_len
    }

    /// Current byte offset within the `$SDS` stream, clamped to
    /// `stream_len()`.
    ///
    /// After the iterator is exhausted, `stream_len() - position()`
    /// gives the stream tail size (bytes after the last valid
    /// entry).
    #[must_use]
    pub fn position(&self) -> u64 {
        self.current_offset.min(self.stream_len)
    }

    /// Advance `current_offset` to the start of the next primary
    /// block and reset `prev_entry_end` to match.
    fn skip_to_next_primary_block(&mut self) {
        let block_pair_index = self.current_offset / SDS_BLOCK_PAIR_SIZE;
        self.current_offset = (block_pair_index + 1) * SDS_BLOCK_PAIR_SIZE;
        self.prev_entry_end = self.current_offset;
    }

    /// Yield the next `$SDS` entry, or `None` if the stream is
    /// exhausted.
    ///
    /// The caller must provide a reusable buffer `buf` for reading
    /// entry data. The returned [`NtfsSdsEntry`] borrows from this
    /// buffer, so the buffer must outlive the entry.
    pub fn next<'b, T>(
        &mut self,
        fs: &mut T,
        buf: &'b mut Vec<u8>,
    ) -> Option<Result<NtfsSdsEntry<'b>>>
    where
        T: Read + Seek,
    {
        loop {
            if self.current_offset >= self.stream_len {
                return None;
            }

            // If we're in a mirror region, skip to next primary.
            let rel = self.current_offset % SDS_BLOCK_PAIR_SIZE;
            if rel >= SDS_BLOCK_SIZE {
                self.skip_to_next_primary_block();
                continue;
            }

            // Read 20-byte header.
            let header_end = self.current_offset + SDS_HEADER_SIZE_U64;
            if header_end > self.stream_len {
                let position = NtfsPosition::new(self.current_offset);
                self.current_offset = self.stream_len;
                return Some(Err(NtfsError::InvalidSdsEntry {
                    position,
                    reason: "truncated $SDS entry header \
                             at end of stream",
                }));
            }

            let mut header = [0u8; SDS_HEADER_SIZE];
            if let Err(e) = sds_read_at(&self.sds_item, fs, self.current_offset, &mut header) {
                self.skip_to_next_primary_block();
                return Some(Err(e));
            }

            // All-zero header = sentinel (end of entries in block).
            if header == [0u8; SDS_HEADER_SIZE] {
                self.skip_to_next_primary_block();
                continue;
            }

            let entry_size = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
            let entry_size_u64 = u64::from(entry_size);
            let position = NtfsPosition::new(self.current_offset);
            let Ok(entry_size_usize) = usize::try_from(entry_size) else {
                self.skip_to_next_primary_block();
                return Some(Err(NtfsError::InvalidSdsEntry {
                    position,
                    reason: "$SDS entry size does not fit the target address space",
                }));
            };

            if let Some(err) = self.validate_entry_size(entry_size, entry_size_u64, rel, position) {
                return Some(Err(err));
            }

            // Read the full entry into the caller's buffer.
            buf.resize(entry_size_usize, 0);
            if let Err(e) = sds_read_at(&self.sds_item, fs, self.current_offset, buf) {
                self.skip_to_next_primary_block();
                return Some(Err(e));
            }

            // Compute slack before this entry.
            let slack_before = self.current_offset.saturating_sub(self.prev_entry_end);

            // Mirror comparison.
            let mirror_status = self.compare_mirror(fs, buf, entry_size_u64);

            // Advance position.
            let aligned_end = align_up(self.current_offset + entry_size_u64, SDS_ENTRY_ALIGNMENT);
            let stream_offset = self.current_offset;
            self.prev_entry_end = aligned_end;
            self.current_offset = aligned_end;

            return Some(Ok(NtfsSdsEntry {
                data: buf,
                stream_offset,
                mirror_status,
                slack_before,
            }));
        }
    }

    /// Validate entry size bounds. Returns an error if invalid,
    /// advancing past the bad block.
    fn validate_entry_size(
        &mut self,
        entry_size: u32,
        entry_size_u64: u64,
        rel: u64,
        position: NtfsPosition,
    ) -> Option<NtfsError> {
        // Zero-size entry with non-zero header = corruption.
        if entry_size == 0 {
            self.skip_to_next_primary_block();
            return Some(NtfsError::InvalidSdsEntry {
                position,
                reason: "$SDS entry has zero size \
                         but non-zero header",
            });
        }

        if entry_size <= u32::try_from(SDS_HEADER_SIZE).expect("the 20-byte SDS header fits in u32")
        {
            self.skip_to_next_primary_block();
            return Some(NtfsError::InvalidSdsEntry {
                position,
                reason: "$SDS entry too small for header",
            });
        }

        if entry_size
            > u32::try_from(SDS_MAX_SIZE).expect("the configured SDS size limit fits in u32")
        {
            self.skip_to_next_primary_block();
            return Some(NtfsError::InvalidSdsEntry {
                position,
                reason: "$SDS entry exceeds maximum \
                         allowed size",
            });
        }

        if rel + entry_size_u64 > SDS_BLOCK_SIZE {
            self.skip_to_next_primary_block();
            return Some(NtfsError::InvalidSdsEntry {
                position,
                reason: "$SDS entry crosses block boundary",
            });
        }

        if self.current_offset + entry_size_u64 > self.stream_len {
            self.current_offset = self.stream_len;
            return Some(NtfsError::InvalidSdsEntry {
                position,
                reason: "$SDS entry extends beyond \
                         stream end",
            });
        }

        None
    }

    /// Compare the primary entry with its mirror copy.
    fn compare_mirror<T>(
        &mut self,
        fs: &mut T,
        primary_buf: &[u8],
        entry_size_u64: u64,
    ) -> NtfsSdsMirrorStatus
    where
        T: Read + Seek,
    {
        let mirror_offset = self.current_offset + SDS_BLOCK_SIZE;
        if mirror_offset + entry_size_u64 > self.stream_len {
            return NtfsSdsMirrorStatus::Unavailable;
        }

        self.mirror_buf.resize(primary_buf.len(), 0);
        match sds_read_at(&self.sds_item, fs, mirror_offset, &mut self.mirror_buf) {
            Ok(()) => {
                if self.mirror_buf[..] == primary_buf[..] {
                    NtfsSdsMirrorStatus::Match
                } else {
                    NtfsSdsMirrorStatus::Mismatch
                }
            }
            Err(_) => NtfsSdsMirrorStatus::Unavailable,
        }
    }
}

/// Read exactly `buf.len()` bytes from the `$SDS` stream at
/// `offset`.
pub(crate) fn sds_read_at<T>(
    sds_item: &NtfsAttributeItem<'_, '_>,
    fs: &mut T,
    offset: u64,
    buf: &mut [u8],
) -> Result<()>
where
    T: Read + Seek,
{
    let sds_attribute = sds_item.to_attribute()?;
    let mut sds_value = sds_attribute.value(fs)?;
    sds_value.seek(fs, SeekFrom::Start(offset))?;
    sds_value.read_exact(fs, buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up_rounds_to_next_multiple() {
        // align must be a power of two; SDS uses 16.
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(15, 16), 16);
        assert_eq!(align_up(16, 16), 16); // already aligned
        assert_eq!(align_up(17, 16), 32);
        assert_eq!(align_up(31, 16), 32);
        assert_eq!(align_up(48, 16), 48);
        // Distinct alignment to pin the mask formula: (v + a - 1) & !(a - 1).
        assert_eq!(align_up(13, 8), 16);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
    }

    #[test]
    fn test_sds_max_size_is_256_kib() {
        // 256 * 1024 = 262144. Pins the `*` (256+1024=1280, 256/1024=0).
        assert_eq!(SDS_MAX_SIZE, 262_144);
    }

    /// Build a 20-byte `$SDS` entry header followed by `payload`.
    ///
    /// Header layout: hash@0 (u32), `security_id@4` (u32),
    /// `sds_offset@8` (u64), `entry_size@16` (u32).
    fn build_sds_entry(
        hash: u32,
        security_id: u32,
        sds_offset: u64,
        entry_size: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&hash.to_le_bytes());
        buf.extend_from_slice(&security_id.to_le_bytes());
        buf.extend_from_slice(&sds_offset.to_le_bytes());
        buf.extend_from_slice(&entry_size.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_sds_entry_header_accessors_exact() {
        let payload = [0xAAu8; 8];
        let data = build_sds_entry(
            0x1122_3344,
            0x5566_7788,
            0x0001_0000,
            u32::try_from(SDS_HEADER_SIZE + payload.len()).expect("test value fits u32"),
            &payload,
        );
        let entry = NtfsSdsEntry {
            data: &data,
            stream_offset: 0x4000,
            mirror_status: NtfsSdsMirrorStatus::Match,
            slack_before: 7,
        };

        assert_eq!(entry.hash(), 0x1122_3344);
        assert_eq!(entry.security_id(), 0x5566_7788);
        assert_eq!(entry.sds_offset(), 0x0001_0000);
        assert_eq!(
            entry.entry_size(),
            u32::try_from(SDS_HEADER_SIZE + payload.len()).expect("test value fits u32")
        );
        assert_eq!(entry.stream_offset(), 0x4000);
        assert_eq!(entry.mirror_status(), NtfsSdsMirrorStatus::Match);
        assert_eq!(entry.slack_before(), 7);
        // Payload is everything after the 20-byte header.
        assert_eq!(entry.entry_payload(), &payload);
    }

    #[test]
    fn test_sds_entry_descriptor_position_uses_header_offset() {
        // A self-relative security descriptor (revision 1, SELF_RELATIVE
        // control 0x8000) whose owner SID offset (bytes 4..8) points past the
        // end of the data. Reading the owner SID then yields an error carrying
        // the descriptor's position, which is stream_offset + SDS_HEADER_SIZE.
        let mut sd = alloc::vec![0u8; 20];
        sd[0] = 1; // revision
        sd[2..4].copy_from_slice(&0x8000u16.to_le_bytes()); // SELF_RELATIVE control
        sd[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes()); // owner offset beyond data
        let data = build_sds_entry(
            0,
            1,
            0,
            u32::try_from(SDS_HEADER_SIZE + sd.len()).expect("test value fits u32"),
            &sd,
        );

        let entry = NtfsSdsEntry {
            data: &data,
            stream_offset: 0x1000,
            mirror_status: NtfsSdsMirrorStatus::Unavailable,
            slack_before: 0,
        };

        let descriptor = entry
            .descriptor()
            .expect("valid security descriptor header");
        let err = descriptor
            .owner_sid()
            .expect("owner offset is non-zero")
            .unwrap_err();
        let NtfsError::InvalidSecurityDescriptor { position, .. } = err else {
            panic!("expected InvalidSecurityDescriptor, got {err}");
        };
        // position = stream_offset(0x1000) + SDS_HEADER_SIZE(20).
        // The `+` -> `-`/`*` mutants on line 133 would change this exact value.
        assert_eq!(
            position.value().unwrap().get(),
            0x1000 + u64::try_from(SDS_HEADER_SIZE).expect("the 20-byte SDS header fits u64")
        );
    }
}
