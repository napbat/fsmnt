//! Cluster-buffered directory entry iterator for exFAT.
//!
//! [`ExFatDirEntries`] reads 32-byte directory entries from a cluster
//! chain and assembles them into complete [`ExFatDirItem`] values --
//! either file entry sets or volume labels.
//!
//! Entry sets may span cluster boundaries: when the current cluster
//! buffer is exhausted mid-entry-set the iterator loads the next
//! cluster from the chain transparently.

use alloc::vec::Vec;

use zerocopy::FromBytes;

use crate::dir_entry::{
    DIR_ENTRY_SIZE, ENTRY_TYPE_BITMAP, ENTRY_TYPE_END, ENTRY_TYPE_FILE, ENTRY_TYPE_NAME,
    ENTRY_TYPE_STREAM, ENTRY_TYPE_UPCASE, ENTRY_TYPE_VOLUME_LABEL, EntryTypeInfo,
    FileDirectoryEntry, FileNameEntry, StreamExtensionEntry, VolumeLabelEntry,
};
use crate::entry_set::{ExFatDirItem, ExFatEntrySet, decode_volume_label, update_set_checksum};
use crate::error::{ExFatError, Result};
use crate::exfat::ExFat;
use crate::fat::ExFatClusterIterator;
use crate::io::{Read, Seek, SeekFrom};

/// A cluster-buffered iterator over directory entries in an exFAT
/// directory.
///
/// Reads one cluster at a time from the cluster chain, then parses
/// 32-byte entries from the buffer. Entry sets that span cluster
/// boundaries are handled transparently.
pub struct ExFatDirEntries<'e> {
    exfat: &'e ExFat,
    cluster_iter: ExFatClusterIterator<'e>,
    buffer: Vec<u8>,
    buffer_offset: usize,
    buffer_valid: usize,
    finished: bool,
    current_cluster_offset: u64,
    include_deleted: bool,
    include_benign: bool,
}

impl<'e> ExFatDirEntries<'e> {
    /// Creates a new directory entry iterator starting at the given
    /// cluster.
    pub(crate) fn new(exfat: &'e ExFat, start_cluster: u32) -> Self {
        Self {
            exfat,
            cluster_iter: exfat.cluster_iter(start_cluster),
            buffer: Vec::new(),
            buffer_offset: 0,
            buffer_valid: 0,
            finished: false,
            current_cluster_offset: 0,
            include_deleted: false,
            include_benign: false,
        }
    }

    /// Enables yielding of deleted/not-in-use entries.
    ///
    /// When enabled, entries with bit 7 clear and type code > 0
    /// are yielded as [`ExFatDirItem::DeletedEntry`].
    #[must_use]
    pub fn with_deleted(mut self) -> Self {
        self.include_deleted = true;
        self
    }

    /// Enables yielding of benign entries.
    ///
    /// When enabled, recognized benign entries (Volume GUID,
    /// `TexFAT` Padding, Vendor Extension, Vendor Allocation)
    /// are yielded as [`ExFatDirItem::BenignEntry`].
    #[must_use]
    pub fn with_benign(mut self) -> Self {
        self.include_benign = true;
        self
    }

    /// Advances the iterator and returns the next directory item.
    ///
    /// Returns `None` when the directory is exhausted (end-of-
    /// directory marker or cluster chain end). Returns
    /// `Some(Err(_))` on I/O errors, truncated entry sets, or
    /// unknown critical entries.
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<ExFatDirItem>>
    where
        T: Read + Seek,
    {
        loop {
            if self.finished {
                return None;
            }

            let entry_bytes = match self.read_entry_bytes(fs) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => {
                    self.finished = true;
                    return Some(Err(e));
                }
                None => {
                    self.finished = true;
                    return None;
                }
            };

            let entry_type = entry_bytes[0];

            // End-of-directory marker.
            if entry_type == ENTRY_TYPE_END {
                self.finished = true;
                return None;
            }

            // Not-in-use entries (bit 7 clear).
            if entry_type & 0x80 == 0 {
                if self.include_deleted && entry_type != ENTRY_TYPE_END {
                    return Some(Ok(ExFatDirItem::DeletedEntry {
                        entry_type,
                        data: entry_bytes,
                        byte_offset: self.last_entry_byte_offset(),
                    }));
                }
                continue;
            }

            match entry_type {
                ENTRY_TYPE_FILE => {
                    let offset = self.last_entry_byte_offset();
                    return Some(self.assemble_file_entry(fs, entry_bytes, offset));
                }
                ENTRY_TYPE_VOLUME_LABEL => {
                    return Some(self.parse_volume_label(&entry_bytes));
                }
                ENTRY_TYPE_BITMAP | ENTRY_TYPE_UPCASE => {
                    // Skip silently -- Phase 3 will handle these.
                }
                _ => {
                    let info = EntryTypeInfo::from_byte(entry_type);
                    if info.is_benign() {
                        if self.include_benign {
                            return Some(Ok(ExFatDirItem::BenignEntry {
                                entry_type,
                                data: entry_bytes,
                                byte_offset: self.last_entry_byte_offset(),
                            }));
                        }
                        continue;
                    }
                    if !info.in_use {
                        continue;
                    }
                    // Unknown critical entry.
                    self.finished = true;
                    return Some(Err(ExFatError::UnknownCriticalEntry {
                        entry_type,
                        byte_offset: self.last_entry_byte_offset(),
                    }));
                }
            }
        }
    }

    /// Reads the next 32 bytes from the cluster buffer, loading
    /// the next cluster if the current buffer is exhausted.
    fn read_entry_bytes<T>(&mut self, fs: &mut T) -> Option<Result<[u8; DIR_ENTRY_SIZE]>>
    where
        T: Read + Seek,
    {
        if self.buffer_offset >= self.buffer_valid {
            if let Err(e) = self.load_next_cluster(fs) {
                return Some(Err(e));
            }
            if self.buffer_valid == 0 {
                return None;
            }
        }

        if self.buffer_offset + DIR_ENTRY_SIZE > self.buffer_valid {
            return None;
        }

        let mut entry = [0u8; DIR_ENTRY_SIZE];
        entry
            .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + DIR_ENTRY_SIZE]);
        self.buffer_offset += DIR_ENTRY_SIZE;
        Some(Ok(entry))
    }

    /// Loads the next cluster from the chain into the buffer.
    fn load_next_cluster<T>(&mut self, fs: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        let cluster = match self.cluster_iter.next(fs) {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(e),
            None => {
                self.buffer_valid = 0;
                self.buffer_offset = 0;
                return Ok(());
            }
        };

        let offset = self.exfat.cluster_offset(cluster)?;
        let size = usize::try_from(self.exfat.cluster_size()).map_err(|_| {
            ExFatError::InvalidEntrySet {
                reason: "cluster size exceeds addressable memory",
                byte_offset: offset,
            }
        })?;

        self.buffer.resize(size, 0);
        fs.seek(SeekFrom::Start(offset))?;
        fs.read_exact(&mut self.buffer[..size])?;

        self.buffer_offset = 0;
        self.buffer_valid = size;
        self.current_cluster_offset = offset;
        Ok(())
    }

    /// Returns the byte offset of the most recently read entry.
    fn last_entry_byte_offset(&self) -> u64 {
        self.current_cluster_offset.saturating_add(
            u64::try_from(self.buffer_offset.saturating_sub(DIR_ENTRY_SIZE)).unwrap_or(u64::MAX),
        )
    }

    /// Assembles a complete file entry set starting with the given
    /// primary entry bytes.
    fn assemble_file_entry<T>(
        &mut self,
        fs: &mut T,
        primary_bytes: [u8; DIR_ENTRY_SIZE],
        primary_offset: u64,
    ) -> Result<ExFatDirItem>
    where
        T: Read + Seek,
    {
        let file_entry = FileDirectoryEntry::read_from_bytes(&primary_bytes).map_err(|_| {
            ExFatError::InvalidEntrySet {
                reason: "failed to parse FileDirectoryEntry",
                byte_offset: primary_offset,
            }
        })?;

        let secondary_count = file_entry.secondary_count;
        if secondary_count < 2 {
            return Err(ExFatError::InvalidEntrySet {
                reason: "secondary_count must be at least 2",
                byte_offset: primary_offset,
            });
        }
        // Spec max: 1 stream + 17 name entries (255 chars / 15 per entry)
        if secondary_count > 18 {
            return Err(ExFatError::InvalidEntrySet {
                reason: "secondary_count exceeds spec maximum of 18",
                byte_offset: primary_offset,
            });
        }

        let mut computed_checksum = 0_u16;
        for (index, byte) in primary_bytes.into_iter().enumerate() {
            if index != 2 && index != 3 {
                computed_checksum = update_set_checksum(computed_checksum, byte);
            }
        }

        // Read secondary entries.
        let mut stream_entry: Option<StreamExtensionEntry> = None;
        let mut name_chars = Vec::new();

        for i in 0..secondary_count {
            let sec_bytes = match self.read_entry_bytes(fs) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => return Err(e),
                None => {
                    self.finished = true;
                    return Err(ExFatError::TruncatedEntrySet {
                        expected: secondary_count,
                        actual: i,
                        byte_offset: primary_offset,
                    });
                }
            };

            for byte in sec_bytes {
                computed_checksum = update_set_checksum(computed_checksum, byte);
            }

            if i == 0 {
                // First secondary must be StreamExtension (0xC0).
                if sec_bytes[0] != ENTRY_TYPE_STREAM {
                    return Err(ExFatError::InvalidEntrySet {
                        reason: "first secondary entry is not \
                                 StreamExtension (0xC0)",
                        byte_offset: primary_offset,
                    });
                }
                let stream = StreamExtensionEntry::read_from_bytes(&sec_bytes).map_err(|_| {
                    ExFatError::InvalidEntrySet {
                        reason: "failed to parse \
                                     StreamExtensionEntry",
                        byte_offset: primary_offset,
                    }
                })?;
                name_chars = Vec::with_capacity(usize::from(stream.name_length));
                stream_entry = Some(stream);
            } else {
                // Remaining secondaries must be FileName (0xC1).
                if sec_bytes[0] != ENTRY_TYPE_NAME {
                    return Err(ExFatError::InvalidEntrySet {
                        reason: "secondary entry is not \
                                 FileName (0xC1)",
                        byte_offset: primary_offset,
                    });
                }
                let name_entry = FileNameEntry::read_from_bytes(&sec_bytes).map_err(|_| {
                    ExFatError::InvalidEntrySet {
                        reason: "failed to parse FileNameEntry",
                        byte_offset: primary_offset,
                    }
                })?;
                let remaining = stream_entry
                    .as_ref()
                    .map_or(0, |stream| usize::from(stream.name_length))
                    .saturating_sub(name_chars.len());
                let (pairs, _) = name_entry.file_name.as_chunks::<2>();
                for bytes in pairs.iter().take(remaining) {
                    name_chars.push(u16::from_le_bytes([bytes[0], bytes[1]]));
                }
            }
        }

        let stream = stream_entry.ok_or(ExFatError::InvalidEntrySet {
            reason: "missing StreamExtension entry",
            byte_offset: primary_offset,
        })?;
        let entry_set =
            ExFatEntrySet::assemble_owned(file_entry, stream, name_chars, computed_checksum);

        Ok(ExFatDirItem::FileEntry(entry_set))
    }

    /// Parses a volume label entry.
    fn parse_volume_label(&self, bytes: &[u8; DIR_ENTRY_SIZE]) -> Result<ExFatDirItem> {
        let vl =
            VolumeLabelEntry::read_from_bytes(bytes).map_err(|_| ExFatError::InvalidEntrySet {
                reason: "failed to parse VolumeLabelEntry",
                byte_offset: self.last_entry_byte_offset(),
            })?;
        Ok(ExFatDirItem::VolumeLabel(decode_volume_label(&vl)))
    }
}

#[cfg(test)]
#[path = "dir_iter_tests/mod.rs"]
mod tests;
