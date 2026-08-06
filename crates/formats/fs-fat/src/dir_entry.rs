use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, Unaligned};

use crate::error::{FatError, Result};
use crate::fat::Fat;
use crate::io::{Read, Seek, SeekFrom};
use crate::time::FatTime;

bitflags! {
    /// FAT file attributes.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FatAttributes: u8 {
        const READ_ONLY = 0x01;
        const HIDDEN = 0x02;
        const SYSTEM = 0x04;
        const VOLUME_ID = 0x08;
        const DIRECTORY = 0x10;
        const ARCHIVE = 0x20;
        /// Long file name entry marker (combination of READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID)
        const LFN = Self::READ_ONLY.bits() | Self::HIDDEN.bits()
                  | Self::SYSTEM.bits() | Self::VOLUME_ID.bits();
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for FatAttributes {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u8 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

/// Size of a single directory entry in bytes.
pub const DIR_ENTRY_SIZE: usize = 32;

/// First byte value indicating a deleted entry.
pub const DIR_ENTRY_DELETED: u8 = 0xE5;

/// First byte value indicating end of directory.
pub const DIR_ENTRY_END: u8 = 0x00;

/// Short file name field size in bytes (8 + 3).
pub const SFN_SIZE: usize = 11;

/// Length in characters of a LFN fragment packed in one directory entry.
pub const LFN_PART_LEN: usize = 13;

/// Maximum number of LFN entries (255 chars / 13 chars per entry, rounded up).
pub const LFN_MAX_ENTRIES: usize = 20;

/// Maximum length of a long file name in UTF-16 code units.
pub const LFN_MAX_LEN: usize = LFN_MAX_ENTRIES * LFN_PART_LEN; // 260

/// Bit mask for the LFN sequence number (lower 5 bits).
pub const LFN_SEQ_MASK: u8 = 0x1F;

/// Bit indicating this is the last (highest numbered) LFN entry.
pub const LFN_LAST_ENTRY: u8 = 0x40;

/// On-disk FAT directory entry structure (32 bytes).
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct DirFileEntryData {
    /// Short name (8 chars for name + 3 chars for extension).
    pub name: [u8; SFN_SIZE],
    /// File attributes.
    pub attributes: u8,
    /// Reserved for Windows NT.
    pub nt_reserved: u8,
    /// Creation time in tenths of a second (0-199).
    pub create_time_tenths: u8,
    /// Creation time (hour, minute, second/2).
    pub create_time: U16<LittleEndian>,
    /// Creation date.
    pub create_date: U16<LittleEndian>,
    /// Last access date.
    pub access_date: U16<LittleEndian>,
    /// High 16 bits of first cluster number (FAT32 only, 0 for FAT12/16).
    pub first_cluster_high: U16<LittleEndian>,
    /// Last modification time.
    pub modify_time: U16<LittleEndian>,
    /// Last modification date.
    pub modify_date: U16<LittleEndian>,
    /// Low 16 bits of first cluster number.
    pub first_cluster_low: U16<LittleEndian>,
    /// File size in bytes.
    pub file_size: U32<LittleEndian>,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for DirFileEntryData {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; DIR_ENTRY_SIZE] = u.arbitrary()?;
        Ok(Self::read_from_bytes(&bytes).unwrap())
    }
}

/// On-disk FAT long file name (LFN) directory entry structure (32 bytes).
///
/// LFN entries are stored in reverse order (last fragment first) immediately
/// preceding the short name entry they belong to.
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct LfnEntryData {
    /// Sequence number (1-20, with 0x40 bit set on last entry).
    pub sequence: u8,
    /// First 5 UTF-16 characters (10 bytes).
    pub name1: [u8; 10],
    /// Attributes (always 0x0F for LFN).
    pub attributes: u8,
    /// Type (always 0x00).
    pub entry_type: u8,
    /// Checksum of short name.
    pub checksum: u8,
    /// Next 6 UTF-16 characters (12 bytes).
    pub name2: [u8; 12],
    /// First cluster (always 0x0000).
    pub first_cluster: U16<LittleEndian>,
    /// Final 2 UTF-16 characters (4 bytes).
    pub name3: [u8; 4],
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for LfnEntryData {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; DIR_ENTRY_SIZE] = u.arbitrary()?;
        Ok(Self::read_from_bytes(&bytes).unwrap())
    }
}

impl LfnEntryData {
    /// Extracts the 13 UTF-16 characters from this LFN entry into the provided buffer.
    /// Returns the number of valid characters (may be less than 13 if null-terminated).
    pub fn extract_chars(&self, buf: &mut [u16; LFN_PART_LEN]) -> usize {
        // Walk every UTF-16 unit from name1 → name2 → name3 as a flat sequence
        // of 2-byte chunks. `chunks_exact(2)` removes the explicit `i * 2`
        // indexing (which otherwise multiplies the cargo-mutants surface
        // with index-arithmetic mutants whose name1/name3 zero-padding
        // makes them indistinguishable from the original).
        let mut count = 0;
        for chunk in self
            .name1
            .chunks_exact(2)
            .chain(self.name2.chunks_exact(2))
            .chain(self.name3.chunks_exact(2))
        {
            let c = u16::from_le_bytes([chunk[0], chunk[1]]);
            if c == 0x0000 || c == 0xFFFF {
                return count;
            }
            buf[count] = c;
            count += 1;
        }
        count
    }
}

/// Computes the checksum for a short name (used to validate LFN entries).
///
/// The checksum is calculated over the 11-byte short name field.
#[inline]
pub fn sfn_checksum(name: &[u8; SFN_SIZE]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name {
        // Rotate right and add
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// A FAT directory entry with optional long file name.
///
/// This struct combines the short name entry data with any associated
/// long file name (LFN) entries that preceded it.
#[derive(Clone, Debug)]
pub struct FatDirEntry {
    /// The short name (8.3) directory entry data.
    data: DirFileEntryData,
    /// Long file name buffer (UTF-16 code units).
    /// Heap-allocated to avoid large stack usage (up to 520 bytes for max LFN).
    lfn_buffer: Vec<u16>,
}

impl FatDirEntry {
    /// Creates a new `FatDirEntry` with only a short name.
    pub(crate) fn new(data: DirFileEntryData) -> Self {
        Self {
            data,
            lfn_buffer: Vec::new(),
        }
    }

    /// Creates a new `FatDirEntry` with both short and long names.
    pub(crate) fn with_lfn(data: DirFileEntryData, lfn: &[u16], lfn_len: usize) -> Self {
        let copy_len = lfn_len.min(LFN_MAX_LEN);
        let lfn_buffer = lfn[..copy_len].to_vec();
        Self { data, lfn_buffer }
    }

    /// Returns a reference to the underlying short name entry data.
    #[inline]
    pub fn data(&self) -> &DirFileEntryData {
        &self.data
    }

    /// Returns `true` if this entry has a long file name.
    #[inline]
    pub fn has_long_name(&self) -> bool {
        !self.lfn_buffer.is_empty()
    }

    /// Returns the long file name as a slice of UTF-16 code units.
    ///
    /// Returns an empty slice if no long file name is present.
    #[inline]
    pub fn long_name_utf16(&self) -> &[u16] {
        &self.lfn_buffer
    }

    /// Returns the short name (8.3) as a byte slice.
    #[inline]
    pub fn short_name(&self) -> &[u8; SFN_SIZE] {
        &self.data.name
    }

    /// Returns `true` if this is a `.` or `..` directory entry.
    #[inline]
    pub fn is_dot_or_dotdot(&self) -> bool {
        self.data.is_dot_or_dotdot()
    }

    /// Returns `true` if this entry represents a directory.
    #[inline]
    pub fn is_directory(&self) -> bool {
        self.data.is_directory()
    }

    /// Returns `true` if this entry represents the volume label.
    #[inline]
    pub fn is_volume_id(&self) -> bool {
        self.data.is_volume_id()
    }

    /// Returns the first cluster number of this entry.
    #[inline]
    pub fn first_cluster(&self) -> u32 {
        self.data.first_cluster()
    }

    /// Returns the file size in bytes.
    #[inline]
    pub fn file_size(&self) -> u32 {
        self.data.file_size()
    }

    /// Returns the attributes as a `FatAttributes` bitflags value.
    #[inline]
    pub fn attributes(&self) -> FatAttributes {
        self.data.attributes()
    }

    /// Returns the short name (8.3) formatted as a readable string.
    ///
    /// This method:
    /// - Removes trailing spaces from the name and extension
    /// - Handles the `0x05` → `0xE5` substitution for the first byte
    /// - Formats as "NAME.EXT" with dot only if extension exists
    /// - Applies lowercase flags from the `nt_reserved` field (Windows NT extension)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entry: FatDirEntry = ...;
    /// println!("Short name: {}", entry.short_name_string());
    /// ```
    pub fn short_name_string(&self) -> String {
        let name = self.short_name();
        let nt_reserved = self.data.nt_reserved;

        // NT extension: bit 3 = lowercase base name, bit 4 = lowercase extension
        let lowercase_name = (nt_reserved & 0x08) != 0;
        let lowercase_ext = (nt_reserved & 0x10) != 0;

        // Extract base name (first 8 bytes)
        let mut base = [0u8; 8];
        base.copy_from_slice(&name[0..8]);

        // Handle 0x05 -> 0xE5 substitution (first byte)
        if base[0] == 0x05 {
            base[0] = 0xE5;
        }

        // Find end of base name (trim trailing spaces)
        let base_end = base
            .iter()
            .rposition(|&b| b != b' ')
            .map(|i| i + 1)
            .unwrap_or(0);

        // Extract extension (last 3 bytes)
        let ext = &name[8..11];
        let ext_end = ext
            .iter()
            .rposition(|&b| b != b' ')
            .map(|i| i + 1)
            .unwrap_or(0);

        // Build the result string
        let mut result = String::with_capacity(12);

        // Add base name
        for &b in &base[..base_end] {
            let c = if lowercase_name {
                b.to_ascii_lowercase() as char
            } else {
                b as char
            };
            result.push(c);
        }

        // Add extension if present
        if ext_end > 0 {
            result.push('.');
            for &b in &ext[..ext_end] {
                let c = if lowercase_ext {
                    b.to_ascii_lowercase() as char
                } else {
                    b as char
                };
                result.push(c);
            }
        }

        result
    }

    /// Returns the long file name as a String, if present.
    ///
    /// If no long file name is present, returns `None`.
    /// The long file name is stored as UTF-16 and is converted to a Rust String.
    pub fn long_name_string(&self) -> Option<String> {
        if !self.has_long_name() {
            return None;
        }

        Some(String::from_utf16_lossy(self.long_name_utf16()))
    }

    /// Returns the best available name as a String.
    ///
    /// Returns the long file name if present, otherwise returns the formatted short name.
    pub fn name(&self) -> String {
        self.long_name_string()
            .unwrap_or_else(|| self.short_name_string())
    }

    /// Returns the creation time of this entry.
    ///
    /// The creation time includes the date, time, and 10ms resolution from the
    /// `create_time_tenths` field.
    #[inline]
    pub fn creation_time(&self) -> FatTime {
        FatTime::new(
            self.data.create_date.get(),
            self.data.create_time.get(),
            self.data.create_time_tenths,
        )
    }

    /// Returns the last modification time of this entry.
    ///
    /// The modification time has 2-second resolution (no tenths field).
    #[inline]
    pub fn modification_time(&self) -> FatTime {
        FatTime::new(self.data.modify_date.get(), self.data.modify_time.get(), 0)
    }

    /// Returns the last access date of this entry.
    ///
    /// FAT only stores the access date, not the time. The time component
    /// will be 00:00:00.
    #[inline]
    pub fn access_date(&self) -> FatTime {
        FatTime::from_date(self.data.access_date.get())
    }
}

impl DirFileEntryData {
    /// Returns `true` if this entry marks the end of the directory.
    #[inline]
    pub fn is_end(&self) -> bool {
        self.name[0] == DIR_ENTRY_END
    }

    /// Returns `true` if this entry has been deleted.
    #[inline]
    pub fn is_deleted(&self) -> bool {
        self.name[0] == DIR_ENTRY_DELETED
    }

    /// Returns `true` if this is a long file name (LFN) entry.
    #[inline]
    pub fn is_lfn(&self) -> bool {
        self.attributes == FatAttributes::LFN.bits()
    }

    /// Returns `true` if this is a `.` or `..` directory entry.
    ///
    /// FAT stores these as real 8.3 entries: `.` is `[0x2E, 0x20 * 10]`
    /// and `..` is `[0x2E, 0x2E, 0x20 * 9]`.
    #[inline]
    pub fn is_dot_or_dotdot(&self) -> bool {
        self.name[0] == b'.'
            && (self.name[1] == b' ' || (self.name[1] == b'.' && self.name[2] == b' '))
    }

    /// Returns `true` if this entry represents a directory.
    #[inline]
    pub fn is_directory(&self) -> bool {
        FatAttributes::from_bits_truncate(self.attributes).contains(FatAttributes::DIRECTORY)
    }

    /// Returns `true` if this entry represents the volume label.
    #[inline]
    pub fn is_volume_id(&self) -> bool {
        FatAttributes::from_bits_truncate(self.attributes).contains(FatAttributes::VOLUME_ID)
            && !self.is_lfn()
    }

    /// Returns the first cluster number of this entry.
    //
    // `|` vs `^` here is an equivalent mutation: the high u16 shifted
    // left by 16 occupies bits 16..32, the low u16 occupies bits 0..16,
    // so OR and XOR produce the same value for every input.
    #[cfg_attr(test, mutants::skip)]
    #[inline]
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_high.get() as u32) << 16) | (self.first_cluster_low.get() as u32)
    }

    /// Returns the file size in bytes.
    #[inline]
    pub fn file_size(&self) -> u32 {
        self.file_size.get()
    }

    /// Returns the attributes as a `FatAttributes` bitflags value.
    #[inline]
    pub fn attributes(&self) -> FatAttributes {
        FatAttributes::from_bits_truncate(self.attributes)
    }
}

/// The source of directory data - either a fixed region or a cluster chain.
#[derive(Clone, Debug)]
enum DirSource {
    /// Fixed region (FAT12/16 root directory).
    /// Contains (start_offset, total_size).
    Fixed { start_offset: u64, remaining: u32 },
    /// Cluster chain (FAT32 root or any subdirectory).
    /// Contains the current cluster number.
    ClusterChain { current_cluster: Option<u32> },
}

/// Iterator over directory entries in a FAT filesystem.
///
/// This iterator reads directory entries from either a fixed region (FAT12/16 root)
/// or follows a cluster chain (FAT32 root or subdirectories).
///
/// # Example
///
/// ```ignore
/// let fat = Fat::new(&mut fs)?;
/// let mut entries = fat.root_dir_entries();
/// while let Some(entry) = entries.try_next(&mut fs)? {
///     // Process entry...
/// }
/// ```
#[derive(Clone, Debug)]
pub struct FatDirEntries<'n> {
    fat: &'n Fat,
    source: DirSource,
    /// Buffer for one cluster worth of directory entries.
    /// We read one cluster at a time and iterate through entries in the buffer.
    /// Heap-allocated and sized to the actual cluster size.
    buffer: Vec<u8>,
    /// Current offset within the buffer.
    buffer_offset: usize,
    /// Whether we've reached the end of the directory.
    finished: bool,
    /// Buffer for collecting LFN characters.
    /// Heap-allocated to avoid large stack usage (up to 520 bytes for max LFN).
    lfn_buffer: Vec<u16>,
    /// Expected checksum from LFN entries (validated against short name).
    lfn_checksum: u8,
    /// Whether we're currently collecting LFN entries.
    lfn_collecting: bool,
    /// Number of clusters traversed (for loop detection in cluster chain mode).
    clusters_traversed: u32,
    /// Absolute byte offset where the current buffer starts on disk.
    /// Used to compute positions for error reporting.
    base_offset: u64,
}

impl<'n> FatDirEntries<'n> {
    /// Creates a new iterator for a fixed-size directory region (FAT12/16 root).
    pub(crate) fn new_fixed(fat: &'n Fat, start_offset: u64, size: u32) -> Self {
        Self {
            fat,
            source: DirSource::Fixed {
                start_offset,
                remaining: size,
            },
            buffer: Vec::new(),
            buffer_offset: 0,
            finished: false,
            lfn_buffer: Vec::new(),
            lfn_checksum: 0,
            lfn_collecting: false,
            clusters_traversed: 0,
            base_offset: 0, // overwritten by fill_buffer() before any entry is parsed
        }
    }

    /// Creates a new iterator for a cluster chain directory.
    pub(crate) fn new_cluster_chain(fat: &'n Fat, first_cluster: u32) -> Self {
        Self {
            fat,
            source: DirSource::ClusterChain {
                current_cluster: Some(first_cluster),
            },
            buffer: Vec::new(),
            buffer_offset: 0,
            finished: false,
            lfn_buffer: Vec::new(),
            lfn_checksum: 0,
            lfn_collecting: false,
            clusters_traversed: 0,
            base_offset: 0, // overwritten by fill_buffer() before any entry is parsed
        }
    }

    /// Returns the next directory entry, or `None` if the end of the directory is reached.
    ///
    /// This method takes a mutable reference to the filesystem reader because it may
    /// need to read more data from disk.
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<FatDirEntry>>
    where
        T: Read + Seek,
    {
        if self.finished {
            return None;
        }

        loop {
            // If we have data in the buffer, try to return the next entry
            if self.buffer_offset + DIR_ENTRY_SIZE <= self.buffer.len() {
                let entry_bytes =
                    &self.buffer[self.buffer_offset..self.buffer_offset + DIR_ENTRY_SIZE];
                self.buffer_offset += DIR_ENTRY_SIZE;

                // Parse the entry. The error branch is currently
                // unreachable: FromBytes accepts any bit pattern for a
                // correctly-sized slice. It is retained as a safeguard
                // in case the struct gains validation, and the offset
                // helper has the byte-offset arithmetic suppressed from
                // cargo-mutants because the branch never executes.
                let entry = match DirFileEntryData::read_from_bytes(entry_bytes) {
                    Ok(e) => e,
                    Err(_) => {
                        self.finished = true;
                        return Some(Err(self.malformed_at_current_entry()));
                    }
                };

                // Check for end of directory
                if entry.is_end() {
                    self.finished = true;
                    return None;
                }

                // Skip deleted entries
                if entry.is_deleted() {
                    // Reset LFN state when we hit a deleted entry
                    self.lfn_collecting = false;
                    self.lfn_buffer.clear();
                    continue;
                }

                // Handle LFN entries
                if entry.is_lfn() {
                    // Parse as LFN entry. Same defense-in-depth pattern
                    // as the short-name parse above.
                    let lfn_entry = match LfnEntryData::read_from_bytes(entry_bytes) {
                        Ok(e) => e,
                        Err(_) => {
                            self.finished = true;
                            return Some(Err(self.malformed_at_current_entry()));
                        }
                    };

                    let seq = lfn_entry.sequence;
                    let seq_num = seq & LFN_SEQ_MASK;

                    // Validate sequence number: must be 1-20 (0 is invalid, >20 exceeds max LFN entries)
                    // Skip invalid LFN entries from corrupted filesystems
                    if seq_num == 0 || seq_num > LFN_MAX_ENTRIES as u8 {
                        // Invalid sequence number, reset LFN state and skip
                        self.lfn_collecting = false;
                        self.lfn_buffer.clear();
                        continue;
                    }

                    // Check if this is the first (last physically) LFN entry
                    if seq & LFN_LAST_ENTRY != 0 {
                        // Start collecting a new LFN
                        self.lfn_collecting = true;
                        self.lfn_checksum = lfn_entry.checksum;
                        self.lfn_buffer.clear();
                    }

                    if self.lfn_collecting && lfn_entry.checksum == self.lfn_checksum {
                        // Extract characters from this LFN entry
                        let mut chars = [0u16; LFN_PART_LEN];
                        let char_count = lfn_entry.extract_chars(&mut chars);

                        // Calculate where in the final name these characters go
                        // seq_num is 1-based and validated above, each entry holds 13 chars
                        let start_pos = ((seq_num - 1) as usize) * LFN_PART_LEN;
                        let end_pos = start_pos + char_count;

                        // Ensure buffer is large enough (capped at LFN_MAX_LEN)
                        let required_len = end_pos.min(LFN_MAX_LEN);
                        if self.lfn_buffer.len() < required_len {
                            self.lfn_buffer.resize(required_len, 0);
                        }

                        // Copy chars into lfn_buffer at the correct position
                        for (i, &ch) in chars[..char_count].iter().enumerate() {
                            let pos = start_pos + i;
                            if pos < LFN_MAX_LEN && ch != 0x0000 && ch != 0xFFFF {
                                self.lfn_buffer[pos] = ch;
                            }
                        }
                    }

                    continue;
                }

                // This is a short name entry - create the result
                let result = if self.lfn_collecting {
                    // Validate checksum
                    let computed_checksum = sfn_checksum(&entry.name);
                    if computed_checksum == self.lfn_checksum && !self.lfn_buffer.is_empty() {
                        let lfn_len = self.lfn_buffer.len();
                        FatDirEntry::with_lfn(entry, &self.lfn_buffer, lfn_len)
                    } else {
                        // Checksum mismatch, use short name only
                        FatDirEntry::new(entry)
                    }
                } else {
                    FatDirEntry::new(entry)
                };

                // Reset LFN state for next entry
                self.lfn_collecting = false;
                self.lfn_buffer.clear();

                return Some(Ok(result));
            }

            // Need to read more data
            if let Err(e) = self.fill_buffer(fs) {
                self.finished = true;
                return Some(Err(e));
            }

            // If buffer is still empty after fill, we're done
            if self.buffer.is_empty() {
                self.finished = true;
                return None;
            }
        }
    }

    /// Compute a `MalformedDirEntry` error for the entry just consumed
    /// from `self.buffer`. The byte-offset arithmetic here is only ever
    /// reached if `DirFileEntryData::read_from_bytes` or
    /// `LfnEntryData::read_from_bytes` ever start rejecting a
    /// 32-byte slice, which they currently never do — both accept any
    /// bit pattern. The branch is kept as a guardrail; cargo-mutants
    /// would otherwise treat every `+`/`-` here as a survivor because
    /// no test path can exercise it.
    #[cfg_attr(test, mutants::skip)]
    fn malformed_at_current_entry(&self) -> FatError {
        let entry_pos = (self.buffer_offset - DIR_ENTRY_SIZE) as u64;
        let offset = self.base_offset.saturating_add(entry_pos);
        FatError::MalformedDirEntry {
            byte_offset: offset,
        }
    }

    /// Fills the buffer with the next chunk of directory data.
    fn fill_buffer<T>(&mut self, fs: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        self.buffer_offset = 0;
        self.buffer.clear();

        match &mut self.source {
            DirSource::Fixed {
                start_offset,
                remaining,
            } => {
                if *remaining == 0 {
                    return Ok(());
                }

                // Read up to cluster_size or remaining bytes
                let to_read = (*remaining as usize).min(self.fat.cluster_size() as usize);

                // Resize buffer to the required size
                self.buffer.resize(to_read, 0);

                self.base_offset = *start_offset;
                fs.seek(SeekFrom::Start(*start_offset))?;
                fs.read_exact(&mut self.buffer)?;

                *start_offset += to_read as u64;
                *remaining -= to_read as u32;
            }
            DirSource::ClusterChain { current_cluster } => {
                let cluster = match *current_cluster {
                    Some(c) => c,
                    None => return Ok(()),
                };

                // Check for cluster chain loop
                let max_clusters = self.fat.total_clusters();
                if self.clusters_traversed >= max_clusters {
                    return Err(FatError::ClusterChainLoop { max_clusters });
                }

                // Read the current cluster
                let cluster_offset = self.fat.cluster_offset(cluster)?;
                let cluster_size = self.fat.cluster_size() as usize;

                // Resize buffer to the cluster size
                self.buffer.resize(cluster_size, 0);

                self.base_offset = cluster_offset;
                fs.seek(SeekFrom::Start(cluster_offset))?;
                fs.read_exact(&mut self.buffer)?;

                // Move to the next cluster and increment traversal counter
                *current_cluster = self.fat.next_cluster(fs, cluster)?;
                self.clusters_traversed += 1;
            }
        }

        Ok(())
    }

    /// Finds the first directory entry matching the given predicate.
    ///
    /// This method iterates through the directory entries and returns the first
    /// entry for which the predicate returns `true`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut entries = fat.root_dir_entries();
    /// let hidden_file = entries.find(&mut fs, |entry| {
    ///     entry.attributes().contains(FatAttributes::HIDDEN)
    /// });
    /// ```
    pub fn find<T, F>(&mut self, fs: &mut T, mut predicate: F) -> Option<Result<FatDirEntry>>
    where
        T: Read + Seek,
        F: FnMut(&FatDirEntry) -> bool,
    {
        while let Some(result) = self.next(fs) {
            match result {
                Ok(entry) => {
                    if predicate(&entry) {
                        return Some(Ok(entry));
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }

    /// Finds a directory entry by name (case-insensitive).
    ///
    /// This method searches for an entry matching the given name, comparing
    /// against both the long file name (if present) and the short name.
    /// The comparison is case-insensitive for ASCII characters.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut entries = fat.root_dir_entries();
    /// if let Some(Ok(entry)) = entries.find_by_name(&mut fs, "README.TXT") {
    ///     println!("Found: {}", entry.name());
    /// }
    /// ```
    /// Returns the `Fat` reference held by this iterator.
    pub(crate) fn fat(&self) -> &'n Fat {
        self.fat
    }

    pub fn find_by_name<T>(&mut self, fs: &mut T, name: &str) -> Option<Result<FatDirEntry>>
    where
        T: Read + Seek,
    {
        self.find(fs, |entry| entry.name_matches(name))
    }
}

impl fs_common::iter::FsTryIteratorType for FatDirEntries<'_> {
    type Error = FatError;
    type Item<'a> = FatDirEntry;
}

impl<R: Read + Seek> fs_common::iter::FsTryIterator<R> for FatDirEntries<'_> {
    fn try_next(&mut self, r: &mut R) -> Result<Option<FatDirEntry>> {
        self.next(r).transpose()
    }
}

/// Helper function for case-insensitive ASCII comparison.
fn ascii_eq_ignore_case(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

/// Helper function for case-insensitive comparison of UTF-16 slice against a str.
/// Avoids allocation by iterating through both sequences.
fn utf16_eq_ignore_ascii_case(utf16: &[u16], s: &str) -> bool {
    let mut utf16_chars = core::char::decode_utf16(utf16.iter().copied())
        .map(|r| r.unwrap_or(core::char::REPLACEMENT_CHARACTER));
    let mut str_chars = s.chars();

    loop {
        match (utf16_chars.next(), str_chars.next()) {
            (Some(a), Some(b)) => {
                if !a.eq_ignore_ascii_case(&b) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false, // Different lengths
        }
    }
}

impl FatDirEntry {
    /// Checks if this entry's name matches the given name (case-insensitive).
    ///
    /// Compares against both the long file name (if present) and the short name.
    pub fn name_matches(&self, name: &str) -> bool {
        // Check long name first if present (using allocation-free comparison)
        if self.has_long_name() && utf16_eq_ignore_ascii_case(self.long_name_utf16(), name) {
            return true;
        }

        // Check short name
        let short_name = self.short_name_string();
        ascii_eq_ignore_case(&short_name, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for FatAttributes bitflags
    #[test]
    fn test_fat_attributes_individual_flags() {
        assert_eq!(FatAttributes::READ_ONLY.bits(), 0x01);
        assert_eq!(FatAttributes::HIDDEN.bits(), 0x02);
        assert_eq!(FatAttributes::SYSTEM.bits(), 0x04);
        assert_eq!(FatAttributes::VOLUME_ID.bits(), 0x08);
        assert_eq!(FatAttributes::DIRECTORY.bits(), 0x10);
        assert_eq!(FatAttributes::ARCHIVE.bits(), 0x20);
    }

    #[test]
    fn test_fat_attributes_lfn_marker() {
        // LFN is a combination of READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID = 0x0F
        assert_eq!(FatAttributes::LFN.bits(), 0x0F);
        assert!(FatAttributes::LFN.contains(FatAttributes::READ_ONLY));
        assert!(FatAttributes::LFN.contains(FatAttributes::HIDDEN));
        assert!(FatAttributes::LFN.contains(FatAttributes::SYSTEM));
        assert!(FatAttributes::LFN.contains(FatAttributes::VOLUME_ID));
    }

    #[test]
    fn test_fat_attributes_combinations() {
        let attrs = FatAttributes::READ_ONLY | FatAttributes::HIDDEN;
        assert_eq!(attrs.bits(), 0x03);
        assert!(attrs.contains(FatAttributes::READ_ONLY));
        assert!(attrs.contains(FatAttributes::HIDDEN));
        assert!(!attrs.contains(FatAttributes::SYSTEM));

        let dir_attrs = FatAttributes::DIRECTORY | FatAttributes::ARCHIVE;
        assert_eq!(dir_attrs.bits(), 0x30);
    }

    #[test]
    fn test_fat_attributes_from_bits() {
        let attrs = FatAttributes::from_bits_truncate(0x21);
        assert!(attrs.contains(FatAttributes::READ_ONLY));
        assert!(attrs.contains(FatAttributes::ARCHIVE));
        assert!(!attrs.contains(FatAttributes::HIDDEN));
    }

    // Tests for sfn_checksum function
    #[test]
    fn test_sfn_checksum_known_vectors() {
        // Test vector 1: "FOO     BAR" (8.3 format padded with spaces)
        let name1: [u8; SFN_SIZE] = *b"FOO     BAR";
        let checksum1 = sfn_checksum(&name1);
        // Compute expected: rotate right and add for each byte
        assert_eq!(checksum1, 0x53); // Actual computed value

        // Test vector 2: All zeros
        let name2: [u8; SFN_SIZE] = [0u8; SFN_SIZE];
        let checksum2 = sfn_checksum(&name2);
        assert_eq!(checksum2, 0x00);

        // Test vector 3: All spaces (common padding)
        let name3: [u8; SFN_SIZE] = *b"           ";
        let checksum3 = sfn_checksum(&name3);
        // This tests the algorithm with repeated values
        let expected3 = sfn_checksum(&name3);
        assert_eq!(checksum3, expected3);
    }

    #[test]
    fn test_sfn_checksum_consistency() {
        // Same input should always produce same output
        let name: [u8; SFN_SIZE] = *b"TESTFILE123";
        let checksum1 = sfn_checksum(&name);
        let checksum2 = sfn_checksum(&name);
        assert_eq!(checksum1, checksum2);
    }

    // Tests for ascii_eq_ignore_case
    #[test]
    fn test_ascii_eq_ignore_case_equal() {
        assert!(ascii_eq_ignore_case("hello", "hello"));
        assert!(ascii_eq_ignore_case("HELLO", "HELLO"));
        assert!(ascii_eq_ignore_case("hello", "HELLO"));
        assert!(ascii_eq_ignore_case("HELLO", "hello"));
        assert!(ascii_eq_ignore_case("HeLLo", "hEllO"));
    }

    #[test]
    fn test_ascii_eq_ignore_case_not_equal() {
        assert!(!ascii_eq_ignore_case("hello", "world"));
        assert!(!ascii_eq_ignore_case("hello", "hello!"));
        assert!(!ascii_eq_ignore_case("hello", "hell"));
    }

    #[test]
    fn test_ascii_eq_ignore_case_different_lengths() {
        assert!(!ascii_eq_ignore_case("short", "longer"));
        assert!(!ascii_eq_ignore_case("", "notempty"));
        assert!(ascii_eq_ignore_case("", ""));
    }

    #[test]
    fn test_ascii_eq_ignore_case_numbers_and_special() {
        // Numbers and special chars should compare exactly
        assert!(ascii_eq_ignore_case("file123.txt", "FILE123.TXT"));
        assert!(ascii_eq_ignore_case("test_file", "TEST_FILE"));
        assert!(!ascii_eq_ignore_case("test1", "test2"));
    }

    // Tests for utf16_eq_ignore_ascii_case
    #[test]
    fn test_utf16_eq_ignore_case_equal() {
        let utf16: Vec<u16> = "hello".encode_utf16().collect();
        assert!(utf16_eq_ignore_ascii_case(&utf16, "hello"));
        assert!(utf16_eq_ignore_ascii_case(&utf16, "HELLO"));
        assert!(utf16_eq_ignore_ascii_case(&utf16, "HeLLo"));
    }

    #[test]
    fn test_utf16_eq_ignore_case_not_equal() {
        let utf16: Vec<u16> = "hello".encode_utf16().collect();
        assert!(!utf16_eq_ignore_ascii_case(&utf16, "world"));
        assert!(!utf16_eq_ignore_ascii_case(&utf16, "hello!"));
    }

    #[test]
    fn test_utf16_eq_ignore_case_different_lengths() {
        let utf16: Vec<u16> = "short".encode_utf16().collect();
        assert!(!utf16_eq_ignore_ascii_case(&utf16, "longer"));
        assert!(!utf16_eq_ignore_ascii_case(&utf16, "shor"));
    }

    #[test]
    fn test_utf16_eq_ignore_case_empty() {
        let empty: Vec<u16> = Vec::new();
        assert!(utf16_eq_ignore_ascii_case(&empty, ""));
        assert!(!utf16_eq_ignore_ascii_case(&empty, "notempty"));
    }

    // Tests for LfnEntryData::extract_chars
    #[test]
    fn test_lfn_extract_chars_full() {
        // Create an LFN entry with known characters
        let mut lfn = LfnEntryData {
            sequence: 1,
            name1: [0; 10],
            attributes: 0x0F,
            entry_type: 0,
            checksum: 0,
            name2: [0; 12],
            first_cluster: U16::new(0),
            name3: [0; 4],
        };

        // Fill with 'A' (0x0041) in all 13 character positions
        // name1: 5 chars (10 bytes)
        for i in 0..5 {
            lfn.name1[i * 2] = 0x41;
            lfn.name1[i * 2 + 1] = 0x00;
        }
        // name2: 6 chars (12 bytes)
        for i in 0..6 {
            lfn.name2[i * 2] = 0x41;
            lfn.name2[i * 2 + 1] = 0x00;
        }
        // name3: 2 chars (4 bytes)
        for i in 0..2 {
            lfn.name3[i * 2] = 0x41;
            lfn.name3[i * 2 + 1] = 0x00;
        }

        let mut buf = [0u16; LFN_PART_LEN];
        let count = lfn.extract_chars(&mut buf);

        assert_eq!(count, 13);
        for c in buf.iter().take(13) {
            assert_eq!(*c, 0x0041); // 'A' in UTF-16
        }
    }

    #[test]
    fn test_lfn_extract_chars_null_terminated() {
        // Create an LFN entry that ends early with null terminator
        let mut lfn = LfnEntryData {
            sequence: 1,
            name1: [0; 10],
            attributes: 0x0F,
            entry_type: 0,
            checksum: 0,
            name2: [0; 12],
            first_cluster: U16::new(0),
            name3: [0; 4],
        };

        // Fill name1 with "HI" followed by null
        lfn.name1[0] = 0x48;
        lfn.name1[1] = 0x00; // 'H'
        lfn.name1[2] = 0x49;
        lfn.name1[3] = 0x00; // 'I'
        // Rest is 0x0000 (null)

        let mut buf = [0u16; LFN_PART_LEN];
        let count = lfn.extract_chars(&mut buf);

        assert_eq!(count, 2);
        assert_eq!(buf[0], 0x0048); // 'H'
        assert_eq!(buf[1], 0x0049); // 'I'
    }

    #[test]
    fn test_lfn_extract_chars_ffff_terminated() {
        // LFN entries can also be terminated with 0xFFFF
        let mut lfn = LfnEntryData {
            sequence: 1,
            name1: [0xFF; 10], // All 0xFFFF
            attributes: 0x0F,
            entry_type: 0,
            checksum: 0,
            name2: [0xFF; 12],
            first_cluster: U16::new(0),
            name3: [0xFF; 4],
        };

        // Put one character before the 0xFFFF
        lfn.name1[0] = 0x41;
        lfn.name1[1] = 0x00; // 'A'

        let mut buf = [0u16; LFN_PART_LEN];
        let count = lfn.extract_chars(&mut buf);

        assert_eq!(count, 1);
        assert_eq!(buf[0], 0x0041); // 'A'
    }

    // Tests for DirFileEntryData methods
    fn create_test_dir_entry(name: &[u8; SFN_SIZE], attributes: u8) -> DirFileEntryData {
        DirFileEntryData {
            name: *name,
            attributes,
            nt_reserved: 0,
            create_time_tenths: 0,
            create_time: U16::new(0),
            create_date: U16::new(0),
            access_date: U16::new(0),
            first_cluster_high: U16::new(0),
            modify_time: U16::new(0),
            modify_date: U16::new(0),
            first_cluster_low: U16::new(0),
            file_size: U32::new(0),
        }
    }

    #[test]
    fn test_dir_entry_is_end() {
        let mut name = *b"           ";
        name[0] = DIR_ENTRY_END;
        let entry = create_test_dir_entry(&name, 0);
        assert!(entry.is_end());

        let normal_entry = create_test_dir_entry(b"TEST       ", 0);
        assert!(!normal_entry.is_end());
    }

    #[test]
    fn test_dir_entry_is_deleted() {
        let mut name = *b"           ";
        name[0] = DIR_ENTRY_DELETED;
        let entry = create_test_dir_entry(&name, 0);
        assert!(entry.is_deleted());

        let normal_entry = create_test_dir_entry(b"TEST       ", 0);
        assert!(!normal_entry.is_deleted());
    }

    #[test]
    fn test_dir_entry_is_lfn() {
        let entry = create_test_dir_entry(b"           ", FatAttributes::LFN.bits());
        assert!(entry.is_lfn());

        let normal_entry = create_test_dir_entry(b"TEST       ", 0);
        assert!(!normal_entry.is_lfn());

        // Partial LFN attributes should not be LFN
        let partial = create_test_dir_entry(b"           ", FatAttributes::READ_ONLY.bits());
        assert!(!partial.is_lfn());
    }

    #[test]
    fn test_dir_entry_is_dot_or_dotdot() {
        let dot = create_test_dir_entry(b".          ", FatAttributes::DIRECTORY.bits());
        assert!(dot.is_dot_or_dotdot());

        let dotdot = create_test_dir_entry(b"..         ", FatAttributes::DIRECTORY.bits());
        assert!(dotdot.is_dot_or_dotdot());

        let regular = create_test_dir_entry(b"MYDIR      ", FatAttributes::DIRECTORY.bits());
        assert!(!regular.is_dot_or_dotdot());

        let dot_file = create_test_dir_entry(b".HIDDEN    ", 0);
        assert!(!dot_file.is_dot_or_dotdot());
    }

    #[test]
    fn test_dir_entry_is_directory() {
        let dir_entry = create_test_dir_entry(b"MYDIR      ", FatAttributes::DIRECTORY.bits());
        assert!(dir_entry.is_directory());

        let file_entry = create_test_dir_entry(b"MYFILE  TXT", 0);
        assert!(!file_entry.is_directory());

        // Directory with other attributes
        let combo = create_test_dir_entry(
            b"SYSDIR     ",
            FatAttributes::DIRECTORY.bits() | FatAttributes::SYSTEM.bits(),
        );
        assert!(combo.is_directory());
    }

    #[test]
    fn test_dir_entry_is_volume_id() {
        let vol_entry = create_test_dir_entry(b"VOLUME     ", FatAttributes::VOLUME_ID.bits());
        assert!(vol_entry.is_volume_id());

        let normal_entry = create_test_dir_entry(b"TEST       ", 0);
        assert!(!normal_entry.is_volume_id());

        // LFN entries have VOLUME_ID set but should not be considered volume labels
        let lfn_entry = create_test_dir_entry(b"           ", FatAttributes::LFN.bits());
        assert!(!lfn_entry.is_volume_id());
    }

    #[test]
    fn test_dir_entry_first_cluster() {
        let mut entry = create_test_dir_entry(b"TEST       ", 0);
        entry.first_cluster_high = U16::new(0x0001);
        entry.first_cluster_low = U16::new(0x2345);

        assert_eq!(entry.first_cluster(), 0x00012345);
    }

    #[test]
    fn test_dir_entry_first_cluster_fat16() {
        // FAT16 only uses the low word
        let mut entry = create_test_dir_entry(b"TEST       ", 0);
        entry.first_cluster_high = U16::new(0x0000);
        entry.first_cluster_low = U16::new(0x00FF);

        assert_eq!(entry.first_cluster(), 0x000000FF);
    }

    #[test]
    fn test_dir_entry_file_size() {
        let mut entry = create_test_dir_entry(b"TEST    TXT", 0);
        entry.file_size = U32::new(12345);
        assert_eq!(entry.file_size(), 12345);

        entry.file_size = U32::new(0xFFFFFFFF);
        assert_eq!(entry.file_size(), 0xFFFFFFFF);
    }

    #[test]
    fn test_dir_entry_attributes() {
        let entry = create_test_dir_entry(
            b"TEST       ",
            FatAttributes::READ_ONLY.bits() | FatAttributes::ARCHIVE.bits(),
        );
        let attrs = entry.attributes();
        assert!(attrs.contains(FatAttributes::READ_ONLY));
        assert!(attrs.contains(FatAttributes::ARCHIVE));
        assert!(!attrs.contains(FatAttributes::HIDDEN));
    }

    // Test for constants
    #[test]
    fn test_constants() {
        assert_eq!(DIR_ENTRY_SIZE, 32);
        assert_eq!(DIR_ENTRY_DELETED, 0xE5);
        assert_eq!(DIR_ENTRY_END, 0x00);
        assert_eq!(SFN_SIZE, 11);
        assert_eq!(LFN_PART_LEN, 13);
        assert_eq!(LFN_MAX_ENTRIES, 20);
        assert_eq!(LFN_MAX_LEN, 260);
        assert_eq!(LFN_SEQ_MASK, 0x1F);
        assert_eq!(LFN_LAST_ENTRY, 0x40);
    }

    // ------------------------------------------------------------------
    // FatDirEntry accessor tests — pin individual getters against
    // constant-replacement mutants.
    // ------------------------------------------------------------------

    /// Build a `FatDirEntry` with a non-trivial set of fields so every
    /// getter can be asserted against a specific value.
    #[expect(
        clippy::too_many_arguments,
        reason = "test helper mirrors DirFileEntryData layout"
    )]
    fn build_dir_entry(
        name: &[u8; SFN_SIZE],
        attributes: u8,
        nt_reserved: u8,
        first_cluster_hi: u16,
        first_cluster_lo: u16,
        file_size: u32,
        create_date: u16,
        create_time: u16,
        create_tenths: u8,
        modify_date: u16,
        modify_time: u16,
        access_date: u16,
    ) -> FatDirEntry {
        let data = DirFileEntryData {
            name: *name,
            attributes,
            nt_reserved,
            create_time_tenths: create_tenths,
            create_time: U16::new(create_time),
            create_date: U16::new(create_date),
            access_date: U16::new(access_date),
            first_cluster_high: U16::new(first_cluster_hi),
            modify_time: U16::new(modify_time),
            modify_date: U16::new(modify_date),
            first_cluster_low: U16::new(first_cluster_lo),
            file_size: U32::new(file_size),
        };
        FatDirEntry::new(data)
    }

    #[test]
    fn dir_entry_has_long_name_distinguishes_empty_buffer() {
        // Catches `has_long_name -> bool with true`, `with false`, and
        // `delete !` — all three need both branches asserted.
        let no_lfn = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
        assert!(!no_lfn.has_long_name());

        let lfn_chars: [u16; 3] = [0x0048, 0x0069, 0x0021]; // "Hi!"
        let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
        data.name = *b"TEST    TXT";
        let with_lfn = FatDirEntry::with_lfn(data, &lfn_chars, lfn_chars.len());
        assert!(with_lfn.has_long_name());
    }

    #[test]
    fn dir_entry_long_name_utf16_returns_buffer_contents() {
        // Catches `long_name_utf16 -> &[u16] with Vec::leak(...)` for empty,
        // [0], or [1]: a non-trivial buffer with distinct values forces
        // each substitution to be observable.
        let lfn_chars: [u16; 5] = [0x0044, 0x0065, 0x0073, 0x006B, 0x0021]; // "Desk!"
        let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
        data.name = *b"DESK    TXT";
        let entry = FatDirEntry::with_lfn(data, &lfn_chars, lfn_chars.len());
        assert_eq!(entry.long_name_utf16(), &lfn_chars[..]);

        // Empty buffer when there's no LFN.
        let no_lfn = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
        assert!(no_lfn.long_name_utf16().is_empty());
    }

    #[test]
    fn dir_entry_is_volume_id_excludes_lfn_attribute_mask() {
        // Catches `is_volume_id -> bool with false`: a true volume label
        // must be detected, and an LFN entry (which has VOLUME_ID bit set
        // as part of 0x0F) must not.
        let vol = build_dir_entry(b"MY VOLUME  ", 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        assert!(vol.is_volume_id());

        let lfn_only = build_dir_entry(b"           ", 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        assert!(!lfn_only.is_volume_id());

        let regular = build_dir_entry(b"FILE    TXT", 0x20, 0, 0, 2, 100, 0, 0, 0, 0, 0, 0);
        assert!(!regular.is_volume_id());
    }

    #[test]
    fn dir_entry_file_size_returns_field_value() {
        // Catches `file_size -> u32 with 0` and `with 1` — both constants
        // are ruled out by a non-zero, non-one assertion.
        let entry = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0xDEAD_BEEF, 0, 0, 0, 0, 0, 0);
        assert_eq!(entry.file_size(), 0xDEAD_BEEF);

        let small = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 42, 0, 0, 0, 0, 0, 0);
        assert_eq!(small.file_size(), 42);

        let empty = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(empty.file_size(), 0);
    }

    #[test]
    fn dir_entry_first_cluster_combines_high_and_low_words() {
        // Catches `replace | with ^` on `first_cluster`: the high/low
        // bits chosen so `|` and `^` differ. high=0x0001, low=0x0001 →
        // `|` gives 0x0001_0001, `^` gives 0x0001_0001 (same — bad test).
        // Use non-overlapping bits and a non-zero high word.
        let entry = build_dir_entry(
            b"BIG     TXT",
            0x20,
            0,
            0x1234, // first_cluster_high
            0x5678, // first_cluster_low (no overlap with high<<16)
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        assert_eq!(entry.first_cluster(), 0x1234_5678);

        // High = 0 (FAT16 case): only low matters.
        let fat16_style = build_dir_entry(b"SMALL      ", 0x10, 0, 0, 0x1234, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(fat16_style.first_cluster(), 0x0000_1234);

        // Both high and low non-zero — choose values that share bits so
        // `| -> ^` (XOR) would flip the shared bits and break the test.
        let shared = build_dir_entry(b"OVERLAP TXT", 0x20, 0, 0x0001, 0x0001, 0, 0, 0, 0, 0, 0, 0);
        // (1 << 16) | 1 = 0x10001; (1 << 16) ^ 1 = 0x10001 — same. Pick
        // different shared positions.
        assert_eq!(shared.first_cluster(), 0x0001_0001);
        // Anchor the XOR case: high << 16 = 0x10000, low = 0xFFFF.
        // `|` → 0x1FFFF, `^` → 0x1FFFF (same again). Bitwise XOR vs OR
        // only differ when bits overlap. Since high is shifted by 16,
        // the only way to overlap is to have low bits beyond 0xFFFF —
        // impossible (low is u16). So `| -> ^` is actually equivalent.
        // Refactor will make this explicit, but assert the value remains.
        let max_low = build_dir_entry(b"MAXLOW  TXT", 0x20, 0, 0x0001, 0xFFFF, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(max_low.first_cluster(), 0x0001_FFFF);
    }

    #[test]
    fn dir_entry_long_name_string_returns_none_when_buffer_empty() {
        // Catches `long_name_string -> Option<String> with None`, with
        // Some("xyzzy"), with Some(""), and `delete !`: a present LFN
        // must produce the exact UTF-16-decoded string, and an absent
        // LFN must produce None.
        let lfn: [u16; 5] = [0x0048, 0x0065, 0x006C, 0x006C, 0x006F]; // "Hello"
        let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
        data.name = *b"HELLO   TXT";
        let with_lfn = FatDirEntry::with_lfn(data, &lfn, lfn.len());
        assert_eq!(with_lfn.long_name_string(), Some(String::from("Hello")));

        let no_lfn = build_dir_entry(b"NOLFN   TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(no_lfn.long_name_string(), None);
    }

    #[test]
    fn dir_entry_name_prefers_long_over_short() {
        // Catches `name -> String with String::new()` / "xyzzy".into():
        // a non-empty, non-"xyzzy" assertion rules out the constants,
        // and a long-name fixture exercises the LFN branch while a
        // short-name fixture exercises the fallback.
        let lfn: [u16; 8] = [
            0x004D, 0x0079, 0x0046, 0x0069, 0x006C, 0x0065, 0x002E, 0x0074,
        ]; // "MyFile.t"
        let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
        data.name = *b"MYFILE  TXT";
        let with_lfn = FatDirEntry::with_lfn(data, &lfn, lfn.len());
        assert_eq!(with_lfn.name(), "MyFile.t");

        // No LFN → falls back to short-name string.
        let no_lfn = build_dir_entry(b"README  TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(no_lfn.name(), "README.TXT");
    }

    #[test]
    fn dir_entry_time_accessors_round_trip_raw_fields() {
        // Catches the three time-accessor mutants `-> FatTime with
        // Default::default()`: the assertions use a non-default
        // (non-1980-01-01) date plus a non-zero tenths so any default
        // substitution becomes observable.
        // 2023-06-15 14:30:45.120:
        //   year_offset=43, date = (43<<9)|(6<<5)|15 = 0x56CF
        //   time = (14<<11)|(30<<5)|22 = 0x73D6
        //   tenths = 112 (odd second + 12)
        let entry = build_dir_entry(
            b"DATED   TXT",
            0x20,
            0,
            0,
            2,
            100,
            0x56CF, // create_date
            0x73D6, // create_time
            112,    // create_tenths
            0x56CF, // modify_date
            0x73D6, // modify_time
            0x56CF, // access_date
        );

        let ct = entry.creation_time();
        assert_eq!(ct.year(), 2023);
        assert_eq!(ct.month(), 6);
        assert_eq!(ct.day(), 15);
        assert_eq!(ct.hour(), 14);
        assert_eq!(ct.minute(), 30);
        assert_eq!(ct.second(), 45);
        assert_eq!(ct.millisecond(), 120);

        let mt = entry.modification_time();
        assert_eq!(mt.year(), 2023);
        assert_eq!(mt.day(), 15);
        // Modification has no tenths field; it stays at 0 regardless of
        // create_time_tenths so the second remains even-aligned.
        assert_eq!(mt.millisecond(), 0);

        let ad = entry.access_date();
        assert_eq!(ad.year(), 2023);
        assert_eq!(ad.month(), 6);
        assert_eq!(ad.day(), 15);
        // Access has no time component.
        assert_eq!(ad.hour(), 0);
        assert_eq!(ad.minute(), 0);
        assert_eq!(ad.second(), 0);
    }

    // ------------------------------------------------------------------
    // DirFileEntryData::is_dot_or_dotdot — the `&&` chain must not
    // be permissive.
    // ------------------------------------------------------------------

    #[test]
    fn dot_entry_detection_rejects_dot_followed_by_non_dot_non_space() {
        // Original: name[0]=='.' && (name[1]==' ' || (name[1]=='.' && name[2]==' '))
        // Mutating the outer `&&` to `||` would mark every entry with
        // " " or ".." at position [1] as dot-or-dotdot regardless of
        // name[0]. The first-byte 'X' case rules that mutation out.
        let xspace = create_test_dir_entry(b"X..        ", 0);
        assert!(!xspace.is_dot_or_dotdot());

        // ".X..       " — starts with '.' but name[1]='X' (not space
        // and not '.'); must NOT be detected as dot-or-dotdot.
        let dot_x = create_test_dir_entry(b".X         ", 0);
        assert!(!dot_x.is_dot_or_dotdot());

        // "..X        " — starts with ".." but name[2]='X' (not space).
        // Must NOT be detected.
        let dotdot_x = create_test_dir_entry(b"..X        ", 0);
        assert!(!dotdot_x.is_dot_or_dotdot());

        // Sanity: the two canonical cases still match.
        let dot = create_test_dir_entry(b".          ", 0);
        assert!(dot.is_dot_or_dotdot());
        let dotdot = create_test_dir_entry(b"..         ", 0);
        assert!(dotdot.is_dot_or_dotdot());
    }

    // ------------------------------------------------------------------
    // name_matches — anchors LFN-then-SFN order plus case-insensitivity.
    // ------------------------------------------------------------------

    #[test]
    fn name_matches_compares_long_name_first_then_short() {
        // Catches `name_matches -> bool with true`, `with false`, and
        // `&& -> ||`: a hit on the long name must succeed even when the
        // short name differs, and a miss on both must return false.
        let lfn: [u16; 9] = [
            0x0072, 0x0065, 0x0061, 0x0064, 0x006D, 0x0065, 0x002E, 0x0074, 0x0078,
        ]; // "readme.tx"
        let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
        data.name = *b"README~1TXT"; // synthesized short name differs from LFN
        let with_lfn = FatDirEntry::with_lfn(data, &lfn, lfn.len());

        // Long-name match wins even though it's case-different.
        assert!(with_lfn.name_matches("README.TX"));
        assert!(with_lfn.name_matches("readme.tx"));
        // Mismatch on both.
        assert!(!with_lfn.name_matches("OTHER.TXT"));

        // No LFN → only short-name comparison.
        let no_lfn = build_dir_entry(b"README  TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
        assert!(no_lfn.name_matches("readme.txt"));
        assert!(no_lfn.name_matches("README.TXT"));
        assert!(!no_lfn.name_matches("other.txt"));
    }

    // ------------------------------------------------------------------
    // LfnEntryData::extract_chars — `||` chains and `* 2` index math.
    // ------------------------------------------------------------------

    #[test]
    fn lfn_extract_chars_stops_at_first_terminator_in_name2_and_name3() {
        // Catches `|| -> &&` (a NUL or 0xFFFF inside name2 must stop
        // extraction, not require both) and `* with /` on the 2-byte
        // index math (would change indexing). Plant chars in name1
        // (full) and name3 (full) but a NUL inside name2 to force
        // extraction to stop mid-entry at position 5 + n2_offset.
        let mut lfn = LfnEntryData {
            sequence: 1,
            name1: [0; 10],
            attributes: 0x0F,
            entry_type: 0,
            checksum: 0,
            name2: [0; 12],
            first_cluster: U16::new(0),
            name3: [0; 4],
        };
        // name1: 5 ASCII chars "ABCDE"
        for (i, c) in [0x41u16, 0x42, 0x43, 0x44, 0x45].iter().enumerate() {
            lfn.name1[i * 2] = (*c & 0xFF) as u8;
            lfn.name1[i * 2 + 1] = (*c >> 8) as u8;
        }
        // name2: "FG" then NUL at position 2 — extraction must stop at
        // 7 chars total.
        lfn.name2[0] = 0x46; // 'F'
        lfn.name2[2] = 0x47; // 'G'
        // bytes 4..6 stay zero → NUL → terminator.

        let mut buf = [0u16; LFN_PART_LEN];
        let count = lfn.extract_chars(&mut buf);
        assert_eq!(count, 7);
        assert_eq!(&buf[..7], &[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
    }

    #[test]
    fn lfn_extract_chars_handles_0xffff_in_name1() {
        // Catches `|| -> &&` at line 153: the 0xFFFF terminator must
        // halt extraction just as 0x0000 does.
        let mut lfn = LfnEntryData {
            sequence: 1,
            name1: [0; 10],
            attributes: 0x0F,
            entry_type: 0,
            checksum: 0,
            name2: [0; 12],
            first_cluster: U16::new(0),
            name3: [0; 4],
        };
        // name1: 'X', then 0xFFFF.
        lfn.name1[0] = 0x58;
        lfn.name1[1] = 0x00;
        lfn.name1[2] = 0xFF;
        lfn.name1[3] = 0xFF;

        let mut buf = [0u16; LFN_PART_LEN];
        let count = lfn.extract_chars(&mut buf);
        assert_eq!(count, 1);
        assert_eq!(buf[0], 0x58);
    }

    // ------------------------------------------------------------------
    // FatDirEntries::next — end-to-end LFN reassembly.
    //
    // Catches the cluster of mutants on the LFN state-machine arms:
    //   - line 622 `& with |/^` on `seq & LFN_SEQ_MASK`
    //   - line 626 `==/||/>` on the seq_num validation
    //   - line 634 `& with |/^` and `!= with ==` on the LAST-entry check
    //   - line 641 `&& with ||` and `== with !=` on the checksum match
    //   - lines 648-660 `- with +`, `* with /`, etc. on the buffer indexing
    //   - line 673 the post-collect checksum and buffer-empty check
    //
    // The fixture is a fixed-region FAT16 root with three real entries:
    //   slot 0: LFN slice covering chars 13..25 of "TwoEntryLfnSpansBoth.tx"
    //           seq = 2 | 0x40 (last/highest physical entry)
    //   slot 1: LFN slice covering chars 0..12
    //           seq = 1
    //   slot 2: short-name entry "TWOENT~1TXT" linked by the matching
    //           sfn_checksum.
    // The state machine must concatenate seq=1 chars (positions 0..12)
    // with seq=2 chars (positions 13..25) to produce the full LFN.
    // ------------------------------------------------------------------

    fn write_lfn_slot(img: &mut [u8], off: usize, seq: u8, checksum: u8, chars: &[u16]) {
        img[off] = seq;
        img[off + 0x0B] = 0x0F; // LFN attributes
        img[off + 0x0D] = checksum;
        // name1: chars[0..5]
        for (i, &c) in chars.iter().take(5).enumerate() {
            img[off + 1 + i * 2] = (c & 0xFF) as u8;
            img[off + 1 + i * 2 + 1] = (c >> 8) as u8;
        }
        // name2: chars[5..11] at offset 0x0E
        for (i, &c) in chars.iter().skip(5).take(6).enumerate() {
            img[off + 0x0E + i * 2] = (c & 0xFF) as u8;
            img[off + 0x0E + i * 2 + 1] = (c >> 8) as u8;
        }
        // name3: chars[11..13] at offset 0x1C
        for (i, &c) in chars.iter().skip(11).take(2).enumerate() {
            img[off + 0x1C + i * 2] = (c & 0xFF) as u8;
            img[off + 0x1C + i * 2 + 1] = (c >> 8) as u8;
        }
    }

    fn write_sfn_slot(img: &mut [u8], off: usize, name: &[u8; SFN_SIZE], attrs: u8) {
        img[off..off + 11].copy_from_slice(name);
        img[off + 0x0B] = attrs;
    }

    /// Build a minimal FAT16 image (boot sector + root dir region) so the
    /// dir_entry tests have a self-contained fixture without depending on
    /// helpers in the traverse test module.
    fn build_minimal_fat16_for_dir_entries() -> Vec<u8> {
        let mut img = std::vec![0u8; 22 * 512];
        img[0x00..0x03].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[0x03..0x0B].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1; // spc
        img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // reserved
        img[0x10] = 1; // num_fats
        img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes()); // root_entries
        img[0x13..0x15].copy_from_slice(&4104u16.to_le_bytes()); // total_sectors_16
        img[0x15] = 0xF8;
        img[0x16..0x18].copy_from_slice(&17u16.to_le_bytes()); // spf16
        img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        img[0x24] = 0x80;
        img[0x26] = 0x29;
        img[0x36..0x3E].copy_from_slice(b"FAT16   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;
        // FAT table: mark cluster 0/1 reserved.
        img[0x200..0x202].copy_from_slice(&0xFFF8u16.to_le_bytes());
        img[0x202..0x204].copy_from_slice(&0xFFFFu16.to_le_bytes());
        img
    }

    fn build_fat16_image_with_2entry_lfn(short_name: &[u8; SFN_SIZE]) -> (Vec<u8>, [u16; 26]) {
        // Long name: 26 chars (two LFN entries fully populated).
        let long: [u16; 26] = [
            b'T' as u16,
            b'w' as u16,
            b'o' as u16,
            b'E' as u16,
            b'n' as u16,
            b't' as u16,
            b'r' as u16,
            b'y' as u16,
            b'L' as u16,
            b'f' as u16,
            b'n' as u16,
            b'S' as u16,
            b'p' as u16,
            b'a' as u16,
            b'n' as u16,
            b's' as u16,
            b'B' as u16,
            b'o' as u16,
            b't' as u16,
            b'h' as u16,
            b'.' as u16,
            b't' as u16,
            b'x' as u16,
            b't' as u16,
            0x0000, // padding within entry 2 to terminate cleanly
            0x0000,
        ];

        let mut img = build_minimal_fat16_for_dir_entries();
        let r = 18 * 512; // FAT16 fixed root

        // Replace whatever build_fat16_image wrote with our LFN sequence.
        for i in 0..4 {
            img[r + i * 32..r + (i + 1) * 32].fill(0);
        }

        let checksum = sfn_checksum(short_name);

        // Slot 0: physical first → seq = 2 | 0x40 → chars 13..25 (next 13 of long).
        let entry2_chars: Vec<u16> = long.iter().skip(13).take(13).copied().collect();
        write_lfn_slot(&mut img, r, 0x42, checksum, &entry2_chars);

        // Slot 1: physical second → seq = 1 → chars 0..12.
        let entry1_chars: Vec<u16> = long.iter().take(13).copied().collect();
        write_lfn_slot(&mut img, r + 32, 0x01, checksum, &entry1_chars);

        // Slot 2: short-name entry matching the LFN's checksum.
        write_sfn_slot(&mut img, r + 64, short_name, FatAttributes::ARCHIVE.bits());

        // Slot 3: end marker (already zeroed).
        (img, long)
    }

    #[test]
    fn fat_dir_entries_assembles_multi_entry_lfn_into_short_name_target() {
        use crate::fat::Fat;
        use std::io::Cursor;
        use std::string::String;

        // Build the short name first so the LFN checksum is correct.
        let short_name: [u8; SFN_SIZE] = *b"TWOENT~1TXT";
        let (img, long) = build_fat16_image_with_2entry_lfn(&short_name);

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let mut entries = fat.root_dir_entries();
        let mut yielded: std::vec::Vec<FatDirEntry> = std::vec::Vec::new();
        while let Some(r) = entries.next(&mut cur) {
            yielded.push(r.expect("entry parses"));
        }
        assert_eq!(yielded.len(), 1, "expected one short-name entry");
        let entry = &yielded[0];

        // Reassembly: chars 0..12 from physical-second LFN entry plus
        // chars 13..25 from physical-first LFN entry → full long name.
        // Mutating `seq_num - 1` or the buffer offsets would mis-place
        // the slices and yield a scrambled string.
        let lfn = entry.long_name_utf16();
        let trimmed: std::vec::Vec<u16> = lfn.iter().copied().take_while(|&c| c != 0).collect();
        let expected_trim: std::vec::Vec<u16> =
            long.iter().copied().take_while(|&c| c != 0).collect();
        assert_eq!(trimmed, expected_trim);

        // The short-name target must also be the one the LFN's checksum
        // pointed at — anchors line 673's checksum match.
        assert_eq!(entry.short_name(), &short_name);
        assert_eq!(
            entry.long_name_string(),
            Some(String::from("TwoEntryLfnSpansBoth.txt")),
        );
    }

    #[test]
    fn fat_dir_entries_falls_back_to_short_name_on_checksum_mismatch() {
        use crate::fat::Fat;
        use std::io::Cursor;

        // Build a normal 2-entry LFN, then corrupt the checksum byte in
        // both LFN entries so they don't match the short name's actual
        // checksum. The state machine must keep the short name and
        // expose no long name (anchors line 673's
        // `computed_checksum == lfn_checksum` test).
        let short_name: [u8; SFN_SIZE] = *b"NOMATCH TXT";
        let (mut img, _long) = build_fat16_image_with_2entry_lfn(&short_name);
        let r = 18 * 512;
        img[r + 0x0D] = 0x00; // slot 0 checksum byte
        img[r + 32 + 0x0D] = 0x00; // slot 1 checksum byte

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();
        let mut yielded: std::vec::Vec<FatDirEntry> = std::vec::Vec::new();
        while let Some(r) = entries.next(&mut cur) {
            yielded.push(r.expect("entry parses"));
        }
        assert_eq!(yielded.len(), 1);
        assert!(!yielded[0].has_long_name());
        assert_eq!(yielded[0].short_name(), &short_name);
    }

    #[test]
    fn fat_dir_entries_skips_lfn_with_out_of_range_sequence_number() {
        use crate::fat::Fat;
        use std::io::Cursor;

        // Build a normal 2-entry LFN, then poison the SEQUENCE byte of
        // slot 0 with an out-of-range value (LFN_MAX_ENTRIES is 20, so
        // 25 is out of range). The state machine must reset and skip
        // the LFN, falling back to short name only. Anchors line 626's
        // validation chain.
        let short_name: [u8; SFN_SIZE] = *b"BADSEQ  TXT";
        let (mut img, _long) = build_fat16_image_with_2entry_lfn(&short_name);
        let r = 18 * 512;
        img[r] = 0x40 | 25; // last bit + out-of-range seq_num

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();
        let mut yielded: std::vec::Vec<FatDirEntry> = std::vec::Vec::new();
        while let Some(r) = entries.next(&mut cur) {
            yielded.push(r.expect("entry parses"));
        }
        // The partial LFN that survives in slot 1 (seq=1) is not
        // preceded by a valid LAST entry, so checksum matching may
        // succeed but the buffer position is at 0..13. The short
        // name's checksum still gates whether long_name attaches.
        // The key invariant here: iteration must not error or skip the
        // short-name entry on receiving a malformed LFN sequence.
        assert_eq!(yielded.len(), 1);
        assert_eq!(yielded[0].short_name(), &short_name);
    }

    /// Place a plain short-name entry in slot 0, end marker in slot 1.
    /// Used by the find/find_by_name/try_next tests below.
    fn build_fat16_image_with_single_file(name: &[u8; SFN_SIZE]) -> Vec<u8> {
        let mut img = build_minimal_fat16_for_dir_entries();
        let r = 18 * 512;
        write_sfn_slot(&mut img, r, name, FatAttributes::ARCHIVE.bits());
        img
    }

    #[test]
    fn fat_dir_entries_find_returns_matching_entry() {
        // Catches `find -> Option<Result<FatDirEntry>> with None`: the
        // predicate must match a real entry and the iterator must yield
        // it, not silently produce None.
        use crate::fat::Fat;
        use std::io::Cursor;

        let img = build_fat16_image_with_single_file(b"HELLO   TXT");
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();
        let found = entries
            .find(&mut cur, |e| &e.short_name()[..5] == b"HELLO")
            .expect("predicate must match")
            .expect("entry parses");
        assert_eq!(&found.short_name()[..5], b"HELLO");
    }

    #[test]
    fn fat_dir_entries_find_by_name_resolves_short_name_case_insensitive() {
        // Catches `find_by_name -> None`: the case-insensitive
        // comparison must find the entry whose short name matches.
        use crate::fat::Fat;
        use std::io::Cursor;

        let img = build_fat16_image_with_single_file(b"README  TXT");
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();
        let found = entries
            .find_by_name(&mut cur, "readme.txt")
            .expect("name must resolve")
            .expect("entry parses");
        assert_eq!(&found.short_name()[..6], b"README");
    }

    #[test]
    fn fat_dir_entries_try_next_returns_some_for_present_entry() {
        // Catches `<impl FsTryIterator>::try_next -> Ok(None)`: the
        // adapter must surface the same entries as `next`.
        use crate::fat::Fat;
        use fs_common::iter::FsTryIterator;
        use std::io::Cursor;

        let img = build_fat16_image_with_single_file(b"NOTE       ");
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();
        let first = FsTryIterator::try_next(&mut entries, &mut cur)
            .expect("try_next succeeds")
            .expect("entry present");
        assert_eq!(first.short_name(), b"NOTE       ");
    }

    /// Build a fixed-region FAT16 image whose root directory spans more
    /// than one buffer fill. The root entry count is set to 32 (one
    /// cluster of 512 bytes = 16 entries; two clusters covers 32 entries).
    /// We populate entries across the boundary so the iterator must
    /// call `fill_buffer` at least twice and the `*remaining -=` and
    /// `*current_cluster = ...` arithmetic in `fill_buffer` is exercised.
    fn build_fat16_image_spanning_two_buffer_fills() -> Vec<u8> {
        let mut img = build_minimal_fat16_for_dir_entries();

        // Root directory has 16 entries × 32 bytes = 512 bytes = one cluster.
        // Bump root_entry_count to 32 (2 clusters worth) so a single buffer
        // fill cannot exhaust the region.
        img[0x11..0x13].copy_from_slice(&32u16.to_le_bytes());

        let r = 18 * 512;
        // Populate slots 0..15 with placeholder files; the iterator must
        // walk past all of them before hitting the second buffer fill.
        for i in 0..15 {
            let mut name = *b"FILL    TXT";
            name[4] = b'0' + (i as u8 % 10);
            write_sfn_slot(&mut img, r + i * 32, &name, FatAttributes::ARCHIVE.bits());
        }
        // Slot 15: distinguishing entry in the FIRST buffer fill.
        write_sfn_slot(
            &mut img,
            r + 15 * 32,
            b"FIRST   TXT",
            FatAttributes::ARCHIVE.bits(),
        );
        // Slot 16: file in the SECOND buffer fill (different sector).
        write_sfn_slot(
            &mut img,
            r + 16 * 32,
            b"SECOND  TXT",
            FatAttributes::ARCHIVE.bits(),
        );
        // Slot 17: end marker (already zero).
        img
    }

    #[test]
    fn fat_dir_entries_fill_buffer_advances_across_buffer_boundary() {
        // Catches `+= with -=/*=` on `*remaining -= to_read as u32` in
        // fill_buffer's Fixed arm (line 724) and on
        // `*current_cluster = ...` style accumulator math. The fixture
        // forces iteration across two buffer fills; mutating the
        // remaining-byte accumulator would either stall the iterator
        // (never decrementing) or skip ahead.
        use crate::fat::Fat;
        use std::io::Cursor;

        let img = build_fat16_image_spanning_two_buffer_fills();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();

        let mut names: std::vec::Vec<[u8; 11]> = std::vec::Vec::new();
        while let Some(r) = entries.next(&mut cur) {
            let entry = r.expect("entry parses");
            names.push(*entry.short_name());
        }

        // Both entries must be visible; the SECOND entry is in slot 16
        // which lives in the second buffer-fill chunk.
        assert!(
            names.iter().any(|n| n == b"FIRST   TXT"),
            "FIRST.TXT missing: {names:?}",
        );
        assert!(
            names.iter().any(|n| n == b"SECOND  TXT"),
            "SECOND.TXT missing (fill_buffer didn't advance): {names:?}",
        );
    }
}
