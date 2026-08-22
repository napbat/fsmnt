use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;
use fsmnt_parser_core::io::BlockCache;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, Unaligned};

use crate::error::{FatError, Result};
use crate::fat::Fat;
use crate::io::{Read, Seek, SeekFrom};
use crate::time::FatTime;

bitflags! {
    /// FAT file attributes.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FatAttributes: u8 {
        /// The entry must not be modified.
        const READ_ONLY = 0x01;
        /// The entry is normally omitted from directory listings.
        const HIDDEN = 0x02;
        /// The entry is reserved for operating-system use.
        const SYSTEM = 0x04;
        /// The entry stores the volume label rather than a file.
        const VOLUME_ID = 0x08;
        /// The entry identifies a subdirectory.
        const DIRECTORY = 0x10;
        /// The entry has changed since it was last archived.
        const ARCHIVE = 0x20;
        /// Long-file-name marker combining the read-only, hidden, system, and volume-ID bits.
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
            .as_chunks::<2>()
            .0
            .iter()
            .chain(self.name2.as_chunks::<2>().0)
            .chain(self.name3.as_chunks::<2>().0)
        {
            let c = u16::from_le_bytes(*chunk);
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
    #[must_use]
    pub fn data(&self) -> &DirFileEntryData {
        &self.data
    }

    /// Returns `true` if this entry has a long file name.
    #[inline]
    #[must_use]
    pub fn has_long_name(&self) -> bool {
        !self.lfn_buffer.is_empty()
    }

    /// Returns the long file name as a slice of UTF-16 code units.
    ///
    /// Returns an empty slice if no long file name is present.
    #[inline]
    #[must_use]
    pub fn long_name_utf16(&self) -> &[u16] {
        &self.lfn_buffer
    }

    /// Returns the short name (8.3) as a byte slice.
    #[inline]
    #[must_use]
    pub fn short_name(&self) -> &[u8; SFN_SIZE] {
        &self.data.name
    }

    /// Returns `true` if this is a `.` or `..` directory entry.
    #[inline]
    #[must_use]
    pub fn is_dot_or_dotdot(&self) -> bool {
        self.data.is_dot_or_dotdot()
    }

    /// Returns `true` if this entry represents a directory.
    #[inline]
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.data.is_directory()
    }

    /// Returns `true` if this entry represents the volume label.
    #[inline]
    #[must_use]
    pub fn is_volume_id(&self) -> bool {
        self.data.is_volume_id()
    }

    /// Returns the first cluster number of this entry.
    #[inline]
    #[must_use]
    pub fn first_cluster(&self) -> u32 {
        self.data.first_cluster()
    }

    /// Returns the file size in bytes.
    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u32 {
        self.data.file_size()
    }

    /// Returns the attributes as a `FatAttributes` bitflags value.
    #[inline]
    #[must_use]
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
    #[must_use]
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
        let base_end = base.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);

        // Extract extension (last 3 bytes)
        let ext = &name[8..11];
        let ext_end = ext.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);

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
    #[must_use]
    pub fn long_name_string(&self) -> Option<String> {
        if !self.has_long_name() {
            return None;
        }

        Some(String::from_utf16_lossy(self.long_name_utf16()))
    }

    /// Returns the best available name as a String.
    ///
    /// Returns the long file name if present, otherwise returns the formatted short name.
    #[must_use]
    pub fn name(&self) -> String {
        self.long_name_string()
            .unwrap_or_else(|| self.short_name_string())
    }

    /// Returns the creation time of this entry.
    ///
    /// The creation time includes the date, time, and 10ms resolution from the
    /// `create_time_tenths` field.
    #[inline]
    #[must_use]
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
    #[must_use]
    pub fn modification_time(&self) -> FatTime {
        FatTime::new(self.data.modify_date.get(), self.data.modify_time.get(), 0)
    }

    /// Returns the last access date of this entry.
    ///
    /// FAT only stores the access date, not the time. The time component
    /// will be 00:00:00.
    #[inline]
    #[must_use]
    pub fn access_date(&self) -> FatTime {
        FatTime::from_date(self.data.access_date.get())
    }
}

impl DirFileEntryData {
    /// Returns `true` if this entry marks the end of the directory.
    #[inline]
    #[must_use]
    pub fn is_end(&self) -> bool {
        self.name[0] == DIR_ENTRY_END
    }

    /// Returns `true` if this entry has been deleted.
    #[inline]
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.name[0] == DIR_ENTRY_DELETED
    }

    /// Returns `true` if this is a long file name (LFN) entry.
    #[inline]
    #[must_use]
    pub fn is_lfn(&self) -> bool {
        self.attributes == FatAttributes::LFN.bits()
    }

    /// Returns `true` if this is a `.` or `..` directory entry.
    ///
    /// FAT stores these as real 8.3 entries: `.` is `[0x2E, 0x20 * 10]`
    /// and `..` is `[0x2E, 0x2E, 0x20 * 9]`.
    #[inline]
    #[must_use]
    pub fn is_dot_or_dotdot(&self) -> bool {
        self.name[0] == b'.'
            && (self.name[1] == b' ' || (self.name[1] == b'.' && self.name[2] == b' '))
    }

    /// Returns `true` if this entry represents a directory.
    #[inline]
    #[must_use]
    pub fn is_directory(&self) -> bool {
        FatAttributes::from_bits_truncate(self.attributes).contains(FatAttributes::DIRECTORY)
    }

    /// Returns `true` if this entry represents the volume label.
    #[inline]
    #[must_use]
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
    #[must_use]
    pub fn first_cluster(&self) -> u32 {
        (u32::from(self.first_cluster_high.get()) << 16) | u32::from(self.first_cluster_low.get())
    }

    /// Returns the file size in bytes.
    #[inline]
    #[must_use]
    pub fn file_size(&self) -> u32 {
        self.file_size.get()
    }

    /// Returns the attributes as a `FatAttributes` bitflags value.
    #[inline]
    #[must_use]
    pub fn attributes(&self) -> FatAttributes {
        FatAttributes::from_bits_truncate(self.attributes)
    }
}

/// The source of directory data - either a fixed region or a cluster chain.
#[derive(Clone, Debug)]
enum DirSource {
    /// Fixed region (FAT12/16 root directory).
    /// Contains (`start_offset`, `total_size`).
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
    /// Most recently used FAT sector for adjacent chain entries.
    fat_cache: BlockCache,
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
            fat_cache: BlockCache::new(usize::from(fat.sector_size())),
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
            fat_cache: BlockCache::new(usize::from(fat.sector_size())),
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
                let Ok(entry) = DirFileEntryData::read_from_bytes(entry_bytes) else {
                    self.finished = true;
                    return Some(Err(self.malformed_at_current_entry()));
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
                    let Ok(lfn_entry) = LfnEntryData::read_from_bytes(entry_bytes) else {
                        self.finished = true;
                        return Some(Err(self.malformed_at_current_entry()));
                    };

                    let seq = lfn_entry.sequence;
                    let seq_num = seq & LFN_SEQ_MASK;

                    // Validate sequence number: must be 1-20 (0 is invalid, >20 exceeds max LFN entries)
                    // Skip invalid LFN entries from corrupted filesystems
                    if seq_num == 0 || usize::from(seq_num) > LFN_MAX_ENTRIES {
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
                        let start_pos = usize::from(seq_num - 1) * LFN_PART_LEN;
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
        let entry_pos = u64::try_from(self.buffer_offset - DIR_ENTRY_SIZE).unwrap_or(u64::MAX);
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
                let remaining_len =
                    usize::try_from(*remaining).map_err(|_| FatError::BpbOverflow)?;
                let cluster_len =
                    usize::try_from(self.fat.cluster_size()).map_err(|_| FatError::BpbOverflow)?;
                let to_read = remaining_len.min(cluster_len);

                // Resize buffer to the required size
                self.buffer.resize(to_read, 0);

                self.base_offset = *start_offset;
                fs.seek(SeekFrom::Start(*start_offset))?;
                fs.read_exact(&mut self.buffer)?;

                *start_offset += u64::try_from(to_read).map_err(|_| FatError::BpbOverflow)?;
                *remaining -= u32::try_from(to_read).map_err(|_| FatError::BpbOverflow)?;
            }
            DirSource::ClusterChain { current_cluster } => {
                let Some(cluster) = *current_cluster else {
                    return Ok(());
                };

                // Check for cluster chain loop
                let max_clusters = self.fat.total_clusters();
                if self.clusters_traversed >= max_clusters {
                    return Err(FatError::ClusterChainLoop { max_clusters });
                }

                // Read the current cluster
                let cluster_offset = self.fat.cluster_offset(cluster)?;
                let cluster_size =
                    usize::try_from(self.fat.cluster_size()).map_err(|_| FatError::BpbOverflow)?;

                // Resize buffer to the cluster size
                self.buffer.resize(cluster_size, 0);

                self.base_offset = cluster_offset;
                fs.seek(SeekFrom::Start(cluster_offset))?;
                fs.read_exact(&mut self.buffer)?;

                // Move to the next cluster and increment traversal counter
                *current_cluster =
                    self.fat
                        .next_cluster_cached(fs, cluster, &mut self.fat_cache)?;
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

    /// Returns the `Fat` reference held by this iterator.
    pub(crate) fn fat(&self) -> &'n Fat {
        self.fat
    }

    /// Finds a directory entry by name using case-insensitive matching.
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
    pub fn find_by_name<T>(&mut self, fs: &mut T, name: &str) -> Option<Result<FatDirEntry>>
    where
        T: Read + Seek,
    {
        self.find(fs, |entry| entry.name_matches(name))
    }
}

impl fsmnt_parser_core::iter::FsTryIteratorType for FatDirEntries<'_> {
    type Error = FatError;
    type Item<'a> = FatDirEntry;
}

impl<R: Read + Seek> fsmnt_parser_core::iter::FsTryIterator<R> for FatDirEntries<'_> {
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
    #[must_use]
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
#[path = "dir_entry_tests/mod.rs"]
mod tests;
