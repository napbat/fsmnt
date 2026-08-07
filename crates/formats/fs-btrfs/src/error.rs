use alloc::string::String;

use thiserror::Error;

use crate::io;

/// Result type returned by the Btrfs parser.
pub type Result<T, E = BtrfsError> = core::result::Result<T, E>;

/// Errors encountered while opening or parsing a Btrfs volume.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BtrfsError {
    /// The reader failed while locating or loading a superblock mirror.
    #[error("I/O error: {0:?}")]
    Io(io::Error),
    /// A supplied superblock buffer is shorter than the on-disk structure.
    #[error("Btrfs superblock is too short: expected {expected} bytes, got {actual}")]
    BufferTooSmall {
        /// Minimum number of bytes required.
        expected: usize,
        /// Number of bytes supplied.
        actual: usize,
    },
    /// A candidate superblock does not carry the Btrfs signature.
    #[error("invalid Btrfs magic: {actual:?}")]
    InvalidMagic {
        /// Eight bytes found in the magic field.
        actual: [u8; 8],
    },
    /// A superblock's physical self-address differs from the mirror read.
    #[error(
        "invalid Btrfs superblock self-address {actual:#x}; expected mirror address {expected:#x}"
    )]
    InvalidPhysicalAddress {
        /// Physical mirror address from which the bytes were read.
        expected: u64,
        /// Physical address stored in the superblock.
        actual: u64,
    },
    /// A reported zoned-device zone size is outside Btrfs's supported range.
    #[error("invalid Btrfs zoned-device zone size: {actual}")]
    InvalidZoneSize {
        /// Reported uniform zone size in bytes.
        actual: u64,
    },
    /// A reported zone has invalid, overlapping, or inconsistent geometry.
    #[error("invalid Btrfs zone geometry at byte offset {start:#x}")]
    InvalidZoneGeometry {
        /// Start offset of the invalid zone or zone pair.
        start: u64,
    },
    /// A zoned superblock pair has a state that cannot occur in Btrfs's log.
    #[error("invalid Btrfs zoned superblock log state for mirror {mirror:#x}")]
    InvalidZonedSuperblockLogState {
        /// Conventional mirror identity associated with the log pair.
        mirror: u64,
    },
    /// No written superblock exists in the reported zoned log pairs.
    #[error("no Btrfs superblock was written to the reported zoned log pairs")]
    ZonedSuperblockNotFound,
    /// The superblock sets state bits that this reader cannot interpret.
    #[error("unsupported Btrfs superblock flags {flags:#x}")]
    UnsupportedSuperblockFlags {
        /// Unsupported bits from the superblock flags field.
        flags: u64,
    },
    /// A fixed superblock field violates an on-disk geometry invariant.
    #[error("invalid Btrfs superblock field {field}: {value}")]
    InvalidSuperblockField {
        /// Name of the invalid field.
        field: &'static str,
        /// Decoded field value.
        value: u64,
    },
    /// The embedded device item identifies a different filesystem.
    #[error("Btrfs superblock and embedded device item UUIDs do not match")]
    SuperblockUuidMismatch,
    /// The declared volume size cannot contain Btrfs's minimum metadata region.
    #[error("invalid Btrfs volume size: {actual} bytes")]
    InvalidTotalBytes {
        /// Declared total volume size.
        actual: u64,
    },
    /// Allocated bytes exceed the declared volume size.
    #[error("Btrfs bytes used ({bytes_used}) exceed total bytes ({total_bytes})")]
    InvalidBytesUsed {
        /// Declared number of allocated bytes.
        bytes_used: u64,
        /// Declared total volume size.
        total_bytes: u64,
    },
    /// The filesystem claims to have no backing devices.
    #[error("Btrfs superblock declares zero devices")]
    InvalidDeviceCount,
    /// A multi-device constructor was called without any readers.
    #[error("no Btrfs device readers were supplied")]
    NoDevices,
    /// The sector size is not a supported power of two.
    #[error("invalid Btrfs sector size: {actual}")]
    InvalidSectorSize {
        /// Sector size stored in the superblock.
        actual: u32,
    },
    /// The tree node size is incompatible with the sector size.
    #[error("invalid Btrfs node size {actual} for sector size {sector_size}")]
    InvalidNodeSize {
        /// Tree node size stored in the superblock.
        actual: u32,
        /// Previously validated sector size.
        sector_size: u32,
    },
    /// The on-disk checksum algorithm is newer than this parser.
    #[error("unsupported Btrfs checksum type {value}")]
    UnsupportedChecksum {
        /// Raw checksum type from the superblock.
        value: u16,
    },
    /// Incompatible feature bits require metadata semantics this parser lacks.
    #[error("unsupported Btrfs incompatible feature flags {flags:#x}")]
    UnsupportedIncompatFeatures {
        /// Unsupported bits from the superblock's incompatibility mask.
        flags: u64,
    },
    /// A checksum did not match the bytes protected by it.
    #[error("invalid {structure} checksum at logical address {logical:#x}")]
    InvalidChecksum {
        /// Kind of structure whose checksum failed.
        structure: &'static str,
        /// Logical address, or the physical superblock address.
        logical: u64,
    },
    /// A checksummed data extent has no checksum item for one sector.
    #[error("missing Btrfs data checksum for logical address {logical:#x}")]
    DataChecksumMissing {
        /// Logical sector lacking a checksum.
        logical: u64,
    },
    /// A fixed-width field or allocation-size calculation overflowed.
    #[error("Btrfs integer calculation overflowed")]
    IntegerOverflow,
    /// A tree root address or level is invalid.
    #[error("invalid {tree} tree root {logical:#x} at level {level}")]
    InvalidTreeRoot {
        /// Human-readable tree name.
        tree: &'static str,
        /// Logical address of the root block.
        logical: u64,
        /// B-tree level recorded by the superblock or root item.
        level: u8,
    },
    /// The embedded system chunk array exceeds its reserved field.
    #[error("invalid Btrfs system chunk array size {actual}")]
    InvalidSystemChunkArraySize {
        /// Size recorded by the superblock.
        actual: u32,
    },
    /// A chunk item is structurally invalid.
    #[error("invalid Btrfs chunk item at logical address {logical:#x}")]
    InvalidChunk {
        /// Logical start address from the chunk key.
        logical: u64,
    },
    /// Two chunk mappings overlap in logical address space.
    #[error("overlapping Btrfs chunks at logical address {logical:#x}")]
    OverlappingChunks {
        /// Start of the later overlapping chunk.
        logical: u64,
    },
    /// No chunk maps a requested logical address.
    #[error("no Btrfs chunk maps logical address {logical:#x}")]
    LogicalAddressUnmapped {
        /// Logical address that could not be translated.
        logical: u64,
    },
    /// A remapped chunk has no remap-tree item covering the requested address.
    #[error("Btrfs remap tree does not cover logical address {logical:#x}")]
    RemapMissing {
        /// Source logical address lacking a translation.
        logical: u64,
    },
    /// A remap-tree item has an invalid key, payload, or address range.
    #[error("invalid Btrfs remap-tree item covering logical address {logical:#x}")]
    InvalidRemapItem {
        /// Requested source logical address.
        logical: u64,
    },
    /// A RAID stripe-tree-managed extent has no item covering the requested address.
    #[error("Btrfs RAID stripe tree does not cover logical address {logical:#x}")]
    RaidStripeMissing {
        /// Data logical address lacking a stripe item.
        logical: u64,
    },
    /// A RAID stripe-tree item has invalid geometry or references an unrelated device.
    #[error("invalid Btrfs RAID stripe-tree item covering logical address {logical:#x}")]
    InvalidRaidStripeItem {
        /// Requested data logical address.
        logical: u64,
    },
    /// A chunk references a device that was not supplied.
    #[error("Btrfs device {device_id} was not supplied")]
    MissingDevice {
        /// Filesystem-local device identifier.
        device_id: u64,
    },
    /// The supplied readers do not form one complete filesystem.
    #[error("Btrfs declares {expected} device(s), but {actual} were supplied")]
    DeviceCountMismatch {
        /// Device count recorded in the superblock.
        expected: u64,
        /// Number of readers supplied by the caller.
        actual: usize,
    },
    /// Supplied members cannot satisfy one chunk's redundancy profile.
    #[error("not enough available devices to read Btrfs chunk at logical address {logical:#x}")]
    InsufficientDevicesForChunk {
        /// Logical start of the unreadable chunk.
        logical: u64,
    },
    /// A supplied member belongs to another Btrfs filesystem.
    #[error("supplied Btrfs device belongs to another filesystem")]
    ForeignDevice,
    /// A device ID or UUID occurred more than once.
    #[error("duplicate Btrfs device {device_id}")]
    DuplicateDevice {
        /// Repeated filesystem-local device identifier.
        device_id: u64,
    },
    /// The requested RAID profile cannot currently be translated.
    #[error("unsupported Btrfs chunk profile {profile:#x}")]
    UnsupportedChunkProfile {
        /// Profile bits from the chunk type field.
        profile: u64,
    },
    /// A tree block's header or item table is malformed.
    #[error("malformed Btrfs tree block at logical address {logical:#x}")]
    MalformedTreeBlock {
        /// Logical address of the tree block.
        logical: u64,
    },
    /// A serialized metadata item has an invalid length or field value.
    #[error("malformed Btrfs item with key ({object_id}, {item_type}, {offset})")]
    MalformedItem {
        /// Key object identifier.
        object_id: u64,
        /// Key type.
        item_type: u8,
        /// Key offset.
        offset: u64,
    },
    /// A required root-tree item was absent.
    #[error("Btrfs tree root {tree_id} was not found")]
    TreeRootNotFound {
        /// Root-tree object identifier.
        tree_id: u64,
    },
    /// A global tree does not contain exactly the roots declared by the
    /// extent-tree-v2 superblock.
    #[error(
        "Btrfs global tree {tree_id} has {actual} root(s); \
         the superblock declares {expected}"
    )]
    GlobalRootCountMismatch {
        /// Root-tree object identifier.
        tree_id: u64,
        /// Number of roots declared in the superblock.
        expected: u64,
        /// Number of root items found.
        actual: u64,
    },
    /// An extent-tree-v2 global root item has a non-contiguous identifier.
    #[error(
        "Btrfs global tree {tree_id} root identifier {actual} \
         appears where identifier {expected} was required"
    )]
    InvalidGlobalRootId {
        /// Root-tree object identifier.
        tree_id: u64,
        /// Contiguous identifier required at this position.
        expected: u64,
        /// Identifier stored in the root-item key.
        actual: u64,
    },
    /// A block-group-tree item is missing or inconsistent with its chunk.
    #[error("invalid Btrfs block-group item at logical address {logical:#x}")]
    InvalidBlockGroupItem {
        /// Logical start address from the block-group key.
        logical: u64,
    },
    /// A block group selects a global root outside the declared root set.
    #[error(
        "Btrfs block group at {logical:#x} selects global root {global_root_id}, \
         but only {global_root_count} root(s) exist"
    )]
    InvalidBlockGroupRootId {
        /// Logical start address of the block group.
        logical: u64,
        /// Identifier stored in the block-group item.
        global_root_id: u64,
        /// Number of declared global roots.
        global_root_count: u64,
    },
    /// A filesystem object or directory name was absent.
    #[error("Btrfs object was not found")]
    NotFound,
    /// An operation requiring a directory received another inode type.
    #[error("Btrfs object is not a directory")]
    NotADirectory,
    /// A requested path names an ordinary object rather than a subvolume root.
    #[error("Btrfs object is not a subvolume")]
    NotASubvolume,
    /// An operation requiring regular file data received another inode type.
    #[error("Btrfs object is not a regular file or symbolic link")]
    NotAFile,
    /// A file extent uses an unsupported encoding.
    #[error(
        "unsupported Btrfs file extent encoding: compression {compression}, \
         encryption {encryption}, other {other_encoding}"
    )]
    UnsupportedExtentEncoding {
        /// Compression identifier.
        compression: u8,
        /// Encryption identifier.
        encryption: u8,
        /// Other encoding flags.
        other_encoding: u16,
    },
    /// Compressed data requires the parser's `std` feature.
    #[error("Btrfs compression type {compression} requires the std feature")]
    CompressionUnavailable {
        /// On-disk compression identifier.
        compression: u8,
    },
    /// Compressed extent bytes are malformed or do not expand to the declared size.
    #[error("Btrfs compression type {compression} failed to decode an extent: {reason}")]
    DecompressionFailed {
        /// On-disk compression identifier.
        compression: u8,
        /// Decoder or extent-range failure.
        reason: String,
    },
    /// A compressed extent has an empty or oversized encoded/decoded length.
    #[error(
        "invalid Btrfs compressed extent lengths: encoded {disk_bytes}, \
         decoded {ram_bytes}; both must be between 1 and {maximum} bytes"
    )]
    InvalidCompressedExtentSize {
        /// Encoded extent length stored on disk.
        disk_bytes: u64,
        /// Decoded extent length declared by the extent.
        ram_bytes: u64,
        /// Maximum encoded and decoded extent length supported by Btrfs.
        maximum: u64,
    },
    /// RAID5/6 cannot reconstruct a stripe after too many failures.
    #[error(
        "Btrfs RAID5/6 recovery has {failures} unavailable stripe(s), \
         but only {parity_stripes} parity stripe(s)"
    )]
    Raid56RecoveryFailed {
        /// Number of data and parity stripes unavailable to reconstruction.
        failures: usize,
        /// Number of parity stripes in the chunk profile.
        parity_stripes: usize,
    },
    /// Extent metadata selected bytes outside the encoded or decoded buffer.
    #[error("Btrfs file extent range exceeds its backing data")]
    InvalidFileExtentRange,
    /// A file cannot fit in the current process address space.
    #[error("Btrfs file size {size} cannot be represented in memory")]
    FileTooLarge {
        /// Logical file length.
        size: u64,
    },
}

impl From<io::Error> for BtrfsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
