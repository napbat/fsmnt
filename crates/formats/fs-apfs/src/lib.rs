//! A low-level Apple File System (APFS) parser implemented in Rust.
//!
//! [APFS](https://en.wikipedia.org/wiki/Apple_File_System) is the default file
//! system on Apple platforms (macOS, iOS, iPadOS, watchOS, tvOS), and the
//! successor to HFS Plus. Unlike NTFS, FAT, or ext, an APFS *container* is a
//! space-management pool that can hold multiple *volumes*. It is copy-on-write,
//! organizes file-system records in B-trees, and supports snapshots, cloning,
//! per-file encryption, and sealed (integrity-verified) volumes.
//!
//! This crate is `no_std`-compatible (with `alloc`) and forbids `unsafe` code,
//! so it is usable from firmware-level code up to user-mode applications.
//!
//! # Status
//!
//! The core parser is implemented and tested: this crate mounts containers,
//! selects the latest valid checkpoint, resolves virtual objects through
//! object maps, walks the catalog B-tree, and reads file content. The
//! on-disk format reference lives in
//! [`docs/`](https://github.com/DataRelicForensics/tracium/tree/master/crates/fs-apfs/docs).
//!
//! Most APIs are parser primitives verified against synthetic on-disk
//! structures; real-image integration tests are fixture-gated (see
//! `tests/fixture.rs` and `testdata/README.md`) and skip when no fixture is
//! present. A capability that depends on data this crate cannot synthesize
//! end to end is marked *partial* below.
//!
//! ## Capability matrix
//!
//! | Capability | Status |
//! |------------|--------|
//! | Container mount, checkpoints, object maps | implemented |
//! | Checkpoint descriptor areas stored as B-trees | implemented |
//! | Volumes, B-trees, catalog, inodes, extents | implemented |
//! | Directory enumeration; Unicode-aware name lookup | implemented |
//! | Extended attributes, extended fields, siblings, clones | implemented |
//! | Snapshots and read-only snapshot volume views | implemented |
//! | Space manager — single- and two-level CAB layouts, free extents | implemented |
//! | Sealed-volume integrity metadata and verification | implemented |
//! | Reaper, Fusion address resolution, keybag parsing | implemented |
//! | Encryption-rolling state, deleted-file recovery | implemented |
//! | `decmpfs` zlib compression | partial — [#227] (LZVN/LZFSE: [#281]) |
//! | `FileVault` key hierarchy and AES-XTS decryption | partial — [#235] |
//! | Encryption-rolling state v1 layout | open — [#279] |
//! | Keybag object-subtype decoding | open — [#280] |
//! | On-disk mutation / write paths | unsupported by design — read-only parser |
//! | Hardware-bound keys (T2 / Secure Enclave) | unsupported — not derivable offline |
//!
//! [#227]: https://github.com/DataRelicForensics/tracium/issues/227
//! [#235]: https://github.com/DataRelicForensics/tracium/issues/235
//! [#279]: https://github.com/DataRelicForensics/tracium/issues/279
//! [#280]: https://github.com/DataRelicForensics/tracium/issues/280
//! [#281]: https://github.com/DataRelicForensics/tracium/issues/281
//!
//! # On-disk layers
//!
//! APFS is split into two layers, reflected in the type-name prefixes used
//! throughout the format:
//!
//! - **Container layer** (`nx_` prefix) — organizes physical space, holds the
//!   container superblock, checkpoints, the space manager, and volume metadata.
//! - **File-system layer** (`j_` prefix) — directory structure, inodes, file
//!   metadata, and file content, stored as key/value records in B-trees.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod apfs;
pub mod btree;
pub mod catalog;
pub mod checkpoint;
pub mod checksum;
pub mod clones;
pub mod container;
pub mod directory;
pub mod efi;
pub mod enc_rolling;
pub mod error;
pub mod extended_field;
pub mod extent;
pub mod fext;
pub mod forensic;
pub mod fusion;
pub mod inode;
pub mod keybag;
pub mod object;
pub mod omap;
pub mod reaper;
pub mod recovery;
pub mod sealed;
pub mod sibling;
pub mod snapshot;
pub mod space_manager;
pub mod time;
pub mod traverse;
pub mod types;
pub mod unicode;
pub mod volume;
pub mod xattr;

pub use apfs::Apfs;
pub use btree::{BtnodeFlags, BtreeFlags, BtreeInfo, BtreeNode, Entry, descend, descend_le};
pub use catalog::{Catalog, CatalogRecord, JKey, JObjType};
pub use checkpoint::{Checkpoint, CheckpointMapPhys, CheckpointMapping, latest_checkpoint};
pub use clones::{ClassifiedExtent, ExtentRefs, JObjKind, PhysicalExtent, classify_extents};
pub use container::{CheckpointArea, NxFeatures, NxFlags, NxIncompatFeatures, NxSuperblock};
pub use directory::{DirEntry, DirEntryType, Directory, NameComparison};
pub use efi::{APFS_GPT_PARTITION_UUID, EfiJumpstart, is_apfs_container};
pub use enc_rolling::{ErPhase, ErRecoveryBlock, ErState, ErStateFlags, GeneralBitmap};
pub use error::{ApfsError, Result};
pub use extended_field::{ExtendedFields, XField, XfFlags};
pub use extent::{DataStream, File, FileExtent};
pub use fext::FextTree;
pub use forensic::{CloneSet, TimelineEvent, TimestampKind, build_clone_map, build_timeline};
pub use fsmnt_parser_core::io;
pub use fusion::{
    FusionAddress, FusionCache, FusionMtVal, FusionReader, FusionWbc, FusionWbcList, decode_address,
};
pub use inode::{FileType, Inode, InodeFlags};
pub use keybag::{Keybag, KeybagEntry, KeybagTag, ProtectionClass};
pub use object::{ObjPhys, StorageClass};
pub use omap::{Omap, OmapFlags, OmapSnapshotFlags, OmapValFlags, OmapValue};
pub use reaper::{ReapList, ReapListEntry, ReapPhase, Reaper, ReaperFlags};
pub use recovery::{
    DeletedFile, OrphanedNode, Provenance, RecoveredObject, diff_snapshot, group_orphans,
    read_deleted_content, scan_unallocated,
};
pub use sealed::{
    ApfsHashType, FileDataHash, HashMismatch, IntegrityMeta, IntegrityMetaFlags, SealReport,
    SealVerification, verify_file_hashes,
};
pub use sibling::{SiblingLink, resolve_sibling};
pub use snapshot::{SnapMetaExt, SnapMetaFlags, Snapshot, snapshot_xid_by_name};
pub use space_manager::{FreeExtent, SpaceManager, SpacemanDevice};
pub use time::ApfsTimestamp;
pub use traverse::{ApfsDir, ApfsTraversalEntry, Volume};
pub use types::{ObjectType, Oid, Paddr, Prange, Uuid, Xid};
pub use unicode::{name_hash, normalize_fold};
pub use volume::{ApfsFeatures, ApfsFsFlags, ApfsIncompatFeatures, ApfsSuperblock, VolumeRole};
pub use xattr::{Xattr, XattrFlags, XattrValue};
