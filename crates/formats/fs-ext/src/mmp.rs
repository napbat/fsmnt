//! Multi-mount protection (MMP) block parsing and verification.
//!
//! When `INCOMPAT_MMP` is set, the filesystem reserves one block (located
//! at `s_mmp_block`) for the MMP record. The kernel updates it
//! periodically while mounted. This module reads the block, classifies
//! the sequence state, and verifies the on-disk checksum when
//! METADATA_CSUM is enabled.
//!
//! `fs-ext` is read-only — this is reporting, not enforcement.

use zerocopy::byteorder::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::checksum::{self, ChecksumState};
use crate::error::{ExtError, Result};

/// MMP magic value (`fs/ext4/ext4.h:2649`, ASCII "MMP\0" LE).
pub(crate) const MMP_MAGIC: u32 = 0x004D_4D50;

/// `mmp_seq` sentinel: clean unmount (`fs/ext4/ext4.h:2650`).
pub(crate) const MMP_SEQ_CLEAN: u32 = 0xFF4D_4D50;
/// `mmp_seq` sentinel: being fscked (`fs/ext4/ext4.h:2651`).
pub(crate) const MMP_SEQ_FSCK: u32 = 0xE24D_4D50;
/// Maximum valid active `mmp_seq` (`fs/ext4/ext4.h:2652`).
pub(crate) const MMP_SEQ_MAX: u32 = 0xE24D_4D4F;

/// On-disk MMP block (`struct mmp_struct`, exactly 1024 bytes).
///
/// Mirrors `fs/ext4/ext4.h:2654-2680`.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawMmpBlock {
    /// 0x000: MMP magic (must be `MMP_MAGIC`).
    pub mmp_magic: U32<LE>,
    /// 0x004: Sequence number, periodically incremented; `MMP_SEQ_CLEAN`
    /// when clean, `MMP_SEQ_FSCK` when fscking.
    pub mmp_seq: U32<LE>,
    /// 0x008: Time of last update (unix seconds, 64-bit).
    pub mmp_time: U64<LE>,
    /// 0x010: Node name (`utsname.nodename`) of the last updater.
    /// Fixed 64-byte buffer, may not be NUL-terminated.
    pub mmp_nodename: [u8; 64],
    /// 0x050: Block-device name of the last updater. 32 bytes, may not
    /// be NUL-terminated.
    pub mmp_bdevname: [u8; 32],
    /// 0x070: MMP check interval in seconds.
    pub mmp_check_interval: U16<LE>,
    /// 0x072: Padding.
    pub mmp_pad1: U16<LE>,
    /// 0x074..0x3FC: 226 × u32 padding to fill the block.
    pub mmp_pad2: [u8; 904],
    /// 0x3FC: CRC32C of `[s_csum_seed || mmp_struct_bytes[0..0x3FC]]`.
    pub mmp_checksum: U32<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawMmpBlock>() == 1024,
    "RawMmpBlock must be exactly 1024 bytes"
);

/// Classified MMP sequence state.
///
/// Mirrors `fs/ext4/ext4.h:2650-2652` plus an `Unknown` catch-all for
/// any other (typically zero or stale) value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtMmpSeqState {
    /// `mmp_seq == EXT4_MMP_SEQ_CLEAN` — last unmount was clean.
    Clean,
    /// `mmp_seq == EXT4_MMP_SEQ_FSCK` — being checked.
    Fsck,
    /// `1 <= mmp_seq <= EXT4_MMP_SEQ_MAX` — actively updated by a
    /// running kernel; the wrapped value is the raw counter.
    Active(u32),
    /// Any other value (commonly zero on a freshly-formatted MMP block).
    Unknown(u32),
}

impl ExtMmpSeqState {
    pub(crate) fn from_raw(seq: u32) -> Self {
        match seq {
            MMP_SEQ_CLEAN => Self::Clean,
            MMP_SEQ_FSCK => Self::Fsck,
            v if v != 0 && v <= MMP_SEQ_MAX => Self::Active(v),
            v => Self::Unknown(v),
        }
    }
}

/// Parsed MMP block.
#[derive(Debug, Clone)]
pub struct ExtMmpBlock {
    /// Classified `mmp_seq` state.
    pub seq_state: ExtMmpSeqState,
    /// `mmp_time` — unix seconds of last update.
    pub time_seconds: u64,
    /// Raw 64-byte `mmp_nodename` (NUL-padded, not guaranteed terminated).
    pub nodename: [u8; 64],
    /// Raw 32-byte `mmp_bdevname` (NUL-padded, not guaranteed terminated).
    pub bdevname: [u8; 32],
    /// MMP poll interval in seconds.
    pub check_interval: u16,
    /// Checksum validation state. `Unknown` when METADATA_CSUM is
    /// disabled; `Valid` / `Invalid` otherwise.
    pub checksum: ChecksumState,
}

/// Compute the kernel MMP checksum: `crc32c(s_csum_seed, mmp[..0x3FC])`.
///
/// Mirrors `fs/ext4/mmp.c::ext4_mmp_csum` (the offset is
/// `offsetof(struct mmp_struct, mmp_checksum)` which is `0x3FC`).
fn compute_mmp_checksum(block_bytes: &[u8; 1024], csum_seed: u32) -> u32 {
    let offset_to_checksum = 0x3FC;
    checksum::ext4_crc32c(csum_seed, &block_bytes[..offset_to_checksum])
}

/// Parse and verify an MMP block from raw bytes.
///
/// Returns `InvalidMmpBlock` on bad magic. Checksum is verified when
/// `csum_seed` is `Some`; when `None`, `checksum` is `Unknown`.
pub(crate) fn parse_mmp_block(
    block_bytes: &[u8; 1024],
    csum_seed: Option<u32>,
) -> Result<ExtMmpBlock> {
    let raw = RawMmpBlock::ref_from_bytes(block_bytes).map_err(|_| ExtError::InvalidMmpBlock {
        reason: "block size mismatch",
    })?;
    if raw.mmp_magic.get() != MMP_MAGIC {
        return Err(ExtError::InvalidMmpBlock {
            reason: "bad MMP magic",
        });
    }

    let checksum = match csum_seed {
        Some(seed) => {
            let computed = compute_mmp_checksum(block_bytes, seed);
            if computed == raw.mmp_checksum.get() {
                ChecksumState::Valid
            } else {
                ChecksumState::Invalid
            }
        }
        None => ChecksumState::Unknown,
    };

    Ok(ExtMmpBlock {
        seq_state: ExtMmpSeqState::from_raw(raw.mmp_seq.get()),
        time_seconds: raw.mmp_time.get(),
        nodename: raw.mmp_nodename,
        bdevname: raw.mmp_bdevname,
        check_interval: raw.mmp_check_interval.get(),
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_block(seq: u32, time: u64, magic: u32) -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        buf[0..4].copy_from_slice(&magic.to_le_bytes());
        buf[4..8].copy_from_slice(&seq.to_le_bytes());
        buf[8..16].copy_from_slice(&time.to_le_bytes());
        buf[0x10..0x14].copy_from_slice(b"host"); // nodename prefix
        buf[0x50..0x54].copy_from_slice(b"sda1"); // bdevname prefix
        buf[0x70..0x72].copy_from_slice(&60u16.to_le_bytes()); // check_interval
        buf
    }

    #[test]
    fn mmp_seq_state_classification() {
        assert_eq!(
            ExtMmpSeqState::from_raw(MMP_SEQ_CLEAN),
            ExtMmpSeqState::Clean
        );
        assert_eq!(ExtMmpSeqState::from_raw(MMP_SEQ_FSCK), ExtMmpSeqState::Fsck);
        assert_eq!(ExtMmpSeqState::from_raw(1), ExtMmpSeqState::Active(1));
        assert_eq!(
            ExtMmpSeqState::from_raw(MMP_SEQ_MAX),
            ExtMmpSeqState::Active(MMP_SEQ_MAX)
        );
        // MMP_SEQ_FSCK is exactly MMP_SEQ_MAX + 1 in the kernel by
        // design, so probe one above FSCK and one below CLEAN to land
        // in the truly-unknown region.
        let above_fsck = MMP_SEQ_FSCK + 1;
        assert_eq!(
            ExtMmpSeqState::from_raw(above_fsck),
            ExtMmpSeqState::Unknown(above_fsck)
        );
        assert_eq!(ExtMmpSeqState::from_raw(0), ExtMmpSeqState::Unknown(0));
    }

    #[test]
    fn parse_clean_block_without_csum() {
        let buf = synthetic_block(MMP_SEQ_CLEAN, 1_700_000_000, MMP_MAGIC);
        let mmp = parse_mmp_block(&buf, None).unwrap();
        assert_eq!(mmp.seq_state, ExtMmpSeqState::Clean);
        assert_eq!(mmp.time_seconds, 1_700_000_000);
        assert_eq!(&mmp.nodename[..4], b"host");
        assert_eq!(&mmp.bdevname[..4], b"sda1");
        assert_eq!(mmp.check_interval, 60);
        assert_eq!(mmp.checksum, ChecksumState::Unknown);
    }

    #[test]
    fn parse_fsck_block() {
        let buf = synthetic_block(MMP_SEQ_FSCK, 42, MMP_MAGIC);
        let mmp = parse_mmp_block(&buf, None).unwrap();
        assert_eq!(mmp.seq_state, ExtMmpSeqState::Fsck);
    }

    #[test]
    fn parse_active_block() {
        let buf = synthetic_block(7, 100, MMP_MAGIC);
        let mmp = parse_mmp_block(&buf, None).unwrap();
        assert_eq!(mmp.seq_state, ExtMmpSeqState::Active(7));
    }

    #[test]
    fn parse_bad_magic_errors() {
        let buf = synthetic_block(MMP_SEQ_CLEAN, 0, 0xDEAD_BEEF);
        let err = parse_mmp_block(&buf, None).unwrap_err();
        match err {
            ExtError::InvalidMmpBlock { reason } => {
                assert_eq!(reason, "bad MMP magic");
            }
            other => panic!("expected InvalidMmpBlock, got {other:?}"),
        }
    }

    #[test]
    fn parse_with_csum_valid_when_planted_correctly() {
        let mut buf = synthetic_block(MMP_SEQ_CLEAN, 1, MMP_MAGIC);
        let seed = 0xCAFE_BABE;
        let csum = compute_mmp_checksum(&buf, seed);
        buf[0x3FC..0x400].copy_from_slice(&csum.to_le_bytes());

        let mmp = parse_mmp_block(&buf, Some(seed)).unwrap();
        assert_eq!(mmp.checksum, ChecksumState::Valid);
    }

    #[test]
    fn parse_with_csum_invalid_when_seed_mismatched() {
        let mut buf = synthetic_block(MMP_SEQ_CLEAN, 1, MMP_MAGIC);
        let seed_planted = 0xCAFE_BABE;
        let csum = compute_mmp_checksum(&buf, seed_planted);
        buf[0x3FC..0x400].copy_from_slice(&csum.to_le_bytes());

        let mmp = parse_mmp_block(&buf, Some(0xDEAD_BEEF)).unwrap();
        assert_eq!(mmp.checksum, ChecksumState::Invalid);
    }

    #[test]
    fn parse_with_csum_invalid_when_block_byte_flipped() {
        let mut buf = synthetic_block(MMP_SEQ_CLEAN, 1, MMP_MAGIC);
        let seed = 0xCAFE_BABE;
        let csum = compute_mmp_checksum(&buf, seed);
        buf[0x3FC..0x400].copy_from_slice(&csum.to_le_bytes());
        // Flip a byte inside the checksummed range.
        buf[0x10] ^= 0x01;

        let mmp = parse_mmp_block(&buf, Some(seed)).unwrap();
        assert_eq!(mmp.checksum, ChecksumState::Invalid);
    }
}
