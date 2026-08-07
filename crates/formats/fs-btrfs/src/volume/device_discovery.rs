//! Device identities discoverable from the chunk tree.

use alloc::vec::Vec;

use super::{BootstrapCandidate, Btrfs, bootstrap_candidates};
use crate::{BtrfsError, Result};
use fsmnt_parser_core::io::{Read, Seek};

/// Identity of one physical member referenced by a Btrfs chunk mapping.
///
/// Btrfs addresses a device by both its numeric device ID and persistent
/// device UUID. The pair remains usable across ordinary multi-device
/// filesystems and seed-device chains whose members have different FSIDs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BtrfsDeviceIdentity {
    device_id: u64,
    device_uuid: [u8; 16],
}

impl BtrfsDeviceIdentity {
    pub(super) const fn new(device_id: u64, device_uuid: [u8; 16]) -> Self {
        Self {
            device_id,
            device_uuid,
        }
    }

    /// Numeric device identifier stored in chunk stripes.
    #[must_use]
    pub const fn device_id(self) -> u64 {
        self.device_id
    }

    /// Persistent device UUID stored in chunk stripes.
    #[must_use]
    pub const fn device_uuid(self) -> [u8; 16] {
        self.device_uuid
    }
}

impl<R: Read + Seek> Btrfs<R> {
    /// Discover every physical member referenced by the filesystem's chunk tree.
    ///
    /// This loads only the system and chunk mappings. It does not require every
    /// member to be present, so callers can use the returned identities to find
    /// ordinary multi-device members and older filesystems in a seed chain.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when no live or backup bootstrap root can provide
    /// a structurally valid chunk tree.
    pub fn discover_device_identities(&mut self) -> Result<Vec<BtrfsDeviceIdentity>> {
        let candidates = bootstrap_candidates(self.superblock());
        let live = BootstrapCandidate::live(self.superblock());
        let mut first_error = None;

        for candidate in candidates {
            self.prepare_bootstrap(candidate);
            match self.load_chunk_mappings(candidate) {
                Ok(()) => {
                    let identities = self.loaded_device_identities();
                    self.prepare_bootstrap(live);
                    return Ok(identities);
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        self.prepare_bootstrap(live);
        Err(first_error.unwrap_or(BtrfsError::IntegerOverflow))
    }

    fn loaded_device_identities(&self) -> Vec<BtrfsDeviceIdentity> {
        let mut identities = Vec::new();
        identities.push(BtrfsDeviceIdentity::new(
            self.primary.superblock.device_id(),
            *self.primary.superblock.device_uuid(),
        ));
        for chunk in &self.chunks {
            for stripe in &chunk.stripes {
                let identity = BtrfsDeviceIdentity::new(stripe.device_id, stripe.device_uuid);
                if !identities.contains(&identity) {
                    identities.push(identity);
                }
            }
        }
        identities.sort_unstable();
        identities
    }
}
