//! Physical and operating-system logical volume source modelling.
//!
//! A partition table identifies a physical extent, but that extent can feed
//! zero, one, or several operating-system logical volumes. This module keeps
//! discovery, source selection, and reader ownership separate so platform
//! crates can represent stacked and multi-device storage accurately.
//!
//! Automatic selection opens one unambiguous [`LogicalVolume`] and does not
//! fall back to physical access. Explicit raw selection produces a
//! [`DeviceSet`]. A filesystem-native mapper such as Btrfs consumes that set
//! directly; a storage-volume parser can instead derive a [`RawVolumeLayout`]
//! and call [`assemble_raw_volume`] before opening a single-device
//! filesystem.

mod assembly;
mod device_set;
mod volume;
mod zones;

pub use assembly::{AssembledVolume, RawAssemblyError, RawVolumeLayout, assemble_raw_volume};
pub use device_set::{DeviceMember, DeviceSet, DeviceSetError, SourceMemberId};
pub use volume::{
    HostVolumeResolver, LogicalVolume, LogicalVolumeId, PartitionAddress, PhysicalExtent,
    SourceOrigin, SourceSelection, VolumeSelectionError, select_logical_volume,
};
pub use zones::{BlockZone, BlockZoneCondition, BlockZoneReporter, BlockZoneType};
