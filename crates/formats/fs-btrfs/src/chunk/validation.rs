//! Chunk-profile geometry validation.

use super::ChunkProfile;

pub(super) fn valid_profile_geometry(
    profile: Option<ChunkProfile>,
    stripe_count: usize,
    sub_stripes: u16,
    exact: bool,
) -> bool {
    match profile {
        Some(ChunkProfile::Single) => stripe_count == 1,
        Some(ChunkProfile::Dup | ChunkProfile::Raid1) => {
            stripe_count >= 2 && (!exact || stripe_count == 2)
        }
        Some(ChunkProfile::Raid0) => stripe_count != 0,
        Some(ChunkProfile::Raid1C3) => stripe_count >= 3 && (!exact || stripe_count == 3),
        Some(ChunkProfile::Raid1C4) => stripe_count >= 4 && (!exact || stripe_count == 4),
        Some(ChunkProfile::Raid5) => stripe_count >= 2,
        Some(ChunkProfile::Raid6) => stripe_count >= 3,
        Some(ChunkProfile::Raid10) => {
            let copies = usize::from(sub_stripes);
            copies == 2 && stripe_count >= copies && stripe_count.is_multiple_of(copies)
        }
        None => false,
    }
}
