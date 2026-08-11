use super::super::{ChunkMapping, ChunkStripe, Result, TYPE_DATA};

pub(super) fn stripe(device_id: u64, offset: u64) -> ChunkStripe {
    ChunkStripe {
        device_id,
        offset,
        device_uuid: [0_u8; 16],
    }
}

pub(super) fn mapping(flags: u64, sub_stripes: u16, stripes: Vec<ChunkStripe>) -> ChunkMapping {
    ChunkMapping {
        logical: 0x10_0000,
        length: 0x40_0000,
        stripe_length: 0x1_0000,
        flags: flags | TYPE_DATA,
        sub_stripes,
        stripes,
    }
}

pub(super) fn validate(mapping: &ChunkMapping) -> Result<()> {
    mapping.validate(4096, 0, 4096)
}
