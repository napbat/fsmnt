fn test_usize_from_u32(value: u32) -> usize {
    usize::try_from(value).expect("test value fits usize")
}

fn test_u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).expect("test value fits u64")
}

include!("part_01.rs");
include!("part_02.rs");
include!("part_03.rs");
include!("part_04.rs");
include!("part_05.rs");
include!("part_06.rs");
include!("part_07.rs");
