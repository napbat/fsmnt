//! Benchmarks for logical-to-physical APFS extent lookup.

use divan::{AllocProfiler, Bencher, black_box};
use fs_apfs::{File, FileExtent};
use fsmnt_testkit::Cursor;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench(args = [1, 64, 1024, 16384])]
fn read_last_fragment(bencher: Bencher, extent_count: usize) {
    let extents = (0..extent_count)
        .map(|index| FileExtent {
            logical_addr: u64::try_from(index).expect("benchmark index fits u64") * 2,
            length: 1,
            phys_block_num: 0,
            crypto_id: 0,
        })
        .collect();
    let size = u64::try_from(extent_count).expect("benchmark extent count fits u64") * 2;
    let file = File::from_extents(size, extents);
    let offset = size - 2;
    let mut reader = Cursor::new([0x5a_u8]);
    let mut output = [0_u8; 1];

    bencher.bench_local(|| {
        let read = file
            .read_at(&mut reader, 1, offset, &mut output)
            .expect("synthetic extent read succeeds");
        black_box((read, output));
    });
}
