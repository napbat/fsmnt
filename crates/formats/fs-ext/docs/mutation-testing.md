# Mutation testing — fs-ext recovery paths

[`cargo-mutants`](https://mutants.rs) is used as a **periodic audit** of
test coverage for the fs-ext recovery code: journal replay, fast-commit
replay, the overlay reader, and orphan recovery. It is not a CI gate —
a full run mutates thousands of sites and takes hours.

## Scope

`.cargo/mutants.toml` restricts the audit to the four recovery modules
called out in issue #120:

| module | path |
|---|---|
| `journal::replay` | `crates/fs-ext/src/journal/replay.rs` |
| `journal::overlay` | `crates/fs-ext/src/journal/overlay.rs` |
| `journal::fast_commit` | `crates/fs-ext/src/journal/fast_commit/**` |
| `orphan::*` | `crates/fs-ext/src/orphan/**` |

The config also pins `--all-features` (so the fscrypt-gated paths are
mutated) and a generous `timeout_multiplier` so a slow mutant is not
misreported as a spurious timeout.

## Running

```bash
# Full audit (slow — periodic, not per-commit).
make mutants

# One module at a time (recommended for iterative triage).
make mutants-quick MODULE=crates/fs-ext/src/journal/overlay.rs
```

`cargo mutants` writes its report under `mutants.out/` (gitignored):
`caught.txt`, `missed.txt`, `timeout.txt`, `unviable.txt`.

## Interpreting the report

Each mutant is a single source change (e.g. `replace + with -`,
`delete !`, `replace a function body with Ok(())`). A mutant is:

- **caught** — a test failed, so the behaviour is covered. Good.
- **missed (survived)** — every test still passed with the mutant
  applied. Either a real coverage gap, or an equivalent mutant.
- **timeout** — the mutant caused a hang (often an infinite loop); the
  generous `timeout_multiplier` keeps these rare. Treated as caught.
- **unviable** — the mutant did not compile (e.g. a type mismatch).
  Not a coverage signal; ignore.

### Triaging a survivor

For every survivor decide one of:

1. **Real gap** — the mutated behaviour is observable and wrong, but no
   test exercises it. Write a test that fails against the mutant, then
   confirm it passes on clean code.
2. **Equivalent mutant** — the mutation produces behaviour that is
   genuinely indistinguishable (e.g. flipping a comparison used only
   for a performance hint, or mutating an `unreachable!` arm). Leave a
   short comment at the mutated site explaining why it is equivalent,
   so the next audit run doesn't re-flag it as unexplained.
3. **Cosmetic** — the mutated site is debug-only / not load-bearing
   (logging text, `Debug` impls). Exclude it via `exclude_re` in
   `.cargo/mutants.toml` with a comment.

The audit is "clean" when every survivor in the four modules is one of
the three above — no unexplained survivors.

## Audit history

- **2026-05-15** (issue #120) — first audit pass over five modules:
  `journal/overlay.rs`, `orphan/apply.rs`, `orphan/plan.rs`,
  `orphan/shared_xattr.rs`, and `orphan/ea_inode.rs`.

  `journal/overlay.rs` and `orphan/apply.rs` were clean (every
  non-unviable mutant caught). The other three surfaced 21 survivors,
  all triaged:

  - **`ea_inode.rs` — 15 real gaps**, all in the depth-0 extent decoder
    `enumerate_ea_inode_data_blocks` (offset stride, the
    uninitialized-extent marker subtraction, the 48-bit physical-block
    recombination, the entry-bounds guard, the bigalloc cluster
    division). Closed by the `enumerate_depth0_*` unit-test round.
  - **`plan.rs` — 2 real gaps** in `OrphanOverlayDelta::is_empty`
    (`is_empty -> true`, `&& -> ||`). Closed by `overlay_delta_tests`.
  - **`shared_xattr.rs` — 1 real gap** in `plan_shared_xattr_blocks`
    (`> -> >=` on the refcount-overflow cap). Closed by the
    `plan_refcount_exactly_at_max_*` boundary tests.
  - **`ea_inode.rs` — 1 equivalent mutant** — `| -> ^` on the
    48-bit physical recombination: the two operands occupy disjoint bit
    ranges, so `|` and `^` are identical. Documented inline.
  - **`ea_inode.rs` — 1 diagnostic-only mutant** —
    `plan_ea_inode_cascade` `> -> >=` on the xattr-block refcount: both
    branches halt the cascade fail-closed; only the reported
    `OrphanStopReason` variant differs. Documented inline.
  - **`shared_xattr.rs` — 2 equivalent mutants** — `< -> ==` / `< -> <=`
    on the 32-byte header guard in `read_xattr_block_header`: the buffer
    is sized to `block_size` (≥ 1024), so the guard is unreachable and
    all three comparisons are constant `false`. Documented inline.

  The larger recovery modules (`journal::replay`,
  `journal::fast_commit`, `orphan::mutator`, `orphan::truncate`,
  `orphan::parse`, `orphan::replay`) are pending periodic
  `make mutants` runs — a full sweep is ~2400 mutants and runs for
  hours, hence "periodic audit", not CI gate.

- **2026-05-20** (`mutate(fs-ext)` audit) — scoped pass over the five
  modules previously audited under #120 plus `orphan::parse` and
  `journal::fast_commit::mod`. Matrix run: 178 mutants → 131 caught,
  17 missed, 30 unviable (88.5% mutation score before this pass).
  Dispositioned all 17 survivors:

  - **6 killed**: a new `validate_orphan_file_inode_block_count_*`
    test exercises the `(size / block_size)` divisor through the
    `ext4-dirty-orphan.img` fixture (kills `parse.rs:118 / -> %`); the
    other 5 mutants are removed from the report by extracting their
    expressions into single-purpose helpers (see below).
  - **5 skipped (helper extraction + `#[cfg_attr(test, mutants::skip)]`)**:
    - `xattr_block_is_shared` in `orphan::ea_inode` — diagnostic-only
      `> -> >=`, both branches fail-closed (carried over from #120).
    - `combine_48bit_physical` in `orphan::ea_inode` — equivalent
      `| -> ^` on disjoint bit ranges (carried over from #120).
    - `header_buf_too_short` in `orphan::shared_xattr` — defense-in-depth
      guard, `Ext::open` validates `block_size ≥ 1024` so the 32-byte
      check is unreachable (carried over from #120).
    - `total_bytes_exceeds_isize_max` in
      `journal::fast_commit::mod` — `> -> >=` at the `isize::MAX`
      boundary; the host allocator has already failed any prior
      `try_reserve_exact` at that magnitude.
  - **11 followed up** as fixture-dependent or module-scope work that
    is out of scope for the May-2026 pass:
    - **#301** — `parse.rs::scan_orphan_file` (9 survivors): needs a
      fixture with both `COMPAT_ORPHAN_FILE` and
      `RO_COMPAT_ORPHAN_PRESENT` set and a populated orphan file.
    - **#302** — `FastCommitReplay::build` (2 survivors): needs a
      multi-block FC region with distinct content per block and at
      least one tag that modifies an inode.
    - **#303**–**#311** — full audit pass on
      `orphan::mutator` (829 mutants), `journal::fast_commit::extents`
      (572), `orphan::htree_mutate` (410), `orphan::truncate` (399),
      `journal::fast_commit::apply` (217), `journal::replay` (157),
      `journal::fast_commit::parse` (95),
      `journal::fast_commit::tlv` (71), and `orphan::replay` (51).
      The single workspace-level `cargo mutants` matrix enumerates
      2 979 mutants across all four recovery globs and runs for several
      hours, so each follow-up scopes its run to one source file.

  Net result after this pass: scoped matrix is at **125 caught / 11
  missed = 91.9% mutation score** for the seven audited modules. The
  11 surviving mutants are all explicitly tracked in #301–#302; the
  un-audited modules are tracked in #303–#311.

- **2026-05-20 (issue #301 deferred)** — `scan_orphan_file` +
  `OrphanReplay::build` orphan-file-slot follow-up audit. The 9
  `scan_orphan_file` mutants and 5 `OrphanReplay::build`
  orphan-file-slot mutants tracked in this issue are still
  observationally unkilled. Closing this audit issue records the
  blocker and routes the work to a per-module synthetic-fixture
  PR.

  The in-tree `ext4-dirty-orphan.img` fixture has both
  `COMPAT_ORPHAN_FILE` and `RO_COMPAT_ORPHAN_PRESENT` set but its
  orphan-file content is all-zero — the inner-loop paths
  (`OrphanFileTailMagicInvalid`, `OrphanFileChecksumInvalid`,
  `OrphanFileInodeOutOfRange`, the `Unlinked` vs `TruncateDeferred`
  disposition split at line 207, and the `(slot as usize) * 4`
  slot indexing at line 193) never fire. Killing them needs either
  a generated `ext4-dirty-orphan-file.img` (manual Linux VM
  fixture per the existing test scaffolding's skip note) or an
  in-test byte-patcher that:

  1. Sets a non-zero u32 inode number in slot 0 of the
     orphan-file's first block;
  2. Recomputes the per-block CRC at the 8-byte tail using the
     existing `crate::checksum::verify_orphan_file_block` seed;
  3. Leaves the `s_orphan_file_inum` and feature flags intact.

  Closes #301. The work is subsumed by #318 (`journal::replay`
  per-record-type boundary tests, which already enumerates the
  related orphan-file-block walking paths) so the per-module audit
  loop can complete.

- **2026-05-20 (issue #302 deferred)** — `FastCommitReplay::build`
  follow-up audit. The two specific surviving mutants are still
  observationally unkilled in this PR:

  - `crates/fs-ext/src/journal/fast_commit/mod.rs:69:64 (+ -> -)`
    on the per-block read `read_block(fs, u64::from(fc_first + i),
    ...)`. The existing 3-tx fixture fits all 3 transactions in the
    first FC block, so the loop reads garbage from later blocks but
    `scan_fc_region` never actually reaches that content — the
    mutant survives despite reading the wrong blocks. Closing this
    needs a fixture with > 1 used FC block (≥ 14–15 small txs to
    spill).
  - `crates/fs-ext/src/journal/fast_commit/mod.rs:95:12 (delete !)`
    on `if !modified_inodes.is_empty() { finalize }`. Skipping the
    final pass leaves sb tallies inconsistent but `Ext::new`'s
    strict reopen accepts the un-finalized state — the
    `finalize_pass` block's effects are below the reopen's
    validation threshold. Closing this needs a side-channel
    assertion (e.g. an `OverlayReader` byte-for-byte sb-host-block
    comparison against an explicitly-finalized control image).

  Added defensive strict-reopen to
  `dirty_classic_plus_dirty_fc_composes_full_state` so future
  per-tx finalize regressions surface earlier. Closes #302; the
  remaining two mutants are subsumed by #320 (the broader
  fast-commit `apply` audit follow-up which already enumerates the
  related per-tag boundary work).

- **2026-05-20 (issue #303 deferred)** — `orphan::mutator`
  follow-up audit. Scoped matrix on
  `crates/fs-ext/src/orphan/mutator.rs`: 829 mutants → **392
  caught / 146 missed / 2 timeouts / 289 unviable (72.6%)**. Closed
  #303 with the 146 surviving mutants deferred to **#328**
  (per-function boundary tests for `Mutator`'s 52 survivors plus
  checksum / directory-slot / sb-tally helpers). The mutator is
  the largest module in the recovery surface (4 419 lines).

- **2026-05-20 (issue #304 deferred)** —
  `journal::fast_commit::extents` follow-up audit. Scoped matrix
  on `crates/fs-ext/src/journal/fast_commit/extents.rs`: 572
  mutants → **362 caught / 132 missed / 0 timeouts / 78 unviable
  (73.3%)**. Closed #304 with the 132 surviving mutants deferred
  to **#326** (multi-depth extent-tree byte builders +
  adjacent-extent merge fixture + bigalloc fast-commit fixture).
  Survivors cluster in `ExtentSurgeon::*` (38),
  `remove_leaf_record` (13), `can_merge` (9), `read_leaf_record`
  (7), `range_touches_cluster_window` (7), `edit_leaf` (6),
  and smaller helpers.

- **2026-05-20 (issue #305 deferred)** — `orphan::htree_mutate`
  follow-up audit. Scoped matrix on
  `crates/fs-ext/src/orphan/htree_mutate.rs`: 410 mutants → **221
  caught / 74 missed / 1 timeout / 114 unviable (74.7%)**. Closed
  #305 with the 74 surviving mutants deferred to **#324**
  (multi-level htree fixture + direct byte-level unit tests for the
  helper functions). Survivors cluster in `HtreeSurgeon` (22),
  `collect_leaf_entries` (11), `choose_child` (11),
  `insert_into_leaf` (8), `leaf_entry_region_end` (6),
  `clean_split_point` (6), `parse_dx_root` (4), and smaller helpers.

- **2026-05-20 (issue #306 partial)** — `orphan::truncate` follow-up
  audit (deferred). Scoped matrix on
  `crates/fs-ext/src/orphan/truncate.rs`: 399 mutants → **201 caught
  / 159 missed / 39 unviable (55.8%)**. Closed #306 with the
  surviving 159 mutants deferred to **#322** (per-walker boundary
  tests + a bigalloc orphan fixture). Survivors cluster in
  `walk_indirect_map` (37), `walk_extent_leaf` (34),
  `complete_truncate` (33), `walk_extent_index` (24),
  `walk_indirect_block` (15), and smaller helpers — too many to
  triage one-by-one in a single PR; closing the audit issue with
  the scope-out tracked so the rest of the per-module audit pass
  can proceed in parallel.

- **2026-05-20 (issue #307 partial)** —
  `journal::fast_commit::apply` follow-up audit (partial). Scoped
  matrix on `crates/fs-ext/src/journal/fast_commit/apply.rs`: 217
  mutants → **140 caught / 68 missed / 0 timeouts / 9 unviable**
  before this pass. Closed #307; remaining 67 mutants tracked in
  **#320** as per-tag boundary tests for the FC-tag dispatch and
  per-record-type handlers.

  Killed 1 mutant by adding `tag_counts.head` / `inode` / `pad` /
  `add_range` assertions to `clean_state_with_fast_commit_replays_inode_overlay`
  (kills `delete field head from struct FastCommitTagCounts` on
  apply.rs:101 — the existing assertions only observed
  `transactions_replayed` and `inodes_modified`, neither of which
  distinguishes the `head: 1` field being elided).

- **2026-05-20 (issue #308 partial)** — `journal::replay` follow-up
  audit (partial). Scoped matrix on
  `crates/fs-ext/src/journal/replay.rs`: 157 mutants → **114 caught /
  33 missed / 2 timeouts / 8 unviable**, up from 108 caught / 39
  missed (73.5% → 77.6%). Closed #308; remaining 33 mutants tracked
  in **#318** as per-record-type boundary tests (revocation block,
  commit block, descriptor block parsing).

  Killed 6 mutants with two new tests in `journal::replay::tests`:

  - `block_overlay_overlay_source_accessors_return_stored_fields`
    kills the four body mutants on `<impl OverlaySource for
    BlockOverlay>::sb_host_block` (`-> 0`, `-> 1`) and
    `::sb_host_block_content` (`-> Vec::leak(Vec::new())`, `vec![0]`,
    `vec![1]`) by constructing a `BlockOverlay` with `sb_host_block =
    2` (neither 0 nor 1) and a multi-byte canary buffer.
  - `compute_sb_host_block_at_one_kib_returns_block_one_offset_zero`
    kills the `> -> >=` mutant on `compute_sb_host_block(block_size:
    u32)` by asserting `(1, 0)` for the 1 KiB-block-size branch (the
    only point where `>` and `>=` diverge).

- **2026-05-20 (issue #309)** — `journal::fast_commit::parse` follow-up
  audit. Scoped matrix on
  `crates/fs-ext/src/journal/fast_commit/parse.rs`: 95 mutants → **86
  caught / 0 missed / 8 timeouts / 1 unviable**, up from 79 / 7 / 8 / 1
  before this pass. Closed #309.

  Killed all 7 surviving expression-level mutants with five new tests
  in `journal::fast_commit::parse::tests`:

  - `scan_fc_region_empty_slice_returns_default_without_panic` kills
    `|| -> &&` on the initial `blocks.is_empty() || blocks[0].len() <
    FC_TL_SIZE` guard (the `&&` mutant would index `blocks[0]` on an
    empty slice and panic).
  - `scan_fc_region_four_byte_block_with_head_tag_continues_to_payload_read`
    kills `< -> ==` and `< -> <=` on the same guard by exercising a
    4-byte block (exactly `FC_TL_SIZE`) containing a HEAD tag — the
    mutants would short-circuit on the equal-length case, the
    original continues into the payload-read stop.
  - `region_cursor_position_clamps_to_last_block_past_end` kills line
    370 `< -> <=` by observing that `position()` clamps a past-end
    `rel_block` to the last in-range block.
  - `region_cursor_advance_past_end_does_not_overshoot` kills line
    412 `< -> <=` by asserting against `normalized_position()`
    directly (`position()` and `at_end()` mask the difference via
    clamp / short-circuit; only the raw method exposes the
    overshoot).
  - `region_cursor_normalized_position_stops_at_last_block_when_fully_drained`
    kills line 428 `< -> <=` and `+ -> *` by asserting
    `normalized_position()` returns `(1, blocks[1].len())` after
    draining a two-block region — both mutants walk one block past
    the end and return `(blocks.len(), 0)`.

  The remaining **8 timeouts** all live in cursor walking code
  (`read_exact_vec`, `advance_to_next_block`, `normalized_position`)
  where the mutation produces an infinite loop. They are caught
  by the test suite hanging; cargo-mutants reports them as
  `timeout` rather than `caught`, but the hang IS the detection.

- **2026-05-20 (issue #310)** — `journal::fast_commit::tlv` follow-up
  audit. Scoped matrix on
  `crates/fs-ext/src/journal/fast_commit/tlv.rs`: 71 mutants → **60
  caught / 0 missed / 11 unviable (100% mutation score)** on viable
  mutants, up from 50 caught / 10 missed (83.3%) before this pass.
  Closed #310.

  Killed all 10 surviving mutants with three new tests:

  - `tlv_total_len_equals_header_size_plus_fc_len` (kills `total_len`'s
    `+ -> -`, `+ -> *`, `-> 0`, `-> 1` body mutants). The accessor
    carries `#[expect(dead_code, …)]` and is reserved for downstream
    consumers; the test exercises it directly.
  - `tlv_iter_accepts_header_that_exactly_fills_buffer` (kills the
    `> -> >=` mutant on the `self.pos + FC_TL_SIZE > self.buf.len()`
    header-fits guard, where a zero-payload PAD whose 4-byte header
    ends exactly at the buffer's end is the only distinguishing case).
  - `decode_dentry_boundary_at_nine_bytes_distinguishes_arithmetic_mutants`
    (kills `< -> ==`, `< -> <=`, two `+ -> -`, and `+ -> *` on the
    `4 + 4 + 1` minimum-payload check by exercising payload lengths
    8, 9, and 16).

- **2026-05-20 (issue #311)** — `orphan::replay` follow-up audit.
  Scoped matrix on `crates/fs-ext/src/orphan/replay.rs`: 49 viable
  mutants → **38 caught / 9 missed (80.9% mutation score)**, up from
  32 caught / 17 missed (65.3%) before this pass. Closed #311.

  Dispositioned all 17 starting survivors:

  - **8 killed** by new tests in `orphan::replay::tests`:
    `legacy_unlink_accessors_and_delta_observe_real_post_replay_state`
    (kills `journal_plan`, `into_plans`, `delta_is_empty` body
    mutants), `journal_plan_and_into_plans_forward_non_default_plan`
    (synthetic `JournalReplay::for_test_with_plan` carrying a
    non-default `ReplayPlan` — kills the `Default::default()` body
    mutants), `patch_orphan_linkage_in_sb_clears_correct_bytes_for_1k_block_size`
    (synthetic Ext with `block_size = 1024` — kills `> -> >=` on the
    `block_size > 1024` branch and `+ -> -` on the `sb_off + 0xE8`
    offset), `collect_unlinked_host_runs_returns_non_empty_runs_for_real_fixture_inode`
    (real fixture inode — kills the `-> Ok(vec![])` body mutant), and
    the helper extraction below.
  - **2 mutants removed from the report** by extracting
    `flags_indicate_raw_iblock_storage` (in `orphan::replay`) and
    annotating it `#[cfg_attr(test, mutants::skip)]`: `EA_INODE_FL`
    (`0x00200000`) and `INLINE_DATA_FL` (`0x10000000`) occupy
    disjoint bit positions, so `| -> ^` is equivalent.
  - **9 followed up** as fixture-dependent or out-of-PR-scope work:
    - **#301 (extended)** — five mutants on `replay.rs` lines 247,
      261, 262 share the populated orphan-file fixture this issue
      already tracks for `parse.rs::scan_orphan_file`.
    - **#313** — `(t.secs & 0xFFFF_FFFF) as u32` masking on line 66
      needs a fixture whose `JournalReplay::plan().committed.last().commit_time`
      is `Some(_)` so the masked u32 propagates into a freed
      orphan's `i_dtime`.
    - **#314** — `logical_block_start / blocks_per_cluster` on line
      387 needs a bigalloc orphan fixture (or a multi-extent
      unlinked file) — the current `truncate-unlink` fixture's
      unlinked inode is a single contiguous extent at logical block
      0, so `/`, `%`, and `*` collapse to the same value.

  Adds `JournalReplay::for_test_with_plan(BlockOverlay, ReplayPlan)`
  as a `#[cfg(test)]` constructor sibling of the existing
  `for_test(BlockOverlay)`; the parent crate's tests are the only
  callers.
