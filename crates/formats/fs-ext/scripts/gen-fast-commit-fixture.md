# Fast-Commit Fixture Generation

> **Status:** Best-effort manual procedure. Not part of the merge
> contract. CI does not invoke this script, and tests skip cleanly
> when the resulting fixture is absent.

## Goal

Produce `crates/fs-ext/testdata/ext4-dirty-fast-commit.img` -- an ext4
filesystem image with crash-induced fast-commit state that real Linux
kernel replay would reconstruct.

## Prerequisites

- Linux VM (host or guest) with kernel 5.10+ and e2fsprogs 1.46.0+
- `mkfs.ext4`, `losetup`, root privileges

## Procedure

1. Create a sparse image:

   ```bash
   dd if=/dev/zero of=ext4-dirty-fast-commit.img bs=1M count=8 conv=sparse
   ```

2. Format with fast-commit:

   ```bash
   mkfs.ext4 -O fast_commit -b 4096 -t ext4 -F ext4-dirty-fast-commit.img
   ```

3. Mount with async-commit so fast-commits can fire without forcing a
   full journal commit:

   ```bash
   LOOP=$(sudo losetup --show -f ext4-dirty-fast-commit.img)
   sudo mkdir -p /mnt/fcfix
   sudo mount -o journal_async_commit "$LOOP" /mnt/fcfix
   ```

4. Apply operations whose effects you want captured in fast-commit
   records:

   ```bash
   sudo touch /mnt/fcfix/created-via-fc.txt
   sudo dd if=/dev/urandom of=/mnt/fcfix/extended-via-fc.bin bs=4096 count=4
   sudo chmod 600 /mnt/fcfix/created-via-fc.txt
   ```

   Force a fast-commit before the next full-journal commit. The most
   reliable trigger is a kernel debugfs path; alternatively
   `sync_file_range` with `SYNC_FILE_RANGE_WRITE` on a touched file.

5. Crash induction (no clean unmount):

   ```bash
   # Option A: host-side hard reset of the loop device while data is
   # in flight.
   # Option B: For VM testing, force-power off the guest with ops in
   # flight.
   # Option C: If you explicitly created a device-mapper layer, suspend
   # or remove that known mapper target to drop in-flight writes.
   sudo umount -f /mnt/fcfix || true
   sudo losetup -d "$LOOP" || true
   ```

6. Validate the fixture:

   ```bash
   # The image must NOT cleanly unmount; classic e2fsck should detect
   # journal-needed state.
   e2fsck -nf ext4-dirty-fast-commit.img && \
       echo "WARN: fixture appears clean; crash induction may not have worked"
   ```

7. Move the fixture into place:

   ```bash
   mv ext4-dirty-fast-commit.img \
      $(git rev-parse --show-toplevel)/crates/fs-ext/testdata/
   ```

## Determinism caveats

- Different kernel/e2fsprogs versions emit different FC record
  sequences for the same operations. Pin the VM to a known
  kernel + e2fsprogs combination if you want reproducible fixtures.
- This procedure is fragile by nature (crash induction is not a
  well-defined API). Expect iteration. If the resulting image cleanly
  mounts, the crash did not capture FC state; repeat steps 3-6.

## When to regenerate

- When upgrading the supported kernel range.
- When adding tests that exercise specific FC record-type combinations
  not yet in the fixture.
- **NOT** as part of every PR. The fixture is checkpoint-frozen.
