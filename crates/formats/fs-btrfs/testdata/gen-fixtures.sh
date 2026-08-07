#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
mkfs_btrfs="${MKFS_BTRFS:-mkfs.btrfs}"
btrfstune_bin="${BTRFSTUNE:-btrfstune}"
loop_one=""
loop_two=""
subvolume_loop=""
raid_mounted=""
raid_loops=()
seed_mounted=""
seed_loops=()
log_loop=""
log_mounted=false
recovery_loop=""
recovery_mounted=false
multi_mounted=false
subvolume_mounted=false
experimental_loop=""
experimental_mounted=false

cleanup() {
    if "${experimental_mounted}"; then
        umount -- "${work_dir}/experimental-mount"
    fi
    if [[ -n "${experimental_loop}" ]] \
        && losetup --list --noheadings "${experimental_loop}" >/dev/null 2>&1; then
        losetup --detach "${experimental_loop}"
    fi
    if "${recovery_mounted}"; then
        umount -- "${work_dir}/recovery-mount"
    fi
    if [[ -n "${recovery_loop}" ]] && losetup --list --noheadings "${recovery_loop}" >/dev/null 2>&1; then
        losetup --detach "${recovery_loop}"
    fi
    if "${log_mounted}"; then
        umount -- "${work_dir}/log-mount"
    fi
    if [[ -n "${log_loop}" ]] && losetup --list --noheadings "${log_loop}" >/dev/null 2>&1; then
        losetup --detach "${log_loop}"
    fi
    if [[ -n "${seed_mounted}" ]] && mountpoint --quiet -- "${seed_mounted}"; then
        umount -- "${seed_mounted}"
    fi
    for loop_device in "${seed_loops[@]}"; do
        if [[ -n "${loop_device}" ]] && losetup --list --noheadings "${loop_device}" >/dev/null 2>&1; then
            losetup --detach "${loop_device}"
        fi
    done
    if [[ -n "${raid_mounted}" ]] && mountpoint --quiet -- "${raid_mounted}"; then
        umount -- "${raid_mounted}"
    fi
    for loop_device in "${raid_loops[@]}"; do
        if [[ -n "${loop_device}" ]] && losetup --list --noheadings "${loop_device}" >/dev/null 2>&1; then
            losetup --detach "${loop_device}"
        fi
    done
    if "${multi_mounted}"; then
        umount -- "${work_dir}/multi-mount"
    fi
    if "${subvolume_mounted}"; then
        umount -- "${work_dir}/subvolume-mount"
    fi
    if [[ -n "${loop_two}" ]]; then
        losetup --detach "${loop_two}"
    fi
    if [[ -n "${loop_one}" ]]; then
        losetup --detach "${loop_one}"
    fi
    if [[ -n "${subvolume_loop}" ]]; then
        losetup --detach "${subvolume_loop}"
    fi
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

write_numbered_lines() {
    local prefix="$1"
    local width="$2"
    local count="$3"
    local destination="$4"

    for number in $(seq 1 "${count}"); do
        printf '%s-%0*d\n' "${prefix}" "${width}" "${number}"
    done > "${destination}"
}

kernel_supports_btrfs_feature() {
    local feature="$1"

    [[ "${EUID}" -eq 0 && -e "/sys/fs/btrfs/features/${feature}" ]]
}

mount_experimental_image() {
    local image="$1"

    mkdir -p -- "${work_dir}/experimental-mount"
    experimental_loop="$(losetup --find --show "${image}")"
    mount -- "${experimental_loop}" "${work_dir}/experimental-mount"
    experimental_mounted=true
}

unmount_experimental_image() {
    umount -- "${work_dir}/experimental-mount"
    experimental_mounted=false
    losetup --detach "${experimental_loop}"
    experimental_loop=""
}

poison_forward_remap_source() {
    local image="$1"
    local remap_range
    local remap_source
    local remap_length
    local source_mapping
    local stripe_physical
    local chunk_logical
    local source_physical

    remap_range="$(
        btrfs inspect-internal dump-tree -t remap "${image}" \
            | awk '
                /key \([0-9]+ REMAP [0-9]+\)/ {
                    source = $4
                    remap_length = $6
                    sub(/^\(/, "", source)
                    sub(/\)$/, "", remap_length)
                    print source, remap_length
                    exit
                }
            '
    )"
    read -r remap_source remap_length <<< "${remap_range}"
    if [[ ! "${remap_source}" =~ ^[0-9]+$ ]] \
        || [[ ! "${remap_length}" =~ ^[0-9]+$ ]]; then
        printf '%s\n' 'balance did not create a valid forward remap' >&2
        return 1
    fi

    source_mapping="$(
        btrfs inspect-internal dump-tree -t chunk "${image}" \
            | awk -v source="${remap_source}" '
                /key \(FIRST_CHUNK_TREE CHUNK_ITEM/ {
                    chunk_logical = $6
                    sub(/\)$/, "", chunk_logical)
                    contains_source = 0
                }
                /^[[:space:]]*length / {
                    chunk_length = $2
                    if ($0 ~ /type DATA([|]|$)/ && source >= chunk_logical && source < chunk_logical + chunk_length) {
                        contains_source = 1
                    }
                }
                /^[[:space:]]*stripe 0 / && contains_source {
                    print $6, chunk_logical
                    exit
                }
            '
    )"
    read -r stripe_physical chunk_logical <<< "${source_mapping}"
    if [[ ! "${stripe_physical}" =~ ^[0-9]+$ ]] \
        || [[ ! "${chunk_logical}" =~ ^[0-9]+$ ]]; then
        printf '%s\n' 'could not locate the remapped source stripe' >&2
        return 1
    fi

    source_physical="$((stripe_physical + remap_source - chunk_logical))"
    if [[ "$((source_physical % 4096))" -ne 0 ]] \
        || [[ "$((remap_length % 4096))" -ne 0 ]]; then
        printf '%s\n' 'remapped source range is not sector aligned' >&2
        return 1
    fi
    dd \
        if=/dev/zero \
        of="${image}" \
        bs=4096 \
        seek="$((source_physical / 4096))" \
        count="$((remap_length / 4096))" \
        conv=notrunc \
        status=none
}

create_raid_stripe_tree_fixture() {
    local fixture_image="${script_dir}/btrfs-raid-stripe-tree.img"
    local working_image="${work_dir}/btrfs-raid-stripe-tree.img"

    if ! kernel_supports_btrfs_feature raid_stripe_tree; then
        printf '%s\n' \
            'skipping populated RAID stripe-tree fixture; an experimental kernel and root are required' \
            >&2
        return
    fi

    truncate -s 536870912 "${working_image}"
    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label fsmnt-btrfs-rst \
        --features raid-stripe-tree \
        --data dup \
        --metadata dup \
        "${working_image}"
    mount_experimental_image "${working_image}"
    python3 - "${work_dir}/experimental-mount/data.bin" <<'PYTHON'
import os
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
pattern = b"fsmnt raid-stripe-tree data 0123456789abcdef\n"
length = 64 * 1024 * 1024
with destination.open("wb") as stream:
    full_blocks, tail = divmod(length, len(pattern))
    stream.write(pattern * full_blocks)
    stream.write(pattern[:tail])
    stream.flush()
    os.fsync(stream.fileno())
PYTHON
    printf '%s\n' 'raid stripe tree kernel fixture' \
        > "${work_dir}/experimental-mount/marker.txt"
    sync --file-system "${work_dir}/experimental-mount"
    unmount_experimental_image
    mv -- "${working_image}" "${fixture_image}"
}

create_remap_tree_fixture() {
    local fixture_image="${script_dir}/btrfs-remap-tree.img"
    local working_image="${work_dir}/btrfs-remap-tree.img"
    local root="${work_dir}/remap-tree-root"

    if ! kernel_supports_btrfs_feature remap_tree; then
        printf '%s\n' \
            'skipping forward-remap fixture; an experimental kernel and root are required' \
            >&2
        return
    fi
    if ! "${btrfstune_bin}" --help 2>&1 \
        | grep --quiet -- '--convert-to-remap-tree'; then
        printf '%s\n' \
            'skipping forward-remap fixture; set BTRFSTUNE to an experimental btrfstune build' \
            >&2
        return
    fi

    mkdir -p -- "${root}/nested"
    printf '%s\n' 'remap tree converted fixture' > "${root}/marker.txt"
    python3 - "${root}/nested/data.bin" <<'PYTHON'
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
pattern = b"fsmnt remap-tree data 0123456789abcdef\n"
length = 8 * 1024 * 1024
with destination.open("wb") as stream:
    full_blocks, tail = divmod(length, len(pattern))
    stream.write(pattern * full_blocks)
    stream.write(pattern[:tail])
PYTHON
    truncate -s 536870912 "${working_image}"
    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label fsmnt-btrfs-remap \
        --rootdir "${root}" \
        --features '^remap-tree' \
        "${working_image}"
    "${btrfstune_bin}" --convert-to-remap-tree "${working_image}"

    mount_experimental_image "${working_image}"
    btrfs balance start -dlimit=1 "${work_dir}/experimental-mount"
    sync --file-system "${work_dir}/experimental-mount"
    unmount_experimental_image
    poison_forward_remap_source "${working_image}"

    mount_experimental_image "${working_image}"
    python3 - "${work_dir}/experimental-mount/nested/data.bin" <<'PYTHON'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
pattern = b"fsmnt remap-tree data 0123456789abcdef\n"
expected_length = 8 * 1024 * 1024
data = source.read_bytes()
full_blocks, tail = divmod(expected_length, len(pattern))
if data != pattern * full_blocks + pattern[:tail]:
    raise SystemExit("kernel read did not follow the forward remap")
PYTHON
    unmount_experimental_image
    mv -- "${working_image}" "${fixture_image}"
}

create_parity_fixture() {
    local profile="$1"
    local metadata_profile="$2"
    local member_count="$3"
    local fixture_name="$4"
    local source_root="$5"
    local label="$6"
    local loops=()

    raid_loops=()
    for member in $(seq 1 "${member_count}"); do
        local image="${script_dir}/${fixture_name}-${member}.img"
        local loop_device
        truncate -s 268435456 "${image}"
        loop_device="$(losetup --find --show "${image}")"
        loops+=("${loop_device}")
        raid_loops+=("${loop_device}")
    done

    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label "${label}" \
        --data "${profile}" \
        --metadata "${metadata_profile}" \
        "${loops[@]}"

    raid_mounted="${work_dir}/${fixture_name}-mount"
    mkdir -p -- "${raid_mounted}"
    mount -- "${loops[0]}" "${raid_mounted}"
    cp --archive -- "${source_root}/." "${raid_mounted}/"
    sync --file-system "${raid_mounted}"
    umount -- "${raid_mounted}"
    raid_mounted=""

    for loop_device in "${loops[@]}"; do
        losetup --detach "${loop_device}"
    done
    raid_loops=()
}

create_seed_chain_fixture() {
    local base_image="${script_dir}/btrfs-seed-base.img"
    local middle_image="${script_dir}/btrfs-seed-middle.img"
    local top_image="${script_dir}/btrfs-seed-top.img"
    local base_loop
    local middle_loop
    local top_loop

    truncate -s 268435456 "${base_image}" "${middle_image}" "${top_image}"
    base_loop="$(losetup --find --show "${base_image}")"
    middle_loop="$(losetup --find --show "${middle_image}")"
    top_loop="$(losetup --find --show "${top_image}")"
    seed_loops=("${base_loop}" "${middle_loop}" "${top_loop}")

    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label fsmnt-btrfs-seed-base \
        "${base_loop}"
    seed_mounted="${work_dir}/seed-mount"
    mkdir -p -- "${seed_mounted}"
    mount -- "${base_loop}" "${seed_mounted}"
    write_numbered_lines 'seed-base-line' 5 32768 "${seed_mounted}/base-only.txt"
    printf '%s\n' 'base layer' > "${seed_mounted}/layer.txt"
    sync --file-system "${seed_mounted}"
    umount -- "${seed_mounted}"
    seed_mounted=""
    "${btrfstune_bin}" -S 1 "${base_loop}"

    mount -- "${base_loop}" "${work_dir}/seed-mount"
    seed_mounted="${work_dir}/seed-mount"
    btrfs device add --force --nodiscard "${middle_loop}" "${seed_mounted}"
    mount -o remount,rw "${seed_mounted}"
    write_numbered_lines 'seed-middle-line' 5 32768 "${seed_mounted}/middle-only.txt"
    printf '%s\n' 'middle layer' > "${seed_mounted}/layer.txt"
    sync --file-system "${seed_mounted}"
    umount -- "${seed_mounted}"
    seed_mounted=""
    "${btrfstune_bin}" -S 1 "${middle_loop}"

    btrfs device scan "${base_loop}" "${middle_loop}"
    mount -- "${middle_loop}" "${work_dir}/seed-mount"
    seed_mounted="${work_dir}/seed-mount"
    btrfs device add --force --nodiscard "${top_loop}" "${seed_mounted}"
    mount -o remount,rw "${seed_mounted}"
    write_numbered_lines 'seed-top-line' 5 32768 "${seed_mounted}/top-only.txt"
    printf '%s\n' 'top layer' > "${seed_mounted}/layer.txt"
    sync --file-system "${seed_mounted}"
    umount -- "${seed_mounted}"
    seed_mounted=""

    for loop_device in "${seed_loops[@]}"; do
        losetup --detach "${loop_device}"
    done
    seed_loops=()
}

create_log_replay_fixture() {
    local working_image="${work_dir}/btrfs-log-working.img"
    local fixture_image="${script_dir}/btrfs-log-replay.img"

    truncate -s 268435456 "${working_image}"
    log_loop="$(losetup --find --show "${working_image}")"
    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label fsmnt-btrfs-log-replay \
        "${log_loop}"

    mkdir -p -- "${work_dir}/log-mount"
    mount -- "${log_loop}" "${work_dir}/log-mount"
    log_mounted=true
    printf '%s\n' 'committed version' > "${work_dir}/log-mount/modified.txt"
    printf '%s\n' 'remove after commit' > "${work_dir}/log-mount/deleted.txt"
    printf '%s\n' 'rename after commit' > "${work_dir}/log-mount/rename-old.txt"
    write_numbered_lines \
        'truncate-me-line' \
        5 \
        8192 \
        "${work_dir}/log-mount/truncated.txt"
    printf '%s\n' 'committed prefix' > "${work_dir}/log-mount/extended.txt"
    python3 - "${work_dir}/log-mount" <<'PYTHON'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def pattern(length: int, multiplier: int, addend: int, modulus: int) -> bytes:
    return bytes((index * multiplier + addend) % modulus for index in range(length))

(root / "large-modified.bin").write_bytes(pattern(1_048_576, 17, 3, 251))
(root / "large-hole.bin").write_bytes(pattern(524_288, 11, 5, 241))
(root / "large-truncated.bin").write_bytes(pattern(786_432, 13, 9, 239))
(root / "large-extended.bin").write_bytes(pattern(131_072, 19, 1, 233))
PYTHON
    btrfs filesystem sync "${work_dir}/log-mount"

    python3 - "${work_dir}/log-mount" <<'PYTHON'
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])

def write_and_fsync(path: pathlib.Path, data: bytes, mode: str = "wb") -> None:
    with path.open(mode) as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def pattern(length: int, multiplier: int, addend: int, modulus: int) -> bytes:
    return bytes((index * multiplier + addend) % modulus for index in range(length))

def fsync_path(path: pathlib.Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())

def fsync_directory(path: pathlib.Path) -> None:
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

write_and_fsync(root / "created.txt", b"created through tree log\n")
write_and_fsync(root / "modified.txt", b"logged version\n")
write_and_fsync(root / "truncated.txt", b"tiny")
write_and_fsync(root / "extended.txt", b"logged suffix\n", "ab")
write_and_fsync(
    root / "large-created.bin",
    pattern(786_432, 23, 7, 229),
)
with (root / "large-modified.bin").open("r+b") as stream:
    stream.seek(327_680)
    stream.write(pattern(196_608, 29, 11, 227))
    stream.flush()
    os.fsync(stream.fileno())
subprocess.run(
    [
        "fallocate",
        "--punch-hole",
        "--keep-size",
        "--offset",
        "131072",
        "--length",
        "131072",
        root / "large-hole.bin",
    ],
    check=True,
)
fsync_path(root / "large-hole.bin")
os.truncate(root / "large-truncated.bin", 100_003)
fsync_path(root / "large-truncated.bin")
write_and_fsync(
    root / "large-extended.bin",
    pattern(196_608, 31, 13, 223),
    "ab",
)
os.unlink(root / "deleted.txt")
os.rename(root / "rename-old.txt", root / "rename-new.txt")
fsync_path(root / "rename-new.txt")
fsync_directory(root)
PYTHON

    cp --reflink=never --sparse=always -- "${working_image}" "${fixture_image}"
    umount -- "${work_dir}/log-mount"
    log_mounted=false
    losetup --detach "${log_loop}"
    log_loop=""
}

create_root_recovery_fixture() {
    local fixture_image="${script_dir}/btrfs-root-recovery.img"

    truncate -s 268435456 "${fixture_image}"
    recovery_loop="$(losetup --find --show "${fixture_image}")"
    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label fsmnt-btrfs-root-recovery \
        "${recovery_loop}"

    mkdir -p -- "${work_dir}/recovery-mount"
    mount -- "${recovery_loop}" "${work_dir}/recovery-mount"
    recovery_mounted=true
    printf '%s\n' 'survives historical root recovery' \
        > "${work_dir}/recovery-mount/stable.txt"
    btrfs filesystem sync "${work_dir}/recovery-mount"

    for transaction in $(seq 1 6); do
        printf 'transaction %s\n' "${transaction}" \
            > "${work_dir}/recovery-mount/latest.txt"
        btrfs filesystem sync "${work_dir}/recovery-mount"
    done

    # Grow the device only after the stable file has aged into every backup
    # slot. Resizing commits a new chunk-tree root while prior records retain
    # the old one, allowing tests to damage the live chunk root as well as the
    # root tree.
    truncate -s 335544320 "${fixture_image}"
    losetup --set-capacity "${recovery_loop}"
    btrfs filesystem resize max "${work_dir}/recovery-mount"
    btrfs filesystem sync "${work_dir}/recovery-mount"

    umount -- "${work_dir}/recovery-mount"
    recovery_mounted=false
    losetup --detach "${recovery_loop}"
    recovery_loop=""
}

root_dir="${work_dir}/root"
image="${script_dir}/btrfs-basic.img"
subvolume_image="${script_dir}/btrfs-subvolumes.img"
multi_image_one="${script_dir}/btrfs-multi-1.img"
multi_image_two="${script_dir}/btrfs-multi-2.img"

mkdir -p -- "${root_dir}/nested/deeper" "${root_dir}/empty"
printf '%s\n' 'hello from fsmnt btrfs' > "${root_dir}/hello.txt"
printf '%s\n' 'nested file contents' > "${root_dir}/nested/deeper/note.txt"
ln -s -- 'nested/deeper/note.txt' "${root_dir}/note-link"
write_numbered_lines \
    'fsmnt-checksum-fixture-line' \
    4 \
    2048 \
    "${root_dir}/checksummed.txt"

truncate -s 1048576 "${root_dir}/sparse.bin"
printf 'tail' | dd of="${root_dir}/sparse.bin" bs=1 seek=1048572 conv=notrunc status=none

truncate -s 268435456 "${image}"
"${mkfs_btrfs}" \
    --force \
    --nodiscard \
    --label fsmnt-btrfs-test \
    --rootdir "${root_dir}" \
    "${image}"

if "${mkfs_btrfs}" -V 2>&1 | grep --quiet -- '+EXPERIMENTAL'; then
    extent_tree_v2_root="${work_dir}/extent-tree-v2-root"
    extent_tree_v2_image="${script_dir}/btrfs-extent-tree-v2.img"
    mkdir -p -- "${extent_tree_v2_root}/nested"
    printf '%s\n' 'extent-tree-v2 through global checksum roots' \
        > "${extent_tree_v2_root}/marker.txt"
    python3 - "${extent_tree_v2_root}/global-roots.bin" <<'PYTHON'
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
pattern = b"fsmnt extent tree v2 checksum pattern 0123456789abcdef\n"
length = 160 * 1024 * 1024
with destination.open("wb") as stream:
    full_blocks, tail = divmod(length, len(pattern))
    stream.write(pattern * full_blocks)
    stream.write(pattern[:tail])
PYTHON
    printf '%s\n' 'late extent-tree-v2 marker' \
        > "${extent_tree_v2_root}/nested/late.txt"
    truncate -s 805306368 "${extent_tree_v2_image}"
    "${mkfs_btrfs}" \
        --force \
        --nodiscard \
        --label fsmnt-btrfs-extent-v2 \
        --rootdir "${extent_tree_v2_root}" \
        --features extent-tree-v2 \
        --num-global-roots 4 \
        "${extent_tree_v2_image}"

    create_raid_stripe_tree_fixture
    create_remap_tree_fixture
else
    printf '%s\n' \
        'skipping extent-tree-v2 fixture; set MKFS_BTRFS to an experimental btrfs-progs build' \
        >&2
fi

multi_root="${work_dir}/multi-root"
mkdir -p -- "${multi_root}"
write_numbered_lines 'multi-device-line' 5 32768 "${multi_root}/striped.txt"
for compression in zlib lzo zstd; do
    write_numbered_lines \
        "compressed-${compression}-line" \
        5 \
        8192 \
        "${multi_root}/${compression}.txt"
done

raid5_root="${work_dir}/raid5-root"
raid6_root="${work_dir}/raid6-root"
mkdir -p -- "${raid5_root}" "${raid6_root}"
write_numbered_lines 'raid5-data-line' 6 131072 "${raid5_root}/parity.txt"
write_numbered_lines 'raid6-data-line' 6 131072 "${raid6_root}/parity.txt"

if [[ "${EUID}" -ne 0 ]]; then
    printf '%s\n' 'subvolume and multi-device fixture generation requires root for loop devices' >&2
    exit 1
fi

truncate -s 268435456 "${subvolume_image}"
subvolume_loop="$(losetup --find --show "${subvolume_image}")"
"${mkfs_btrfs}" \
    --force \
    --nodiscard \
    --label fsmnt-btrfs-subvolumes \
    "${subvolume_loop}"

mkdir -p -- "${work_dir}/subvolume-mount"
mount -- "${subvolume_loop}" "${work_dir}/subvolume-mount"
subvolume_mounted=true
btrfs subvolume create "${work_dir}/subvolume-mount/root"
btrfs subvolume create "${work_dir}/subvolume-mount/home"
mkdir -p \
    "${work_dir}/subvolume-mount/root/etc" \
    "${work_dir}/subvolume-mount/root/home" \
    "${work_dir}/subvolume-mount/root/var/lib"
printf '%s\n' 'selected default root' \
    > "${work_dir}/subvolume-mount/root/etc/root-marker.txt"
printf '%s\n' 'selected home subvolume' \
    > "${work_dir}/subvolume-mount/home/home-marker.txt"
btrfs subvolume create "${work_dir}/subvolume-mount/root/var/lib/nested"
printf '%s\n' 'selected nested subvolume' \
    > "${work_dir}/subvolume-mount/root/var/lib/nested/nested-marker.txt"
btrfs subvolume snapshot -r \
    "${work_dir}/subvolume-mount/root" \
    "${work_dir}/subvolume-mount/root-snapshot"
root_subvolume_id="$(
    btrfs subvolume show "${work_dir}/subvolume-mount/root" \
        | awk '$1 == "Subvolume" && $2 == "ID:" { print $3 }'
)"
if [[ -z "${root_subvolume_id}" ]]; then
    printf '%s\n' 'could not determine root fixture subvolume ID' >&2
    exit 1
fi
btrfs subvolume set-default \
    "${root_subvolume_id}" \
    "${work_dir}/subvolume-mount"
sync --file-system "${work_dir}/subvolume-mount"
umount -- "${work_dir}/subvolume-mount"
subvolume_mounted=false
losetup --detach "${subvolume_loop}"
subvolume_loop=""

truncate -s 268435456 "${multi_image_one}"
truncate -s 268435456 "${multi_image_two}"
loop_one="$(losetup --find --show "${multi_image_one}")"
loop_two="$(losetup --find --show "${multi_image_two}")"
"${mkfs_btrfs}" \
    --force \
    --nodiscard \
    --label fsmnt-btrfs-multi \
    --data raid0 \
    --metadata raid1 \
    "${loop_one}" \
    "${loop_two}"

mkdir -p -- "${work_dir}/multi-mount"
mount -- "${loop_one}" "${work_dir}/multi-mount"
multi_mounted=true
cp --archive -- "${multi_root}/." "${work_dir}/multi-mount/"
for compression in zlib lzo zstd; do
    btrfs property set \
        "${work_dir}/multi-mount/${compression}.txt" \
        compression \
        "${compression}"
    btrfs filesystem defragment \
        -f \
        "-c${compression}" \
        "${work_dir}/multi-mount/${compression}.txt"
done
sync --file-system "${work_dir}/multi-mount"
umount -- "${work_dir}/multi-mount"
multi_mounted=false
losetup --detach "${loop_two}"
loop_two=""
losetup --detach "${loop_one}"
loop_one=""

create_parity_fixture \
    raid5 \
    raid1 \
    3 \
    btrfs-raid5 \
    "${raid5_root}" \
    fsmnt-btrfs-raid5
create_parity_fixture \
    raid6 \
    raid1c4 \
    4 \
    btrfs-raid6 \
    "${raid6_root}" \
    fsmnt-btrfs-raid6
create_seed_chain_fixture
create_log_replay_fixture
create_root_recovery_fixture
