#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
loop_one=""
loop_two=""
multi_mounted=false

cleanup() {
    if "${multi_mounted}"; then
        umount -- "${work_dir}/multi-mount"
    fi
    if [[ -n "${loop_two}" ]]; then
        losetup --detach "${loop_two}"
    fi
    if [[ -n "${loop_one}" ]]; then
        losetup --detach "${loop_one}"
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

root_dir="${work_dir}/root"
image="${script_dir}/btrfs-basic.img"
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
mkfs.btrfs \
    --force \
    --nodiscard \
    --label fsmnt-btrfs-test \
    --rootdir "${root_dir}" \
    "${image}"

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

if [[ "${EUID}" -ne 0 ]]; then
    printf '%s\n' 'multi-device fixture generation requires root for loop devices' >&2
    exit 1
fi

truncate -s 268435456 "${multi_image_one}"
truncate -s 268435456 "${multi_image_two}"
loop_one="$(losetup --find --show "${multi_image_one}")"
loop_two="$(losetup --find --show "${multi_image_two}")"
mkfs.btrfs \
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
