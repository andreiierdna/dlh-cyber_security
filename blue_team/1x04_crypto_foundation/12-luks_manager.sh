#!/bin/bash
set -euo pipefail
umask 077

readonly MAPPER="secure_vol"
readonly DEVICE="/dev/mapper/${MAPPER}"
OPENED=0
MOUNTED=0
MOUNT_DIR=""

usage() {
    cat <<EOF
Usage:
  $0 create <image_file> <size_MiB>
  $0 open   <image_file> <mount_directory>
  $0 close  <mount_directory>

Linux lab only; run with sudo. Uses one mapping: ${MAPPER}.
create refuses existing files and creates LUKS2 with an ext4 filesystem.
open leaves the volume mounted; close refuses unrelated mounts.
Passphrases are entered directly into cryptsetup, never stored by this script.
EOF
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

# Only clean up a mapping opened by this invocation; never force an unmount.
cleanup() {
    local status=$?
    trap - EXIT
    if (( OPENED )); then
        if (( MOUNTED )); then
            if ! umount -- "$MOUNT_DIR"; then
                echo "[ERROR] Unmount failed; ${MAPPER} remains open. Close it manually." >&2
                exit 1
            fi
        fi
        if ! cryptsetup luksClose "$MAPPER"; then
            echo "[ERROR] ${MAPPER} remains open. Close it manually." >&2
            exit 1
        fi
    fi
    exit "$status"
}

if [[ ${1:-} == --help ]]; then
    usage
    exit 0
fi
[[ $# -ge 1 ]] || { usage; exit 1; }
MODE="$1"
case "$MODE" in
    create)
        [[ $# -eq 3 ]] || { usage; exit 1; }
        IMAGE="$2"
        SIZE="$3"
        [[ "$SIZE" =~ ^[1-9][0-9]*$ ]] || die "Size must be a positive integer in MiB."
        [[ ! -e "$IMAGE" && ! -L "$IMAGE" ]] || die "Refusing to overwrite: $IMAGE"
        ;;
    open)
        [[ $# -eq 3 ]] || { usage; exit 1; }
        IMAGE="$2"
        MOUNT_DIR="$3"
        [[ -f "$IMAGE" && ! -L "$IMAGE" ]] || die "Image must be an existing regular file, not a symlink."
        ;;
    close)
        [[ $# -eq 2 ]] || { usage; exit 1; }
        MOUNT_DIR="$2"
        ;;
    *) die "Unknown mode '$MODE'; use create, open, or close." ;;
esac

[[ $(uname -s) == Linux ]] || die "Linux with dm-crypt/loop support is required."
[[ $EUID -eq 0 ]] || die "Run with sudo."
for tool in cryptsetup dd mkfs.ext4 mount umount findmnt readlink mkdir; do
    command -v "$tool" >/dev/null 2>&1 || die "Missing dependency: $tool"
done
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$MODE" in
    create)
        [[ ! -e "$DEVICE" ]] || die "Mapping ${MAPPER} is already in use."
        # GNU dd's exclusive creation also prevents overwriting a raced-in file.
        dd if=/dev/zero of="$IMAGE" bs=1M count="$SIZE" conv=excl
        cryptsetup luksFormat --type luks2 "$IMAGE"
        cryptsetup luksOpen "$IMAGE" "$MAPPER"
        OPENED=1
        mkfs.ext4 "$DEVICE"
        cryptsetup luksClose "$MAPPER"
        OPENED=0
        echo "[INFO] Created and closed: $IMAGE"
        ;;
    open)
        [[ ! -e "$DEVICE" ]] || die "Mapping ${MAPPER} is already in use."
        [[ ! -L "$MOUNT_DIR" ]] || die "Mount directory must not be a symlink."
        mkdir -p -- "$MOUNT_DIR"
        MOUNT_DIR=$(readlink -f -- "$MOUNT_DIR")
        if findmnt -rn --mountpoint "$MOUNT_DIR" >/dev/null; then
            die "Mount directory is already mounted."
        fi
        shopt -s nullglob dotglob
        contents=("$MOUNT_DIR"/*)
        [[ ${#contents[@]} -eq 0 ]] || die "Mount directory must be empty."
        cryptsetup luksOpen "$IMAGE" "$MAPPER"
        OPENED=1
        mount -o nodev,nosuid -- "$DEVICE" "$MOUNT_DIR"
        MOUNTED=1
        echo "[INFO] Mounted ${MAPPER} at $MOUNT_DIR"
        # A successful open deliberately leaves the mapping mounted.
        OPENED=0
        ;;
    close)
        [[ -b "$DEVICE" ]] || die "Mapping ${MAPPER} is not open."
        [[ -d "$MOUNT_DIR" ]] || die "Mount directory does not exist."
        MOUNT_DIR=$(readlink -f -- "$MOUNT_DIR")
        SOURCE=$(findmnt -rn -o SOURCE --mountpoint "$MOUNT_DIR") || die "Directory is not a mount point."
        [[ $(readlink -f -- "$SOURCE") == $(readlink -f -- "$DEVICE") ]] || die "Refusing to unmount an unrelated filesystem."
        umount -- "$MOUNT_DIR"
        cryptsetup luksClose "$MAPPER"
        echo "[INFO] Unmounted and closed ${MAPPER}."
        ;;
esac
