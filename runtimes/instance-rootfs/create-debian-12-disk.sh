#!/bin/bash

set -euf

# Variables
ROOTFS_FILE="./debian-12.btrfs"
MOUNT_ORIGIN_DIR="/mnt/debian"
MOUNT_DIR="/mnt/vm"
IMAGE_PATH="images/cloud/bookworm/latest/debian-12-genericcloud-amd64.tar.xz"
# cloud.debian.org redirects every download to one host of the umu.se cluster;
# when that host is broken, its siblings still serve the same files.
IMAGE_MIRRORS="https://cloud.debian.org https://laotzu.ftp.acc.umu.se https://gemmei.ftp.acc.umu.se https://saimei.ftp.acc.umu.se"
IMAGE_NAME="debian-12-genericcloud.tar.xz"
IMAGE_RAW_NAME="disk.raw"

# Cleanup previous run
umount "$MOUNT_ORIGIN_DIR" || true
umount "$MOUNT_DIR" || true
rm -f "$ROOTFS_FILE"

# Prepare directories
mkdir -p "$MOUNT_ORIGIN_DIR"
mkdir -p "$MOUNT_DIR"

# Download Debian image
echo "Downloading Debian 12 image"
download_image() {
    for mirror in $IMAGE_MIRRORS; do
        curl -fL "$mirror/$IMAGE_PATH" -o "$IMAGE_NAME" && return 0
        echo "Download from $mirror failed, trying the next mirror" >&2
    done
    echo "No mirror served $IMAGE_PATH" >&2
    return 1
}
download_image

# Allocate 1GB rootfs.btrfs file
echo "Allocate 1GB $ROOTFS_FILE file"
fallocate -l 1G "$ROOTFS_FILE"
mkfs.btrfs -m single --label root "$ROOTFS_FILE"
mount "$ROOTFS_FILE" "$MOUNT_DIR"

# Extract Debian image
echo "Extracting Debian 12 image"
tar xvf "$IMAGE_NAME"

# Mount first partition of Debian Image
LOOPDISK=$(losetup --find --show $IMAGE_RAW_NAME)
partx -u "$LOOPDISK"
mount "$LOOPDISK"p1 "$MOUNT_ORIGIN_DIR"

# Fix boot partition missing
sed -i '$d' "$MOUNT_ORIGIN_DIR"/etc/fstab

# Copy Debian image to rootfs
echo "Copying Debian 12 image to $ROOTFS_FILE file"
cp -vap "$MOUNT_ORIGIN_DIR/." "$MOUNT_DIR"

# Cleanup and unmount
umount "$MOUNT_ORIGIN_DIR"
partx -d "$LOOPDISK"
losetup -d "$LOOPDISK"
umount "$MOUNT_DIR"
rm "$IMAGE_RAW_NAME"
rm "$IMAGE_NAME"
