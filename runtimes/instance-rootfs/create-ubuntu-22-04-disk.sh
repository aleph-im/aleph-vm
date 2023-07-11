#!/bin/bash

set -euf

# Variables
ROOTFS_FILE="./rootfs.btrfs"
ROOTFS_DIR="./rootfs"
MOUNT_DIR="/mnt/vm"
IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64-root.tar.xz"

# Cleanup previous run
umount "$MOUNT_DIR" || true
rm -f "$ROOTFS_FILE"
rm -rf "$ROOTFS_DIR"

# Prepare directories
mkdir -p "$MOUNT_DIR"
mkdir -p "$ROOTFS_DIR"

# Download Ubuntu image
echo "Downloading Ubuntu 22.04 image"
curl -L --remote-name "$IMAGE_URL"

# Create rootfs.btrfs file
echo "Creating rootfs.btrfs file"
dd if=/dev/zero of="$ROOTFS_FILE" bs=1M count=1400
mkfs.btrfs "$ROOTFS_FILE"
mount "$ROOTFS_FILE" "$MOUNT_DIR"

# Extract Ubuntu image to rootfs
echo "Extracting Ubuntu 22.04 image"
tar xvf jammy-server-cloudimg-amd64-root.tar.xz -C "$MOUNT_DIR"

# Cleanup and unmount
umount "$MOUNT_DIR"
