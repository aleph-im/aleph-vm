#!/bin/bash

set -euf

# Variables
ROOTFS_FILENAME="./rootfs.img"
IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64-disk-kvm.img"
IMAGE_NAME="jammy-server-cloudimg-amd64-disk-kvm.img"

# Cleanup previous run
rm -f "$ROOTFS_FILENAME"

# Download Ubuntu image
echo "Downloading Ubuntu 22.04 image"
curl -L "$IMAGE_URL" -o "$IMAGE_NAME"

# Rename final file
mv "$IMAGE_NAME" "$ROOTFS_FILENAME"
