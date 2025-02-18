#!/bin/bash

set -euf

# Variables
ROOTFS_FILENAME="./rootfs.img"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
IMAGE_NAME="noble-server-cloudimg-amd64.img"

# Cleanup previous run
rm -f "$ROOTFS_FILENAME"

# Download Ubuntu image
echo "Downloading Ubuntu 24.04 image"
curl -L "$IMAGE_URL" -o "$IMAGE_NAME"

# Rename final file
mv "$IMAGE_NAME" "$ROOTFS_FILENAME"
