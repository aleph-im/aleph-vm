#!/bin/bash

set -euf

# Variables
ROOTFS_FILENAME="./rootfs.img"
IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
IMAGE_NAME="debian-12-genericcloud-amd64.qcow2"

# Cleanup previous run
rm -f "$ROOTFS_FILENAME"

# Download Ubuntu image
echo "Downloading Debian 12 image"
curl -L "$IMAGE_URL" -o "$IMAGE_NAME"

# Rename final file
mv "$IMAGE_NAME" "$ROOTFS_FILENAME"
