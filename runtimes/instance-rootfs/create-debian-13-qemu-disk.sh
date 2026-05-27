#!/bin/bash

set -euf

# Variables
ROOTFS_FILENAME="./rootfs.img"
IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
IMAGE_NAME="debian-13-genericcloud-amd64.qcow2"

# Cleanup previous run
rm -f "$ROOTFS_FILENAME"

# Download Debian image
echo "Downloading Debian 13 image"
curl -L "$IMAGE_URL" -o "$IMAGE_NAME"

# Rename final file
mv "$IMAGE_NAME" "$ROOTFS_FILENAME"
