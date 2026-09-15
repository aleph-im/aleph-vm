#!/bin/bash

set -euf

# Variables
ROOTFS_FILENAME="./rootfs.img"
IMAGE_PATH="images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
# cloud.debian.org redirects every download to one host of the umu.se cluster;
# when that host is broken, its siblings still serve the same files.
IMAGE_MIRRORS="https://cloud.debian.org https://laotzu.ftp.acc.umu.se https://gemmei.ftp.acc.umu.se https://saimei.ftp.acc.umu.se"
IMAGE_NAME="debian-12-genericcloud-amd64.qcow2"

# Cleanup previous run
rm -f "$ROOTFS_FILENAME"

# Download Ubuntu image
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

# Rename final file
mv "$IMAGE_NAME" "$ROOTFS_FILENAME"
