#!/bin/sh

umount /mnt/vm
rm ./rootfs.btrfs
rm -rf ./rootfs
mkdir -p /mnt/vm
mkdir -p ./rootfs

set -euf

curl -L --remote-name https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64-root.tar.xz

echo "Creating rootfs.btrfs file"
# Create a 1,4 GB partition
dd if=/dev/zero of=rootfs.btrfs bs=1MB count=1400
mkfs.btrfs rootfs.btrfs
mount rootfs.btrfs /mnt/vm

echo "Building Ubuntu 22.04 image"
tar xvf jammy-server-cloudimg-amd64-root.tar.xz -C /mnt/vm/
umount /mnt/vm
