#!/bin/sh

umount /mnt/vm
rm ./rootfs.ext4
mkdir -p /mnt/vm

set -euf

echo "Creating rootfs.ext4 file"
# Create a 1,5 GB partition
dd if=/dev/zero of=rootfs.ext4 bs=1MB count=1500
mkfs.ext4 rootfs.ext4
mount rootfs.ext4 /mnt/vm

echo "Building Docker image"
rm -rf ./docker-image
docker buildx build -t docker-image --output type=local,dest=./docker-image .

echo "Copying Docker image content to final rootfs file"
cp -vap ./docker-image/. /mnt/vm
umount /mnt/vm

echo "Cleaning Docker generated files"
rm -rf ./docker-image
