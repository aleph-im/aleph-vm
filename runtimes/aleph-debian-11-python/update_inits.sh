#!/bin/sh

rm ./rootfs.squashfs

set -euf

cp ./init0.sh ./rootfs/sbin/init
cp ./init1.py ./rootfs/root/init1.py
chmod +x ./rootfs/sbin/init
chmod +x ./rootfs/root/init1.py

mksquashfs ./rootfs/ ./rootfs.squashfs

echo "OK"
