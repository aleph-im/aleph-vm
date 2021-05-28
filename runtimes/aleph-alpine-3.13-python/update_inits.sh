#!/bin/sh

umount /mnt/rootfs

set -euf

mount ./rootfs.ext4 /mnt/rootfs

cp ./init0.sh /mnt/rootfs/sbin/init
cp ./init1.py /mnt/rootfs/root/init1.py
chmod +x /mnt/rootfs/sbin/init
chmod +x /mnt/rootfs/root/init1.py

umount /mnt/rootfs

echo "OK"
