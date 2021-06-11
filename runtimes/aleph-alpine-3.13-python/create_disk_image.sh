#!/bin/sh

umount /mnt/rootfs

set -euf

curl -fsSL -o ./alpine-miniroot.tgz https://dl-cdn.alpinelinux.org/alpine/v3.13/releases/x86_64/alpine-minirootfs-3.13.5-x86_64.tar.gz

dd if=/dev/zero of=./rootfs.ext4 bs=1M count=500
mkfs.ext4 ./rootfs.ext4
mkdir -p /mnt/rootfs
mount ./rootfs.ext4 /mnt/rootfs
tar --preserve-permissions --same-owner -xf  ./alpine-miniroot.tgz --directory /mnt/rootfs

cat /etc/resolv.conf > /mnt/rootfs/etc/resolv.conf

chroot /mnt/rootfs /bin/sh <<EOT
apk update
apk add util-linux
apk add python3
apk add openssh-server
apk add socat

apk add py3-pip
apk add py3-aiohttp py3-msgpack
pip install fastapi

apk add git pkgconf gcc py3-wheel python3-dev musl-dev py3-cffi libffi-dev autoconf automake libtool make
pip install aleph-client>=0.2.5 coincurve==15.0.0

# Compile all Python bytecode
python3 -m compileall -f /usr/lib/python3.8/site-packages

echo -e "toor\ntoor" | passwd root

mkdir -p /overlay

## Generate SSH host keys
#ssh-keygen -q -N "" -t dsa -f /etc/ssh/ssh_host_dsa_key
#ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
#ssh-keygen -q -N "" -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key
#ssh-keygen -q -N "" -t ed25519 -f /etc/ssh/ssh_host_ed25519_key

# Set up a login terminal on the serial console (ttyS0):
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
EOT

echo "PermitRootLogin yes" >> /mnt/rootfs/etc/ssh/sshd_config

# Generate SSH host keys
systemd-nspawn -D /mnt/rootfs/ ssh-keygen -q -N "" -t dsa -f /etc/ssh/ssh_host_dsa_key
systemd-nspawn -D /mnt/rootfs/ ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
systemd-nspawn -D /mnt/rootfs/ ssh-keygen -q -N "" -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key
systemd-nspawn -D /mnt/rootfs/ ssh-keygen -q -N "" -t ed25519 -f /etc/ssh/ssh_host_ed25519_key

cat <<EOT > /mnt/rootfs/etc/inittab
# /etc/inittab

::sysinit:/sbin/init sysinit
::sysinit:/sbin/init boot
::wait:/sbin/init default

# Set up a couple of getty's
tty1::respawn:/sbin/getty 38400 tty1
tty2::respawn:/sbin/getty 38400 tty2
tty3::respawn:/sbin/getty 38400 tty3
tty4::respawn:/sbin/getty 38400 tty4
tty5::respawn:/sbin/getty 38400 tty5
tty6::respawn:/sbin/getty 38400 tty6

# Put a getty on the serial port
ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100

# Stuff to do for the 3-finger salute
::ctrlaltdel:/sbin/reboot

# Stuff to do before rebooting
::shutdown:/sbin/init shutdown
EOT

# Custom init
mv /mnt/rootfs/sbin/init /mnt/rootfs/sbin/init.copy
cp ./init0.sh /mnt/rootfs/sbin/init
cp ./init1.py /mnt/rootfs/root/init1.py
chmod +x /mnt/rootfs/sbin/init
chmod +x /mnt/rootfs/root/init1.py

umount /mnt/rootfs
