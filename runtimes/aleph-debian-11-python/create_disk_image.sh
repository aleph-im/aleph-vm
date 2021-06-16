#!/bin/sh

rm ./rootfs.squashfs

set -euf

rm -fr ./rootfs
mkdir ./rootfs

debootstrap --variant=minbase bullseye ./rootfs http://deb.debian.org/debian/

chroot ./rootfs /bin/sh <<EOT
apt-get install -y --no-install-recommends --no-install-suggests \
  python3-minimal \
  openssh-server \
  socat libsecp256k1-0 \
  \
  python3-aiohttp python3-msgpack \
  python3-setuptools \
  python3-pip python3-cytoolz python3-pydantic \
  iproute2 unzip \
  nodejs

pip3 install fastapi

echo "Pip installing aleph-client"
pip3 install 'aleph-client>=0.2.5' 'coincurve==15.0.0'

# Compile all Python bytecode
python3 -m compileall -f /usr/local/lib/python3.9

#echo -e "toor\ntoor" | passwd root

mkdir -p /overlay

# Set up a login terminal on the serial console (ttyS0):
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
EOT

echo "PermitRootLogin yes" >> ./rootfs/etc/ssh/sshd_config

# Generate SSH host keys
#systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t dsa -f /etc/ssh/ssh_host_dsa_key
#systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
#systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key
#systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t ed25519 -f /etc/ssh/ssh_host_ed25519_key

cat <<EOT > ./rootfs/etc/inittab
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

# Reduce size
rm -fr ./rootfs/root/.cache
rm -fr ./rootfs/var/cache
rm -fr ./rootfs/usr/share/doc
rm -fr ./rootfs/usr/share/man
rm -fr ./rootfs/var/lib/apt/lists/

# Custom init
cp ./init0.sh ./rootfs/sbin/init
cp ./init1.py ./rootfs/root/init1.py
chmod +x ./rootfs/sbin/init
chmod +x ./rootfs/root/init1.py

mksquashfs ./rootfs/ ./rootfs.squashfs
