#!/bin/sh

rm ./rootfs.squashfs

set -euf

rm -fr ./rootfs
mkdir ./rootfs

debootstrap --variant=minbase bookworm ./rootfs http://deb.debian.org/debian/

chroot ./rootfs /bin/sh <<EOT

set -euf

apt-get install -y --no-install-recommends --no-install-suggests \
  python3-minimal \
  openssh-server \
  socat libsecp256k1-1 \
  python3-aiohttp python3-msgpack \
  python3-setuptools python3-venv \
  python3-pip python3-cytoolz python3-pydantic \
  iproute2 unzip \
  nodejs npm \
  build-essential python3-dev \
  python3-fastapi \
  docker.io \
  cgroupfs-mount \
  nftables \
  iputils-ping curl \
  locales

# Update locale settings to en_US UTF-8
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen en_US.UTF-8

echo "Pip installing aleph-sdk-python"
mkdir -p /opt/aleph/libs
pip3 install --target /opt/aleph/libs 'aleph-sdk-python==1.0.0' 'aleph-message==0.4.9' 'fastapi~=0.109.2'

# Compile Python code to bytecode for faster execution
# -o2 is needed to compile with optimization level 2 which is what we launch init1.py ("python -OO")
# otherwise they are not used
python3 -m compileall -o 2 -f /usr/local/lib/python3.11
python3 -m compileall -o 2 -f /opt/aleph/libs

echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

mkdir -p /overlay

# Set up a login terminal on the serial console (ttyS0):
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
EOT

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
mkdir -p ./rootfs/var/cache/apt/archives/partial
rm -fr ./rootfs/usr/share/doc
rm -fr ./rootfs/usr/share/man
rm -fr ./rootfs/var/lib/apt/lists/

# Custom init
cp ./init0.sh ./rootfs/sbin/init
cp ./init1.py ./rootfs/root/init1.py
cp ./loading.html ./rootfs/root/loading.html
chmod +x ./rootfs/sbin/init
chmod +x ./rootfs/root/init1.py

mksquashfs ./rootfs/ ./rootfs.squashfs
