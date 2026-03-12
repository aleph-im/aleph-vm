#!/bin/bash

set -euf -o pipefail

kversion="6.19.6"
kconfig="6.1"

# apt install ncurses-dev flex bison bc

rm -fr "linux-$kversion" "linux-$kversion.tar" "linux-$kversion.tar.sign" "linux-$kversion.tar.xz" "build"


curl -OL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kversion.tar.xz"
curl -OL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kversion.tar.sign"
unxz linux-$kversion.tar.xz

gpg --locate-keys torvalds@kernel.org gregkh@kernel.org
gpg --verify linux-$kversion.tar.sign linux-$kversion.tar

tar -xvf linux-$kversion.tar

cp "microvm-kernel-x86_64-$kconfig.config" "linux-$kversion/.config"

cd "linux-$kversion/"
make olddefconfig
make menuconfig

make -j$(nproc) vmlinux

# Copy the updated config locally for documentation
cd ../
cp "linux-$kversion/.config" ./linux.config

mkdir build
cp "linux-$kversion/vmlinux" build/
sha256sum "build/vmlinux" > build/vmlinux.sha256
