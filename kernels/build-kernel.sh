#!/bin/bash

set -euf -o pipefail

# apt install ncurses-dev flex bison bc

rm -fr linux-5.10.197 linux-5.10.197.tar linux-5.10.197.tar.sign  linux-5.10.197.tar.xz


curl -OL "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.197.tar.xz"
curl -OL "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.197.tar.sign"
unxz linux-5.10.197.tar.xz

gpg --locate-keys torvalds@kernel.org gregkh@kernel.org
gpg --verify linux-5.10.197.tar.sign linux-5.10.197.tar

tar -xvf linux-5.10.197.tar

cp microvm-kernel-x86_64-5.10.config linux-5.10.197/.config

cd linux-5.10.197/
make menuconfig

make -j$(nproc) vmlinux

# Copy the updated config locally for documentation
cp linux-5.10.197/.config ./linux.config
