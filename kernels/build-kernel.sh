#!/bin/bash
set -euf -o pipefail

curl -OL "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.124.tar.xz"
curl -OL "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.124.tar.sign"
unxz linux-5.10.124.tar.xz

gpg --locate-keys torvalds@kernel.org gregkh@kernel.org
gpg --verify linux-5.10.124.tar.sign linux-5.10.124.tar

tar -xvf linux-5.10.124.tar

cp microvm-kernel-x86_64-5.10.config linux-5.10.124/.config

cd linux-5.10.124/
make menuconfig

make -j32 vmlinux