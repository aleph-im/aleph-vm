#!/bin/bash
#set -euf -o pipefail

mkdir -p /opt/firecracker
mkdir -p /opt/firecracker-release

curl -C - -o /opt/firecracker/vmlinux.bin "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"

curl -fsSL -C - https://github.com/firecracker-microvm/firecracker/releases/download/v1.1.0/firecracker-v1.1.0-x86_64.tgz | tar -xz --directory /opt/firecracker-release
cp /opt/firecracker-release/release-v*/firecracker-v* /opt/firecracker/firecracker
cp /opt/firecracker-release/release-v*/jailer-v* /opt/firecracker/jailer

echo "Looking for libnftables.so.1..."
cp $(find /nix/store/ | grep nftables-1.0.5 | grep libnftables.so.1.1 | head -n 1) ./libnftables.so.1
