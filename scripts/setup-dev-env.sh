#!/usr/bin/env bash

# Install VM supervisor dependencies
sudo apt update
sudo apt install -y \
  acl \
  curl \
  debootstrap \
  python3 \
  python3-aiodns \
  python3-aiohttp \
  python3-aioredis \
  python3-alembic \
  python3-cpuinfo \
  python3-jsonschema \
  python3-msgpack \
  python3-nftables \
  python3-packaging \
  python3-pip \
  python3-psutil \
  python3-setproctitle \
  python3-sqlalchemy \
  redis \
  squashfs-tools \
  sudo \
  systemd-container


# Install Firecracker
sudo useradd jailman
sudo mkdir -p /opt/firecracker
curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.0.0/firecracker-v1.1.1-x86_64.tgz | sudo tar -xz --directory /opt/firecracker
