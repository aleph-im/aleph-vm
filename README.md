# Aleph VM Supervisor

> Note: This is still early prototyping.

Web service to run Python code in Firecracker VMs for the [Aleph.im](https://aleph.im/) project.

This project provides a service that runs untrusted Python code in Firecracker
"micro virtual machines".

The following instructions are tested while running as root, either on bare metal or on a
VM that allows virtualisation (`/dev/kvm`) such as a DigitalOcean droplet.

## Installation

These instructions have been tested on Debian 10 Buster, and should work on recent versions
of Ubuntu as well.

Install system dependencies

```shell
apt update
apt -y upgrade
apt install -y git python3 python3-aiohttp sudo acl curl systemd-container
useradd jailman
```

Download Firecracker and Jailer from the 
[Firecracker project releases](https://github.com/firecracker-microvm/firecracker/releases):
```shell
mkdir /opt/firecracker
chown $(whoami) /opt/firecracker
curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v0.24.2/firecracker-v0.24.2-x86_64.tgz | tar -xz --directory /opt/firecracker

# Link binaries on version-agnostic paths:
ln /opt/firecracker/firecracker-v* /opt/firecracker/firecracker
ln /opt/firecracker/jailer-v* /opt/firecracker/jailer
```

Clone this reposotiry on the host machine and enter it.

```shell
git clone https://github.com/aleph-im/aleph-vm.git
cd aleph-vm/
````

Build the runtime rootfs (will be distributed as binary in the future):

```shell
cd ./runtimes/aleph-alpine-3.13-python
bash ./create_disk_image.sh
# Run it a second time to solve a bug
bash ./create_disk_image.sh
cd ../..
```

Setup the jailer working directory:

```shell
mkdir /srv/jailer
```

## Running

Run the VM Supervisor with Python:
```shell
export PYTHONPATH=$(pwd)
python3 -m vm_supervisor
```

Test running code from an Aleph.im post on:
http://localhost:8080/run/fastapi/

## Production

https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md

## Compile your kernel

A lot of time at boot is saved by disabling keyboard support in the kernel.
See `dmesg` logs for the exact timing saved.

Start from https://github.com/firecracker-microvm/firecracker/blob/master/docs/rootfs-and-kernel-setup.md

Then disable:
`CONFIG_INPUT_KEYBOARD`
`CONFIG_INPUT_MISC`
`CONFIG_INPUT_FF_MEMLESS`
`CONFIG_SERIO`
