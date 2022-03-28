
# VM Supervisor

Web service to run untrusted Aleph VM functions in a secure environment
for the [Aleph.im](https://aleph.im/) project.

The project currently supports running applications written in Python 
within [Firecracker](https://github.com/firecracker-microvm/firecracker) 
"micro virtual machines". 

More languages and virtualization technologies may be added in the future.

## 1. Supported platforms

### Hardware

Quoting [Firecracker](https://github.com/firecracker-microvm/firecracker#supported-platforms)
supported platforms:

> We continuously test Firecracker on machines with the following CPUs micro-architectures: 
Intel Skylake, Intel Cascade Lake, AMD Zen2 and ARM64 Neoverse N1.
>
> Firecracker is generally available on Intel x86_64, AMD x86_64 and ARM64 CPUs 
> (starting from release v0.24) that offer hardware virtualization support, 
> and that are released starting with 2015. 

 A device named `/dev/kvm` should be present on compatible systems.

### Operating System

These instructions have been tested on Debian 11 Bullseye, and should work on recent versions
of Ubuntu as well (20.04+).

### Hosting providers

Bare metal servers from most hosting providers should be compatible with the VM Supervisor.

A few hosting providers offer compatible virtual machines.
- Compatible ✓ : DigitalOcean Droplet. AWS ECS Bare Metal. 
- Incompatible ✖ : AWS EC2 other than Bare Metal.

Probably [Google Cloud instances with Nested Virtualization](https://cloud.google.com/compute/docs/instances/enable-nested-virtualization-vm-instances).

### Note on containers

While not supported at the moment, it is possible to run the VM Supervisor inside a Docker
container. 

This will be less secure since the `Jailer` tool used to secure Firecracker MicroVMs
will not run inside containers. Pass the command-lien argument `--no-jailer` to disable the Jailer
when running the VM Supervisor.

## 2. Installation

### 2.b. Install system dependencies

```shell
apt update
apt install -y git python3 python3-aiohttp python3-msgpack python3-aiodns python3-sqlalchemy python3-setproctitle redis python3-aioredis \
 python3-psutil sudo acl curl systemd-container squashfs-tools debootstrap
useradd jailman
```

### 2.c. Download Firecracker and Jailer
from the [Firecracker project releases](https://github.com/firecracker-microvm/firecracker/releases):
```shell
mkdir /opt/firecracker
curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.0.0/firecracker-v1.0.0-x86_64.tgz | tar -xz --directory /opt/firecracker

# Link binaries on version-agnostic paths:
ln /opt/firecracker/release-*/firecracker-v* /opt/firecracker/firecracker
ln /opt/firecracker/release-*/jailer-v* /opt/firecracker/jailer
```

### 2.d. Clone this repository on the host machine and enter it.

```shell
git clone https://github.com/aleph-im/aleph-vm.git
cd aleph-vm/
````

### 2.e. Install Pydantic

[PyDantic](https://pydantic-docs.helpmanual.io/) 
is used to parse and validate Aleph messages.

```shell
apt install -y --no-install-recommends --no-install-suggests python3-pip
pip3 install pydantic[dotenv]
pip3 install aleph-message
```

### 2.f. Create the jailer working directory:

```shell
mkdir -p /var/lib/aleph/vm/jailer
```

### 2.g. Download a Linux kernel

This downloads an optimized kernel built by the Aleph team.

A more optimized kernel may be made available in the future.
See section _Compile your kernel_ below to build your own.

```shell
curl -fsSL -o /opt/firecracker/vmlinux.bin https://github.com/aleph-im/aleph-vm/releases/download/0.1.0/vmlinux.bin
```

## 3. Running

Run the VM Supervisor with Python:
```shell
export PYTHONPATH=$(pwd)
python3 -m vm_supervisor
```
or in debug mode:
```shell
python3 -m vm_supervisor -vv --system-logs
```

Test accessing the service on
http://localhost:4020/

## 4. Configuration

The VM Supervisor can be configured using command-line arguments or using environment variables.

List the available command-lien arguments using:
```shell
python3 -m vm_supervisor --help
```

List available using environment variables using:
```shell
python3 -m vm_supervisor --print-config --do-not-run
```

Configuration environment variables can be stored in a file named `.env` in the local directory.

Example content for `.env`:
```shell
ALEPH_VM_DNS_RESOLUTION=resolvectl
ALEPH_VM_NETWORK_INTERFACE=enp7s0
```



```

## 6. Production security concerns

See advanced security related concerns here:
https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md

## 7. Customization

### 7.a. Build a runtime

A runtime consist in the root filesystem used by a VM.

Runtimes contain a customized init that allows the VM Supervisor to run
functions within the MicroVM.

Official Aleph runtimes are built using scripts located in 
in [`../runtimes`](../runtimes), and are distributed on the Aleph network.

To build the default runtime locally:

```shell
cd ./runtimes/aleph-alpine-3.13-python
bash ./create_disk_image.sh
# Run it a second time to solve a bug
bash ./create_disk_image.sh
cd ../..
```

### 7.b. Compile your kernel

Boot time can be shortened by disabling keyboard support in the kernel.
See `dmesg` logs for the exact timing saved.

Start from https://github.com/firecracker-microvm/firecracker/blob/master/docs/rootfs-and-kernel-setup.md

Then disable:
`CONFIG_INPUT_KEYBOARD`
`CONFIG_INPUT_MISC`
`CONFIG_INPUT_FF_MEMLESS` and
`CONFIG_SERIO`.
