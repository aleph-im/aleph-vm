
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

These instructions have been tested on Debian 10 Buster, and should work on recent versions
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
apt install -y git python3 python3-aiohttp python3-msgpack sudo acl curl systemd-container
useradd jailman
```

### 2.c. Download Firecracker and Jailer
from the [Firecracker project releases](https://github.com/firecracker-microvm/firecracker/releases):
```shell
mkdir /opt/firecracker
chown $(whoami) /opt/firecracker
curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v0.24.2/firecracker-v0.24.2-x86_64.tgz | tar -xz --directory /opt/firecracker

# Link binaries on version-agnostic paths:
ln /opt/firecracker/firecracker-v* /opt/firecracker/firecracker
ln /opt/firecracker/jailer-v* /opt/firecracker/jailer
```

### 2.d. Clone this reposotiry on the host machine and enter it.

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
pip3 install aleph-message>=0.1.6
```

### 2.f. Create the jailer working directory:

```shell
mkdir /srv/jailer
```

### 2.g. Download a Linux kernel

This downloads the example kernel built by the Firecracker team.

A more optimized kernel will be made available in the future.
See section _Compile your kernel_ below to build your own.

```shell
curl -fsSL -o ./kernels/vmlinux.bin https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
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
http://localhost:8080/

## 4. Configuration

The VM Supervisor can be configured using command-line arguments:
```shell
python3 -m vm_supervisor --help
```
and using environment variables, which can be found using:
```shell
python3 -m vm_supervisor --print-config --do-not-run
```

## 5. Reverse-proxy

A reverse-proxy is required for production use. It allows:

 - A different domain name for each VM function
 - Secure connections using HTTPS
 - Load balancing between multiple servers

Using a different domain name for each VM function is important when running web applications, 
both for security and usability purposes. 

The VM Supervisor supports using domains in the form `https://identifer.vm.yourdomain.org`, where
_identifier_ is the identifier/hash of the message describing the VM function and `yourdomain.org` 
represents your domain name.

### 5.a. Wildcard certificates

A wildcard certificate is recommended to allow any subdomain of your domain to work.

You can create one using [Let's Encrypt](https://letsencrypt.org/) and
[Certbot](https://certbot.eff.org/) with the following instructions.

```shell
sudo apt install -y certbot

certbot certonly --manual --email email@yourdomain.org --preferred-challenges dns \
  --server https://acme-v02.api.letsencrypt.org/directory --agree-tos \
  -d 'vm.yourdomain.org,*.vm.youdomain.org'
```

### 5.b. Reverse Proxy

In this documentation, we will install the modern [Caddy](https://caddyserver.com/) reverse-proxy.

To install on Debian/Ubuntu, according to the
[official instructions](https://caddyserver.com/docs/install#debian-ubuntu-raspbian):
```shell
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo apt-key add -
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

Then give Caddy access to the certificates generated by Certbot:
```shell
chmod 750 /etc/letsencrypt/live/
chmod 750 /etc/letsencrypt/archive/
chmod 640 /etc/letsencrypt/archive/vm.yourdomain.org/privkey1.pem
chgrp -R caddy /etc/letsencrypt/archive/
chgrp -R caddy /etc/letsencrypt/live/
```

Configure Caddy:
```shell
cat >/etc/caddy/Caddyfile <<EOL

vm.yourdomain.org:443 {
    tls /etc/letsencrypt/live/vm.yourdomain.org/fullchain.pem /etc/letsencrypt/live/vm.yourdomain.org/privkey.pem
    reverse_proxy http://127.0.0.1:8080 {
        # Forward Host header to the backend
        header_up Host {host}
    }
}

*.vm.yourdomain.org:443 {
    tls /etc/letsencrypt/live/vm.yourdomain.org/fullchain.pem /etc/letsencrypt/live/vm.yourdomain.org/privkey.pem
    reverse_proxy http://127.0.0.1:8080 {
        # Forward Host header to the backend
        header_up Host {host}
    }
}
EOL
```

Finally, restard Caddy:
```shell
sudo systemctl restart caddy
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
