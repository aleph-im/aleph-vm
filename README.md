# Aleph-VM

The Aleph-VM project allows you to run programs on [Aleph.im](https://aleph.im/).

Aleph-VM is optimized to run programs on demand in a "function-as-as-service",
as a response to HTTP requests.

Programs can be written in any language as long as they can run a web server.
They benefit from running in their own, customizable Linux virtual environment.

Writing programs in Python using ASGI compatible frameworks (
[FastAPI](https://github.com/tiangolo/fastapi), 
[Django](https://docs.djangoproject.com/en/3.0/topics/async/),
...) allows developers to use advanced functionnalities not yet available for other languages.

## 1. Creating and running an Aleph Program 

Have a look at [tutorials/README.md](tutorials/README.md) for a tutorial on how to program VMs
as a user.

The rest of this document focuses on how to run an Aleph-VM node that hosts and executes the programs. 

## 2. Installing Aleph-VM on a server

### 0. Requirements

- A [supported Linux server](./vm_supervisor/README.md#1-supported-platforms)
- A public domain name from a trusted registar and domain. 

In order to run an Aleph.im Compute Resource Node, you will also need the following resources:

- CPU (2 options):
  - Min. 8 cores / 16 threads, 3.0 ghz+ CPU (gaming CPU for fast boot-up of microVMs)
  - Min. 12 core / 24 threads, 2.4ghz+ CPU (datacenter CPU for multiple concurrent loads)
- RAM: 64GB
- STORAGE: 1TB (Nvme SSD prefered, datacenter fast HDD possible under conditions, you’ll want a big and fast cache)
- BANDWIDTH: Minimum of 500 MB/s

You will need a public domain name with access to add TXT and wildcard records.

This documentation will use the invalid `vm.example.org` domain name. Replace it when needed.

### 1. Quick install

To quickly install Aleph-VM on a [supported Linux system](./vm_supervisor/README.md#1-supported-platforms)
for production purposes:

```shell
sudo apt update
sudo apt upgrade
sudo apt install -y docker.io
sudo docker run -d -p 127.0.0.1:4021:4021/tcp --restart=always --name vm-connector alephim/vm-connector:alpha
wget https://github.com/aleph-im/aleph-vm/releases/download/0.1.7/aleph-vm.debian-0.1.7-0.deb
sudo apt install .//aleph-vm.debian-0.1.7-0.deb
```

### Configuration

Update the configuration in `/etc/aleph-vm/supervisor.env`. 

You will want to insert your domain name in the for of:
```
ALEPH_VM_DOMAIN_NAME=vm.example.org
```

On Ubuntu, the default network interface is not `eth0` and you will want to configure the default interface. Due to the DNS being handled by `systemd-resolved` on Ubuntu, you should also configure the DNS to use `resolvectl`.
```
ALEPH_VM_NETWORK_INTERFACE=enp0s1
ALEPH_VM_DNS_RESOLUTION=resolvectl
```
(don't forget to replace `enp0s1` with the name of your default network interface).

You can find all available options in [./vm_supervisor/conf.py](./vm_supervisor/conf.py). Prefix them with `ALEPH_VM_`.

### Reverse Proxy

We document how to use Caddy as a reverse proxy since it does automatic HTTPS certificates.

First, create a domain name that points to the server on IPv4 and IPv6.

This is a simple configuration. For more options, check [CONFIGURE_CADDY.md](CONFIGURE_CADDY.md).
```shell
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo apt-key add -
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy

sudo cat >/etc/caddy/Caddyfile <<EOL
{
    https_port 443
    on_demand_tls {
        interval 60s
        burst    5
    }
}
vm.example.org:443, *:443 {
    tls {
        on_demand
    }
    reverse_proxy http://127.0.0.1:4020 {
        # Forward Host header to the backend
        header_up Host {host}
    }
} 
EOL

systemctl restart caddy
```

### Test

https://vm.yourdomain.org/vm/17412050fa1c103c41f983fe305c1ce8c6a809040762cdc1614bc32a06a28a63/state/increment

## 3. Architecture

![Aleph im VM - Details](https://user-images.githubusercontent.com/404665/127126908-3225a633-2c36-4129-8766-9810f2fcd7d6.png)

### VM Supervisor

Actually runs the programs in a secure environment on virtualization enabled systems. 

See [vm_supervisor/README.md](./vm_supervisor/README.md).

### VM Connector

Assist with operations related to the Aleph network.

See [vm_connector/README.md](./vm_connector/README.md).


---

![aleph.im logo](https://aleph.im/assets/img/logo-wide.1832dbae.svg)
