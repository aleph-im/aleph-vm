# Aleph-VM

> Note: This project is still early prototyping.

The Aleph-VM project allows you to run programs on [Aleph.im](https://aleph.im/).

Programs can currently be written in Python using ASGI compatible frameworks (
[FastAPI](https://github.com/tiangolo/fastapi), 
[Django](https://docs.djangoproject.com/en/3.0/topics/async/),
...) and respond to HTTP requests. 

Alternatively, programs written in any language can listen to HTTP requests on port 8080.

### 1. Writing Aleph-VM programs

Have a look at [tutorials/README.md](tutorials/README.md) for a tutorial on how to program VMs
as a user.

The rest of this document focuses on how to run an Aleph-VM node that hosts and executes the programs. 

## 1. Quick install

To quickly install Aleph-VM on a [supported Linux system](./vm_supervisor/README.md#1-supported-platforms)
for production purposes:

```shell
sudo apt update
sudo apt install -y docker.io
sudo docker run -d -p 127.0.0.1:4021:4021/tcp --restart=always --name vm-connector alephim/vm-connector:alpha
wget https://github.com/aleph-im/aleph-vm/releases/download/0.1.6-1/aleph-vm-0.1.6-1.deb
sudo apt install ./aleph-vm-0.1.6-1.deb
```

### Configuration

You can update the configuration in `/etc/aleph-vm/supervisor.env`. 

On Ubuntu, the default network interface is not `eth0` and you will want to configure the default interface in the form of:
```
ALEPH_VM_NETWORK_INTERFACE=enp0s1
```

You can find all available options in [./vm_supervisor/conf.py](./vm_supervisor/conf.py).

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
vm.yourdomain.org:443, *:443 {
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

## 2. Architecture

![Aleph im VM - Details](https://user-images.githubusercontent.com/404665/127126908-3225a633-2c36-4129-8766-9810f2fcd7d6.png)

### VM Supervisor

Actually runs the programs in a secure environment on virtualization enabled systems. 

See [vm_supervisor/README.md](./vm_supervisor/README.md).

### VM Connector

Assist with operations related to the Aleph network.

See [vm_connector/README.md](./vm_connector/README.md).

## Creating and running an Aleph Program 

See [examples/README.md](./examples/README.md).

---

![aleph.im logo](https://aleph.im/assets/img/logo-wide.1832dbae.svg)
