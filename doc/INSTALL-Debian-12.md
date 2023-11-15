# Installing Aleph-VM on a server / Debian 12 Bookworm

## 0. Introduction

For production using official Debian packages.

## 1. Requirements

- A [supported Linux server](../src/aleph/vm/orchestrator/README.md#1-supported-platforms)
- A public domain name from a registrar and top level domain you trust. 

In order to run an official Aleph.im Compute Resource Node (CRN), you will also need the following resources:

- CPU (2 options):
  - Min. 8 cores / 16 threads, 3.0 ghz+ CPU (gaming CPU for fast boot-up of microVMs)
  - Min. 12 core / 24 threads, 2.4ghz+ CPU (datacenter CPU for multiple concurrent loads)
- RAM: 64GB
- STORAGE: 1TB (NVMe SSD preferred, datacenter fast HDD possible under conditions, you’ll want a big and fast cache)
- BANDWIDTH: Minimum of 500 MB/s

You will need a public domain name with access to add TXT and wildcard records.

> 💡 This documentation will use the invalid `vm.example.org` domain name. Replace it when needed.

## 2. Installation

Run the following commands as `root`:

First install the [VM-Connector](../vm_connector/README.md) using Docker:
```shell
apt update
apt upgrade
apt install -y docker.io apparmor-profiles
docker run -d -p 127.0.0.1:4021:4021/tcp --restart=always --name vm-connector alephim/vm-connector:alpha
```

Then install the [VM-Supervisor](../src/aleph/vm/orchestrator/README.md) using the official Debian package.
The procedure is similar for updates.
```shell
wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/0.3.0/aleph-vm.debian-12.deb
apt install /opt/aleph-vm.debian-12.deb
```

Reboot if required (new kernel, ...).

### Configuration

Update the configuration in `/etc/aleph-vm/supervisor.env` using your favourite editor.

#### Hostname

You will want to insert your domain name in the form of:
```
ALEPH_VM_DOMAIN_NAME=vm.example.org
```

#### Network configuration

The network configuration is detected automatically.

The default network interface is detected automatically from the IP routes. 
You can configure the default interface manually instead by adding:
```
ALEPH_VM_NETWORK_INTERFACE=enp0s1
```
(don't forget to replace `enp0s1` with the name of your default network interface).

You can configure the DNS resolver manually by using one of the following options:
```
ALEPH_VM_DNS_RESOLUTION=resolvectl
ALEPH_VM_DNS_RESOLUTION=resolv.conf
```

> 💡 You can instead specify the DNS resolvers used by the VMs using `ALEPH_VM_DNS_NAMESERVERS=["1.2.3.4", "5.6.7.8"]`.

#### Volumes and partitions

Two directories are used to store data from the network:
- `/var/lib/aleph/vm` contains all the execution and persistent data.
- `/var/cache/aleph/vm` contains data downloaded from the network.

These two directories must be stored on the same partition.
That partition must meet the minimum requirements specified for a CRN.

> 💡 This is required due to the software using hard links to optimize performance and disk usage.

#### Applying changes

Finally, restart the service:
```shell
systemctl restart aleph-vm-supervisor
```

## 3. Reverse Proxy

We document how to use Caddy as a reverse proxy since it manages and renews HTTPS certificates automatically.

Any other reverse-proxy (Nginx, HAProxy, Apache2, ...) should do the job as well, just make sure to renew the 
HTTPS/TLS certificates on time.

First, create a domain name that points to the server on IPv4 (A) and IPv6 (AAAA).

This is a simple configuration. For more options, check [CONFIGURE_CADDY.md](CONFIGURE_CADDY.md).

Again, run these commands as `root`:
```shell
 apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install caddy
```

Then, after replacing the domain `vm.example.org` with your own, use configure Caddy:
```shell
cat >/etc/caddy/Caddyfile <<EOL
{
    https_port 443
    on_demand_tls {
        interval 60s
        burst    5
    }
}
vm.example.org:443 {
    reverse_proxy http://127.0.0.1:4020 {
        # Forward Host header to the backend
        header_up Host {host}
    }
} 
EOL
```
Finally, restart Caddy to use the new configuration:
```shell
systemctl restart caddy
```

## 4. Test

Open https://[YOUR DOMAIN] in a web browser, wait for diagnostic to complete and look for 

> ![image](https://user-images.githubusercontent.com/404665/150202090-91a02536-4e04-4af2-967f-fe105d116e1f.png)

If you face an issue, check the logs of the different services for errors:

VM-Supervisor:
```shell
journalctl -f -u aleph-vm-supervisor.service 
```

Caddy:
```shell
journalctl -f -u caddy.service 
```

VM-Connector:
```shell
docker logs -f vm-connector
```

### Common errors

#### "Network interface eth0 does not exist"

Did you update the configuration file `/etc/aleph-vm/supervisor.env` with `ALEPH_VM_NETWORK_INTERFACE` equal to 
the default network interface of your server ?

#### "Aleph Connector unavailable"

Investigate the installation of the VM-Connector using Docker in step 2.
