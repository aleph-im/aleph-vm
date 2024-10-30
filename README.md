# Aleph-VM

The Aleph-VM project allows you to run programs on [Aleph.im](https://aleph.im/).

Aleph-VM is optimized to run programs on demand in a "function-as-as-service",
as a response to HTTP requests.

Programs can be written in any language as long as they can run a web server.
They benefit from running in their own, customizable Linux virtual environment.

Writing programs in Python using ASGI compatible frameworks (
[FastAPI](https://github.com/tiangolo/fastapi), 
[Django](https://docs.djangoproject.com/en/3.0/topics/async/),
...) allows developers to use advanced functionalities not yet available for other languages.

# Production install for Aleph-VM
## Installation from packages


Head over to the  official user doc https://docs.aleph.im/nodes/compute/ on how to run an Aleph.im Compute Resource
Node

## 2. Install Aleph-VM from source

This method is not recommended, except for development and testing.
Read the installation document for the various components and the developer documentaation. 

1. Install the [VM-Connector](./vm_connector/README.md)
2. Install the [VM-Supervisor](src/aleph/vm/orchestrator/README.md).
3. Install and configure a reverse-proxy such as [Caddy](./CONFIGURE_CADDY.md)

## Create and run an Aleph Program 

Have a look at [tutorials/README.md](tutorials/README.md) for a tutorial on how to program VMs
as a user.

The rest of this document focuses on how to run an Aleph-VM node that hosts and executes the programs. 

# Developer setup
As aleph-vm is highly integrated with the Linux system, modify it with it and run as root; it is HIGHLY advised to deploy it in a separate machine or server in the cloud.

Note that aleph-vm do not run on Mac or Windows, not even the test suite. 

A typical development set up would be to have a copy of the repo on your local machine and a deployment on a remote computer   to run and test it.
You can sync the remote dev using rsync or using the Remote interpreter option in pycharm.

## Deploying for dev on the remote
We use the Debian package as a base as it contain the binary such as firecracker and sevctl, system configuration and, will install the dependencies.

Unless specifically working on the vm-connector, it's easier to use the image from Docker. (
see [VM-Connector/READNE](./vm_connector/README.md) for detail)

```shell
docker run -d -p 127.0.0.1:4021:4021/tcp --restart=always --name vm-connector alephim/vm-connector:alpha
```


Then install the debian package. Replace 1.2.0 with the latest released version of course.

On Debian 12 (Bookworm):
```shell
wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/1.2.0/aleph-vm.debian-12.deb
apt install /opt/aleph-vm.debian-12.deb
```

On Ubuntu 22.04 (Jammy Jellyfish):
```
sudo wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/1.2.0/aleph-vm.ubuntu-22.04.deb
sudo apt install /opt/aleph-vm.ubuntu-22.04.deb
```

On Ubuntu 24.04 (Noble Numbat):
```
sudo wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/1.2.0/aleph-vm.ubuntu-24.04.deb
sudo apt install /opt/aleph-vm.ubuntu-24.04.deb
```

Deactivate the systemd service so the system version is not run and doesn't conflict with the version you will launch by hand.  

```shell
sudo systemctl disable aleph-vm-supervisor.service
```

Clone the repository and create a virtual env to contain the dependency it.

Inside the virtual env run
```shell
pip install -e .
```
This will install aleph-vm inside the  venv  in development mode, allowing you to run directly the aleph-vm command.


## Testing
see  [Testinc doc](./TESTING.md)

# Architecture

![Aleph im VM - Details](https://user-images.githubusercontent.com/404665/127126908-3225a633-2c36-4129-8766-9810f2fcd7d6.png)

### VM Supervisor (also called Orchestrator)

Actually runs the programs in a secure environment on virtualization enabled systems. 

See [vm_supervisor/README.md](src/aleph/vm/orchestrator/README.md).

### VM Connector

Assist with operations related to the Aleph network.

See [vm_connector/README.md](./vm_connector/README.md).

---

![aleph.im logo](https://aleph.im/assets/img/logo-wide.1832dbae.svg)
