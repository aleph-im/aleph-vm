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

## 1. Install Aleph-VM from packages

Install Aleph-VM to run an Aleph.im Compute Resource Node easily from official pre-built packages.

- [On Debian 11](./doc/INSTALL-Debian-11.md)
- [On Debian 12](./doc/INSTALL-Debian-12.md)
- [On Ubuntu 22.04](./doc/INSTALL-Ubuntu-22.04.md)

## 2. Install Aleph-VM from source

For development and testing, install Aleph-VM from source.

1. Install the [VM-Connector](./vm_connector/README.md)
2. Install the [VM-Supervisor](src/aleph/vm/orchestrator/README.md).
3. Install and configure a reverse-proxy such as [Caddy](./CONFIGURE_CADDY.md)

## 3. Create and run an Aleph Program 

Have a look at [tutorials/README.md](tutorials/README.md) for a tutorial on how to program VMs
as a user.

The rest of this document focuses on how to run an Aleph-VM node that hosts and executes the programs. 

## 4. Architecture

![Aleph im VM - Details](https://user-images.githubusercontent.com/404665/127126908-3225a633-2c36-4129-8766-9810f2fcd7d6.png)

### VM Supervisor

Actually runs the programs in a secure environment on virtualization enabled systems. 

See [vm_supervisor/README.md](src/aleph/vm/orchestrator/README.md).

### VM Connector

Assist with operations related to the Aleph network.

See [vm_connector/README.md](./vm_connector/README.md).

---

![aleph.im logo](https://aleph.im/assets/img/logo-wide.1832dbae.svg)
