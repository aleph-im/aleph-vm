# Aleph VM

> Note: This project is still early prototyping.

The Aleph VM project allows you to run programs on [Aleph.im](https://aleph.im/).

These programs can currently be written in Python using ASGI compatible frameworks (
[FastAPI](https://github.com/tiangolo/fastapi), 
[Django](https://docs.djangoproject.com/en/3.0/topics/async/), 
[Sanic](https://sanicframework.org/),
...) and respond to HTTP requests.

## Architecture

![image](https://user-images.githubusercontent.com/404665/115885445-452f5180-a450-11eb-856e-f4071023a105.png)

### VM Supervisor

Actually runs the programs in a secure environment on virtualization enabled systems. 

See [vm_supervisor/README.md](./vm_supervisor/README.md).

### VM Connector

Schedules the execution of programs on VM Supervisors and assists
them with operations related to the Aleph network.

See [vm_connector/README.md](./vm_connector/README.md).

---

![aleph.im logo](https://aleph.im/assets/img/logo-wide.1832dbae.svg)
