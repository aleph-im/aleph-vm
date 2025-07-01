# Aleph-VM

The Aleph-VM project allows you to run programs on [Aleph Cloud](https://aleph.cloud/).

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


Head over to the  official user doc [https://docs.aleph.cloud/nodes/compute/introduction/](https://docs.aleph.cloud/nodes/compute/introduction/) on how to run an Aleph Cloud Compute Resource
Node

## 2. Install Aleph-VM from source

This method is not recommended, except for development and testing.
Read the installation document for the various components and the developer documentation. 

1. Install the [VM-Connector](./vm_connector/README.md)
2. Install the [VM-Supervisor](src/aleph/vm/orchestrator/README.md).
3. Install and configure a reverse-proxy such as [Caddy](./CONFIGURE_CADDY.md)

## Create and run an Aleph Program 

Have a look at [tutorials/README.md](tutorials/README.md) for a tutorial on how to program VMs
as a user.

The rest of this document focuses on how to run an Aleph-VM node that hosts and executes the programs. 

# Developer Setup

Due to aleph-vm’s deep integration with the Linux system, it must be run with root privileges and configured
specifically for Linux. **It is strongly recommended** to deploy aleph-vm on a dedicated machine or a cloud-based server
to ensure security and stability.

> **Note**: aleph-vm does not run on macOS or Windows, including for testing purposes.

### Recommended Development Environment

A typical setup for developing aleph-vm involves:

1. Cloning the repository on your local machine for code editing.
2. Setting up a remote Linux server for deployment and testing.

You can synchronize changes to the remote server using tools like `rsync` or PyCharm’s Remote Interpreter feature.

## Remote Development Deployment

To deploy aleph-vm for development on a remote server, we start with the Debian package as it includes essential binaries like `firecracker` and `sevctl`, system
   configuration, and dependencies.

1. **Run the vm-connector.**

The vm-connector need to run for aleph-vm to works, even when running py.test.

Unless your focus is developing the VM-Connector, using the Docker image is easier.
   See the [VM-Connector README](./vm_connector/README.md) for more details.

   ```shell
   docker run -d -p 127.0.0.1:4021:4021/tcp --restart=always --name vm-connector alephim/vm-connector:alpha
   ```

2. **Install the Debian Package**
   Replace `1.2.0` with the latest release version.

   **On Debian 12 (Bookworm)**:
   ```shell
   wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/1.2.0/aleph-vm.debian-12.deb
   sudo apt install /opt/aleph-vm.debian-12.deb
   ```

   **On Ubuntu 22.04 (Jammy Jellyfish)**:
   ```shell
   sudo wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/1.2.0/aleph-vm.ubuntu-22.04.deb
   sudo apt install /opt/aleph-vm.ubuntu-22.04.deb
   ```

   **On Ubuntu 24.04 (Noble Numbat)**:
   ```shell
   sudo wget -P /opt https://github.com/aleph-im/aleph-vm/releases/download/1.2.0/aleph-vm.ubuntu-24.04.deb
   sudo apt install /opt/aleph-vm.ubuntu-24.04.deb
   ```

3. **Disable Systemd Service**  
   To prevent conflicts, deactivate the system version of aleph-vm by disabling its `systemd` service.

   ```shell
   sudo systemctl disable aleph-vm-supervisor.service
   ```

4. **Clone the Repository and Set Up a Virtual Environment**
    - Clone the aleph-vm repository to your development environment.
    - Create a virtual environment to manage dependencies.

   Inside the virtual environment, run:

   ```shell
   pip install -e .
   ```

   This installs aleph-vm in "editable" mode within the virtual environment, allowing you to use the `aleph-vm` command
   directly during development.

## Testing
See [Testing doc](./TESTING.md)

## Code Formatting and Linting

To help maintain a clean and consistent codebase, we provide automated tools for formatting and style checks.
To ensure your code is properly **formatted** according to project standards, you can use:

```bash
hatch linting:fmt
```

**Typing** helps ensure your code adheres to expected type annotations, improving reliability and clarity. To validate
typing in your code, use:
```bash
hatch linting:typing
```

These checks are also validated in Continuous Integration (CI) alongside unit tests. To ensure a smooth workflow, we 
recommend running these commands before committing changes.

**Linting** checks for potential errors, coding style violations, and patterns that may lead to bugs or reduce code
quality (e.g., unused variables, incorrect imports, or inconsistent naming). While linting is not currently enforced in
Continuous Integration (CI), it is considered a best practice to check linting manually to maintain high-quality code.
You can manually lint your code by running:

```bash
hatch fmt
```

Following these best practices can help streamline code reviews and improve overall project quality.

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
