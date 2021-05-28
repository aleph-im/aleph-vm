# This is mainly a copy of the installation instructions from [vm_supervisor/README.md]

FROM debian:buster

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    sudo acl curl systemd-container  \
     python3 python3-aiohttp python3-msgpack python3-pip \
     && rm -rf /var/lib/apt/lists/*

RUN useradd jailman

RUN mkdir /opt/firecracker
RUN chown $(whoami) /opt/firecracker
RUN curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v0.24.2/firecracker-v0.24.2-x86_64.tgz | tar -xz --directory /opt/firecracker

# Link binaries on version-agnostic paths:
RUN ln /opt/firecracker/firecracker-v* /opt/firecracker/firecracker
RUN ln /opt/firecracker/jailer-v* /opt/firecracker/jailer

RUN pip3 install typing-extensions aleph-message pydantic

RUN mkdir /srv/jailer

ENV PYTHONPATH /mnt

# Networking does not work in Docker containers
ENV ALEPH_VM_ALLOW_VM_NETWORKING False
# Jailer does not work in Docker containers
ENV ALEPH_VM_USE_JAILER False
# Use fake test data
ENV ALEPH_VM_FAKE_DATA True

# Make it easy to enter this command from a shell script
RUN echo "python3 -m vm_supervisor -p -vv --system-logs --benchmark 1 --profile" >> /root/.bash_history

WORKDIR /root/aleph-vm
