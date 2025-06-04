# This is mainly a copy of the installation instructions from [orchestrator/README.md]

FROM debian:bookworm

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    sudo acl curl squashfs-tools git \
    python3 python3-aiohttp python3-alembic python3-msgpack python3-pip python3-aiodns python3-aioredis\
    python3-nftables python3-psutil python3-setproctitle python3-sqlalchemy python3-packaging ndppd nftables \
    && rm -rf /var/lib/apt/lists/*

RUN useradd jailman

RUN mkdir /opt/firecracker
RUN chown $(whoami) /opt/firecracker
RUN curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.3.3/firecracker-v1.3.3-x86_64.tgz | tar -xz --no-same-owner --directory /opt/firecracker
RUN curl -fsSL -o /opt/firecracker/vmlinux.bin https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin

# Link binaries on version-agnostic paths:
RUN ln /opt/firecracker/release-*/firecracker-v* /opt/firecracker/firecracker
RUN ln /opt/firecracker/release-*/jailer-v* /opt/firecracker/jailer

RUN pip3 install typing-extensions 'aleph-message~=1.0.1'

RUN mkdir -p /var/lib/aleph/vm/jailer

ENV PYTHONPATH /mnt

# Networking only works in privileged containers
ENV ALEPH_VM_ALLOW_VM_NETWORKING False
ENV ALEPH_VM_NETWORK_INTERFACE "tap0"
# Jailer does not work in Docker containers
ENV ALEPH_VM_USE_JAILER False
# Use fake test data
ENV ALEPH_VM_FAKE_DATA True
# Allow connections from host
ENV ALEPH_VM_SUPERVISOR_HOST "0.0.0.0"

# Make it easy to enter this command from a shell script
RUN echo "python3 -m vm_supervisor --print-settings --very-verbose --system-logs --profile -f ./examples/example_fastapi" >> /root/.bash_history

RUN mkdir /opt/aleph-vm/
COPY ./vm_supervisor /opt/aleph-vm/vm_supervisor
COPY ./firecracker /opt/aleph-vm/firecracker
COPY ./guest_api /opt/aleph-vm/guest_api
COPY ./examples /opt/aleph-vm/examples
COPY ./runtimes /opt/aleph-vm/runtimes

WORKDIR /opt/aleph-vm

CMD "bash"
