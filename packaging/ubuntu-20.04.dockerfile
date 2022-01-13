FROM ubuntu:20.04

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    make \
    git \
    curl \
    sudo \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY ../vm_supervisor ./vm_supervisor
COPY ../guest_api ./guest_api
COPY ../firecracker ./firecracker
COPY ../packaging ./packaging
COPY ../kernels ./kernels

COPY ../examples/ ./examples

RUN mkdir -p ./runtimes/aleph-debian-11-python
COPY ../runtimes/aleph-debian-11-python/rootfs.squashfs ./runtimes/aleph-debian-11-python/rootfs.squashfs
