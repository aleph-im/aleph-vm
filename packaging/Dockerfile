FROM debian:bullseye

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    make \
    git \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY ../vm_supervisor ./vm_supervisor
COPY ../guest_api ./guest_api
COPY ../firecracker ./firecracker
COPY ../packaging ./packaging
COPY ../kernels ./kernels
