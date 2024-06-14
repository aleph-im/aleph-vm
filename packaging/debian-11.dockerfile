FROM rust:bullseye

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    make \
    git \
    curl \
    sudo \
    python3-pip \
    cargo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY ../src/aleph/ ./src/aleph
COPY ../packaging ./packaging
COPY ../kernels ./kernels

COPY ../examples/ ./examples
