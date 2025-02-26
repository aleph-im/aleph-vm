FROM rust:1.79.0-bookworm

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    make \
    git \
    curl \
    sudo \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY ../src/aleph ./src/aleph
COPY ../packaging ./packaging
COPY ../kernels ./kernels

COPY ../examples/ ./examples
