FROM rust:1.79.0-bookworm

# protobuf-compiler: protoc for tonic-build (rust/crates/supervisor-proto).
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    make \
    git \
    curl \
    sudo \
    python3-pip \
    python3-venv \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Preinstall the toolchain pinned in rust/rust-toolchain.toml (design doc
# 2026-07-04-rust-supervisor-daemon-design.md, section 9) in its own layer,
# before the sources, so local image rebuilds do not re-download it on every
# source change. rustup reads the file when invoked from inside rust/.
COPY ../rust/rust-toolchain.toml ./rust/rust-toolchain.toml
RUN cd ./rust && rustup show

COPY ../src/aleph ./src/aleph
COPY ../proto ./proto
COPY ../rust ./rust
COPY ../packaging ./packaging
COPY ../kernels ./kernels

COPY ../examples/ ./examples
