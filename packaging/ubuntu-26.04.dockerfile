FROM ubuntu:26.04

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

# rustup instead of the distro cargo: plain cargo ignores
# rust-toolchain.toml, rustup enforces the pin. The default toolchain
# mirrors rust/rust-toolchain.toml (if they drift, rustup auto-installs the
# toml channel below); sevctl builds with the same toolchain.
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain 1.90
ENV PATH="/root/.cargo/bin:${PATH}"

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
