FROM ubuntu:22.04

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    make \
    git \
    curl \
    sudo \
    python3-pip \
    python3-venv \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# protoc for tonic-build (rust/crates/supervisor-proto). jammy's
# protobuf-compiler is 3.12, too old for proto3 `optional` (needs >= 3.15);
# install the upstream release matching the 3.21.12 the other distros ship.
RUN curl -fsSL -o /tmp/protoc.zip \
        https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip \
    && unzip -o /tmp/protoc.zip -d /usr/local bin/protoc 'include/*' \
    && rm /tmp/protoc.zip

# rustup instead of the distro cargo: plain cargo ignores
# rust-toolchain.toml, rustup enforces the pin (jammy's rustc is also too
# old for edition 2024). The default toolchain mirrors
# rust/rust-toolchain.toml (if they drift, rustup auto-installs the toml
# channel below); sevctl builds with the same toolchain.
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
