FROM rust:bullseye

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     python3-pip \
     squashfs-tools \
     && rm -rf /var/lib/apt/lists/*

RUN pip install aleph-client

WORKDIR /usr/src/example_http_rust
COPY . .

RUN cargo install --path .
