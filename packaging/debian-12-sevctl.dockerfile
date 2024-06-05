# Build sevctl inside an OCI Image with an upstream version of Rust.
# sevctl requires a version of Rust more recent than the one available in Debian stable.
# The binary built should be static and portable across Linux systems (to be validated).

FROM rust:1.78.0-bookworm
WORKDIR /opt
RUN git clone --depth 1 --branch v0.4.3 https://github.com/virtee/sevctl.git
WORKDIR /opt/sevctl
RUN cargo build --release --target x86_64-unknown-linux-gnu

VOLUME /target
CMD cp /opt/sevctl/target/x86_64-unknown-linux-gnu/release/sevctl /target/sevctl
