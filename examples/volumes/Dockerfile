FROM debian:bookworm

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    python3-venv \
    squashfs-tools \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install 'aleph-message~=1.0.1'

CMD mksquashfs /opt/venv /mnt/volume-venv.squashfs
