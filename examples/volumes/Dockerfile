FROM debian:bullseye

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    python3-venv \
    squashfs-tools \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
RUN /opt/venv/bin/pip install 'git+https://github.com/aleph-im/aleph-message.git@hoh-durable-vms'

CMD mksquashfs /opt/venv /mnt/volume-venv.squashfs
