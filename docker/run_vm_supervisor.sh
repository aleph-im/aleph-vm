#!/bin/sh

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -t alephim/vm-supervisor-dev -f docker/vm_supervisor-dev.dockerfile .

$DOCKER_COMMAND run -ti --rm \
  -v "$(pwd)/runtimes/aleph-debian-11-python/rootfs.squashfs:/opt/aleph-vm/runtimes/aleph-debian-11-python/rootfs.squashfs:ro" \
  -v "$(pwd)/examples/volumes/volume-venv.squashfs:/opt/aleph-vm/examples/volumes/volume-venv.squashfs:ro" \
  -v "$(pwd)/vm_supervisor:/opt/aleph-vm/vm_supervisor:ro" \
  -v "$(pwd)/firecracker:/opt/aleph-vm/firecracker:ro" \
  --device /dev/kvm \
  -p 4020:4020 \
  alephim/vm-supervisor-dev $@
