#!/bin/sh

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -t alephim/vm-supervisor-dev -f docker/vm_supervisor-dev-docker.dockerfile .

$DOCKER_COMMAND run -ti --privileged --name=vm_supervisor_docker --rm \
  -v "$(pwd)/runtimes/aleph-docker/:/opt/aleph-vm/runtimes/aleph-docker/:ro" \
  -v "$(pwd)/examples/volumes/docker-data.squashfs:/opt/aleph-vm/examples/volumes/docker-data.squashfs:ro" \
  -v "$(pwd)/examples/example_docker_container:/opt/aleph-vm/examples/example_docker_container:ro" \
  -v "$(pwd)/vm_supervisor:/opt/aleph-vm/vm_supervisor:ro" \
  -v "$(pwd)/firecracker:/opt/aleph-vm/firecracker:ro" \
  --device /dev/kvm \
  -p 4020:4020 \
  alephim/vm-supervisor-dev $@
