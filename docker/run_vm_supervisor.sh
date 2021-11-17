#!/bin/sh

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -ti -t aleph-vm-supervisor -f docker/vm_supervisor.dockerfile .

$DOCKER_COMMAND run -ti --rm \
  -v $(pwd):/root/aleph-vm \
  --device /dev/kvm \
  -p 4020:4020 \
  aleph-vm-supervisor \
  bash
#  python3 -m vm_supervisor -p -vv --system-logs --profile -f ./examples/example_fastapi_2
