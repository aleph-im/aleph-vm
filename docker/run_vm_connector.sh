#!/bin/sh

set -euf

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -t aleph-connector -f docker/vm_connector.dockerfile .

$DOCKER_COMMAND run -ti --rm -p 4021:4021/tcp \
  -v "$(pwd)/kernels:/opt/kernels:ro" \
  -v "$(pwd)/vm_connector:/opt/vm_connector:ro" \
  --name aleph-connector \
  aleph-connector "$@"
