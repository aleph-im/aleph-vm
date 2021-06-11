#!/bin/sh

set -euf

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -t aleph-vm-build-squashfs .
$DOCKER_COMMAND run --rm -v "$(pwd)":/mnt aleph-vm-build-squashfs
