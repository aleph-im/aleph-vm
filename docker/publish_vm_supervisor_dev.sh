#!/bin/bash
set -euf -o pipefail

if hash docker 2> /dev/null
then
  DOCKER_COMMAND=docker
else
  DOCKER_COMMAND=podman
fi

#VERSION=$(git describe --tags)-alpha
VERSION=alpha

$DOCKER_COMMAND build -t alephim/vm-supervisor-dev -f docker/vm_supervisor-dev.dockerfile .

$DOCKER_COMMAND tag alephim/vm-supervisor-dev alephim/vm-supervisor-dev:$VERSION
$DOCKER_COMMAND push alephim/vm-supervisor-dev:$VERSION docker.io/alephim/vm-supervisor-dev:$VERSION
echo docker.io/alephim/vm-supervisor-dev:$VERSION
