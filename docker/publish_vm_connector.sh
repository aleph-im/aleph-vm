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

$DOCKER_COMMAND build -t alephim/vm-connector -f docker/vm_connector.dockerfile .

$DOCKER_COMMAND tag alephim/vm-connector alephim/vm-connector:$VERSION
$DOCKER_COMMAND push alephim/vm-connector:$VERSION docker.io/alephim/vm-connector:$VERSION
echo docker.io/alephim/pyaleph-node:$VERSION
