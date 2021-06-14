#!/bin/sh

set -euf

docker build -t aleph-connector -f docker/vm_connector.dockerfile .

docker run -ti --rm -p 8000:8000/tcp \
  -v "$(pwd)/kernels:/opt/kernels:ro" \
  -v "$(pwd)/vm_connector:/opt/vm_connector:ro" \
  --name aleph-connector \
  aleph-connector "$@"
