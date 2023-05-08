#!/bin/sh

export PYTHONPATH=$(pwd)

export ALEPH_VM_ALLOW_VM_NETWORKING=False
export ALEPH_VM_NETWORK_INTERFACE=tap0
export ALEPH_VM_USE_JAILER=False
export ALEPH_VM_FAKE_DATA=True
export ALEPH_VM_SUPERVISOR_HOST=0.0.0.0

export BENCHMARK_FAKE_DATA_PROGRAM=$(pwd)/examples/example_docker_container
export FAKE_DATA_MESSAGE=$(pwd)/examples/message_from_aleph_docker_runtime.json
export FAKE_DATA_DATA=$(pwd)/examples/data/
export FAKE_DATA_RUNTIME=$(pwd)/runtimes/aleph-docker/rootfs.squashfs
export FAKE_DATA_VOLUME=$(pwd)/examples/volumes/docker/layers:/opt/docker/layers,$(pwd)/examples/volumes/docker/metadata:/opt/docker/metadata


python3 -m vm_supervisor --print-settings --very-verbose --system-logs --profile -f ./examples/example_docker_container