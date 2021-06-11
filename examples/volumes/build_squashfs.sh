#!/bin/sh

set -euf

podman build -t aleph-vm-build-squashfs .
podman run --rm -ti -v "$( dirname "$0" )":/mnt aleph-vm-build-squashfs
