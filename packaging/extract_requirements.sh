#!/bin/bash
set -euf -o pipefail

export DEBIAN_FRONTEND=noninteractive

apt update
apt --yes install /opt/packaging/target/aleph-vm.deb
pip freeze > $1
