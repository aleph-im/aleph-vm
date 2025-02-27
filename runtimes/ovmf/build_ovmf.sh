#! /bin/bash
# Script to build OVMF + Grub for confidential computing. The resulting image will be
# a single firmware image containing OVMF and Grub so that the entirety of the unencrypted
# boot code can be measured before feeding secrets to the VM.

set -eo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

GRUB_DIR="${SCRIPT_DIR}/downloads/grub"
EDK2_DIR="${SCRIPT_DIR}/downloads/edk2"

if [ ! -d "${GRUB_DIR}" ]; then
  echo "Grub directory not found: ${GRUB_DIR}" >&2
fi

if [ ! -d "${EDK2_DIR}" ]; then
  echo "EDK2 directory not found: ${EDK2_DIR}" >&2
fi

apt-get update
# Packages for Grub
apt-get install -y autoconf autopoint binutils bison flex gcc gettext git make pkg-config python3 python-is-python3
# Packages for OVMF (there are some duplicates with Grub, kept for documentation)
apt-get install -y bison build-essential dosfstools flex iasl libgmp3-dev libmpfr-dev mtools nasm subversion texinfo uuid-dev

cd $GRUB_DIR
./bootstrap
./configure --prefix /usr/ --with-platform=efi --target=x86_64
make
make install

# Build OVMF
cd $EDK2_DIR
OvmfPkg/build.sh -b RELEASE -p OvmfPkg/AmdSev/AmdSevX64.dsc
