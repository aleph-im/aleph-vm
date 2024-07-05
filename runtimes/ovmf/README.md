# OVMF build for Confidential VMs

The files in this directory build a version of OVMF able to store SEV secrets
in a physical memory region that will then be accessible by Grub. The final OVMF image
also include Grub in order to measure OVMF+Grub before loading secrets inside
the VM.

This process relies on the patch sets produced by James Bottomley:
https://listman.redhat.com/archives/edk2-devel-archive/2020-November/msg01247.html

## Build instructions

As this requires a patched version of Grub, it is advised to build both tools inside a container.


e.g using podman
```
# Clone grub and edk2, and apply the patches
bash ./download_dependencies.sh
podman run -v ./build_ovmf.sh:/opt/build_ovmf.sh  -v ./downloads:/opt/downloads\
 ubuntu:22.04  bash /opt/download_dependencies.sh
# The OVMF.fd file will be in `downloads/edk2/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd
cp downloads/edk2/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd confidential-OVMF.fd
```
