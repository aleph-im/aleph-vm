#KERNEL="/boot/vmlinuz-5.19.0-38-generic"
KERNEL="/home/olivier/git/aleph/aleph-vm/kernels/linux-5.12.10-normal/arch/x86/boot/bzImage"
#KERNEL="/tmp/linux/arch/x86/boot/bzImage"
#KERNEL="/home/odesenfans/git/aleph/aleph-vm/kernels/linux-5.10.124/vmlinux"
#ROOTFS=alpine.qcow2
ROOTFS="/home/olivier/git/aleph/aleph-vm/runtimes/aleph-debian-11-python/rootfs.squashfs"
CODE_VOLUME="/home/olivier/git/aleph/aleph-vm/examples/example_fastapi.squashfs"
VENV_VOLUME="/home/olivier/git/aleph/aleph-vm/examples/volumes/volume-venv.squashfs"

VMN=3

qemu-system-x86_64 \
	-enable-kvm \
	-cpu host \
	-m 512 -smp 2 \
	-nodefaults \
	-no-user-config \
	-nographic \
	-serial mon:stdio \
	-no-reboot \
	-device vhost-vsock-pci,guest-cid=${VMN} \
	-drive id=root,file=${ROOTFS},format=raw,if=virtio \
	-drive id=code,file=${CODE_VOLUME},format=raw,if=virtio \
	-drive id=venv,file=${VENV_VOLUME},format=raw,if=virtio \
	-kernel ${KERNEL} \
	-append "console=ttyS0 root=/dev/vda" \
  -machine pit=off,pic=off
#  -machine pit=off,pic=off,isa-serial=off,rtc=off
