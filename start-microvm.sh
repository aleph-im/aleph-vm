#KERNEL=linux-5.12.10/arch/x86_64/boot/bzImage
KERNEL="/home/olivier/git/aleph/aleph-vm/kernels/linux-5.10.124/arch/x86/boot/bzImage"
#KERNEL="/home/odesenfans/git/aleph/aleph-vm/kernels/linux-5.10.124/vmlinux"
#ROOTFS=alpine.qcow2
ROOTFS="/home/olivier/git/aleph/aleph-vm/runtimes/aleph-debian-11-python/rootfs.squashfs"
CODE_VOLUME="/home/olivier/git/aleph/aleph-vm/examples/example_fastapi.squashfs"
VENV_VOLUME="/home/olivier/git/aleph/aleph-vm/examples/volumes/volume-venv.squashfs"

qemu-system-x86_64 \
	-M microvm,x-option-roms=off,isa-serial=off,rtc=off \
	-no-acpi -enable-kvm \
	-cpu host \
	-m 512 -smp 2 \
	-nodefaults -no-user-config -nographic -no-reboot \
	-device virtio-serial-device -chardev stdio,id=virtiocon0 \
	-device virtconsole,chardev=virtiocon0 \
	-drive id=root,file=${ROOTFS},format=raw,if=none \
	-device virtio-blk-device,drive=root \
	-drive id=code,file=${CODE_VOLUME},format=raw,if=none \
	-device virtio-blk-device,drive=code \
	-drive id=venv,file=${VENV_VOLUME},format=raw,if=none \
	-device virtio-blk-device,drive=venv \
	-kernel ${KERNEL} \
	-append "console=hvc0 root=/dev/vda rw acpi=off reboot=t panic=-1"
