KERNEL=linux-5.12.10/arch/x86_64/boot/bzImage

qemu-system-x86_64 \
	-M microvm,x-option-roms=off,isa-serial=off,rtc=off \
	-no-acpi -enable-kvm \
	-cpu host \
	-nodefaults -no-user-config -nographic -no-reboot \
	-device virtio-serial-device -chardev stdio,id=virtiocon0 \
	-device virtconsole,chardev=virtiocon0 \
	-drive id=root,file=alpine.qcow2,format=qcow2,if=none \
	-device virtio-blk-device,drive=root \
	-kernel ${KERNEL} \
	-append "console=hvc0 root=/dev/vda rw acpi=off reboot=t panic=-1"
