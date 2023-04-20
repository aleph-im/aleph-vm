QCOW2_IMAGE_FILE="/home/olivier/Downloads/debian-11-nocloud-amd64-20230124-1270.qcow2"
#IMAGE_FILE="/home/olivier/Downloads/debian-11-nocloud-amd64-20230124-1270.raw"
#IMAGE_FILE="/home/olivier/git/aleph/aleph-vm/runtimes/aleph-debian-11-python/rootfs.squashfs"
IMAGE_FILE="/home/olivier/git/aleph/aleph-vm/runtimes/test/rootfs.ext4"
#KERNEL="/boot/vmlinuz-5.19.0-38-generic"
#KERNEL="/home/olivier/git/aleph/aleph-vm/kernels/linux-5.10.124/vmlinux"
KERNEL="/home/olivier/git/aleph/aleph-vm/kernels/linux-5.12.10/arch/x86_64/boot/bzImage"

#qemu-system-x86_64 -M microvm \
#   -enable-kvm -cpu host -m 512m -smp 2 \
#   -kernel ${KERNEL} \
#   -append "earlyprintk=ttyS0 console=ttyS0 root=/dev/vda reboot=k panic=1 pci=off ro noapic nomodules random.trust_cpu=on" \
#   -nodefaults -no-user-config -nographic \
#   -serial stdio \
#   -drive id=rootfs,file=${IMAGE_FILE},format=raw \
#   -device virtio-blk-device,drive=rootfs \
#   -netdev tap,id=tap0,script=no,downscript=no \
#   -device virtio-net-device,netdev=tap0

# Boots the Debian image (tested)
#qemu-system-x86_64 -M microvm \
#   -enable-kvm -cpu host -m 512m -smp 2 \
#   -nodefaults -no-user-config -nographic \
#   -serial stdio \
#   -drive id=test,file=${QCOW2_IMAGE_FILE},format=qcow2,if=none \
#   -device virtio-blk-device,drive=test \
#   -netdev tap,id=tap0,script=no,downscript=no \
#   -device virtio-net-device,netdev=tap0

/usr/local/bin/qemu-system-x86_64 \
  -drive format=qcow2,file=/home/olivier/Downloads/debian-11-nocloud-amd64-20230124-1270.qcow2 \
  -enable-kvm \
  -m 2048 \
  -nic user,model=virtio \
  -nographic \
  -serial mon:stdio
