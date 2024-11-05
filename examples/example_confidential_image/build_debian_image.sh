#!/bin/bash

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

ROOTFS_DIR=""
IMAGE_SIZE="4GB"
IMAGE_FILE=""
MAPPER_NAME="cr_root"
LOOP_DEVICE_ID=""
MAPPED_DEVICE_ID=""
MOUNT_POINT=""
CLEANUP_DONE=false

cleanup() {
  if [ "$CLEANUP_DONE" = true ]; then
    return
  fi
  CLEANUP_DONE=true
  if mountpoint -q "${MOUNT_POINT}"; then
    sudo umount --recursive "${MOUNT_POINT}" || echo "Failed to unmount ${MOUNT_POINT}"
  fi
  if [ -n "${MAPPED_DEVICE_ID}" ]; then
    sudo cryptsetup close "${MAPPED_DEVICE_ID}" || echo "Failed to close encrypted device ${MAPPED_DEVICE_ID}"
  fi
  if [ -n "${LOOP_DEVICE_ID}" ]; then
    sudo losetup -d "${LOOP_DEVICE_ID}" || echo "Failed to detach loop device ${LOOP_DEVICE_ID}"
  fi
  if [ -f "${KEY_FILE}" ]; then
    rm -f "${KEY_FILE}" || echo "Failed to remove key file ${KEY_FILE}"
  fi
}


# Trap command to catch and handle various signals:
# - EXIT: Triggered when the script exits (normal completion or an error).
# - HUP (SIGHUP): Signal 1, sent when the controlling terminal is closed (e.g., terminal window closed or SSH session logout).
# - INT (SIGINT): Signal 2, sent when the user interrupts the process (e.g., pressing Ctrl+C).
# - QUIT (SIGQUIT): Signal 3, sent when the user requests the process to quit and perform a core dump (e.g., pressing Ctrl+\).
# - PIPE (SIGPIPE): Signal 13, sent when attempting to write to a pipe without a reader (e.g., in scripts using pipelines if a command in the pipeline exits prematurely).
# - TERM (SIGTERM): Signal 15, sent by the kill command to request the process to terminate gracefully.
trap cleanup EXIT HUP INT QUIT PIPE TERM

error_handler() {
	echo ""
	echo "An error occured while building the image and the process was not completed properly."
	echo "Please check the log, fix any error if required and restart the script."
	echo "For more help see https://docs.aleph.im/computing/confidential/encrypted-disk/"
}

trap error_handler ERR

usage() {
  cat <<USAGE >&2
Usage:
    $0 --rootfs-dir ROOTFS_DIR [--image-size IMAGE_SIZE] [--password DISK_PASSWORD] [--mapper-name MAPPER_NAME]
    -o IMAGE_FILE | --output IMAGE_FILE       Image file to use. Defaults to "<ROOTFS_DIR>.img."
    -p DISK_PASSWORD | --password=DISK_PASSWORD   Password to use for the encrypted disk. Automatically generated if not specified.
    -r ROOTFS_DIR | --rootfs-dir=ROOTFS_DIR   Directory containing the original rootfs.
    -s IMAGE_SIZE | --image-size IMAGE_SIZE   Size of the target image, ex: 20GB. Defaults to 4GB.
    -m MAPPER_NAME | --mapper-name=MAPPER_NAME   Device mapped name for encrypted disk. Default to "cr_root" if not specified.
USAGE
}

while true; do
  case "$1" in
  -o | --output)
    IMAGE_FILE=$2
    shift 2
    ;;
  -p | --password)
    DISK_PASSWORD=$2
    shift 2
    ;;
  -r | --rootfs-dir)
    ROOTFS_DIR=$2
    shift 2
    ;;
  -s | --image-size)
    IMAGE_SIZE=$2
    shift 2
    ;;
  -m | --mapper-name)
      MAPPER_NAME=$2
      shift 2
      ;;
  *)
    break
    ;;
  esac
done

if [ -z "${ROOTFS_DIR}" ]; then
  usage
  exit 1
fi

if [ -z "${DISK_PASSWORD}" ]; then
  echo "No disk password provided. Generating one..."
  DISK_PASSWORD=$(
    tr </dev/urandom -dc _A-Z-a-z-0-9 | head -c${1:-16}
    echo
  )
fi

if [ -z "${IMAGE_FILE}" ]; then
  IMAGE_FILE="$(basename ${ROOTFS_DIR}).img"
fi

BOOT_PARTITION_SIZE=100MiB
KEY_FILE="${SCRIPT_DIR}/os_partition.key"

truncate -s "${IMAGE_SIZE}" "${IMAGE_FILE}"

# Create two partitions: a FAT32 boot partition for Grub and an ext4 partition for Debian
# TODO: is there a way to do all this without sudo?
echo "Creating partitions..."
sudo parted "${IMAGE_FILE}" mklabel gpt
sudo parted "${IMAGE_FILE}" mkpart primary 1Mib "${BOOT_PARTITION_SIZE}"
sudo parted "${IMAGE_FILE}" mkpart primary "${BOOT_PARTITION_SIZE}" 100%

# Mark partition 1 as boot+ESP
sudo parted "${IMAGE_FILE}" set 1 esp on
sudo parted "${IMAGE_FILE}" set 1 boot on

# Mount the disk as a loop device and get the device ID
LOOP_DEVICE_ID=$(sudo losetup --partscan --find --show "${IMAGE_FILE}")
BOOT_PARTITION_DEVICE_ID="${LOOP_DEVICE_ID}p1"
OS_PARTITION_DEVICE_ID="${LOOP_DEVICE_ID}p2"

# Format the boot partition
echo "Formatting the boot partition..."
sudo mkfs.vfat "${BOOT_PARTITION_DEVICE_ID}"

echo "Encrypting and formatting the OS partition..."
MAPPED_DEVICE_ID="/dev/mapper/${MAPPER_NAME}"
MOUNT_POINT="/mnt/${MAPPER_NAME}"
echo -n "${DISK_PASSWORD}" >"${KEY_FILE}"

sudo cryptsetup --batch-mode --type luks1 --key-file "${KEY_FILE}" luksFormat "${OS_PARTITION_DEVICE_ID}"
sudo cryptsetup open --key-file "${KEY_FILE}" "${OS_PARTITION_DEVICE_ID}" "${MAPPER_NAME}"
sudo mkfs.ext4 "${MAPPED_DEVICE_ID}"

echo "Copying root file system to the new OS partition..."
sudo mkdir -p "${MOUNT_POINT}"
sudo mount "${MAPPED_DEVICE_ID}" "${MOUNT_POINT}"
sudo cp --archive "${ROOTFS_DIR}"/* "${MOUNT_POINT}"

echo "Configuring root file system..."
for m in run sys proc dev; do sudo mount --bind /$m ${MOUNT_POINT}/$m; done
sudo cp "${SCRIPT_DIR}/setup_debian_rootfs.sh" "${KEY_FILE}" "${MOUNT_POINT}"
sudo chroot "${MOUNT_POINT}" bash setup_debian_rootfs.sh --loop-device-id "${LOOP_DEVICE_ID}" --mapper-name "${MAPPER_NAME}"
sudo rm "${MOUNT_POINT}/setup_debian_rootfs.sh" "${KEY_FILE}"

cleanup

echo "Done! The new image is available as ${IMAGE_FILE}."
echo "Disk password: ${DISK_PASSWORD}"
