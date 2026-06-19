"""Generate a cloud-init ISO image for the VM configuration.

This module automates the creation of a cloud-init ISO image, which is utilized for configuring the
Virtual Machine. The configurations included in this process are the hostname, SSH keys, and network settings.

The generated ISO image, created using the `cloud-localds` command, is intended to be mounted as a CD-ROM inside the
VM. Upon booting, the VM's cloud-init service detects this CD-ROM and applies the configurations based on the data it
contains.

Refer to the cloud-init documentation, in particular the NoCloud datasource which is the method we are using.
https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html

See also the cloud-localds  man page (1)
"""

import json
from tempfile import NamedTemporaryFile

import yaml

# get_hostname_from_hash is the Aleph hostname convention, shared, neutral
# vocabulary; re-exported here for the cloud-init builder that uses it.
from aleph.vm.utils import get_hostname_from_hash, run_in_subprocess

__all__ = ["get_hostname_from_hash", "encode_user_data"]


def encode_user_data(
    hostname,
    ssh_authorized_keys,
    has_gpu: bool = False,
    is_confidential: bool = False,
    install_guest_agent: bool = True,
) -> bytes:
    """Creates user data configuration file for cloud-init tool"""
    config: dict[str, str | bool | list[str] | list[list[str]]] = {
        "hostname": hostname,
        "disable_root": False,
        "ssh_pwauth": False,
        "ssh_authorized_keys": ssh_authorized_keys,
        "resize_rootfs": True,
        "package_update": True,
    }

    bootcmd: list[list[str]] = []

    # Confidential instances use LUKS encryption. Cloud-init's growpart
    # expands the partition but can't resize the LUKS container (no keyfile).
    # Run growpart + cryptsetup resize + resize2fs ourselves in bootcmd,
    # which runs before cloud-init's cc_growpart/cc_resizefs modules.
    if is_confidential:
        bootcmd.append(["sh", "-c", "growpart /dev/vda 2 || true"])
        bootcmd.append(["sh", "-c", "cryptsetup resize cr_root || true"])
        bootcmd.append(["sh", "-c", "resize2fs /dev/mapper/cr_root || true"])

    # Add kernel boot parameters for GPU instances to speed up PCI enumeration
    # This significantly reduces boot time when large GPU BARs (Resizable BAR) are present
    if has_gpu:
        bootcmd += [
            # Update GRUB configuration to add PCI optimization parameters
            # pci=realloc=off: Skip PCI resource reallocation during boot
            # pci=noaer: Disable Advanced Error Reporting to reduce probing overhead
            [
                "sed",
                "-i",
                's/^GRUB_CMDLINE_LINUX_DEFAULT="\\(.*\\)"/GRUB_CMDLINE_LINUX_DEFAULT="\\1 pci=realloc=off pci=noaer"/',
                "/etc/default/grub",
            ],
            # Update GRUB for Debian/Ubuntu systems
            ["sh", "-c", "command -v update-grub >/dev/null 2>&1 && update-grub || true"],
            # Update GRUB for RHEL/CentOS systems
            [
                "sh",
                "-c",
                "command -v grub2-mkconfig >/dev/null 2>&1 && grub2-mkconfig -o /boot/grub2/grub.cfg || true",
            ],
        ]

    if bootcmd:
        config["bootcmd"] = bootcmd

    if install_guest_agent:
        config["packages"] = ["qemu-guest-agent"]
        config["runcmd"] = ["systemctl start qemu-guest-agent.service"]

    cloud_config_header = "#cloud-config\n"
    config_output = yaml.safe_dump(config, default_flow_style=False, sort_keys=False)
    content = (cloud_config_header + config_output).encode()
    return content


def create_metadata_file(hostname, vm_id) -> bytes:
    """Creates metadata configuration file for cloud-init tool"""
    metadata = {
        "instance-id": f"iid-instance-{vm_id}",
        "local-hostname": hostname,
    }
    return json.dumps(metadata).encode()


def create_network_file(ip, ipv6, ipv6_gateway, nameservers, route) -> bytes:
    """Creates network configuration file for cloud-init tool"""
    network = {
        "ethernets": {
            "eth0": {
                # Match the config to the `virtio` driver since the network interface name is not constant across distro
                "match": {"driver": "virtio_net"},
                "addresses": [ip, ipv6],
                "gateway4": route,
                "gateway6": ipv6_gateway,
                "nameservers": {
                    "addresses": nameservers,
                },
                # there is a bug in Centos 7 where it will try DHCP if the key is present, even if set to false
                # https://stackoverflow.com/questions/59757022/set-static-ip-using-cloud-init-on-centos-7-with-terraform-kvm
                # Thus theses are commented for now
                # "dhcp4": False,
                # "dhcp6": False,
            },
        },
        "version": 2,
    }
    return yaml.safe_dump(network, default_flow_style=False, sort_keys=False).encode()


async def create_cloud_init_drive_image(
    disk_image_path,
    hostname,
    vm_id,
    ip,
    ipv6,
    ipv6_gateway,
    nameservers,
    route,
    ssh_authorized_keys,
    has_gpu: bool = False,
    is_confidential: bool = False,
    install_guest_agent: bool = True,
):
    with (
        NamedTemporaryFile() as user_data_config_file,
        NamedTemporaryFile() as network_config_file,
        NamedTemporaryFile() as metadata_config_file,
    ):
        user_data = encode_user_data(
            hostname,
            ssh_authorized_keys,
            has_gpu=has_gpu,
            is_confidential=is_confidential,
            install_guest_agent=install_guest_agent,
        )
        user_data_config_file.write(user_data)
        user_data_config_file.flush()
        network_config = create_network_file(ip, ipv6, ipv6_gateway, nameservers, route)
        network_config_file.write(network_config)
        network_config_file.flush()

        metadata_config = create_metadata_file(hostname, vm_id)
        metadata_config_file.write(metadata_config)
        metadata_config_file.flush()

        await run_in_subprocess(
            [
                "cloud-localds",
                f"--network-config={network_config_file.name}",
                str(disk_image_path),
                user_data_config_file.name,
                metadata_config_file.name,
            ]
        )
