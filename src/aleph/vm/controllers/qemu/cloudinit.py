import base64
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Union

import yaml
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.controllers.interface import AlephControllerInterface
from aleph.vm.hypervisors.firecracker.config import Drive
from aleph.vm.utils import is_command_available, run_in_subprocess

# https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html


def get_hostname_from_hash(vm_hash: ItemHash) -> str:
    item_hash_binary: bytes = base64.b16decode(vm_hash.encode().upper())
    return base64.b32encode(item_hash_binary).decode().strip("=").lower()


def encode_user_data(hostname, ssh_authorized_keys) -> bytes:
    """Creates user data configuration file for cloud-init tool"""
    config: dict[str, Union[str, bool, list[str]]] = {
        "hostname": hostname,
        "disable_root": False,
        "ssh_pwauth": False,
        "ssh_authorized_keys": ssh_authorized_keys,
        # Avoid the resize error because we already do it on the VM disk creation stage
        "resize_rootfs": False,
    }
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
                # Math the config to the `virtio` driver since the network interface name is not constant across distro
                "match": {"driver": "virtio_net"},
                "addresses": [ip, ipv6],
                "gateway4": route,
                "gateway6": ipv6_gateway,
                "nameservers": {
                    "addresses": nameservers,
                },
                # there is a bug in Centos 7 where it will try DHCP if the key is present, even if set to false
                # https://stackoverflow.com/questions/59757022/set-static-ip-using-cloud-init-on-centos-7-with-terraform-kvm
                # so we comment those for now
                # "dhcp4": False,
                # "dhcp6": False,
            },
        },
        "version": 2,
    }
    return yaml.safe_dump(network, default_flow_style=False, sort_keys=False).encode()


async def create_cloud_init_drive_image(
    disk_image_path, hostname, vm_id, ip, ipv6, ipv6_gateway, nameservers, route, ssh_authorized_keys
):
    with (
        NamedTemporaryFile() as user_data_config_file,
        NamedTemporaryFile() as network_config_file,
        NamedTemporaryFile() as metadata_config_file,
    ):
        user_data = encode_user_data(hostname, ssh_authorized_keys)
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


class CloudInitMixin(AlephControllerInterface):
    async def _create_cloud_init_drive(self) -> Drive:
        """Creates the cloud-init volume to configure and setup the VM"""
        # assert self.enable_networking and self.tap_interface, f"Network not enabled for VM {self.vm_id}"
        ssh_authorized_keys = self.resources.message_content.authorized_keys or []
        if settings.USE_DEVELOPER_SSH_KEYS:
            ssh_authorized_keys += settings.DEVELOPER_SSH_KEYS
        ip = self.get_vm_ip()
        route = self.get_vm_route()
        ipv6 = self.get_vm_ipv6()
        ipv6_gateway = self.get_vm_ipv6_gateway()
        vm_id = self.vm_id
        nameservers = settings.DNS_NAMESERVERS
        hostname = get_hostname_from_hash(self.vm_hash)

        disk_image_path: Path = settings.EXECUTION_ROOT / f"cloud-init-{self.vm_hash}.img"
        assert is_command_available("cloud-localds")

        await create_cloud_init_drive_image(
            disk_image_path,
            hostname,
            vm_id,
            ip,
            ipv6,
            ipv6_gateway,
            nameservers,
            route,
            ssh_authorized_keys,
        )

        return Drive(
            drive_id="Fake",
            path_on_host=disk_image_path,
            is_root_device=False,
            is_read_only=True,
        )
