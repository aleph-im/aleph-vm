import base64
import json
from tempfile import NamedTemporaryFile
from typing import Union, Optional

import yaml
from aleph.vm.conf import settings

from aleph.vm.utils import run_in_subprocess, is_command_available

from aleph.vm.hypervisors.firecracker.config import Drive

from aleph.vm.controllers.qemu import AlephControllerInterface


# https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html

class CloudInitMixin(AlephControllerInterface):
    def _get_hostname(self) -> str:
        item_hash_binary: bytes = base64.b16decode(self.vm_hash.encode().upper())
        return base64.b32encode(item_hash_binary).decode().strip("=").lower()

    def _encode_user_data(self) -> bytes:
        """Creates user data configuration file for cloud-init tool"""

        ssh_authorized_keys = self.resources.message_content.authorized_keys or []

        config: dict[str, Union[str, bool, list[str]]] = {
            "hostname": self._get_hostname(),
            "disable_root": False,
            "ssh_pwauth": False,
            "ssh_authorized_keys": ssh_authorized_keys,
            # Avoid the resize error because we already do it on the VM disk creation stage
            "resize_rootfs": False,
        }

        cloud_config_header = "#cloud-config\n"
        config_output = yaml.safe_dump(config, default_flow_style=False, sort_keys=False)

        return (cloud_config_header + config_output).encode()

    def _create_network_file(self) -> bytes:
        """Creates network configuration file for cloud-init tool"""

        assert self.enable_networking and self.tap_interface, f"Network not enabled for VM {self.vm_id}"

        ip = self.get_vm_ip()
        route = self.get_vm_route()
        ipv6 = self.get_vm_ipv6()
        ipv6_gateway = self.get_vm_ipv6_gateway()
        # TODO : had to change from eth0 -> ens3 for qemu
        # check for portable solution
        network = {
            "ethernets": {
                "ens3": {
                    "dhcp4": False,
                    "dhcp6": False,
                    "addresses": [ip, ipv6],
                    "gateway4": route,
                    "gateway6": ipv6_gateway,
                    "nameservers": {
                        "addresses": settings.DNS_NAMESERVERS,
                    },
                },
            },
            "version": 2,
        }

        return yaml.safe_dump(network, default_flow_style=False, sort_keys=False).encode()

    def _create_metadata_file(self) -> bytes:
        """Creates metadata configuration file for cloud-init tool"""

        metadata = {
            "instance-id": f"iid-instance-{self.vm_id}",
            "local-hostname": self._get_hostname(),
        }

        return json.dumps(metadata).encode()

    async def _create_cloud_init_drive(self) -> Drive:
        """Creates the cloud-init volume to configure and setup the VM"""

        assert is_command_available('cloud-localds')

        disk_image_path = settings.EXECUTION_ROOT / f"cloud-init-{self.vm_hash}.img"

        with NamedTemporaryFile() as user_data_config_file:
            user_data = self._encode_user_data()
            user_data_config_file.write(user_data)
            user_data_config_file.flush()
            with NamedTemporaryFile() as network_config_file:
                network_config = self._create_network_file()
                network_config_file.write(network_config)
                network_config_file.flush()
                with NamedTemporaryFile() as metadata_config_file:
                    metadata_config = self._create_metadata_file()
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

        return Drive(
            drive_id='Fake',
            path_on_host=disk_image_path,
            is_root_device=False,
            is_read_only=True,
        )
