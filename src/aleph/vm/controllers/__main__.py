import argparse
import asyncio
import json
import logging
import signal
import sys
from asyncio.subprocess import Process
from pathlib import Path
from typing import Union

from aleph.vm.hypervisors.firecracker.microvm import MicroVM
from aleph.vm.hypervisors.qemu.qemuvm import QemuVM
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator

from .configuration import (
    Configuration,
    HypervisorType,
    QemuVMConfiguration,
    VMConfiguration,
)

logger = logging.getLogger(__name__)


def configuration_from_file(path: Path):
    with open(path) as f:
        data = json.load(f)
        return Configuration.parse_obj(data)


def parse_args(args):
    parser = argparse.ArgumentParser(prog="instance", description="Aleph.im Instance Client")
    parser.add_argument("-c", "--config", dest="config_path", required=True)
    parser.add_argument(
        "-i",
        "--initialize-network-settings",
        dest="initialize_network_settings",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-p",
        "--print-settings",
        dest="print_settings",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )
    return parser.parse_args(args)


async def execute_persistent_vm(config: Configuration):
    if config.hypervisor == HypervisorType.firecracker:
        assert isinstance(config.vm_configuration, VMConfiguration)
        execution = MicroVM(
            vm_id=config.vm_id,
            firecracker_bin_path=config.vm_configuration.firecracker_bin_path,
            jailer_base_directory=config.settings.JAILER_BASE_DIR,
            use_jailer=config.vm_configuration.use_jailer,
            jailer_bin_path=config.vm_configuration.jailer_bin_path,
            init_timeout=config.vm_configuration.init_timeout,
        )

        execution.prepare_start()
        process = await execution.start(config.vm_configuration.config_file_path)
    else:
        assert isinstance(config.vm_configuration, QemuVMConfiguration)
        execution = QemuVM(config.vm_hash, config.vm_configuration)
        process = await execution.start()

    return execution, process


async def handle_persistent_vm(config: Configuration, execution: Union[MicroVM, QemuVM], process: Process):
    # Catch the terminating signal and send a proper message to the vm to stop it so it close files properly
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, execution.send_shutdown_message)

    if config.settings.PRINT_SYSTEM_LOGS:
        execution.start_printing_logs()

    await process.wait()
    logger.info(f"Process terminated with {process.returncode}")


async def run_persistent_vm(config: Configuration):
    execution, process = await execute_persistent_vm(config)
    await handle_persistent_vm(config=config, execution=execution, process=process)
    return execution, process


def main():
    args = parse_args(sys.argv[1:])

    config_path = Path(args.config_path)
    if not config_path.is_file():
        logger.error(f"Configuration file {config_path} not found")
        exit(1)

    config = configuration_from_file(config_path)

    log_format = "%(asctime)s | %(levelname)s | %(message)s"
    logging.basicConfig(
        level=args.loglevel,
        format=log_format,
    )

    if args.print_settings:
        print(config.settings.display())

    config.settings.check()

    if args.initialize_network_settings:
        network = Network(
            vm_ipv4_address_pool_range=config.settings.IPV4_ADDRESS_POOL,
            vm_network_size=config.settings.IPV4_NETWORK_PREFIX_LENGTH,
            external_interface=config.settings.NETWORK_INTERFACE,
            ipv6_allocator=make_ipv6_allocator(
                allocation_policy=config.settings.IPV6_ALLOCATION_POLICY,
                address_pool=config.settings.IPV6_ADDRESS_POOL,
                subnet_prefix=config.settings.IPV6_SUBNET_PREFIX,
            ),
            use_ndp_proxy=config.settings.USE_NDP_PROXY,
            ipv6_forwarding_enabled=config.settings.IPV6_FORWARDING_ENABLED,
        )

        network.setup()

    asyncio.run(run_persistent_vm(config))


if __name__ == "__main__":
    main()
