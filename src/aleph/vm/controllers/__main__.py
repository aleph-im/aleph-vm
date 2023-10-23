import argparse
import asyncio
import logging
import json
import sys
from pathlib import Path

from pydantic import BaseModel

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None

from aiohttp.web_exceptions import HTTPBadRequest, HTTPInternalServerError

from aleph_message.models import ItemHash, InstanceContent

from aleph.vm.controllers.firecracker.program import (
    FileTooLargeError,
    ResourceDownloadError,
    VmSetupError,
)
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInit

from aleph.vm.conf import settings, Settings
from aleph.vm.pool import VmPool
from aleph.vm.utils import HostNotFoundError

logger = logging.getLogger(__name__)

pool: VmPool


class Configuration(BaseModel):
    vm_hash: ItemHash
    instance_configuration: InstanceContent
    settings: Settings


def configuration_from_file(path: Path):
    with open(path) as f:
        data = json.load(f)
        return Configuration.parse_obj(data)


def parse_args(args):
    parser = argparse.ArgumentParser(prog="instance", description="Aleph.im Instance Client")
    parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        required=True
    )
    parser.add_argument(
        "-i",
        "--initial-pool-settings",
        dest="initial_pool_settings",
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
    return parser.parse_args(args)


async def run_instance(config: Configuration):
    global pool
    vm_hash = config.vm_hash
    try:
        execution = await pool.create_a_vm(
            vm_hash=vm_hash,
            message=config.instance_configuration,
            original=config.instance_configuration,
        )
    except ResourceDownloadError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPBadRequest(reason="Code, runtime or data not available")
    except FileTooLargeError as error:
        raise HTTPInternalServerError(reason=error.args[0])
    except VmSetupError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during vm initialisation")
    except MicroVMFailedInit as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during runtime initialisation")
    except HostNotFoundError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Host did not respond to ping")

    if not execution.vm:
        msg = "The VM has not been created"
        raise ValueError(msg)

    return execution


def main():
    global pool
    args = parse_args(sys.argv[1:])

    pool = VmPool(initialize_network_settings=args.initial_pool_settings)

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

    settings.update(**config.settings)

    settings.setup()
    if args.print_settings:
        print(settings.display())

    settings.check()

    asyncio.run(run_instance(config))
