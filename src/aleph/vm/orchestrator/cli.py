import argparse
import asyncio
import contextlib
import logging
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from statistics import mean
from typing import cast

import alembic.command
import alembic.config
import sentry_sdk
from aiohttp.web import Request, Response
from aleph_message.models import ItemHash
from sqlalchemy.ext.asyncio import create_async_engine

from aleph.vm.conf import ALLOW_DEVELOPER_SSH_KEYS, make_db_url, settings
from aleph.vm.models import VmExecution
from aleph.vm.pool import VmPool
from aleph.vm.version import __version__, get_version_from_apt, get_version_from_git

from . import metrics, supervisor
from .custom_logs import setup_handlers
from .pubsub import PubSub
from .run import run_code_on_event, run_code_on_request, start_persistent_vm

logger = logging.getLogger(__name__)


def parse_args(args):
    parser = argparse.ArgumentParser(prog="orchestrator", description="Aleph.im VM Supervisor")
    parser.add_argument(
        "--system-logs",
        action="store_true",
        dest="system_logs",
        default=settings.PRINT_SYSTEM_LOGS,
    )
    parser.add_argument(
        "--no-network",
        action="store_false",
        dest="allow_vm_networking",
        default=settings.ALLOW_VM_NETWORKING,
    )
    parser.add_argument(
        "--no-jailer",
        action="store_false",
        dest="use_jailer",
        default=settings.USE_JAILER,
    )
    parser.add_argument("--jailer", action="store_true", dest="use_jailer", default=settings.USE_JAILER)
    parser.add_argument(
        "--prealloc",
        action="store",
        type=int,
        dest="prealloc_vm_count",
        required=False,
        default=settings.PREALLOC_VM_COUNT,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        help="set loglevel to INFO",
        action="store_const",
        const=logging.INFO,
        default=settings.LOG_LEVEL,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )
    parser.add_argument(
        "-d",
        "--debug-asyncio",
        dest="debug_asyncio",
        help="Enable asyncio debugging",
        action="store_true",
        default=settings.DEBUG_ASYNCIO,
    )
    parser.add_argument(
        "-p",
        "--print-settings",
        dest="print_settings",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-n",
        "--do-not-run",
        dest="do_not_run",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        action="store_true",
        default=False,
        help="Add extra info for profiling",
    )
    parser.add_argument(
        "--benchmark",
        dest="benchmark",
        type=int,
        default=0,
        help="Number of benchmarks to run",
    )
    parser.add_argument(
        "-f",
        "--fake-data-program",
        dest="fake_data_program",
        type=str,
        default=None,
        help="Path to project containing fake data",
    )
    parser.add_argument(
        "-i",
        "--run-test-instance",
        dest="run_test_instance",
        action="store_true",
        default=False,
        help="Run a test instance from the network instead of starting the entire supervisor",
    )
    parser.add_argument(
        "-k",
        "--run-fake-instance",
        dest="run_fake_instance",
        action="store_true",
        default=False,
        help="Run a fake instance from a local rootfs instead of starting the entire supervisor",
    )
    parser.add_argument(
        "-r",
        "--fake-instance-base",
        dest="fake_instance_base",
        type=str,
        default=settings.FAKE_INSTANCE_BASE,
        help="Filesystem path of the base for the rootfs of fake instances. An empty value signals a download instead.",
    )
    parser.add_argument(
        "--developer-ssh-keys",
        dest="use_developer_ssh_keys",
        action="store_true",
        default=False,
        help="Authorize the developer's SSH keys to connect instead of those specified in the message",
    )
    return parser.parse_args(args)


class FakeRequest:
    headers: dict[str, str]
    raw_headers: list[tuple[bytes, bytes]]
    match_info: dict
    method: str
    query_string: str
    read: Callable


async def benchmark(runs: int):
    """Measure program performance by immediately running the supervisor
    with fake requests.
    """
    ref = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    settings.FAKE_DATA_PROGRAM = settings.BENCHMARK_FAKE_DATA_PROGRAM

    fake_request = FakeRequest()  # type: ignore[operator]
    fake_request.match_info = {"ref": ref, "suffix": "/"}
    fake_request.method = "GET"
    fake_request.query_string = ""

    fake_request.headers = {"host": "127.0.0.1", "content-type": "application/json"}
    fake_request.raw_headers = [(name.encode(), value.encode()) for name, value in fake_request.headers.items()]

    async def fake_read() -> bytes:
        return b""

    fake_request.read = fake_read

    logger.info("--- Start benchmark ---")

    bench: list[float] = []

    loop = asyncio.get_event_loop()
    pool = VmPool()
    await pool.setup()

    # Does not make sense in benchmarks
    settings.WATCH_FOR_MESSAGES = False
    settings.WATCH_FOR_UPDATES = False

    # Finish setting up the settings
    settings.setup()
    settings.check()

    # First test all methods
    settings.REUSE_TIMEOUT = 0.1
    for path in (
        "/",
        "/lifespan",
        "/environ",
        "/messages",
        "/internet",
        "/post_a_message",
        "/cache/set/foo/bar",
        "/cache/get/foo",
        "/cache/keys",
    ):
        fake_request.match_info["suffix"] = path
        response: Response = await run_code_on_request(
            vm_hash=ref, path=path, pool=pool, request=cast(Request, fake_request)
        )
        assert response.status == 200

    # Disable VM timeout to exit benchmark properly
    settings.REUSE_TIMEOUT = 0 if runs == 1 else 0.1
    path = "/"
    for _run in range(runs):
        t0 = time.time()
        fake_request.match_info["suffix"] = path
        response2: Response = await run_code_on_request(
            vm_hash=ref, path=path, pool=pool, request=cast(Request, fake_request)
        )
        assert response2.status == 200
        bench.append(time.time() - t0)

    logger.info(f"BENCHMARK: n={len(bench)} avg={mean(bench):03f} min={min(bench):03f} max={max(bench):03f}")
    logger.info(bench)

    result = await run_code_on_event(vm_hash=ref, event=None, pubsub=PubSub(), pool=pool)
    print("Event result", result)


async def start_instance(item_hash: ItemHash, pubsub: PubSub | None, pool) -> VmExecution:
    """Run an instance from an InstanceMessage."""
    return await start_persistent_vm(item_hash, pubsub, pool)


async def run_instances(instances: list[ItemHash]) -> None:
    """Run instances from a list of message identifiers."""
    logger.info(f"Instances to run: {instances}")
    loop = asyncio.get_event_loop()
    pool = VmPool()
    # The main program uses a singleton pubsub instance in order to watch for updates.
    # We create another instance here since that singleton is not initialized yet.
    # Watching for updates on this instance will therefore not work.
    pubsub: PubSub | None = None

    await asyncio.gather(*[start_instance(instance_id, pubsub, pool) for instance_id in instances])

    await asyncio.Event().wait()  # wait forever


@contextlib.contextmanager
def change_dir(directory: Path):
    current_directory = Path.cwd()
    try:
        os.chdir(directory)
        yield
    finally:
        os.chdir(current_directory)


def run_db_migrations(connection):
    project_dir = Path(__file__).parent

    alembic_cfg = alembic.config.Config("alembic.ini")
    alembic_cfg.attributes["configure_logger"] = False
    alembic_cfg.attributes["connection"] = connection
    logging.getLogger("alembic").setLevel(logging.CRITICAL)

    with change_dir(project_dir):
        alembic.command.upgrade(alembic_cfg, "head")


async def run_async_db_migrations():
    async_engine = create_async_engine(make_db_url(), echo=False)
    async with async_engine.begin() as conn:
        await conn.run_sync(run_db_migrations)


def main():
    args = parse_args(sys.argv[1:])

    log_format = (
        "%(relativeCreated)4f | %(levelname)s | %(message)s"
        if args.profile
        else "%(asctime)s | %(levelname)s %(name)s:%(lineno)s | %(message)s"
    )
    # log_format = "[%(asctime)s] p%(process)s {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"

    handlers = setup_handlers(args, log_format)
    logging.basicConfig(
        level=args.loglevel,
        format=log_format,
        handlers=handlers,
    )

    logging.getLogger("aiosqlite").setLevel(settings.LOG_LEVEL)
    logging.getLogger("sqlalchemy.engine").setLevel(settings.LOG_LEVEL)
    # Example to set a higher lever on a sub component when developing
    # logging.getLogger("aleph.vm.haproxy").setLevel(logging.DEBUG)

    settings.update(
        USE_JAILER=args.use_jailer,
        PRINT_SYSTEM_LOGS=args.system_logs,
        PREALLOC_VM_COUNT=args.prealloc_vm_count,
        ALLOW_VM_NETWORKING=args.allow_vm_networking,
        FAKE_DATA_PROGRAM=args.fake_data_program,
        DEBUG_ASYNCIO=args.debug_asyncio,
        FAKE_INSTANCE_BASE=args.fake_instance_base,
    )

    if args.run_fake_instance:
        settings.USE_FAKE_INSTANCE_BASE = True

    if args.use_developer_ssh_keys:
        settings.USE_DEVELOPER_SSH_KEYS = ALLOW_DEVELOPER_SSH_KEYS

    if sentry_sdk:
        if settings.SENTRY_DSN:
            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                server_name=settings.DOMAIN_NAME,
                # Set traces_sample_rate to 1.0 to capture 100%
                # of transactions for performance monitoring.
                # We recommend adjusting this value in production.
                traces_sample_rate=1.0,
                release=__version__,
            )
            sentry_sdk.set_context(
                "version",
                {
                    "git": get_version_from_git(),
                    "apt": get_version_from_apt(),
                },
            )
        else:
            logger.debug("Sentry SDK found with no DSN configured.")
    else:
        logger.debug(
            "Sentry SDK not found. \n"
            "Use `pip install sentry-sdk` and configure SENTRY_DSN if you'd like to monitor errors."
        )

    settings.setup()
    if args.print_settings:
        print(settings.display())

    settings.check()

    if not args.do_not_run:
        logger.debug("Initialising the DB...")
        # Check and create execution database
        engine = metrics.setup_engine()
        asyncio.run(metrics.create_tables(engine))
        # After creating it run the DB migrations
        asyncio.run(run_async_db_migrations())
        logger.debug("DB up to date.")

    if args.benchmark > 0:
        asyncio.run(benchmark(runs=args.benchmark), debug=args.debug_asyncio)
        logger.info("Finished")
        sys.exit(0)
    elif args.do_not_run:
        logger.info("Option --do-not-run, exiting")
    elif args.run_test_instance:
        asyncio.run(run_instances([ItemHash(settings.TEST_INSTANCE_ID)]))
        logger.info("Finished")
        sys.exit(0)
    elif args.run_fake_instance:
        asyncio.run(run_instances([ItemHash(settings.FAKE_INSTANCE_ID)]))
        logger.info("Finished")
        sys.exit(0)
    else:
        supervisor.run()
