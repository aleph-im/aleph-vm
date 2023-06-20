import argparse
import asyncio
import contextlib
import logging
import os
import sys
import time
from pathlib import Path
from statistics import mean
from typing import Callable, Dict, List, Tuple

from aiohttp.web import Request, Response

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None

import alembic.command
import alembic.config
from aleph_message.models import ItemHash

from . import metrics, supervisor
from .conf import make_db_url, settings
from .pubsub import PubSub
from .run import run_code_on_event, run_code_on_request, start_persistent_vm

logger = logging.getLogger(__name__)


def parse_args(args):
    parser = argparse.ArgumentParser(
        prog="vm_supervisor", description="Aleph.im VM Supervisor"
    )
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
    parser.add_argument(
        "--jailer", action="store_true", dest="use_jailer", default=settings.USE_JAILER
    )
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
        default=logging.WARNING,
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
        "-k",
        "--run-test-instance",
        dest="run_test_instance",
        action="store_true",
        default=False,
        help="Run a test instance instead of starting the entire supervisor",
    )
    return parser.parse_args(args)


async def benchmark(runs: int):
    """Measure program performance by immediately running the supervisor
    with fake requests.
    """
    engine = metrics.setup_engine()
    metrics.create_tables(engine)

    ref = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    settings.FAKE_DATA_PROGRAM = settings.BENCHMARK_FAKE_DATA_PROGRAM

    FakeRequest: Request

    class FakeRequest:  # type: ignore[no-redef]
        headers: Dict[str, str]
        raw_headers: List[Tuple[bytes, bytes]]
        match_info: Dict
        method: str
        query_string: str
        read: Callable

    fake_request = FakeRequest()  # type: ignore[operator]
    fake_request.match_info = {"ref": ref, "suffix": "/"}
    fake_request.method = "GET"
    fake_request.query_string = ""

    fake_request.headers = {"host": "127.0.0.1", "content-type": "application/json"}
    fake_request.raw_headers = [
        (name.encode(), value.encode()) for name, value in fake_request.headers.items()
    ]

    async def fake_read() -> bytes:
        return b""

    fake_request.read = fake_read

    logger.info("--- Start benchmark ---")

    bench: List[float] = []

    # Does not make sense in benchmarks
    settings.WATCH_FOR_MESSAGES = False
    settings.WATCH_FOR_UPDATES = False

    # First test all methods
    settings.REUSE_TIMEOUT = 0.1
    for path in (
        "/",
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
            vm_hash=ref, path=path, request=fake_request
        )
        assert response.status == 200

    # Disable VM timeout to exit benchmark properly
    settings.REUSE_TIMEOUT = 0 if runs == 1 else 0.1
    path = "/"
    for run in range(runs):
        t0 = time.time()
        fake_request.match_info["suffix"] = path
        response2: Response = await run_code_on_request(
            vm_hash=ref, path=path, request=fake_request
        )
        assert response2.status == 200
        bench.append(time.time() - t0)

    logger.info(
        f"BENCHMARK: n={len(bench)} avg={mean(bench):03f} "
        f"min={min(bench):03f} max={max(bench):03f}"
    )
    logger.info(bench)

    event = None
    result = await run_code_on_event(vm_hash=ref, event=event, pubsub=PubSub())
    print("Event result", result)


async def run_instance(item_hash: ItemHash):
    """Run an instance from an InstanceMessage."""

    # The main program uses a singleton pubsub instance in order to watch for updates.
    # We create another instance here since that singleton is not initialized yet.
    # Watching for updates on this instance will therefore not work.
    dummy_pubsub = PubSub()

    await start_persistent_vm(item_hash, dummy_pubsub)


@contextlib.contextmanager
def change_dir(directory: Path):
    current_directory = Path.cwd()
    try:
        os.chdir(directory)
        yield
    finally:
        os.chdir(current_directory)


def run_db_migrations():
    project_dir = Path(__file__).parent

    db_url = make_db_url()
    alembic_cfg = alembic.config.Config("alembic.ini")
    alembic_cfg.attributes["configure_logger"] = False
    logging.getLogger("alembic").setLevel(logging.CRITICAL)

    with change_dir(project_dir):
        alembic.command.upgrade(alembic_cfg, "head", tag=db_url)


def main():
    args = parse_args(sys.argv[1:])

    log_format = (
        "%(relativeCreated)4f | %(levelname)s | %(message)s"
        if args.profile
        else "%(asctime)s | %(levelname)s | %(message)s"
    )
    logging.basicConfig(
        level=args.loglevel,
        format=log_format,
    )

    settings.update(
        USE_JAILER=args.use_jailer,
        PRINT_SYSTEM_LOGS=args.system_logs,
        PREALLOC_VM_COUNT=args.prealloc_vm_count,
        ALLOW_VM_NETWORKING=args.allow_vm_networking,
        FAKE_DATA_PROGRAM=args.fake_data_program,
        DEBUG_ASYNCIO=args.debug_asyncio,
    )

    if sentry_sdk:
        if settings.SENTRY_DSN:
            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                server_name=settings.DOMAIN_NAME,
                # Set traces_sample_rate to 1.0 to capture 100%
                # of transactions for performance monitoring.
                # We recommend adjusting this value in production.
                traces_sample_rate=1.0,
            )
        else:
            logger.debug("Sentry SDK found with no DNS configured.")
    else:
        logger.debug(
            "Sentry SDK not found. \n"
            "Use `pip install sentry-sdk` and configure SENTRY_DSN if you'd like to monitor errors."
        )

    settings.setup()
    if args.print_settings:
        print(settings.display())

    settings.check()

    logger.debug("Initialising the DB...")
    run_db_migrations()
    logger.debug("DB up to date.")

    if args.benchmark > 0:
        asyncio.run(benchmark(runs=args.benchmark), debug=args.debug_asyncio)
        logger.info("Finished")
        sys.exit(0)
    elif args.do_not_run:
        logger.info("Option --do-not-run, exiting")
    elif args.run_test_instance:
        logger.info("Running test instance virtual machine")
        instance_item_hash = settings.FAKE_INSTANCE_ID
        settings.update(
            FAKE_DATA_INSTANCE=True,
        )

        async def forever():
            await run_instance(item_hash=instance_item_hash)
            await asyncio.sleep(1000)

        asyncio.run(forever())
        logger.info("Finished")
        sys.exit(0)
    else:
        supervisor.run()


if __name__ == "__main__":
    main()
