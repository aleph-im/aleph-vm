import argparse
import asyncio
import logging
import sys
import time
from asyncio import coroutine
from statistics import mean
from typing import List

from aiohttp.web import Response

from vm_supervisor.models import VmHash
from . import supervisor
from .conf import settings

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
    return parser.parse_args(args)


async def benchmark(runs: int):
    """Measure performance by immediately running the supervisor
    with fake requests.
    """
    ref = VmHash("9b1ef4d969e393c871cef25bab345c8eaabfe81d1fc6536f287be4f6bb7c852a")

    class FakeRequest: pass

    fake_request = FakeRequest()
    fake_request.match_info = {"ref": ref, "suffix": "/"}
    fake_request.method = "GET"
    fake_request.query_string = ""
    fake_request.headers = []
    fake_request.raw_headers = []
    # noinspection PyDeprecation
    fake_request.text = coroutine(lambda: None)

    logger.info("--- Start benchmark ---")

    bench: List[float] = []

    # First test all methods
    settings.REUSE_TIMEOUT = 0.1
    for path in ("/", "/messages", "/internet", "/post_a_message",
                 "/cache/set/foo/bar", "/cache/get/foo", "/cache/keys"):
        fake_request.match_info["suffix"] = path
        response: Response = await supervisor.run_code(message_ref=ref,
                                                       path=path,
                                                       request=fake_request)
        assert response.status == 200

    # Disable VM timeout to exit benchmark properly
    settings.REUSE_TIMEOUT = 0 if runs == 1 else 0.1
    path = "/"
    for run in range(runs):
        t0 = time.time()
        fake_request.match_info["suffix"] = path
        response: Response = await supervisor.run_code(message_ref=ref,
                                                       path=path,
                                                       request=fake_request)
        assert response.status == 200
        bench.append(time.time() - t0)

    logger.info(f"BENCHMARK: n={len(bench)} avg={mean(bench):03f} "
                f"min={min(bench):03f} max={max(bench):03f}")
    logger.info(bench)


def main():
    args = parse_args(sys.argv[1:])

    log_format = "%(relativeCreated)4f | %(levelname)s | %(message)s" if args.profile \
        else "%(asctime)s | %(levelname)s | %(message)s"
    logging.basicConfig(
        level=args.loglevel,
        format=log_format,
    )

    settings.update(
        USE_JAILER=args.use_jailer,
        PRINT_SYSTEM_LOGS=args.system_logs,
        PREALLOC_VM_COUNT=args.prealloc_vm_count,
        ALLOW_VM_NETWORKING=args.allow_vm_networking,
    )
    settings.setup()
    if args.print_settings:
        print(settings.display())

    settings.check()

    if args.benchmark > 0:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(benchmark(runs=args.benchmark))
        print("Finished")
    elif args.do_not_run:
        logger.info("Option --do-not-run, exiting")
    else:
        supervisor.run()


if __name__ == "__main__":
    main()
