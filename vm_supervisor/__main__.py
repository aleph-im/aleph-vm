import argparse
import logging
import sys

from . import supervisor
from .conf import settings

logger = logging.getLogger(__name__)


def parse_args(args):
    parser = argparse.ArgumentParser(
        prog="vm_supervisor",
        description="Aleph.im VM Supervisor")
    parser.add_argument(
        '--system-logs',
        action="store_true",
        dest="system_logs",
        default=settings.PRINT_SYSTEM_LOGS)
    parser.add_argument(
        '--no-jailer',
        action="store_false",
        dest="use_jailer",
        default=settings.USE_JAILER)
    parser.add_argument(
        '--jailer',
        action="store_true",
        dest="use_jailer",
        default=settings.USE_JAILER)
    parser.add_argument(
        '--prealloc',
        action="store",
        type=int,
        dest="prealloc_vm_count",
        required=False,
        default=settings.PREALLOC_VM_COUNT,
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO,
        default=logging.WARNING,
    )
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


if __name__ == '__main__':

    args = parse_args(sys.argv[1:])
    logging.basicConfig(level=args.loglevel)
    settings.update(
        USE_JAILER=args.use_jailer,
        PRINT_SYSTEM_LOGS=args.system_logs,
        PREALLOC_VM_COUNT=args.prealloc_vm_count,
    )
    supervisor.run()
