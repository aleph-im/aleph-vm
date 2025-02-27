import contextlib
import logging
from contextvars import ContextVar

from aleph_message.models import ItemHash

from aleph.vm.models import VmExecution

ctx_current_execution: ContextVar[VmExecution | None] = ContextVar("current_execution")
ctx_current_execution_hash: ContextVar[ItemHash | None] = ContextVar("current_execution_hash")


@contextlib.contextmanager
def set_vm_for_logging(vm_hash):
    token = ctx_current_execution_hash.set(vm_hash)
    try:
        yield
    finally:
        ctx_current_execution_hash.reset(token)


class InjectingFilter(logging.Filter):
    """
    A filter which injects context-specific information into logs
    """

    def filter(self, record):
        vm_hash = ctx_current_execution_hash.get(None)
        if not vm_hash:
            vm_execution: VmExecution | None = ctx_current_execution.get(None)
            if vm_execution:
                vm_hash = vm_execution.vm_hash

        if not vm_hash:
            return False

        record.vm_hash = vm_hash
        return True


def setup_handlers(args, log_format):
    # Set up two custom handler, one that will add the VM information if present and the other print if not
    execution_handler = logging.StreamHandler()
    execution_handler.addFilter(InjectingFilter())
    execution_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s %(name)s:%(lineno)s | {%(vm_hash)s} %(message)s ")
    )
    non_execution_handler = logging.StreamHandler()
    non_execution_handler.addFilter(lambda x: ctx_current_execution_hash.get(None) is None)
    non_execution_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s %(name)s:%(lineno)s | %(message)s ")
    )
    return [non_execution_handler, execution_handler]
