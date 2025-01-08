import asyncio
import logging
from collections.abc import Callable, Generator
from datetime import datetime, timedelta
from typing import List, TypedDict

from systemd import journal

logger = logging.getLogger(__name__)


class EntryDict(TypedDict):
    SYSLOG_IDENTIFIER: str
    MESSAGE: str
    __REALTIME_TIMESTAMP: datetime


def make_logs_queue(stdout_identifier, stderr_identifier, skip_past=False) -> tuple[asyncio.Queue, Callable[[], None]]:
    """Create a queue which streams the logs for the process.

    @param stdout_identifier: journald identifier for process stdout
    @param stderr_identifier: journald identifier for process stderr
    @param skip_past: Skip past history.
    @return: queue and function to cancel the queue.

    The consumer is required to call the queue cancel function when it's done consuming the queue.

    Works by creating a journald reader, and using `add_reader` to call a callback when
    data is available for reading.
    In the callback we check the message type and fill the queue accordingly

    For more information refer to the sd-journal(3) manpage
    and systemd.journal module documentation.
    """
    r = journal.Reader()
    r.add_match(SYSLOG_IDENTIFIER=stdout_identifier)
    r.add_match(SYSLOG_IDENTIFIER=stderr_identifier)
    queue: asyncio.Queue = asyncio.Queue(maxsize=5)
    tasks: List[asyncio.Future] = []

    async def process_messages() -> None:
        loop.remove_reader(r.fileno())
        entry: EntryDict
        for entry in r:
            log_type = "stdout" if entry["SYSLOG_IDENTIFIER"] == stdout_identifier else "stderr"
            msg = entry["MESSAGE"]
            await queue.put((log_type, msg))
            r.process()  # reset fd status
        r.process()  # reset fd status
        loop.add_reader(r.fileno(), _ready_for_read)

    def _ready_for_read() -> None:
        task = loop.create_task(process_messages(), name=f"process_messages-queue-{id(queue)}")
        tasks.append(task)
        task.add_done_callback(tasks.remove)

    if skip_past:
        # seek_tail doesn't work see https://github.com/systemd/systemd/issues/17662
        r.seek_realtime(datetime.now() - timedelta(seconds=10))

    loop = asyncio.get_event_loop()
    loop.add_reader(r.fileno(), _ready_for_read)
    r.process()

    def do_cancel():
        logger.info(f"cancelling reader {r}")
        loop.remove_reader(r.fileno())
        for task in tasks:
            task.cancel()
        r.close()

    return queue, do_cancel


def get_past_vm_logs(stdout_identifier, stderr_identifier) -> Generator[EntryDict, None, None]:
    """Get existing log for the VM identifiers.

    @param stdout_identifier: journald identifier for process stdout
    @param stderr_identifier: journald identifier for process stderr
    @return: an iterator of log entry

    Works by creating a journald reader, and using `add_reader` to call a callback when
    data is available for reading.

    For more information refer to the sd-journal(3) manpage
    and systemd.journal module documentation.
    """
    r = journal.Reader()
    r.add_match(SYSLOG_IDENTIFIER=stdout_identifier)
    r.add_match(SYSLOG_IDENTIFIER=stderr_identifier)

    r.seek_head()
    yield from r
