import asyncio
import logging
from datetime import datetime
from typing import Callable, Generator, TypedDict

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
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def _ready_for_read() -> None:
        change_type = r.process()  # reset fd status
        if change_type != journal.APPEND:
            return
        entry: EntryDict
        for entry in r:
            log_type = "stdout" if entry["SYSLOG_IDENTIFIER"] == stdout_identifier else "stderr"
            msg = entry["MESSAGE"]
            asyncio.create_task(queue.put((log_type, msg)))

    if skip_past:
        r.seek_tail()

    loop = asyncio.get_event_loop()
    loop.add_reader(r.fileno(), _ready_for_read)

    def do_cancel():
        logger.info(f"cancelling reader {r}")
        loop.remove_reader(r.fileno())
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
    for entry in r:
        yield entry
