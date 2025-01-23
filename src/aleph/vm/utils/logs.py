import asyncio
import logging
from collections.abc import Callable, Generator
from datetime import datetime, timedelta
from typing import TypedDict

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
    journal_reader = journal.Reader()
    journal_reader.add_match(SYSLOG_IDENTIFIER=stdout_identifier)
    journal_reader.add_match(SYSLOG_IDENTIFIER=stderr_identifier)
    queue: asyncio.Queue = asyncio.Queue(maxsize=5)
    tasks: list[asyncio.Task] = []

    loop = asyncio.get_event_loop()

    async def process_messages() -> None:
        """Enqueue all the available log entries, wait if queue is full, then wait for new message via add_reader"""
        # Remove reader so we don't get called again while processing
        loop.remove_reader(journal_reader.fileno())
        entry: EntryDict
        for entry in journal_reader:
            log_type = "stdout" if entry["SYSLOG_IDENTIFIER"] == stdout_identifier else "stderr"
            msg = entry["MESSAGE"]
            # will wait if queue is full
            await queue.put((log_type, msg))
            journal_reader.process()  # reset fd status
        journal_reader.process()  # reset fd status
        # Call _ready_for_read read when entries are readable again, this is non-blocking
        loop.add_reader(journal_reader.fileno(), _ready_for_read)

    def _ready_for_read() -> None:
        # wrapper around process_messages as add_reader don't take an async func
        task = loop.create_task(process_messages(), name=f"process_messages-queue-{id(queue)}")
        tasks.append(task)
        task.add_done_callback(tasks.remove)

    if skip_past:
        # seek_tail doesn't work see https://github.com/systemd/systemd/issues/17662
        journal_reader.seek_realtime(datetime.now() - timedelta(seconds=10))

    _ready_for_read()

    def do_cancel():
        logger.info(f"cancelling queue and reader {journal_reader}")
        loop.remove_reader(journal_reader.fileno())
        for task in tasks:
            task.cancel()
        journal_reader.close()

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
