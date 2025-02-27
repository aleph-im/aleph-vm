from asyncio import QueueEmpty

from aleph.vm.utils.logs import make_logs_queue


def test_make_logs_queue():
    stdout_identifier = "test_stdout"
    stderr_identifier = "test_stderr"
    queue, do_cancel = make_logs_queue(stdout_identifier, stderr_identifier)
    import pytest

    with pytest.raises(QueueEmpty):
        while queue.get_nowait():
            queue.task_done()
    do_cancel()
