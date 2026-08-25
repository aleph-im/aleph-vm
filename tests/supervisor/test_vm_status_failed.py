"""A dead controller unit must report FAILED, not BOOTING.

systemd sets ActiveState=failed only once Restart=on-failure has given up, so
a unit in that state is not coming back on its own. Reporting it as BOOTING
(what a bool "is it active" collapses to) makes a crashed VM indistinguishable
from one still starting, and start_persistent_vm then waits for a VM that will
never run instead of taking its recreate branch.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from aleph.vm.supervisor.local import LocalSupervisor, _to_vm_info
from aleph.vm.supervisor_interface.types import VmStatus

SERVICE = "aleph-vm-controller@decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca.service"
NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def _execution(**times_kwargs):
    times = SimpleNamespace(
        defined_at=None,
        preparing_at=None,
        prepared_at=None,
        starting_at=None,
        started_at=None,
        stopping_at=None,
        stopped_at=None,
    )
    for key, value in times_kwargs.items():
        setattr(times, key, value)
    return SimpleNamespace(
        vm_id="abc",
        vm=None,
        times=times,
        is_program=False,
        is_confidential=False,
        is_awaiting_confidential_init=False,
        hypervisor=None,
        gpus=[],
        persistent=True,
        controller_service=SERVICE,
    )


class TestFailedControllerUnit:
    def test_failed_unit_reports_failed(self):
        execution = _execution(starting_at=NOW, started_at=NOW)
        assert _to_vm_info(execution, "failed").status is VmStatus.FAILED

    def test_failed_unit_names_the_unit_in_status_message(self):
        execution = _execution(starting_at=NOW, started_at=NOW)
        assert SERVICE in _to_vm_info(execution, "failed").status_message

    def test_stopping_takes_precedence_over_a_failed_unit(self):
        """A unit that fails while stopping is stopping, not crashed: the
        operator asked for it to go away and it is going away."""
        execution = _execution(starting_at=NOW, started_at=NOW, stopping_at=NOW)
        assert _to_vm_info(execution, "failed").status is VmStatus.STOPPING


class TestUnchangedStates:
    def test_active_unit_reports_running(self):
        execution = _execution(starting_at=NOW, started_at=NOW)
        assert _to_vm_info(execution, "active").status is VmStatus.RUNNING

    def test_inactive_unit_while_starting_still_reports_booting(self):
        """The window between StartUnit and the unit going active must keep
        reporting BOOTING; only "failed" is terminal."""
        execution = _execution(starting_at=NOW)
        assert _to_vm_info(execution, "inactive").status is VmStatus.BOOTING

    def test_not_loaded_unit_before_start_reports_defined(self):
        assert _to_vm_info(_execution(), "not-loaded").status is VmStatus.DEFINED

    def test_running_state_carries_no_status_message(self):
        execution = _execution(starting_at=NOW, started_at=NOW)
        assert _to_vm_info(execution, "active").status_message == ""

    def test_failed_unit_reports_no_uptime(self):
        execution = _execution(starting_at=NOW, started_at=NOW)
        assert _to_vm_info(execution, "failed").uptime_secs == 0


class TestBatchedListing:
    """list_vms takes the batched path (one ListUnits for every VM), which has
    its own state lookup and could report the per-VM path's answer wrongly."""

    @pytest.mark.asyncio
    async def test_list_vms_reports_failed_for_a_dead_unit(self):
        execution = _execution(starting_at=NOW, started_at=NOW)
        execution.systemd_manager = SimpleNamespace()
        # Both APIs, as the real manager has them: on the boolean one a failed
        # unit is simply "not active", which is what used to lose the reason.
        systemd = SimpleNamespace(
            get_services_states=lambda services: {s: "failed" for s in services},
            get_services_active_states=lambda services: {s: False for s in services},
        )
        pool = SimpleNamespace(executions={"abc": execution}, systemd_manager=systemd, network=None)

        infos = await LocalSupervisor(pool=pool).list_vms()

        assert [info.status for info in infos] == [VmStatus.FAILED]
