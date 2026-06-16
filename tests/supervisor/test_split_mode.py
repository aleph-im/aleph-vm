"""Split mode: agent wiring when ALEPH_VM_SUPERVISOR_GRPC_SOCKET is set."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web

from aleph.vm.conf import settings
from aleph.vm.orchestrator.supervisor import setup_webapp, stop_all_vms
from aleph.vm.orchestrator.utils import require_vm_pool
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.local import LocalSupervisor


def test_split_mode_wires_grpc_supervisor(mocker):
    mocker.patch.object(settings, "SUPERVISOR_GRPC_SOCKET", Path("/run/aleph/supervisor.sock"))
    app = setup_webapp(pool=None)
    supervisor = app["supervisor"]
    assert isinstance(supervisor, GrpcSupervisor)
    assert supervisor.socket_path == "/run/aleph/supervisor.sock"
    assert app["vm_pool"] is None


def test_build_supervisor_factory_selects_path(mocker):
    from aleph.vm.orchestrator.supervisor import build_supervisor

    mocker.patch.object(settings, "SUPERVISOR_GRPC_SOCKET", None)
    pool = SimpleNamespace(executions={})
    assert isinstance(build_supervisor(settings, pool), LocalSupervisor)

    mocker.patch.object(settings, "SUPERVISOR_GRPC_SOCKET", Path("/run/aleph/supervisor.sock"))
    grpc = build_supervisor(settings, pool=None)
    assert isinstance(grpc, GrpcSupervisor)


def test_inprocess_mode_wires_inprocess_supervisor(mocker):
    mocker.patch.object(settings, "SUPERVISOR_GRPC_SOCKET", None)
    pool = SimpleNamespace(executions={})
    app = setup_webapp(pool=pool)
    assert isinstance(app["supervisor"], LocalSupervisor)


def test_require_vm_pool_501_in_split_mode():
    request = SimpleNamespace(app={"vm_pool": None})
    with pytest.raises(web.HTTPNotImplemented):
        require_vm_pool(request)


def test_require_vm_pool_returns_pool():
    pool = SimpleNamespace()
    request = SimpleNamespace(app={"vm_pool": pool})
    assert require_vm_pool(request) is pool


@pytest.mark.asyncio
async def test_stop_all_vms_is_a_no_op_without_a_pool():
    # Split mode: the daemon owns the VMs; agent shutdown must not stop them.
    await stop_all_vms({"vm_pool": None})
