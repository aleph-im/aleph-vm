"""``reconcile_port_forwards``'s strict mode: convergence callers whose VM
already has forwards must not treat a transient aggregate-fetch failure as
"the user removed every port" and converge onto the SSH-only fallback,
tearing the user's own forwards down. The aggregate watcher and the
user-triggered refresh endpoint pass ``strict=True``; the legacy-SEV
post-init first setup keeps the lenient default (nothing to tear down yet).
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_snp_instance_port_map import VM_ID, FakeSupervisor

from aleph.vm.agent import run as run_module
from aleph.vm.supervisor_interface.types import Protocol

USER_PORT = 8080


def _plain_instance_content():
    return SimpleNamespace(address="0xabc", environment=SimpleNamespace(trusted_execution=None))


@pytest.mark.asyncio
async def test_strict_reconcile_propagates_aggregate_failure(monkeypatch):
    """strict=True: an aggregate-fetch failure raises with no forwards
    touched, so the caller skips the pass instead of converging."""
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(side_effect=RuntimeError("CCN down")))
    supervisor = FakeSupervisor([22, USER_PORT])

    with pytest.raises(RuntimeError, match="CCN down"):
        await run_module.reconcile_port_forwards(supervisor, VM_ID, _plain_instance_content(), strict=True)

    assert supervisor.ports() == {22, USER_PORT}
    assert supervisor.removed == []
    assert supervisor.added == []


@pytest.mark.asyncio
async def test_lenient_default_converges_on_the_ssh_fallback(monkeypatch):
    """The lenient default keeps the pre-existing first-setup behavior: an
    aggregate failure falls back to SSH-only and converges onto it. This is
    exactly why convergence callers must not use the default."""
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(side_effect=RuntimeError("CCN down")))
    supervisor = FakeSupervisor([22, USER_PORT])

    await run_module.reconcile_port_forwards(supervisor, VM_ID, _plain_instance_content())

    assert supervisor.ports() == {22}
    assert supervisor.removed == [(USER_PORT, Protocol.TCP)]


@pytest.mark.asyncio
async def test_strict_reconcile_still_converges_when_the_fetch_works(monkeypatch):
    """strict only changes failure handling: with the aggregate reachable,
    a strict pass applies the user's declared set normally."""
    payload = {str(VM_ID): {"ports": {str(USER_PORT): {"tcp": True, "udp": False}}}}
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value=payload))
    supervisor = FakeSupervisor([22])

    await run_module.reconcile_port_forwards(supervisor, VM_ID, _plain_instance_content(), strict=True)

    assert supervisor.ports() == {22, USER_PORT}
    assert supervisor.removed == []
