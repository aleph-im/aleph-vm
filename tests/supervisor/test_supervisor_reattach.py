"""Config-driven, message-free reattach helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor_interface.errors import (
    InternalSupervisorError,
    VmAlreadyExistsError,
)
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(
                path=Path("/data/rootfs.qcow2"),
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        ],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _bare_pool() -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    pool._failed_reattach = {}
    return pool


@pytest.mark.asyncio
async def test_handle_dead_controller_stops_service():
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH)

    await pool._handle_dead_controller(config)

    pool.systemd_manager.stop_and_disable.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")


@pytest.mark.asyncio
async def test_failed_reattach_does_not_abort_the_rest(tmp_path):
    """A single VM whose restore raises (e.g. an unsupported confidential
    config) must not stop the other active VMs from reattaching."""
    hash_ok = "a" * 64
    hash_bad = "b" * 64
    pool = _bare_pool()
    pool.systemd_manager.get_services_active_states = MagicMock(
        return_value={
            f"aleph-vm-controller@{hash_ok}.service": True,
            f"aleph-vm-controller@{hash_bad}.service": True,
        }
    )
    for h in (hash_ok, hash_bad):
        (tmp_path / f"{h}-controller.json").write_text("{}")
    configs = {hash_ok: SimpleNamespace(vm_hash=hash_ok, vm_id=1), hash_bad: SimpleNamespace(vm_hash=hash_bad, vm_id=2)}

    async def fake_restore(config, vm_index, vm_id):
        if str(config.vm_hash) == hash_bad:
            msg = "reattach supports QemuVMConfiguration only"
            raise RuntimeError(msg)
        pool.executions[vm_id] = SimpleNamespace(vm_index=vm_index)

    with (
        patch("aleph.vm.pool.settings", SimpleNamespace(EXECUTION_ROOT=tmp_path)),
        patch("aleph.vm.pool.load_controller_configuration", side_effect=lambda h: configs[h]),
        patch.object(pool, "_restore_running_execution_from_config", side_effect=fake_restore),
        patch.object(pool, "_handle_dead_controller", new_callable=AsyncMock) as dead,
        patch.object(pool, "_cleanup_orphan_resources") as cleanup,
    ):
        await pool.load_persistent_executions()

    # The healthy VM reattached despite the other one failing.
    assert VmId(hash_ok) in pool.executions
    # The failed VM's live controller is left running, not killed as "dead".
    dead.assert_not_called()
    # And it is protected from the orphan sweep so cleanup cannot delete its
    # config or tear down its networking while the VM is still running.
    _, kwargs = cleanup.call_args
    assert kwargs["protected_vm_ids"] == {2}
    assert kwargs["protected_vm_hashes"] == {hash_bad}


@pytest.mark.asyncio
async def test_cleanup_orphan_resources_treats_protected_as_active(monkeypatch):
    """A protected (failed-reattach) VM must not be swept: its vm_index and
    hash are unioned into the active sets the cleanup helpers receive."""
    pool = _bare_pool()
    seen: dict[str, object] = {}
    monkeypatch.setattr("aleph.vm.pool.get_existing_nftables_ruleset", lambda: [])
    monkeypatch.setattr(pool, "_cleanup_orphan_port_redirects", lambda _ruleset: None)
    monkeypatch.setattr(pool, "_cleanup_orphan_nft_chains", lambda ids, _ruleset: seen.update(ids=ids))
    monkeypatch.setattr(pool, "_cleanup_orphan_tap_interfaces", lambda _ids: None)
    monkeypatch.setattr(pool, "_cleanup_orphan_controller_configs", lambda hashes: seen.update(hashes=hashes))

    pool._cleanup_orphan_resources(protected_vm_ids={5}, protected_vm_hashes={"c" * 64})

    assert seen["ids"] == {5}
    assert seen["hashes"] == {"c" * 64}


@pytest.mark.asyncio
async def test_restore_running_execution_from_config_registers_execution(monkeypatch):
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH, vm_id=7)

    monkeypatch.setattr("aleph.vm.pool.spec_from_controller_configuration", lambda _c: _spec())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))

    from aleph.vm.models import VmExecution

    monkeypatch.setattr(VmExecution, "prepare", AsyncMock())
    fake_vm = SimpleNamespace(support_snapshot=False, start_guest_api=AsyncMock())
    monkeypatch.setattr(VmExecution, "create", MagicMock(return_value=fake_vm))

    await pool._restore_running_execution_from_config(config, vm_index=7, vm_id=_HASH)

    assert _HASH in pool.executions
    execution = pool.executions[_HASH]
    assert execution.spec is not None
    assert execution.vm_spec is execution.spec
    fake_vm.start_guest_api.assert_awaited_once()
    assert execution.ready_event.is_set()


def _fake_existing_config(monkeypatch, tmp_path) -> SimpleNamespace:
    """Point the on-disk config probe at an existing file and stub the loader."""
    config_path = tmp_path / f"{_HASH}-controller.json"
    config_path.write_text("{}")
    config = SimpleNamespace(vm_hash=_HASH, vm_id=7)
    monkeypatch.setattr("aleph.vm.pool.get_controller_configuration_path", lambda _h: config_path)
    monkeypatch.setattr("aleph.vm.pool.load_controller_configuration", lambda _h: config)
    return config


@pytest.mark.asyncio
async def test_readopt_live_controller_readopts_when_active(monkeypatch, tmp_path):
    """A create for a VM whose controller is still running but untracked
    re-adopts it (retries the reattach) instead of creating a duplicate."""
    pool = _bare_pool()
    _fake_existing_config(monkeypatch, tmp_path)
    pool.systemd_manager.get_service_active_state = MagicMock(return_value="active")
    adopted = SimpleNamespace()

    async def fake_restore(_cfg, vm_index, vm_id):
        assert vm_index == 7  # config.vm_id is the vm_index
        pool.executions[vm_id] = adopted

    monkeypatch.setattr(pool, "_restore_running_execution_from_config", fake_restore)

    assert await pool._readopt_live_controller(VmId(_HASH)) is adopted
    pool.systemd_manager.get_service_active_state.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")


@pytest.mark.asyncio
async def test_readopt_live_controller_none_without_config(monkeypatch, tmp_path):
    """No on-disk config -> nothing to re-adopt -> normal create proceeds.
    The loader is never called, so it cannot log a spurious warning."""
    pool = _bare_pool()
    monkeypatch.setattr(
        "aleph.vm.pool.get_controller_configuration_path", lambda _h: tmp_path / f"{_HASH}-controller.json"
    )
    loader = MagicMock(side_effect=AssertionError("loader must not run when the config file is absent"))
    monkeypatch.setattr("aleph.vm.pool.load_controller_configuration", loader)

    assert await pool._readopt_live_controller(VmId(_HASH)) is None
    loader.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["inactive", "failed", "not-loaded"])
async def test_readopt_live_controller_none_when_positively_down(monkeypatch, tmp_path, state):
    """Config exists but the controller is positively down -> no live VM to
    clobber, so a normal create (a clean restart-from-disk) is allowed to
    proceed."""
    pool = _bare_pool()
    _fake_existing_config(monkeypatch, tmp_path)
    pool.systemd_manager.get_service_active_state = MagicMock(return_value=state)
    assert await pool._readopt_live_controller(VmId(_HASH)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unknown", "activating", "deactivating"])
async def test_readopt_live_controller_raises_when_state_indeterminate(monkeypatch, tmp_path, state):
    """When systemd cannot tell whether the controller is live (a D-Bus error
    or a transitional state), the create must fail so the agent retries later,
    instead of falling through to a fresh create over a live controller."""
    pool = _bare_pool()
    _fake_existing_config(monkeypatch, tmp_path)
    pool.systemd_manager.get_service_active_state = MagicMock(return_value=state)
    with pytest.raises(InternalSupervisorError):
        await pool._readopt_live_controller(VmId(_HASH))


@pytest.mark.asyncio
async def test_create_vm_from_spec_short_circuits_to_readopt(monkeypatch):
    """create_vm_from_spec returns the re-adopted execution and never reaches
    fresh-create admission when a live untracked controller is found."""
    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    sentinel = SimpleNamespace(vm_spec=_spec())
    monkeypatch.setattr(pool, "_readopt_live_controller", AsyncMock(return_value=sentinel))
    pool.check_spec_admission = MagicMock(side_effect=AssertionError("must not reach fresh create"))

    assert await pool.create_vm_from_spec(_spec()) is sentinel
    pool.check_spec_admission.assert_not_called()


@pytest.mark.asyncio
async def test_create_vm_from_spec_readopt_requires_same_spec(monkeypatch):
    """A create whose spec differs from the re-adopted VM's spec is a
    conflict, same as the tracked-running idempotency branch: the caller must
    not silently get a VM with the old vcpus/memory."""
    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    readopted = SimpleNamespace(vm_spec=_spec())
    monkeypatch.setattr(pool, "_readopt_live_controller", AsyncMock(return_value=readopted))

    from dataclasses import replace

    with pytest.raises(VmAlreadyExistsError):
        await pool.create_vm_from_spec(replace(_spec(), vcpus=4))


@pytest.mark.asyncio
async def test_readopt_live_controller_raises_on_vm_index_conflict(monkeypatch, tmp_path):
    """The untracked VM's on-disk vm_index may have been handed to a newer VM
    after the failed reattach. Re-adopting on it would rewire the other VM's
    tap/nftables (the restore path trusts the index), and a fresh create over
    the live controller is forbidden, so the only safe outcome is to fail."""
    pool = _bare_pool()
    _fake_existing_config(monkeypatch, tmp_path)  # config.vm_id (vm_index) == 7
    pool.executions[VmId("f" * 64)] = SimpleNamespace(vm_index=7)
    pool.systemd_manager.get_service_active_state = MagicMock(return_value="active")
    restore = AsyncMock(side_effect=AssertionError("must not restore on a conflicting vm_index"))
    monkeypatch.setattr(pool, "_restore_running_execution_from_config", restore)

    with pytest.raises(InternalSupervisorError):
        await pool._readopt_live_controller(VmId(_HASH))
    restore.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_vm_from_spec_readopt_failure_does_not_fall_through(monkeypatch):
    """The fail-closed contract of _readopt_live_controller: when re-adoption
    fails (the original transient cause persists), the exception propagates
    out of create_vm_from_spec and the fresh-create path is never reached."""
    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    monkeypatch.setattr(pool, "_readopt_live_controller", AsyncMock(side_effect=RuntimeError("reattach still failing")))
    pool.check_spec_admission = MagicMock(side_effect=AssertionError("must not reach fresh create"))

    with pytest.raises(RuntimeError, match="reattach still failing"):
        await pool.create_vm_from_spec(_spec())
    pool.check_spec_admission.assert_not_called()


@pytest.mark.asyncio
async def test_retry_readopts_a_failed_vm(monkeypatch):
    """A queued failed VM is dropped from the retry set once it re-adopts."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    pool.systemd_manager.get_service_active_state = MagicMock(return_value="active")
    pool._failed_reattach = {VmId(_HASH): _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7)}

    async def fake_restore(_cfg, vm_index, vm_id):
        pool.executions[vm_id] = SimpleNamespace(vm_index=vm_index)

    monkeypatch.setattr(pool, "_restore_running_execution_from_config", fake_restore)

    await pool._retry_failed_reattachments_once()

    assert VmId(_HASH) not in pool._failed_reattach
    assert VmId(_HASH) in pool.executions


@pytest.mark.asyncio
async def test_retry_drops_dead_controller(monkeypatch):
    """A controller that died since startup must not be re-adopted as a
    phantom running execution: it is cleaned up and dequeued for good."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    pool.systemd_manager.get_service_active_state = MagicMock(return_value="inactive")
    state = _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7)
    pool._failed_reattach = {VmId(_HASH): state}
    restore = AsyncMock()
    monkeypatch.setattr(pool, "_restore_running_execution_from_config", restore)
    dead = AsyncMock()
    monkeypatch.setattr(pool, "_handle_dead_controller", dead)

    await pool._retry_failed_reattachments_once()

    assert VmId(_HASH) not in pool._failed_reattach
    assert VmId(_HASH) not in pool.executions
    dead.assert_awaited_once_with(state.config)
    restore.assert_not_awaited()
    pool.systemd_manager.get_service_active_state.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")


@pytest.mark.asyncio
async def test_retry_unknown_state_counts_as_failed_attempt(monkeypatch):
    """A D-Bus error ("unknown") is not proof the controller is dead: the
    entry stays queued, no restore or cleanup happens, one attempt is spent."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    pool.systemd_manager.get_service_active_state = MagicMock(return_value="unknown")
    state = _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7)
    pool._failed_reattach = {VmId(_HASH): state}
    restore = AsyncMock()
    monkeypatch.setattr(pool, "_restore_running_execution_from_config", restore)
    dead = AsyncMock()
    monkeypatch.setattr(pool, "_handle_dead_controller", dead)

    await pool._retry_failed_reattachments_once()

    assert VmId(_HASH) in pool._failed_reattach
    assert state.attempts == 2
    assert state.exhausted is False
    restore.assert_not_awaited()
    dead.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_exhausts_and_leaves_vm_running(monkeypatch):
    """After MAX attempts the VM is exhausted, kept as unmanaged, and NOT
    auto-stopped (Option B)."""
    from aleph.vm.pool import REATTACH_RETRY_MAX_ATTEMPTS, _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    pool.systemd_manager.get_service_active_state = MagicMock(return_value="active")
    state = _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7)
    pool._failed_reattach = {VmId(_HASH): state}

    async def always_fail(_cfg, _vm_index, _vm_id):
        msg = "still broken"
        raise RuntimeError(msg)

    monkeypatch.setattr(pool, "_restore_running_execution_from_config", always_fail)

    for _ in range(REATTACH_RETRY_MAX_ATTEMPTS):
        await pool._retry_failed_reattachments_once()

    assert state.exhausted is True
    assert VmId(_HASH) in pool._failed_reattach
    assert VmId(_HASH) in pool.unmanaged_vm_ids
    pool.systemd_manager.stop_and_disable.assert_not_called()


@pytest.mark.asyncio
async def test_retry_drops_vm_adopted_elsewhere(monkeypatch):
    """If the VM is already in the pool (adopted by an on-demand create), the
    retry drops it without attempting another restore."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    pool._failed_reattach = {VmId(_HASH): _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7)}
    pool.executions[VmId(_HASH)] = SimpleNamespace(vm_index=7)
    restore = AsyncMock()
    monkeypatch.setattr(pool, "_restore_running_execution_from_config", restore)

    await pool._retry_failed_reattachments_once()

    assert VmId(_HASH) not in pool._failed_reattach
    restore.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_drops_exhausted_vm_adopted_elsewhere(monkeypatch):
    """Even a given-up (exhausted) entry is dropped once another path tracks
    the VM: the adopted-elsewhere cleanup runs before the exhausted skip."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    state = _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7, exhausted=True)
    pool._failed_reattach = {VmId(_HASH): state}
    pool.executions[VmId(_HASH)] = SimpleNamespace(vm_index=7)
    restore = AsyncMock()
    monkeypatch.setattr(pool, "_restore_running_execution_from_config", restore)

    await pool._retry_failed_reattachments_once()

    assert VmId(_HASH) not in pool._failed_reattach
    restore.assert_not_awaited()


@pytest.mark.asyncio
async def test_discard_failed_reattach_stops_unit_and_removes_config():
    """Deleting a queued (here: even exhausted) failed-reattach VM stops its
    controller, removes its on-disk definition and dequeues it for good."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()
    state = _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=7), vm_index=7, exhausted=True)
    pool._failed_reattach = {VmId(_HASH): state}

    with patch("aleph.vm.pool.remove_controller_configuration") as remove_config:
        discarded = await pool.discard_failed_reattach(VmId(_HASH))

    assert discarded is True
    assert VmId(_HASH) not in pool._failed_reattach
    pool.systemd_manager.stop_and_disable.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")
    remove_config.assert_called_once_with(_HASH)


@pytest.mark.asyncio
async def test_discard_failed_reattach_without_entry_is_a_noop():
    pool = _bare_pool()
    pool.creation_lock = asyncio.Lock()

    discarded = await pool.discard_failed_reattach(VmId(_HASH))

    assert discarded is False
    pool.systemd_manager.stop_and_disable.assert_not_called()


def test_get_unique_vm_index_skips_failed_reattach_indexes(monkeypatch):
    """A queued/exhausted failed-reattach VM still owns its vm_index (tap,
    nft chains): handing it to a fresh create would let that create tear
    down the live VM's networking."""
    from aleph.vm.pool import _FailedReattach

    pool = _bare_pool()
    monkeypatch.setattr("aleph.vm.pool.settings.START_ID_INDEX", 4, raising=False)
    pool.executions = {VmId("a" * 64): SimpleNamespace(vm_index=4)}
    pool._failed_reattach = {VmId(_HASH): _FailedReattach(config=SimpleNamespace(vm_hash=_HASH, vm_id=5), vm_index=5)}

    assert pool.get_unique_vm_index() == 6


@pytest.mark.asyncio
async def test_retry_loop_returns_immediately_without_failures():
    """A clean startup (no failed reattachments) makes the loop a no-op."""
    pool = _bare_pool()
    pool._failed_reattach = {}
    await pool.run_reattach_retry_loop()  # must not hang
