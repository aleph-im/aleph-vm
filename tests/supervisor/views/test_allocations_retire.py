"""The allocation stop loop retires deallocated VMs as GONE.

Split out of the old ``tests/supervisor/test_views.py``, which was removed
with the Python supervisor daemon: these cases only ever needed a
``Supervisor``, so they drive ``setup_webapp`` with a mock of that interface.
"""

import json
import time as time_module
from hashlib import sha256
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import InstanceContent, ItemHash
from eth_account import Account
from eth_account.messages import encode_defunct

from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.agent.vm.retire import RetireReason
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    GpuDevice,
    IpAssignment,
    PciAddress,
    VmId,
    VmInfo,
    VmStatus,
)

VM_HASH = ItemHash("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")

# A hold-tier instance. The tier no longer matters to the stop loop; the
# stream-paid variant below pins that.
_HOLD_INSTANCE_CONTENT = {
    "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
    "time": 1713874241.800818,
    "allow_amend": False,
    "metadata": None,
    "authorized_keys": None,
    "variables": None,
    "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
    "resources": {"vcpus": 1, "memory": 256, "seconds": 30, "published_ports": None},
    "payment": {"type": "hold", "chain": "BASE"},
    "requirements": None,
    "replaces": None,
    "rootfs": {
        "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
        "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
        "use_latest": True,
        "comment": "",
        "persistence": "host",
        "size_mib": 1000,
    },
}


# The same instance paid by a Superfluid stream to this node.
_STREAM_INSTANCE_CONTENT = {
    **_HOLD_INSTANCE_CONTENT,
    "payment": {"type": "superfluid", "chain": "BASE", "receiver": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"},
}


def _make_aleph_eip191_v1_header(account, *, method="POST", path="/control/allocations", body=b"", iat=None) -> str:
    payload = {
        "method": method,
        "path": path,
        "body_sha256": sha256(body).hexdigest(),
        "iat": iat if iat is not None else int(time_module.time()),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signed = account.sign_message(encode_defunct(payload_bytes))
    return f"Aleph-EIP191-V1 sig={signed.signature.hex()},payload={payload_bytes.hex()}"


@pytest.fixture()
def scheduler_auth(monkeypatch):
    """Authorize a throwaway scheduler key and sign requests as it.

    Returns a callable that serializes the body and produces the matching
    `Aleph-EIP191-V1` headers. The signature binds method, path and body hash,
    so the caller must send the returned bytes verbatim (`data=`, not `json=`).
    """
    account = Account.create()
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [account.address])

    def _sign(body_dict=None, *, path="/control/allocations", method="POST"):
        body = b"" if body_dict is None else json.dumps(body_dict).encode()
        header = _make_aleph_eip191_v1_header(account, method=method, path=path, body=body)
        headers = {"Authorization": header}
        if body_dict is not None:
            headers["Content-Type"] = "application/json"
        return body, headers

    return _sign


def _running_vm_info(vm_hash=VM_HASH, *, gpus=(), confidential_mode=ConfidentialMode.NONE):
    return VmInfo(
        vm_id=VmId(str(vm_hash)),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        confidential_mode=confidential_mode,
        gpus=list(gpus),
    )


_A_GPU = GpuDevice(pci_host=PciAddress("0000:01:00.0"), device_id="10de:27b0", model="RTX 4000", supports_x_vga=True)


def _make_app_with_supervisor(supervisor):
    """Create a minimal webapp whose supervisor is the given double."""
    app = setup_webapp(supervisor=supervisor)
    app["pubsub"] = None
    app["supervisor"] = supervisor
    return app


@pytest.mark.asyncio
async def test_update_allocations_stop_loop_uses_supervisor(aiohttp_client, mocker, scheduler_auth):
    """update_allocations' stop loop must retire executions no longer in the
    allocation rather than hand-rolling delete_vm plus the record cleanup.

    Status is read from supervisor.list_vms() (VmInfo); persistence from the
    registry.
    """
    vm_hash = str(VM_HASH)
    message = InstanceContent.model_validate(_HOLD_INSTANCE_CONTENT)

    fake_supervisor = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[_running_vm_info(vm_hash)]))
    app = _make_app_with_supervisor(fake_supervisor)

    # Seed registry so the app knows the VM.
    app["vm_registry"].record(vm_hash, message=message, original=message, persistent=True)

    retire = mocker.patch("aleph.vm.agent.allocation.teardown.retire_vm", new_callable=AsyncMock)
    client = await aiohttp_client(app)

    # Empty allocation: vm_hash is not in persistent_vms or instances, so it must be stopped.
    body, headers = scheduler_auth({"persistent_vms": []})
    response = await client.post("/control/allocations", data=body, headers=headers)
    assert response.status == 200
    resp_json = await response.json()
    assert vm_hash in resp_json["stopped"]

    # Permanent dealloc goes through retire_vm(GONE), which owns the supervisor
    # quiesce, registry.forget and the persisted record cleanup.
    retire.assert_awaited_once_with(
        ItemHash(vm_hash), RetireReason.GONE, supervisor=fake_supervisor, registry=app["vm_registry"]
    )
    fake_supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_stop_loop_stops_eligible_vm(aiohttp_client, mocker, scheduler_auth):
    """A running, persistent, hold-tier VM not in the allocation must be
    retired as GONE and reported in stopped[]."""
    message = InstanceContent.model_validate(_HOLD_INSTANCE_CONTENT)

    fake_supervisor = MagicMock(
        delete_vm=AsyncMock(),
        list_vms=AsyncMock(return_value=[_running_vm_info()]),
    )
    app = _make_app_with_supervisor(fake_supervisor)
    app["vm_registry"].record(VM_HASH, message=message, original=message, persistent=True)
    retire = mocker.patch("aleph.vm.agent.allocation.teardown.retire_vm", new_callable=AsyncMock)

    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"persistent_vms": []})
    response = await client.post("/control/allocations", data=body, headers=headers)
    assert response.status == 200
    resp_json = await response.json()

    assert str(VM_HASH) in resp_json["stopped"]
    retire.assert_awaited_once_with(VM_HASH, RetireReason.GONE, supervisor=fake_supervisor, registry=app["vm_registry"])
    fake_supervisor.delete_vm.assert_not_awaited()


@pytest.mark.parametrize(
    "info",
    [
        _running_vm_info(),
        _running_vm_info(gpus=[_A_GPU]),
        _running_vm_info(confidential_mode=ConfidentialMode.SEV),
    ],
    ids=["plain", "gpu", "confidential"],
)
@pytest.mark.asyncio
async def test_stop_loop_stops_a_payg_vm_absent_from_the_allocation(aiohttp_client, mocker, scheduler_auth, info):
    """PAYG is scheduler-owned: the scheduler's payment gate validates the
    stream and drops an unpaid instance from the plan, and that decision only
    takes effect if the stop loop honours the absence. GPU-bearing and
    confidential PAYG included: those exclusions exist for hold-tier VMs the
    scheduler does not place, and most of the PAYG fleet carries a GPU."""
    message = InstanceContent.model_validate(_STREAM_INSTANCE_CONTENT)

    fake_supervisor = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[info]))
    app = _make_app_with_supervisor(fake_supervisor)
    app["vm_registry"].record(VM_HASH, message=message, original=message, persistent=True)
    retire = mocker.patch("aleph.vm.agent.allocation.teardown.retire_vm", new_callable=AsyncMock)

    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"persistent_vms": []})
    response = await client.post("/control/allocations", data=body, headers=headers)
    assert response.status == 200
    resp_json = await response.json()

    assert str(VM_HASH) in resp_json["stopped"]
    retire.assert_awaited_once_with(VM_HASH, RetireReason.GONE, supervisor=fake_supervisor, registry=app["vm_registry"])


@pytest.mark.asyncio
async def test_update_allocations_starts_a_payg_instance(aiohttp_client, mocker, scheduler_auth):
    """The scheduler dispatches validated PAYG through /control/allocations,
    so the start path must not gate on payment tier. Pins that the allocating
    half already works, since the stop half now relies on it."""
    message = InstanceContent.model_validate(_STREAM_INSTANCE_CONTENT)

    fake_supervisor = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[]))
    app = _make_app_with_supervisor(fake_supervisor)
    app["vm_registry"].record(VM_HASH, message=message, original=message, persistent=True)
    start = mocker.patch("aleph.vm.agent.views.start_persistent_vm", new_callable=AsyncMock)

    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"instances": [str(VM_HASH)]})
    response = await client.post("/control/allocations", data=body, headers=headers)
    assert response.status == 200
    resp_json = await response.json()

    assert str(VM_HASH) in resp_json["successful"]
    assert start.await_args.args[0] == VM_HASH
