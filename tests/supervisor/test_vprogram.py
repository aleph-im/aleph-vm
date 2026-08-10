"""V-PROGRAM (verifiable SEV-SNP program) support in the agent.

Uses the canonical cross-SDK fixture message (item_hash 4c319b6b...); see
docs/plans/2026-07-11-vprogram-scheduler-support-design.md.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import (
    InstanceMessage,
    ItemHash,
    PaymentType,
    ProgramMessage,
    VerifiableProgramContent,
    VerifiableProgramMessage,
    parse_message,
)

from aleph.vm.agent.messages import update_message
from aleph.vm.agent.resources import Allocation
from aleph.vm.agent.run import create_vm_execution, run_code_on_request
from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.agent.tasks import _group_executions_by_payment
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.vm_type import VmType

FIXTURE = Path(__file__).parent / "fixtures" / "vprogram_message.json"
# SHA-256 of "test", used by the existing views tests as the allocation token
TEST_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def load_vprogram_message() -> VerifiableProgramMessage:
    message = parse_message(json.loads(FIXTURE.read_text()))
    assert isinstance(message, VerifiableProgramMessage)
    return message


def test_vm_type_v_program():
    message = load_vprogram_message()
    assert isinstance(message.content, VerifiableProgramContent)
    assert VmType.from_message_content(message.content) == VmType.v_program
    # .name is exposed in the executions list and must match the scheduler's
    # "v_program" vm-type string
    assert VmType.v_program.name == "v_program"


def test_storage_executable_assert_accepts_vprogram():
    # get_message asserts the parsed message is executable; the union must
    # include VerifiableProgramMessage
    message = load_vprogram_message()
    assert isinstance(message, InstanceMessage | ProgramMessage | VerifiableProgramMessage)


def test_agent_record_is_vprogram():
    message = load_vprogram_message()
    record = AgentVmRecord(message=message.content, original=message.content, persistent=True)
    assert record.is_vprogram
    # The schema enforces credit payment; node-side sweep exclusion is explicit
    assert record.uses_payment_credit


@pytest.mark.asyncio
async def test_update_message_vprogram_is_noop():
    message = load_vprogram_message()
    # Must not attempt any amend resolution (would hit the network):
    # v-programs are immutable and every reference is pinned by exact hash
    await update_message(message)


def _running_vm_info(vm_hash: str) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_hash),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        confidential_mode=ConfidentialMode.SEV_SNP,
        gpus=[],
    )


def test_allocation_model_v_programs():
    # New bucket parses; old payloads without the key still validate
    allocation = Allocation.model_validate({"persistent_vms": []})
    assert allocation.v_programs == set()
    vm_hash = load_vprogram_message().item_hash
    allocation = Allocation.model_validate({"v_programs": [str(vm_hash)]})
    assert allocation.v_programs == {vm_hash}


@pytest.mark.asyncio
async def test_update_allocations_starts_v_programs(aiohttp_client, mocker):
    """v_programs hashes go through the same start path as instances."""
    message = load_vprogram_message()
    vm_hash = str(message.item_hash)

    app = setup_webapp(supervisor=LocalSupervisor(None))
    app["pubsub"] = None
    app["supervisor"] = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[]))

    mock_start = mocker.patch("aleph.vm.agent.views.start_persistent_vm", new_callable=AsyncMock)
    settings.ALLOCATION_TOKEN_HASH = TEST_TOKEN_HASH
    client = await aiohttp_client(app)

    response = await client.post(
        "/control/allocations",
        json={"v_programs": [vm_hash]},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    resp_json = await response.json()
    assert vm_hash in resp_json["successful"]
    assert mock_start.await_count == 1
    assert mock_start.await_args.args[0] == ItemHash(vm_hash)


@pytest.mark.asyncio
async def test_update_allocations_stops_descheduled_vprogram(aiohttp_client, mocker):
    """The scheduler is the single source of truth for v-programs: absence from
    the allocation stops them, despite being credit-paid and confidential
    (both of which spare other VM types)."""
    message = load_vprogram_message()
    vm_hash = str(message.item_hash)

    app = setup_webapp(supervisor=LocalSupervisor(None))
    app["pubsub"] = None
    app["vm_registry"].record(ItemHash(vm_hash), message=message.content, original=message.content, persistent=True)

    fake_supervisor = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[_running_vm_info(vm_hash)]))
    app["supervisor"] = fake_supervisor

    mock_delete_records = mocker.patch("aleph.vm.agent.views.delete_records_for_vm", new_callable=AsyncMock)
    settings.ALLOCATION_TOKEN_HASH = TEST_TOKEN_HASH
    client = await aiohttp_client(app)

    response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    resp_json = await response.json()
    assert vm_hash in resp_json["stopped"]
    fake_supervisor.delete_vm.assert_awaited_once_with(VmId(vm_hash))
    mock_delete_records.assert_awaited_once_with(vm_hash)
    assert ItemHash(vm_hash) not in app["vm_registry"]


@pytest.mark.asyncio
async def test_update_allocations_spares_scheduled_vprogram(aiohttp_client, mocker):
    """A running v-program still listed in v_programs must not be stopped."""
    message = load_vprogram_message()
    vm_hash = str(message.item_hash)

    mocker.patch("aleph.vm.agent.views.start_persistent_vm", new_callable=AsyncMock)
    app = setup_webapp(supervisor=LocalSupervisor(None))
    app["pubsub"] = None
    app["vm_registry"].record(ItemHash(vm_hash), message=message.content, original=message.content, persistent=True)

    fake_supervisor = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[_running_vm_info(vm_hash)]))
    app["supervisor"] = fake_supervisor

    settings.ALLOCATION_TOKEN_HASH = TEST_TOKEN_HASH
    client = await aiohttp_client(app)

    response = await client.post(
        "/control/allocations",
        json={"v_programs": [vm_hash]},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    resp_json = await response.json()
    assert vm_hash not in resp_json["stopped"]
    fake_supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_vm_execution_vprogram_fails_cleanly(mocker):
    """The allocation is accepted but the SNP launch path is not wired yet:
    create must raise the create-path vocabulary (VmSetupError), which
    update_allocations reports per-VM."""
    message = load_vprogram_message()
    mocker.patch("aleph.vm.agent.run.load_updated_message", new_callable=AsyncMock, return_value=(message, message))

    with pytest.raises(VmSetupError, match="SEV-SNP"):
        await create_vm_execution(
            message.item_hash,
            supervisor=MagicMock(),
            registry=AgentVmRegistry(),
            capacity=MagicMock(),
            persistent=True,
        )


@pytest.mark.asyncio
async def test_run_code_rejects_vprogram():
    """On-demand execution endpoints must reject v-programs: they are
    scheduler-controlled."""
    from aiohttp.web_exceptions import HTTPBadRequest

    message = load_vprogram_message()
    registry = AgentVmRegistry()
    registry.record(message.item_hash, message=message.content, original=message.content, persistent=True)

    request = MagicMock()
    request.app = {
        "supervisor": MagicMock(),
        "expiry": MagicMock(),
        "update_watcher": MagicMock(),
        "vm_registry": registry,
        "capacity": MagicMock(),
        "program_client": MagicMock(),
    }

    with pytest.raises(HTTPBadRequest, match="scheduler-controlled"):
        await run_code_on_request(message.item_hash, "/", request)


def test_payment_sweep_excludes_vprograms():
    """V-Programs are credit-paid by schema but must never be grouped into the
    node-side payment sweep: the CCN and the scheduler enforce their budget."""
    message = load_vprogram_message()
    vm_hash = str(message.item_hash)

    registry = AgentVmRegistry()
    registry.record(ItemHash(vm_hash), message=message.content, original=message.content, persistent=True)

    grouped = _group_executions_by_payment([_running_vm_info(vm_hash)], registry, PaymentType.credit)
    assert grouped == {}
