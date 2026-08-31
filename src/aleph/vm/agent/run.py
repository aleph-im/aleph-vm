import asyncio
import json
import logging
from dataclasses import replace
from typing import Any

import msgpack
from aiohttp import ClientResponseError, web
from aiohttp.web_exceptions import (
    HTTPBadGateway,
    HTTPBadRequest,
    HTTPGatewayTimeout,
    HTTPInternalServerError,
    HTTPServiceUnavailable,
)
from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ItemHash,
    ProgramContent,
    VerifiableProgramContent,
)
from msgpack import UnpackValueError
from multidict import CIMultiDict

from aleph.vm.agent.aggregate import get_user_settings
from aleph.vm.agent.capacity import (
    CapacityManager,
    requested_gpu_ids,
    requirements_from_message,
)
from aleph.vm.agent.expiry import ExpiryManager
from aleph.vm.agent.snp_instance_launch import (
    build_snp_instance_spec,
    is_snp_instance,
    remove_snp_instance_staging,
)
from aleph.vm.agent.translate import build_create_vm_spec, build_program_create_vm_spec
from aleph.vm.agent.update_watcher import UpdateWatcher
from aleph.vm.agent.vm.program_client import ProgramGuestClient
from aleph.vm.agent.vm_registry import AgentVmRegistry, persist_record
from aleph.vm.agent.vprogram_launch import (
    build_vprogram_spec,
    remove_vprogram_staging,
    resolve_vprogram_attestation_port,
)
from aleph.vm.conf import settings
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor_interface import errors as supervisor_errors
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import (
    FileTooLargeError,
    ResourceDownloadError,
    VmNotFoundError,
    VmSetupError,
)
from aleph.vm.supervisor_interface.types import (
    GuestPort,
    HostPort,
    PortForwardSpec,
    Protocol,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils import HostNotFoundError

from .messages import load_updated_message
from .pubsub import PubSub

logger = logging.getLogger(__name__)

# Readiness poll for the spec create path (replaces execution.becomes_ready()).
_START_POLL_TIMEOUT_SECONDS = 120.0
_START_POLL_INTERVAL_SECONDS = 0.5


async def build_asgi_scope(path: str, request: web.Request) -> dict[str, Any]:
    # ASGI mandates lowercase header names
    headers = tuple((name.lower(), value) for name, value in request.raw_headers)
    return {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": headers,
        "body": await request.read(),
    }


async def build_event_scope(event) -> dict[str, Any]:
    """Build an ASGI scope for an event."""
    return {
        "type": "aleph.message",
        "body": event,
    }


def _is_spec_eligible(content) -> bool:
    """True when the supervisor's message-free create path can handle this message.

    Instances are QEMU-only, so every instance reaches build_create_vm_spec.
    That includes GPU instances (the agent resolves a concrete host card
    through its CapacityManager before create_vm) and confidential instances
    (the spec carries spec.tee and the engine takes the confidential launch
    path, leaving the VM awaiting its owner's session). An InstanceContent that
    explicitly requests a Firecracker hypervisor is rejected by
    build_create_vm_spec with InvalidBackendError: instances do not run on
    Firecracker.
    """
    return isinstance(content, InstanceContent)


async def resolve_port_forwards(vm_id: VmId, content, *, strict: bool = False) -> list[PortForwardSpec]:
    """Agent-side policy: translate the user's port-forwarding aggregate settings
    into the set of forwards the hypervisor should apply.

    This is the agent half of the old VmExecution.fetch_port_redirect_config_and_setup.
    Nothing here touches nftables; the caller applies each spec through
    supervisor.add_port_forward. host_port is left 0; the hypervisor assigns it.

    ``strict=True`` turns an aggregate-fetch failure into an exception instead
    of the SSH-only fallback. The fallback is right on create (worst case the
    VM starts with SSH only), but a convergence caller reconciling an already
    forwarded VM must not treat "could not fetch" as "the user removed every
    port": converging on the fallback set would tear the user's forwards down
    on a transient CCN error. Strict callers skip reconciling instead.
    """
    ports_requests: dict[int, dict[str, bool]] = {}
    try:
        settings_for_user = await get_user_settings(content.address, "port-forwarding")
        vm_port_forwarding = settings_for_user.get(str(vm_id), {}) or {}
        fetched = vm_port_forwarding.get("ports", {})
        ports_requests = {int(port): flags for port, flags in fetched.items()}
    except Exception:
        if strict:
            raise
        logger.info("Could not fetch port redirect settings for %s", content.address, exc_info=True)

    # Always forward SSH.
    ports_requests.setdefault(22, {"tcp": True, "udp": False})

    forwards: list[PortForwardSpec] = []
    for vm_port, flags in ports_requests.items():
        for protocol in (Protocol.TCP, Protocol.UDP):
            if flags.get(protocol.value):
                forwards.append(
                    PortForwardSpec(
                        vm_id=vm_id,
                        host_port=HostPort(0),
                        vm_port=GuestPort(int(vm_port)),
                        protocol=protocol,
                    )
                )
    return forwards


async def _reconcile_forwards(supervisor: Supervisor, vm_id: VmId, desired_specs: list[PortForwardSpec]) -> None:
    """Diff `desired_specs` against what the hypervisor currently reports for
    `vm_id` and issue add/remove calls so the two converge. The hypervisor
    owns application and persistence; this is pure agent policy, and it is
    idempotent: calling it again with the same desired set (e.g. on
    re-adoption) issues no calls at all.
    """
    desired = {(int(spec.vm_port), spec.protocol): spec for spec in desired_specs}
    current = {(int(info.vm_port), info.protocol): info for info in await supervisor.list_port_forwards(vm_id)}
    for key, info in current.items():
        if key not in desired:
            await supervisor.remove_port_forward(vm_id, info.host_port, info.protocol)
    for key, spec in desired.items():
        if key not in current:
            await supervisor.add_port_forward(spec)


async def reconcile_port_forwards(supervisor: Supervisor, vm_id: VmId, content) -> None:
    """Drive the hypervisor's forwards to match the aggregate settings.

    Agent policy half of the old fetch_port_redirect_config_and_setup: compute
    the desired set, then converge through ``_reconcile_forwards``.
    """
    await _reconcile_forwards(supervisor, vm_id, await resolve_port_forwards(vm_id, content))


def resolve_vprogram_port_forwards(vm_id: VmId, attest_port: int | None) -> list[PortForwardSpec]:
    """The only forward a V-PROGRAM gets: the manifest's RA-TLS attestation
    port (tcp), mapped to a host IPv4 port so an external client (the aleph
    CLI) can reach the guest's RA-TLS endpoint. Host-only DNAT,
    measurement-neutral: unlike instances, no user aggregate is consulted and
    SSH is never force-added. `attest_port` is None when the manifest
    declared no aleph.ra-tls tcp transport; that V-PROGRAM gets no mapping.
    """
    if attest_port is None:
        return []
    return [
        PortForwardSpec(
            vm_id=vm_id,
            host_port=HostPort(0),
            vm_port=GuestPort(int(attest_port)),
            protocol=Protocol.TCP,
        )
    ]


async def reconcile_vprogram_port_forwards(supervisor: Supervisor, vm_id: VmId, attest_port: int | None) -> None:
    """Drive the hypervisor's forwards to match the V-PROGRAM's single
    attestation-port mapping. Reuses ``_reconcile_forwards``, so it is
    idempotent by construction: both the create path and the re-adoption
    path (``reconcile_adopted_port_forwards``) call it safely.
    """
    await _reconcile_forwards(supervisor, vm_id, resolve_vprogram_port_forwards(vm_id, attest_port))


async def reconcile_adopted_port_forwards(supervisor: Supervisor, registry: AgentVmRegistry, vm_hash: ItemHash) -> None:
    """Best-effort port-forward healing for a VM adopted already-created.

    The create path applies forwards right after the VM first reaches RUNNING;
    a VM re-adopted on a later allocation (typically after an agent restart)
    skipped that step in this agent's lifetime. If the previous life crashed
    in the window between RUNNING and the forward setup, the VM is up but
    unreachable (no SSH for an instance, no attestation endpoint for a
    V-PROGRAM); for instances, the port-forwarding aggregate may also have
    changed while the agent was down, past the live aggregate watcher.
    Converge the hypervisor state here.

    Best-effort by design, unlike the create path (which fails loudly and
    tears the VM down): the adopted VM is already up and possibly serving, so
    a healing failure must never fail the allocation and invite scheduler
    churn. Skipping leaves exactly the state we found.
    """
    record = registry.get(vm_hash)
    if record is None:
        # Nothing to derive the desired forward set from (agent DB loss).
        logger.warning("No agent record for adopted VM %s; port forwards left as found", vm_hash)
        return
    vm_id = VmId(str(vm_hash))
    content = record.message
    try:
        if isinstance(content, VerifiableProgramContent):
            attest_port = await resolve_vprogram_attestation_port(content)
            await reconcile_vprogram_port_forwards(supervisor, vm_id, attest_port)
        elif _is_spec_eligible(content):
            # strict: a failed aggregate fetch must skip healing, not converge
            # the VM onto the SSH-only fallback set (which would remove the
            # user's aggregate-declared forwards on a transient CCN error).
            await _reconcile_forwards(supervisor, vm_id, await resolve_port_forwards(vm_id, content, strict=True))
        # Programs get no agent-side forwards: nothing to heal.
    except Exception:
        logger.warning("Could not reconcile port forwards for adopted VM %s; left as found", vm_hash, exc_info=True)


class VmStartupError(Exception):
    """A VM was created but never reached the running state: it entered a
    terminal status (FAILED/STOPPED) or timed out before RUNNING.

    Agent-internal (raised by ``_wait_until_running``, never crosses the
    Supervisor boundary), so it is not part of the SupervisorError vocabulary.
    ``create_vm_execution_or_raise_http_error`` (instances, v-programs) and
    ``_raise_http_for_program_error`` (on-demand programs) map it to a clear
    HTTP reason instead of the generic "unhandled error" bucket, so the
    mapping covers every VM type."""


async def _wait_until_running(
    supervisor: Supervisor,
    vm_id: VmId,
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> VmInfo:
    """Poll get_vm until the VM reports RUNNING.

    In-process the first poll already reports RUNNING (create_vm blocked until
    boot); across a future gRPC boundary this does real work. Raises
    VmStartupError on a terminal status or after `timeout` seconds.

    `timeout`/`interval` default to the module constants, resolved at call time
    so tests (and operators) can override them by patching the constants.
    """
    if timeout is None:
        timeout = _START_POLL_TIMEOUT_SECONDS
    if interval is None:
        interval = _START_POLL_INTERVAL_SECONDS
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        info = await supervisor.get_vm(vm_id)
        if info.status is VmStatus.RUNNING:
            return info
        if info.status in (VmStatus.STOPPED, VmStatus.FAILED):
            msg = f"VM {vm_id} entered status {info.status.value} while waiting to start"
            raise VmStartupError(msg)
        if asyncio.get_running_loop().time() >= deadline:
            msg = f"VM {vm_id} did not reach RUNNING within {timeout}s"
            raise VmStartupError(msg)
        await asyncio.sleep(interval)


_ATTEST_READY_TIMEOUT_SECONDS = 90.0
_ATTEST_READY_POLL_INTERVAL_SECONDS = 2.0


async def _wait_until_attest_endpoint_listens(
    supervisor: Supervisor,
    vm_id: VmId,
    attest_port: int,
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> None:
    """Gate a confidential create on the guest's RA-TLS attestation service
    accepting a TCP connection.

    RUNNING only proves the controller unit is active: an SNP launch can wedge
    inside firmware while QEMU lives on, and the attestation endpoint is the
    guest's sole consumer-facing contract. A guest that never listens is a
    failed launch and must fail the create loudly (the caller tears down and
    the scheduler retries), not survive as a zombie the owner can only watch.
    """
    if timeout is None:
        timeout = _ATTEST_READY_TIMEOUT_SECONDS
    if interval is None:
        interval = _ATTEST_READY_POLL_INTERVAL_SECONDS
    info = await supervisor.get_vm(vm_id)
    address = info.ipv4.address
    if not address:
        msg = f"VM {vm_id} has no IPv4 assignment to reach its attestation endpoint"
        raise VmStartupError(msg)
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(address, attest_port), timeout=5.0)
        except (OSError, asyncio.TimeoutError):
            if asyncio.get_running_loop().time() >= deadline:
                msg = (
                    f"VM {vm_id} guest attestation endpoint {address}:{attest_port} did not "
                    f"accept a TCP connection within {timeout}s: the guest likely failed to boot"
                )
                raise VmStartupError(msg) from None
            await asyncio.sleep(interval)
        else:
            writer.close()
            await writer.wait_closed()
            return


async def finish_instance_create(supervisor: Supervisor, vm_id: VmId, content) -> None:
    """Post-create completion shared by the normal create path and the migration
    import runner: wait until the instance reports RUNNING, then apply the
    agent's resolved port forwards (always-22 plus the user's port-forwarding
    aggregate) through supervisor.add_port_forward.

    create_vm_from_spec only reloads *persisted* host port mappings, so a fresh
    destination (migration) would otherwise come up with no port forward at all
    - no SSH, and mapped_ports empty. Running the same tail here keeps a migrated
    instance identical to a freshly created one.
    """
    await _wait_until_running(supervisor, vm_id)
    for forward in await resolve_port_forwards(vm_id, content):
        await supervisor.add_port_forward(forward)


async def _wait_until_gone(
    supervisor: Supervisor,
    vm_id: VmId,
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> None:
    """Poll get_vm until the VM is gone (VmNotFoundError)."""
    if timeout is None:
        timeout = _START_POLL_TIMEOUT_SECONDS
    if interval is None:
        interval = _START_POLL_INTERVAL_SECONDS
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            return
        if asyncio.get_running_loop().time() >= deadline:
            msg = f"VM {vm_id} did not stop within {timeout}s"
            raise asyncio.TimeoutError(msg)
        await asyncio.sleep(interval)


def _admit(capacity: CapacityManager, content: ExecutableContent, vm_hash: ItemHash, *, is_instance: bool) -> None:
    """Agent-side admission, ahead of any download.

    Disk is judged here and only here: build_*_spec downloads the resources and
    creates the volume files, so a disk check after it would measure space this
    VM has already taken. Refusing here also means a host with no room never
    pays for the download.

    ``is_instance`` is passed explicitly rather than taken from the message:
    a V-PROGRAM is an SNP VM and belongs in the instance memory bucket, but it
    is not an InstanceContent, which is all requirements_from_message can see.
    """
    requirements = requirements_from_message(content)
    capacity.check_capacity(
        memory_mib=requirements.memory_mib,
        vcpus=requirements.vcpus,
        disk_mib=requirements.disk_mib,
        max_volume_mib=requirements.max_volume_mib,
        is_instance=is_instance,
        exclude_vm_hash=vm_hash,
    )


async def create_vm_execution(
    vm_hash: ItemHash,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    persistent: bool = False,
) -> None:
    """Create a VM for the given message.

    Every supported content type is created through the Supervisor abstraction:
    programs through the spec program path, instances (QEMU-only, including
    confidential and GPU instances) through the spec path. Capacity admission
    (the memory buckets, vCPU overcommit) and GPU resolution are agent policy,
    run through ``capacity`` before create_vm; the supervisor only enforces its
    mechanism backstops. The agent records and persists its own knowledge of
    the VM and returns None; the hypervisor object lives behind the supervisor.
    The agent never touches a VmPool: there is no legacy pool fallback anymore.
    An unsupported content type is rejected with a clear error.
    """
    message, original_message = await load_updated_message(vm_hash)

    logger.debug(f"Message: {json.dumps(message.model_dump(exclude_none=True), indent=4, sort_keys=True, default=str)}")

    content = message.content
    if isinstance(content, ProgramContent):
        # Programs go through the spec path. Persistent programs boot under
        # systemd now; their guest configuration (code push) is applied lazily
        # on the first request through _ensure_program_vm. On-demand programs
        # are created and configured per request there too, so this branch only
        # does eager work for the persistent (scheduled) case.
        _admit(capacity, content, vm_hash, is_instance=False)
        spec, _resources = await build_program_create_vm_spec(vm_hash, content)
        capacity.check_capacity(
            memory_mib=content.resources.memory,
            vcpus=content.resources.vcpus,
            disk_mib=0,
            is_instance=False,
            exclude_vm_hash=vm_hash,
        )
        info = await supervisor.create_vm(spec)
        record = registry.record(
            vm_hash, message=content, original=original_message.content, persistent=bool(content.on.persistent)
        )
        try:
            await _wait_until_running(supervisor, info.vm_id)
        except Exception:
            registry.forget(vm_hash)
            try:
                await supervisor.delete_vm(info.vm_id)
            except Exception:
                logger.exception("Teardown of half-started program VM %s failed", vm_hash)
            raise
        await persist_record(vm_hash, record)
        return None

    if _is_spec_eligible(content):
        # Record the owner identity up front — BEFORE build_create_vm_spec (which
        # downloads the confidential rootfs/firmware, several seconds) and before
        # create_vm (~20s). The scheduler exposes placement earlier, so a
        # confidential owner's one-shot init-session call can land anywhere in that
        # download+create window. Recording here lets the operator API answer
        # owner-auth immediately via get_agent_record_or_404; otherwise that lookup
        # 404s before the awaiting-init wait can even run, the owner's single call
        # is lost, and the test forgets the instance (which the reconcile then
        # reaps). The endpoint still waits for the VM to reach the awaiting-init
        # state before initializing it; the supervisor machinery never reads this
        # record. Spec-eligible VMs are QEMU instances, always persistent.
        record = registry.record(vm_hash, message=content, original=original_message.content, persistent=True)
        snp_instance = is_snp_instance(content)
        attest_port: int | None = None
        try:
            _admit(capacity, content, vm_hash, is_instance=True)
            if snp_instance:
                # SEV-SNP confidential instances build through the dedicated
                # LUKS-rootfs SNP launch path, not build_create_vm_spec (which
                # would build a SEV spec with no firmware, since these
                # messages carry no trusted_execution.firmware). GPU
                # passthrough is not supported yet on this path: reject
                # before any staging I/O runs.
                if requested_gpu_ids(content):
                    msg = "GPU passthrough is not supported on SEV-SNP instances yet"
                    raise VmSetupError(msg)
                spec, attest_port = await build_snp_instance_spec(vm_hash, content)
            else:
                spec = await build_create_vm_spec(vm_hash, content)
            # Agent-side admission, after the download so a failed download
            # never consumes a GPU hold: bucket from the message type, then
            # resolve the requested device_ids to concrete host cards (owner =
            # message.address, consuming this owner's own holds). This VM's
            # own registry record (the early owner record above) is excluded
            # from the committed sums.
            capacity.check_capacity(
                memory_mib=content.resources.memory,
                vcpus=content.resources.vcpus,
                disk_mib=0,
                is_instance=True,
                exclude_vm_hash=vm_hash,
            )
            if not snp_instance:
                # GPU resolution only applies to the legacy spec path: SNP
                # instances are rejected above before reaching here.
                requested_gpus = requested_gpu_ids(content)
                if requested_gpus:
                    resolved_gpus = await capacity.resolve_gpus(requested_gpus, owner=content.address)
                    spec = replace(spec, gpus=resolved_gpus)
            info = await supervisor.create_vm(spec)
        except Exception:
            # build or create failed: drop the early record so a failed create
            # never leaves a dangling owner-identity entry behind (a record with no
            # VM the supervisor knows about). Nothing is persisted yet, so
            # forgetting the in-memory entry is sufficient.
            registry.forget(vm_hash)
            if snp_instance:
                # build_snp_instance_spec may have already extracted the
                # runtime bundle (e.g. capacity admission fails after
                # staging): do not leak it.
                remove_snp_instance_staging(vm_hash)
            raise
        if info.awaiting_confidential_init:
            # A confidential VM is created but not started: only the owner can
            # start it, by uploading the session certificates via
            # /confidential/initialize. Waiting for RUNNING would block forever,
            # and there are no port forwards to apply on a VM that is not up.
            # This mirrors the message path, which never waits on a confidential
            # VM either. SNP instances never set this: the daemon boots them
            # immediately, so this branch is SEV-only.
            await persist_record(vm_hash, record)
            return None
        try:
            await finish_instance_create(supervisor, info.vm_id, content)
            if attest_port is not None:
                # The guest attestation service (aleph.ra-tls) the runtime
                # manifest pinned: forward it alongside SSH and the user's
                # own aggregate so the owner can attest post-boot.
                await supervisor.add_port_forward(
                    PortForwardSpec(
                        vm_id=info.vm_id,
                        host_port=HostPort(0),
                        vm_port=GuestPort(attest_port),
                        protocol=Protocol.TCP,
                    )
                )
                await _wait_until_attest_endpoint_listens(supervisor, info.vm_id, attest_port)
        except Exception:
            # Readiness or port-forward setup failed: tear the half-started VM
            # down, but never let a teardown error mask the original failure.
            registry.forget(vm_hash)
            try:
                await supervisor.delete_vm(info.vm_id)
            except Exception:
                logger.exception("Teardown of half-started VM %s failed", vm_hash)
            if snp_instance:
                remove_snp_instance_staging(vm_hash)
            raise
        # Agent persists its own knowledge; the hypervisor object is not
        # touched. Registry rehydration and past-logs owner-auth read the
        # message back from the agent DB.
        await persist_record(vm_hash, record)
        return None

    if isinstance(content, VerifiableProgramContent):
        # V-PROGRAM: an auto-booting SEV-SNP VM. build_vprogram_spec fetches
        # the runtime manifest, integrity-checks and stages the measured
        # bundle, and returns a spec whose TeeConfig takes the SNP launch
        # path. Mirrors the instance path above: record early, build spec,
        # create, wait, persist; forget (and tear down) on failure. Unlike
        # SEV instances there is no owner session to wait for: the daemon
        # boots an SNP VM immediately (awaiting_confidential_init is never
        # set), so the plain readiness wait applies.
        record = registry.record(vm_hash, message=content, original=original_message.content, persistent=True)
        try:
            _admit(capacity, content, vm_hash, is_instance=True)
            spec, attest_port = await build_vprogram_spec(vm_hash, content)
            # Agent-side admission after the download, like the instance path:
            # a failed bundle fetch never consumes capacity.
            capacity.check_capacity(
                memory_mib=content.resources.memory,
                vcpus=content.resources.vcpus,
                disk_mib=0,
                is_instance=True,
                exclude_vm_hash=vm_hash,
            )
            info = await supervisor.create_vm(spec)
        except Exception:
            registry.forget(vm_hash)
            # build_vprogram_spec may have already extracted the bundle (e.g.
            # capacity admission fails after staging): do not leak it.
            remove_vprogram_staging(vm_hash)
            raise
        try:
            await _wait_until_running(supervisor, info.vm_id)
            # Host-only DNAT so an external client (the aleph CLI) can reach
            # the guest's RA-TLS attestation endpoint; measurement-neutral
            # (no guest image/cmdline change) and idempotent via the same
            # reconcile machinery the instance path uses.
            #
            # A reconcile failure lands in the teardown branch below on
            # purpose, mirroring the instance path: a V-PROGRAM whose
            # attestation endpoint cannot be mapped is unreachable for its
            # sole consumer, so failing the create loudly (and letting the
            # scheduler retry) beats keeping an unusable VM alive.
            await reconcile_vprogram_port_forwards(supervisor, info.vm_id, attest_port)
            if attest_port is not None:
                await _wait_until_attest_endpoint_listens(supervisor, info.vm_id, attest_port)
        except Exception:
            registry.forget(vm_hash)
            try:
                await supervisor.delete_vm(info.vm_id)
            except Exception:
                logger.exception("Teardown of half-started V-PROGRAM %s failed", vm_hash)
            remove_vprogram_staging(vm_hash)
            raise
        await persist_record(vm_hash, record)
        return None

    # Every supported content type is handled above: programs through the spec
    # program path, instances (plain, GPU, confidential) through the spec path.
    # There is no pool fallback anymore. Anything else is genuinely unsupported.
    raise HTTPBadRequest(
        reason="Unsupported message type",
        text=f"VM {vm_hash} has content type {type(content).__name__}, which this CRN cannot run.",
    )


async def create_vm_execution_or_raise_http_error(
    vm_hash: ItemHash,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    persistent: bool = False,
) -> None:
    # The spec path tears down and forgets a half-started VM inside
    # create_vm_execution (registry.forget + supervisor.delete_vm), so this
    # wrapper only translates failures to HTTP responses. The agent holds no
    # pool to clean up.
    try:
        return await create_vm_execution(
            vm_hash=vm_hash, supervisor=supervisor, registry=registry, capacity=capacity, persistent=persistent
        )
    except ResourceDownloadError as error:
        logger.exception(error)
        raise HTTPBadRequest(reason="Code, runtime or data not available") from error
    except (InsufficientResourcesError, supervisor_errors.InsufficientResourcesError) as error:
        # The spec path's atomic admission surfaces the boundary error through
        # LocalSupervisor.create_vm (translating_errors).
        logger.warning("Refusing %s: %s", vm_hash, error)
        raise HTTPServiceUnavailable(
            reason="Insufficient capacity",
            text="This CRN cannot host the requested workload at this time.",
        ) from error
    except FileTooLargeError as error:
        raise HTTPInternalServerError(reason=error.args[0]) from error
    except VmStartupError as error:
        # Created but never reached RUNNING (terminal status or start timeout):
        # a distinct, expected outcome, not the generic "unhandled error".
        logger.warning("VM %s failed to start: %s", vm_hash, error)
        raise HTTPInternalServerError(reason="VM failed to start") from error
    except VmSetupError as error:
        logger.exception(error)
        raise HTTPInternalServerError(reason="Error during vm initialisation") from error
    except HostNotFoundError as error:
        logger.exception(error)
        raise HTTPInternalServerError(reason="Host did not respond to ping") from error
    except ClientResponseError as error:
        logger.exception(error)
        if error.status == 404:
            raise HTTPInternalServerError(reason=f"Item hash {vm_hash} not found") from error
        else:
            raise HTTPInternalServerError(reason=f"Error downloading {vm_hash}") from error
    except Exception as error:
        logger.exception(error)
        raise HTTPInternalServerError(reason="Unhandled error during initialisation") from error


async def _resolve_program_content(vm_hash: ItemHash, registry: AgentVmRegistry):
    """The (message, original) contents for a program, from the agent's own
    registry when known, else loaded from the network."""
    record = registry.get(vm_hash)
    if record is not None:
        return record.message, record.original
    message, original_message = await load_updated_message(vm_hash)
    return message.content, original_message.content


def _raise_http_for_program_error(error: Exception, vm_hash: ItemHash) -> None:
    """Map program create/setup failures to HTTP responses.

    Both the agent-side download phase and the supervisor boundary now raise the
    closed ``supervisor_interface.errors.SupervisorError`` vocabulary, so the
    branches below match a single error hierarchy.
    """
    if isinstance(error, ResourceDownloadError):
        logger.exception(error)
        raise HTTPBadRequest(reason="Code, runtime or data not available") from error
    if isinstance(error, (InsufficientResourcesError, supervisor_errors.InsufficientResourcesError)):
        logger.warning("Refusing %s: %s", vm_hash, error)
        raise HTTPServiceUnavailable(
            reason="Insufficient capacity",
            text="This CRN cannot host the requested workload at this time.",
        ) from error
    if isinstance(error, FileTooLargeError):
        raise HTTPInternalServerError(reason=str(error) or "File too large") from error
    if isinstance(error, VmStartupError):
        # Created but never reached RUNNING (terminal status or start timeout):
        # a distinct, expected outcome, not the generic "unhandled error".
        logger.warning("VM %s failed to start: %s", vm_hash, error)
        raise HTTPInternalServerError(reason="VM failed to start") from error
    if isinstance(error, VmSetupError):
        logger.exception(error)
        raise HTTPInternalServerError(reason="Error during vm initialisation") from error
    if isinstance(error, supervisor_errors.MicroVMInitError):
        logger.exception(error)
        raise HTTPInternalServerError(reason="Error during runtime initialisation") from error
    if isinstance(error, (HostNotFoundError, supervisor_errors.HostNotFoundError)):
        logger.exception(error)
        raise HTTPInternalServerError(reason="Host did not respond to ping") from error
    if isinstance(error, ClientResponseError):
        logger.exception(error)
        if error.status == 404:
            raise HTTPInternalServerError(reason=f"Item hash {vm_hash} not found") from error
        raise HTTPInternalServerError(reason=f"Error downloading {vm_hash}") from error
    logger.exception(error)
    raise HTTPInternalServerError(reason="Unhandled error during initialisation") from error


async def _ensure_program_vm(
    vm_hash: ItemHash,
    content: ProgramContent,
    original,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    program_client: ProgramGuestClient,
) -> VmInfo:
    """Get-or-create a serving-ready program VM through the supervisor.

    A VM this agent process did not configure is recreated rather than
    reused: the runtime accepts exactly one configuration push per boot, so
    "unknown" and "already configured" are indistinguishable from outside.

    Serialised per VM: two concurrent cold requests must not both
    create-and-configure (the second would push a second configuration to a
    booted runtime). The first holds the lock through setup; followers then
    take the fast path on re-check.
    """
    vm_id = VmId(str(vm_hash))
    async with program_client.creation_lock(vm_id):
        try:
            info: VmInfo | None = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            info = None

        if info is not None:
            if info.status is VmStatus.RUNNING and program_client.is_ready(vm_id):
                return info
            logger.info("Program VM %s is %s/unconfigured; recreating", vm_hash, info.status.value)
            await program_client.forget(vm_id)
            try:
                await supervisor.delete_vm(vm_id)
            except VmNotFoundError:
                pass
            await _wait_until_gone(supervisor, vm_id)

        try:
            spec, resources = await build_program_create_vm_spec(vm_hash, content)
            capacity.check_capacity(
                memory_mib=content.resources.memory,
                vcpus=content.resources.vcpus,
                disk_mib=0,
                is_instance=False,
                exclude_vm_hash=vm_hash,
            )
            await supervisor.create_vm(spec)
            record = registry.record(
                vm_hash, message=content, original=original, persistent=bool(content.on.persistent)
            )
            try:
                info = await _wait_until_running(supervisor, vm_id)
                await program_client.setup_program(info, content, resources)
            except Exception:
                registry.forget(vm_hash)
                await program_client.forget(vm_id)
                try:
                    await supervisor.delete_vm(vm_id)
                except Exception:
                    logger.exception("Teardown of half-started program VM %s failed", vm_hash)
                raise
            await persist_record(vm_hash, record)
            return info
        except web.HTTPException:
            raise
        except Exception as error:
            _raise_http_for_program_error(error, vm_hash)
            raise  # pragma: no cover - _raise_http_for_program_error always raises


def _program_result_response(result_raw: bytes, *, vm_hash: ItemHash, code_ref: str) -> web.Response:
    """Translate the runtime's msgpack reply into the HTTP response."""
    result = msgpack.loads(result_raw, raw=False)

    logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

    if "traceback" in result:
        # An error took place, the stacktrace of the error will be returned.
        # TODO: Add an option for VM developers to prevent stacktraces from being exposed.

        # The Diagnostics VM checks for the proper handling of exceptions.
        # This fills the logs with noisy stack traces, so we ignore this specific error.
        ignored_errors = ['raise CustomError("Whoops")', "main.CustomError: Whoops"]

        if settings.IGNORE_TRACEBACK_FROM_DIAGNOSTICS and any(
            ignored_error in result["traceback"] for ignored_error in ignored_errors
        ):
            logger.debug('Ignored traceback from CustomError("Whoops")')
        else:
            logger.warning(result["traceback"])

        return web.Response(
            status=HTTPInternalServerError.status_code,
            reason="Error in VM execution",
            body=result["traceback"],
            content_type="text/plain",
        )

    # HTTP Headers require specific data structure
    headers = CIMultiDict([(key.decode().lower(), value.decode()) for key, value in result["headers"]["headers"]])
    if "content-length" not in headers:
        headers["Content-Length".lower()] = str(len(result["body"]["body"]))
    for header in ["Content-Encoding", "Transfer-Encoding", "Vary"]:
        if header in headers:
            del headers[header]

    headers.update(
        {
            "Aleph-Program-ItemHash": str(vm_hash),
            "Aleph-Program-Code-Ref": code_ref,
        }
    )

    return web.Response(
        status=result["headers"]["status"],
        body=result["body"]["body"],
        headers=headers,
    )


async def run_code_on_request(vm_hash: ItemHash, path: str, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """
    supervisor: Supervisor = request.app["supervisor"]
    expiry: ExpiryManager = request.app["expiry"]
    update_watcher: UpdateWatcher = request.app["update_watcher"]
    registry: AgentVmRegistry = request.app["vm_registry"]
    capacity: CapacityManager = request.app["capacity"]
    program_client: ProgramGuestClient = request.app["program_client"]
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    content, original = await _resolve_program_content(vm_hash, registry)
    if isinstance(content, VerifiableProgramContent):
        raise HTTPBadRequest(reason=f"VM {vm_hash} is a V-PROGRAM: executions are scheduler-controlled")
    if not isinstance(content, ProgramContent):
        raise HTTPBadRequest(reason=f"VM {vm_hash} is an instance, not a program")

    persistent = bool(content.on.persistent)
    info = await _ensure_program_vm(
        vm_hash,
        content,
        original,
        supervisor=supervisor,
        registry=registry,
        capacity=capacity,
        program_client=program_client,
    )

    scope: dict = await build_asgi_scope(path, request)
    timeout = content.resources.seconds

    try:
        # On-demand programs are recreated per request; the agent reaches their
        # guest channel directly. A persistent program is long-lived behind the
        # supervisor, which runs the code over the channel on its side.
        if persistent:
            result_raw = await supervisor.run_program_code(vm_id, scope, timeout=timeout)
        else:
            result_raw = await program_client.run_code(info, scope, timeout=timeout)

        if result_raw == b"":
            # Missing result from the init process of the virtual machine, not
            # even an error message. It may have completely crashed. Tear an
            # on-demand VM down (it is recreated on a future request); a
            # persistent VM is left for the scheduler to restart.
            if not persistent:
                await supervisor.delete_vm(vm_id)
                await program_client.forget(vm_id)

            return web.Response(
                status=HTTPBadGateway.status_code,
                reason="No response from VM",
                text="VM did not respond and was shut down",
            )

        return _program_result_response(result_raw, vm_hash=vm_hash, code_ref=content.code.ref)
    except asyncio.TimeoutError:
        logger.warning(f"VM {vm_hash} did not respond within `resource.seconds`")
        return HTTPGatewayTimeout(body="Program did not respond within `resource.seconds`")
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                update_watcher.watch(vm_id, vm_hash, request.app["pubsub"])
            # Persistent programs are long-running by design: never idle-reap them.
            if not persistent:
                expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        elif not persistent:
            update_watcher.cancel(vm_id)
            await supervisor.delete_vm(vm_id)
            await program_client.forget(vm_id)


async def run_code_on_event(
    vm_hash: ItemHash,
    event,
    pubsub: PubSub,
    *,
    supervisor: Supervisor,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    program_client: ProgramGuestClient,
):
    """
    Execute code in response to an event.
    """
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    content, original = await _resolve_program_content(vm_hash, registry)
    if isinstance(content, VerifiableProgramContent):
        raise HTTPBadRequest(reason=f"VM {vm_hash} is a V-PROGRAM: executions are scheduler-controlled")
    if not isinstance(content, ProgramContent):
        raise HTTPBadRequest(reason=f"VM {vm_hash} is an instance, not a program")

    persistent = bool(content.on.persistent)
    info = await _ensure_program_vm(
        vm_hash,
        content,
        original,
        supervisor=supervisor,
        registry=registry,
        capacity=capacity,
        program_client=program_client,
    )

    scope: dict = await build_event_scope(event)

    try:
        if persistent:
            result_raw = await supervisor.run_program_code(vm_id, scope, timeout=content.resources.seconds)
        else:
            result_raw = await program_client.run_code(info, scope, timeout=content.resources.seconds)
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=HTTPInternalServerError.status_code,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        logger.info(f"Result: {result['body']}")
        return result["body"]

    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                update_watcher.watch(vm_id, vm_hash, pubsub)
            # Persistent programs are long-running by design: never idle-reap them.
            if not persistent:
                expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        elif not persistent:
            update_watcher.cancel(vm_id)
            await supervisor.delete_vm(vm_id)
            await program_client.forget(vm_id)


async def start_persistent_vm(
    vm_hash: ItemHash,
    pubsub: PubSub | None,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
) -> None:
    vm_id = VmId(str(vm_hash))
    try:
        info: VmInfo | None = await supervisor.get_vm(vm_id)
    except VmNotFoundError:
        info = None

    if info is not None:
        if info.awaiting_confidential_init:
            # Only the owner can start it, by uploading the session certificates
            # via /confidential/initialize. Waiting for RUNNING or recreating it
            # would loop forever, so leave it untouched.
            logger.info(f"{vm_hash} is waiting for its owner to initialize the confidential session")
        elif info.status == VmStatus.RUNNING:
            logger.info(f"{vm_hash} is already running")
        elif info.status in (VmStatus.DEFINED, VmStatus.BOOTING):
            logger.info(f"{vm_hash} is already starting")
            await _wait_until_running(supervisor, vm_id)
        elif info.status == VmStatus.STOPPING:
            logger.info(f"{vm_hash} is stopping, waiting before restart")
            await _wait_until_gone(supervisor, vm_id)
            info = None
        elif info.status == VmStatus.STOPPED:
            # A cleanly stopped VM is resumed in place: stop/start is a
            # pause/resume that preserves the definition and disks, not a
            # delete + recreate.
            logger.info(f"{vm_hash} is stopped, starting it")
            await supervisor.start_vm(vm_id)
            await _wait_until_running(supervisor, vm_id)
        else:  # FAILED
            logger.info(f"{vm_hash} in terminal state {info.status}, recreating")
            # Crash recovery is a delete+recreate cycle, not a dealloc: keep
            # the persisted host-port forwards (the owner's SSH forward among
            # them) so the recreated VM reloads the same host ports.
            await supervisor.delete_vm(vm_id, keep_port_mappings=True)
            info = None
        if info is not None and not info.awaiting_confidential_init:
            # Every branch that kept `info` ends with a RUNNING VM this agent
            # did not create in its own lifetime. Only the create path applies
            # forwards, so heal them here: a previous life crashing between
            # RUNNING and the forward setup leaves the VM up but unreachable
            # forever otherwise. Best-effort; never fails the allocation.
            # The recreate branches (info = None) reconcile in the create path.
            await reconcile_adopted_port_forwards(supervisor, registry, vm_hash)

    if info is None:
        logger.info(f"Starting persistent virtual machine with id: {vm_hash}")
        await create_vm_execution(
            vm_hash=vm_hash, supervisor=supervisor, registry=registry, capacity=capacity, persistent=True
        )
        # A confidential VM is created but left awaiting its owner's session
        # (only the owner can start it via /confidential/initialize). Waiting
        # for RUNNING would block forever, so re-read the status and skip the
        # readiness barrier when it is awaiting init.
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            info = None
        if info is not None and info.awaiting_confidential_init:
            logger.info(f"{vm_hash} is waiting for its owner to initialize the confidential session")
        else:
            # create_vm_execution blocks until RUNNING in-process today; this
            # re-poll is the explicit readiness barrier (and stays correct if a
            # future out-of-process create returns before the VM is RUNNING).
            await _wait_until_running(supervisor, vm_id)

    # Scheduled long-running: it must not idle-expire.
    expiry.cancel(vm_id)

    if pubsub and settings.WATCH_FOR_UPDATES:
        update_watcher.watch(vm_id, vm_hash, pubsub)
