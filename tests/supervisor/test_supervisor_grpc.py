"""GrpcSupervisor conformance + wire behavior over a real UDS channel.

Stands up the real gRPC server (grpc_server.serve_unix) wrapping an
InProcessSupervisor on a temp Unix socket and drives it through the
GrpcSupervisor client. Conformance checks mirror SupervisorContractTests;
the sync shape checks from that suite are re-asserted here as async tests
because the server fixture must live on the test's event loop.
"""

import inspect
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from conformance import STUB_METHODS

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import (
    FileTooLargeError,
    InsufficientResourcesError,
    InternalSupervisorError,
    InvalidBackendError,
    MicroVMInitError,
    NotImplementedSupervisorError,
    ResourceDownloadError,
    SupervisorError,
    VmNotFoundError,
    VmSetupError,
)
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.grpc_server import serve_unix
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import (
    GuestPort,
    HealthStatus,
    HostPort,
    LogChunk,
    LogSource,
    PortForwardSpec,
    Protocol,
    VmId,
)


class FakePool:
    def __init__(self):
        self.executions = {}


class _ServerHarness:
    """Server + client pair on a short-lived UDS path."""

    def __init__(self, wrapped: Supervisor):
        self.wrapped = wrapped
        self._tmpdir = tempfile.TemporaryDirectory(prefix="sup-grpc-")
        self.socket_path = Path(self._tmpdir.name) / "supervisor.sock"
        self.server = None
        self.client: GrpcSupervisor | None = None

    async def __aenter__(self) -> GrpcSupervisor:
        self.server = await serve_unix(self.wrapped, self.socket_path)
        self.client = GrpcSupervisor(self.socket_path)
        return self.client

    async def __aexit__(self, *exc):
        if self.client is not None:
            await self.client.close()
        if self.server is not None:
            await self.server.stop(grace=None)
        self._tmpdir.cleanup()


@pytest_asyncio.fixture
async def harness():
    harness = _ServerHarness(InProcessSupervisor(pool=FakePool()))
    async with harness as client:
        yield client


@pytest.mark.asyncio
async def test_is_a_supervisor(harness):
    assert isinstance(harness, Supervisor)
    assert type(harness).__abstractmethods__ == frozenset()


@pytest.mark.asyncio
async def test_streaming_methods_are_async_generators(harness):
    for name in ("stream_logs", "download_backup"):
        assert inspect.isasyncgenfunction(getattr(harness, name))


@pytest.mark.asyncio
async def test_stub_methods_raise_not_implemented_over_the_wire(harness):
    """Server-side NotImplementedSupervisorError crosses back class-exact."""
    for name in STUB_METHODS:
        method = getattr(harness, name)
        sig = inspect.signature(method)
        dummy_args = [
            b"" if "bytes" in (p.annotation or "") else "x"
            for p in sig.parameters.values()
            if p.default is inspect.Parameter.empty
            and p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        with pytest.raises(NotImplementedSupervisorError):
            if inspect.isasyncgenfunction(method):
                async for _ in method(*dummy_args):
                    pass
            else:
                await method(*dummy_args)


@pytest.mark.asyncio
async def test_health_over_the_wire(harness):
    info = await harness.health()
    assert info.status is HealthStatus.OK
    assert info.vm_count == 0


@pytest.mark.asyncio
async def test_get_host_info_over_the_wire(harness):
    info = await harness.get_host_info()
    assert info.cpu_count > 0
    assert info.memory_mib > 0
    assert info.kernel_version


@pytest.mark.asyncio
async def test_get_vm_not_found_over_the_wire(harness):
    with pytest.raises(VmNotFoundError):
        await harness.get_vm(VmId("does-not-exist"))


@pytest.mark.asyncio
async def test_delete_vm_not_found_over_the_wire(harness):
    with pytest.raises(VmNotFoundError):
        await harness.delete_vm(VmId("does-not-exist"))


@pytest.mark.asyncio
async def test_list_vms_empty_over_the_wire(harness):
    assert await harness.list_vms() == []


@pytest.mark.asyncio
async def test_list_port_forwards_empty_over_the_wire(harness):
    assert await harness.list_port_forwards() == []


@pytest.mark.asyncio
async def test_add_port_forward_not_found_over_the_wire(harness):
    spec = PortForwardSpec(
        vm_id=VmId("does-not-exist"), host_port=HostPort(0), vm_port=GuestPort(22), protocol=Protocol.TCP
    )
    with pytest.raises(VmNotFoundError):
        await harness.add_port_forward(spec)


class _RaisingSupervisor(InProcessSupervisor):
    """In-process supervisor whose lifecycle calls raise a chosen error."""

    def __init__(self, error: SupervisorError):
        super().__init__(pool=FakePool())
        self._error = error

    async def get_vm(self, vm_id):
        raise self._error

    async def stream_logs(self, vm_id, include_history=False):
        if False:  # pragma: no cover - makes this an async generator
            yield
        raise self._error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        VmNotFoundError("vm gone"),
        InsufficientResourcesError("no memory"),
        ResourceDownloadError("ipfs down"),
        FileTooLargeError("too big"),
        VmSetupError("setup blew up"),
        MicroVMInitError("init blew up"),
        InvalidBackendError("nope"),
        InternalSupervisorError("catch-all"),
    ],
    ids=lambda error: type(error).__name__,
)
async def test_errors_round_trip_class_exact(error):
    async with _ServerHarness(_RaisingSupervisor(error)) as client:
        with pytest.raises(type(error)) as exc_info:
            await client.get_vm(VmId("x"))
        assert str(error) in str(exc_info.value)
        assert exc_info.value.code is error.code


@pytest.mark.asyncio
async def test_stream_error_round_trips_class_exact():
    async with _ServerHarness(_RaisingSupervisor(VmSetupError("stream broke"))) as client:
        with pytest.raises(VmSetupError):
            async for _ in client.stream_logs(VmId("x")):
                pass


class _StreamingSupervisor(InProcessSupervisor):
    def __init__(self):
        super().__init__(pool=FakePool())

    async def stream_logs(self, vm_id, include_history=False):
        for index in range(3):
            yield LogChunk(timestamp_ns=index, line=f"line {index}", source=LogSource.STDOUT)


@pytest.mark.asyncio
async def test_stream_logs_streams_chunks():
    async with _ServerHarness(_StreamingSupervisor()) as client:
        chunks = [chunk async for chunk in client.stream_logs(VmId("x"))]
    assert [chunk.line for chunk in chunks] == ["line 0", "line 1", "line 2"]
    assert all(chunk.source is LogSource.STDOUT for chunk in chunks)


class _RecordingSupervisor(InProcessSupervisor):
    """Records reinstall_vm kwargs to pin the optional-bool default."""

    def __init__(self):
        super().__init__(pool=FakePool())
        self.calls = []

    async def reinstall_vm(self, vm_id, wipe_volumes=True):
        self.calls.append((vm_id, wipe_volumes))
        raise VmNotFoundError(vm_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("wipe_volumes", [True, False])
async def test_reinstall_wipe_volumes_crosses_explicitly(wipe_volumes):
    wrapped = _RecordingSupervisor()
    async with _ServerHarness(wrapped) as client:
        with pytest.raises(VmNotFoundError):
            await client.reinstall_vm(VmId("x"), wipe_volumes=wipe_volumes)
    assert wrapped.calls == [("x", wipe_volumes)]


@pytest.mark.asyncio
async def test_get_vm_spec_round_trips_over_the_wire():
    """GetVmSpec returns the spec class-exact: DTO → proto → DTO."""
    from pathlib import Path
    from types import SimpleNamespace

    from aleph.vm.supervisor.types import (
        Backend,
        CreateVmSpec,
        DiskFormat,
        DiskRole,
        DiskSpec,
        GuestChannelSpec,
        NetworkConfig,
    )

    spec = CreateVmSpec(
        vm_id=VmId("feed" * 16),
        backend=Backend.FIRECRACKER,
        kernel_path=Path("/opt/kernel/vmlinux.bin"),
        initrd_path=Path(""),
        disks=[
            DiskSpec(
                path=Path("/data/rootfs.squashfs"), readonly=True, format=DiskFormat.SQUASHFS, role=DiskRole.ROOTFS
            )
        ],
        vcpus=1,
        memory_mib=256,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=False,
        guest_channel=GuestChannelSpec(ready_port=52, ready_timeout_secs=30),
    )
    pool = FakePool()
    pool.executions["feed" * 16] = SimpleNamespace(vm_spec=spec)
    harness = _ServerHarness(InProcessSupervisor(pool=pool))
    async with harness as client:
        assert await client.get_vm_spec(VmId("feed" * 16)) == spec
