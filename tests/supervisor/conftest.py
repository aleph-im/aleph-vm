"""Shared fixtures and a reusable CreateVmSpec factory for supervisor tests.

The message-free VmExecution is built from a CreateVmSpec via
VmExecution.from_spec(...). This factory mirrors the per-file _spec helpers
(see test_supervisor_spec_admission.py / test_supervisor_spec_pool_create.py)
so migrated tests share one construction path.
"""

from __future__ import annotations

import json
import time
from hashlib import sha256
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    TeeConfig,
    VmId,
)

_DEFAULT_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"


def make_spec(
    *,
    vm_hash: str = _DEFAULT_HASH,
    backend: Backend = Backend.QEMU,
    tee: TeeConfig | None = None,
    gpus: list[GpuSpec] | None = None,
    persistent: bool = True,
    memory_mib: int = 256,
    vcpus: int = 1,
    internet: bool = True,
    with_rootfs: bool = True,
    rootfs_path: Path = Path("/data/rootfs.qcow2"),
) -> CreateVmSpec:
    """Build a CreateVmSpec for tests, parameterized over the fields the
    migrated VmExecution tests exercise."""
    disks: list[DiskSpec] = []
    if with_rootfs:
        disks.append(
            DiskSpec(
                path=rootfs_path,
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        )
    return CreateVmSpec(
        vm_id=VmId(vm_hash),
        backend=backend,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=tee,
        network=NetworkConfig(internet_access=internet, requested_ipv6="", ipv6_prefix_len=0),
        gpus=gpus or [],
        numa_node=None,
        persistent=persistent,
    )


@pytest.fixture
def spec_factory():
    """Fixture handle for make_spec, for tests that prefer dependency injection."""
    return make_spec


def sign_message(content_dict: dict, account, *, chain: str = "ETH", message_type: str = "INSTANCE") -> dict:
    """A full message envelope signed the way the network does: item_hash is
    sha256(item_content), and the signature covers chain/sender/type/hash."""
    item_content = json.dumps(content_dict)
    item_hash = sha256(item_content.encode()).hexdigest()
    buffer = f"{chain}\n{account.address}\n{message_type}\n{item_hash}".encode()
    signature = account.sign_message(encode_defunct(buffer)).signature.hex()
    return {
        "chain": chain,
        "sender": account.address,
        "type": message_type,
        "item_hash": item_hash,
        "item_type": "inline",
        "item_content": item_content,
        "content": content_dict,
        "signature": signature if signature.startswith("0x") else "0x" + signature,
        "time": 1.0,
        "channel": "TEST",
    }


def instance_content_dict(address: str) -> dict:
    """A minimal QEMU instance content, owned by ``address``."""
    return {
        "address": address,
        "time": 1.0,
        "allow_amend": False,
        "environment": {"internet": True, "aleph_api": False, "hypervisor": "qemu"},
        "resources": {"vcpus": 2, "memory": 2048, "seconds": 300},
        "volumes": [],
        "rootfs": {
            "parent": {"ref": "d" * 64, "use_latest": False},
            "persistence": "host",
            "size_mib": 10000,
        },
    }


@pytest.fixture
def signed_message():
    """Build a correctly signed instance message under a fresh key.

    Returns a callable so a test can sign its own content, or sign the
    default one and then break it."""

    def make(content: dict | None = None, *, account=None) -> dict:
        account = account or Account.create()
        return sign_message(content or instance_content_dict(account.address), account)

    return make


@pytest.fixture
def scheduler_auth(monkeypatch):
    """Authorize a throwaway scheduler key and sign requests as it.

    The signed payload binds the method, the path and the body hash, so the
    caller must pass the exact path it will POST to.
    """
    account = Account.create()
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [account.address])

    def sign(body_dict: dict | bytes, *, path: str = "/control/allocations", method: str = "POST"):
        # Bytes are signed as given, for a test that sends something that is
        # not JSON at all.
        body = body_dict if isinstance(body_dict, bytes) else json.dumps(body_dict).encode()
        payload = {
            "method": method,
            "path": path,
            "body_sha256": sha256(body).hexdigest(),
            "iat": int(time.time()),
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signed = account.sign_message(encode_defunct(payload_bytes))
        header = f"Aleph-EIP191-V1 sig={signed.signature.hex()},payload={payload_bytes.hex()}"
        return body, {"Authorization": header, "Content-Type": "application/json"}

    return sign


def reset_agent_state() -> None:
    """Empty the agent's process-wide storage state and uninstall its hooks.

    Five module globals survive a test: the live-VM snapshot the cache pass
    judges orphans against, the creates in flight, the memoised reclaimable
    totals, the downloads charged to the cache budget, and the hashes the
    supervisor listed last. They are caches and in-process bookkeeping, not
    wiring, so nothing resets them at import time, and a test that leaves one
    populated changes what the next test sees: a stale live snapshot spares a
    directory the next test expects purged, a leaked ``_creating`` entry makes
    every later namespace look like a create in flight, and a memoised total
    answers a question about a tree the next test has since rewritten. That is
    the whole of the order dependence in these files, and the tests that reach
    into these globals by hand only ever cleaned up the one they touched.

    The installed hooks go back to none for the same reason. Every test that
    installs one puts it back today, but a test that dies between installing an
    evictor and its cleanup would leave later placements evicting into that
    test's tree, which is exactly the class of leak this closes for the state.

    ``clean_agent_state`` calls this around every test; a test may call it
    directly to pin that it does.
    """
    import aleph.vm.agent.vm.cache as cache_module
    import aleph.vm.agent.vm.reclaimable as reclaimable_module
    import aleph.vm.agent.vm.reconciler as reconciler_module
    import aleph.vm.storage as storage_module
    from aleph.vm.hooks import AgentHooks, install_hooks

    cache_module._live_snapshot = None
    reconciler_module._last_supervisor_hashes = set()
    reconciler_module._creating.clear()
    reclaimable_module._reclaimable_cache.clear()
    storage_module._reserved_downloads.clear()
    install_hooks(AgentHooks())


@pytest.fixture(autouse=True)
def clean_agent_state():
    """Reset the agent's process-wide state on the way in as well as on the way
    out, so a test is unaffected by a module that was imported and exercised
    before the fixture existed."""
    reset_agent_state()
    yield
    reset_agent_state()
