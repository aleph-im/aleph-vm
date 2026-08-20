"""build_program_create_vm_spec threads the program's persistence into the spec."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, ProgramContent
from aleph_message.models.execution.base import Encoding

from aleph.vm.agent import translate
from aleph.vm.supervisor_interface.types import Backend

_VM_HASH = ItemHash("deadbeef" * 8)


def _program_message(*, persistent: bool) -> ProgramContent:
    msg = MagicMock()
    msg.__class__ = ProgramContent
    msg.on.persistent = persistent
    msg.resources.vcpus = 1
    msg.resources.memory = 128
    msg.environment.internet = False
    return msg


def _fake_resources(tmp_path: Path):
    runtime = tmp_path / "runtime.squashfs"
    runtime.write_bytes(b"runtime")
    kernel = tmp_path / "vmlinux.bin"
    kernel.write_bytes(b"kernel")
    return SimpleNamespace(
        rootfs_path=runtime,
        kernel_image_path=kernel,
        code_encoding=Encoding.zip,  # inline code -> no CODE disk
        code_path=tmp_path / "code.zip",
        volumes=[],
        download_all=AsyncMock(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("persistent", [True, False])
async def test_program_spec_threads_persistence(monkeypatch, tmp_path, persistent):
    resources = _fake_resources(tmp_path)
    monkeypatch.setattr(translate, "ProgramDownloader", lambda *a, **k: resources)

    spec, returned = await translate.build_program_create_vm_spec(_VM_HASH, _program_message(persistent=persistent))

    assert returned is resources
    assert spec.backend is Backend.FIRECRACKER
    assert spec.persistent is persistent
    assert spec.guest_channel is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("persistent", [True, False])
async def test_program_spec_pins_the_microvm_ipv6_hextet(monkeypatch, tmp_path, persistent):
    # Under the static policy, both persistent and non-persistent programs must
    # compute the 0x1 microvm hextet the daemon and scheduler expect. A
    # persistent program deriving its type from the message would drift to 0x2.
    from aleph.vm.conf import IPv6AllocationPolicy, settings

    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "1111:2222:3333:4444::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)
    resources = _fake_resources(tmp_path)
    monkeypatch.setattr(translate, "ProgramDownloader", lambda *a, **k: resources)

    spec, _ = await translate.build_program_create_vm_spec(_VM_HASH, _program_message(persistent=persistent))

    assert spec.network.requested_ipv6 == "1111:2222:3333:4444:1:dead:beef:dea0/124"
    assert spec.network.ipv6_prefix_len == 124
