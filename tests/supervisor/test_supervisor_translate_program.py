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
    monkeypatch.setattr(translate, "AlephProgramResources", lambda *a, **k: resources)

    spec, returned = await translate.build_program_create_vm_spec(_VM_HASH, _program_message(persistent=persistent))

    assert returned is resources
    assert spec.backend is Backend.FIRECRACKER
    assert spec.persistent is persistent
    assert spec.guest_channel is not None
