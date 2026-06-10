"""_to_vm_info reports the precise TEE mode and the attached GPUs."""

from types import SimpleNamespace

from aleph.vm.resources import HostGPU
from aleph.vm.supervisor.inprocess import _to_vm_info
from aleph.vm.supervisor.types import ConfidentialMode


def _execution(*, confidential=False, policy=0, gpus=()):
    times = SimpleNamespace(
        defined_at=None,
        preparing_at=None,
        prepared_at=None,
        starting_at=None,
        started_at=None,
        stopping_at=None,
        stopped_at=None,
    )
    vm = SimpleNamespace(tap_interface=None, confidential_policy=policy) if policy else None
    return SimpleNamespace(
        vm_hash="abc",
        vm=vm,
        times=times,
        is_instance=True,
        is_program=False,
        is_confidential=confidential,
        hypervisor=None,
        gpus=list(gpus),
        persistent=True,
    )


def test_non_confidential_reports_none():
    info = _to_vm_info(_execution(confidential=False), running=True)
    assert info.confidential_mode is ConfidentialMode.NONE


def test_sev_policy_reports_sev():
    info = _to_vm_info(_execution(confidential=True, policy=0x1), running=True)  # NO_DBG, no ES bit
    assert info.confidential_mode is ConfidentialMode.SEV


def test_sev_es_policy_reports_sev_es():
    info = _to_vm_info(_execution(confidential=True, policy=0x4), running=True)  # SEV_ES bit
    assert info.confidential_mode is ConfidentialMode.SEV_ES


def test_gpus_are_reported_as_devices():
    gpu = HostGPU(pci_host="0000:01:00.0", supports_x_vga=True, device_id="10de:2504", model="RTX 3090")
    info = _to_vm_info(_execution(gpus=[gpu]), running=True)
    assert [(g.pci_host, g.device_id, g.model, g.supports_x_vga) for g in info.gpus] == [
        ("0000:01:00.0", "10de:2504", "RTX 3090", True)
    ]


def test_gpu_model_none_becomes_empty_string():
    gpu = HostGPU(pci_host="0000:02:00.0", supports_x_vga=False, device_id="10de:1111", model=None)
    info = _to_vm_info(_execution(gpus=[gpu]), running=True)
    assert info.gpus[0].model == ""


def test_confidential_but_not_yet_launched_reports_sev():
    """is_confidential with no hypervisor object yet (vm=None) -> SEV (sub-mode refines once launched)."""
    info = _to_vm_info(_execution(confidential=True, policy=0), running=True)
    assert info.confidential_mode is ConfidentialMode.SEV
