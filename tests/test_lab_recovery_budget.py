"""Historical recovery refuses missing host/container resource limits."""

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from aegis.operations.lab_backup import SnapshotError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import lab_recovery_runtime as runtime  # noqa: E402
from test_lab_recovery import owned as owned  # noqa: F401, E402


@pytest.mark.parametrize(
    "problem",
    [None, "cpu", "memory", "swap", "tasks", "disk_read", "disk_write", "disk_missing", "device"],
)
def test_historical_host_effects_require_real_cgroup_limits(tmp_path, monkeypatch, problem):
    group = tmp_path / "user.slice/recovery.service"
    group.mkdir(parents=True)
    values = {
        "cpu.max": "25000 100000",
        "memory.max": str(runtime.MEMORY),
        "memory.swap.max": "0",
        "pids.max": "32",
        "io.max": "259:0 rbps=2097152 wbps=2097152 riops=max wiops=max",
    }
    replacements = {
        "cpu": ("cpu.max", "max 100000"),
        "memory": ("memory.max", "max"),
        "swap": ("memory.swap.max", "1"),
        "tasks": ("pids.max", "33"),
        "disk_read": ("io.max", "259:0 rbps=max wbps=2097152"),
        "disk_write": ("io.max", "259:0 rbps=2097152 wbps=4194304"),
        "disk_missing": ("io.max", ""),
    }
    if problem in replacements:
        key, value = replacements[problem]
        values[key] = value
    for key, value in values.items():
        (group / key).write_text(value)
    original_read, original_stat = Path.read_text, Path.stat
    monkeypatch.setattr(runtime, "CGROUP_ROOT", tmp_path)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **kw: (
            "0::/user.slice/recovery.service\n"
            if str(self) == "/proc/self/cgroup"
            else original_read(self, *a, **kw)
        ),
    )
    monkeypatch.setattr(
        Path,
        "stat",
        lambda self, *a, **kw: (
            SimpleNamespace(
                st_mode=stat.S_IFREG if problem == "device" else stat.S_IFBLK,
                st_rdev=os.makedev(259, 0),
            )
            if str(self) == runtime.IO_DEVICE
            else original_stat(self, *a, **kw)
        ),
    )
    if problem:
        with pytest.raises(SnapshotError, match="recovery_.*required"):
            runtime.check_host_budget()
    else:
        runtime.check_host_budget()


@pytest.mark.parametrize("field", ["NanoCpus", "BlkioDeviceReadBps", "BlkioDeviceWriteBps"])
def test_container_resource_limit_drift_blocks_effects(owned, field):
    operation, daemon = owned
    operation.create("fixture", "sha256:" + "d" * 64, "/bin/tar", ["fixture"], [])
    entry = next(iter(daemon.objects.values()))
    entry["host"][field] = 1_000_000_000 if field == "NanoCpus" else []
    with pytest.raises(SnapshotError, match="runtime_mismatch"):
        operation.validate("fixture")
