import runpy
from dataclasses import replace
from pathlib import Path

import pytest

preflight = runpy.run_path(Path(__file__).resolve().parents[1] / "scripts/wazuh_host_preflight.py")
GIB = preflight["GIB"]
Resources = preflight["Resources"]
failures = preflight["failures"]
memory_available = preflight["memory_available"]


def test_resource_gate_accepts_exact_floor():
    assert failures(Resources(4, 8 * GIB, 50 * GIB, 262144)) == []


@pytest.mark.parametrize(
    "change",
    [
        {"cpus": 3},
        {"available_bytes": 8 * GIB - 1},
        {"docker_free_bytes": 50 * GIB - 1},
        {"max_map_count": 262143},
    ],
)
def test_resource_gate_refuses_each_insufficient_resource(change):
    assert len(failures(replace(Resources(4, 8 * GIB, 50 * GIB, 262144), **change))) == 1


def test_memory_uses_available_not_total_free_or_swap():
    assert (
        memory_available("MemTotal: 999999 kB\nMemAvailable: 123 kB\nSwapFree: 999 kB")
        == 123 * 1024
    )


@pytest.mark.parametrize(
    "content", ["MemFree: 999 kB", "MemAvailable: -1 kB", "MemAvailable: 8 GB"]
)
def test_unreliable_memory_information_fails_closed(content):
    with pytest.raises(ValueError):
        memory_available(content)
