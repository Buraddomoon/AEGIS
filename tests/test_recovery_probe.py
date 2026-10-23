"""The in-container probe must reject other destinations before any I/O."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "recovery_probe", Path(__file__).resolve().parents[1] / "scripts/recovery_probe.py"
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
URI = "postgresql+psycopg://aegis_recovery:" + "a" * 64 + "@127.0.0.1:5432/aegis_restore"


@pytest.mark.parametrize(
    "mutation",
    [
        {"OPERATING_MODE": "normal"},
        {"OPERATING_MODE": ""},
        {"DATABASE_URL": URI.replace("127.0.0.1", "example.invalid")},
        {"DATABASE_URL": URI.replace("aegis_recovery:", "postgres:")},
        {"DATABASE_URL": URI.replace("/aegis_restore", "/aegis")},
        {"DATABASE_URL": URI + "?options=unreviewed"},
        {"RECOVERY_ACCESS_TOKEN": "short"},
    ],
)
def test_probe_refuses_wrong_scope_before_network_or_database(monkeypatch, mutation):
    for key, value in {
        "OPERATING_MODE": "recovery",
        "DATABASE_URL": URI,
        "RECOVERY_ACCESS_TOKEN": "b" * 64,
        **mutation,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(probe, "request", lambda *a, **kw: pytest.fail("HTTP attempted"))
    monkeypatch.setattr(
        probe.psycopg, "connect", lambda *a, **kw: pytest.fail("Database attempted")
    )
    with pytest.raises(RuntimeError, match="restricted"):
        probe.main()


def test_probe_accepts_only_the_fixed_rehearsal_environment(monkeypatch):
    monkeypatch.setenv("OPERATING_MODE", "recovery")
    monkeypatch.setenv("DATABASE_URL", URI)
    monkeypatch.setenv("RECOVERY_ACCESS_TOKEN", "b" * 64)
    probe.require_rehearsal_environment()
