"""Bounded transport children are Python fixtures, never Docker."""

import subprocess
import sys
from pathlib import Path

import pytest
from aegis.operations import lab_backup as snapshot

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import lab_recovery_transport as transport  # noqa: E402


@pytest.mark.parametrize(
    "script,code",
    [
        ("import time; time.sleep(2)", "timeout"),
        ("import sys; sys.stdout.buffer.write(b'x'*70000)", "output_limit"),
        ("import sys; sys.stderr.buffer.write(b'private-value'*7000)", "stderr_limit"),
    ],
)
def test_transport_timeout_overflow_kills_reaps_and_never_echoes_bytes(monkeypatch, script, code):
    real = subprocess.Popen
    children = []

    def child(args, **kwargs):
        assert args[0] == "/usr/bin/docker" and "unix:///var/run/docker.sock" in args
        assert kwargs["env"] == transport.ENV
        process = real([sys.executable, "-c", script], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", child)
    with pytest.raises(snapshot.SnapshotError, match=code) as error:
        transport.run(["version"], timeout=0.1 if code == "timeout" else 5)
    assert "private-value" not in str(error.value)
    assert children and all(
        c.poll() is not None and c.stdout.closed and c.stderr.closed for c in children
    )
