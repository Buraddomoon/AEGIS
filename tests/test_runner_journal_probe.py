"""Probe contract uses private SQLite fixtures only; no real /state or daemon."""

import io
import json
import subprocess
import sys

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import journal_probe
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle


def invoke(bundle, monkeypatch, capsys, payload=None, sha256=None):
    encoded = json.dumps(bundle).encode() if payload is None else payload
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(encoded)))
    code = journal_probe.main(["--expected-sha256", sha256 or digest(bundle)])
    output = capsys.readouterr()
    assert output.err == ""
    return code, json.loads(output.out), output.out


def test_probe_reads_only_fixed_journal_and_emits_no_proof_content(
    journal, bundle, monkeypatch, capsys
):
    monkeypatch.setattr(journal_probe, "STATE_DIRECTORY", journal[0])
    code, result, raw = invoke(bundle, monkeypatch, capsys)
    assert code == 0
    assert result["status"] == "journal_snapshot_consistent_not_activated"
    assert result["snapshot"]["expected_proofs_matched"] == 1
    assert result["proof_bundle_sha256"] == digest(bundle)
    assert all(result[key] is False for key in journal_probe.FLAGS)
    assert str(journal[0]) not in raw
    assert bundle["proofs"][0]["spec"]["marker"] not in raw
    assert bundle["proofs"][0]["reason"] not in raw
    assert bundle["proofs"][0]["spec"]["job_id"] not in raw


@pytest.mark.parametrize("problem", ["hash", "oversized", "invalid", "duplicate", "deep"])
def test_untrusted_stdin_is_rejected_before_accessing_state(bundle, monkeypatch, capsys, problem):
    monkeypatch.setattr(journal_probe, "review", lambda *a: pytest.fail("Input must fail first"))
    payload = None
    sha256 = None
    if problem == "hash":
        sha256 = "0" * 64
    elif problem == "oversized":
        payload = b"x" * (journal_probe.MAX_INPUT + 1)
    elif problem == "invalid":
        payload = b"private-sensitive-sentinel"
    elif problem == "duplicate":
        payload = b'{"proofs":[],"proofs":[]}'
    else:
        payload = b"[" * 1500 + b"]" * 1500
    code, result, raw = invoke(bundle, monkeypatch, capsys, payload=payload, sha256=sha256)
    assert code == 1 and result["status"] == "rejected"
    assert all(result[key] is False for key in journal_probe.FLAGS)
    assert "private-sensitive-sentinel" not in raw


def test_missing_state_is_rejected_without_creating_directory(
    bundle, tmp_path, monkeypatch, capsys
):
    path = tmp_path / "missing"
    monkeypatch.setattr(journal_probe, "STATE_DIRECTORY", path)
    code, result, _ = invoke(bundle, monkeypatch, capsys)
    assert code == 1 and result["code"] == "journal_review_failed"
    assert not path.exists()


def test_cli_accepts_no_root_command_target_or_activation_option():
    result = subprocess.run(
        [sys.executable, "-m", "aegis.lab_runner.journal_probe", "--help"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert "--expected-sha256" in result.stdout
    assert all(
        option not in result.stdout for option in ("--root", "--command", "--target", "--apply")
    )


def test_probe_import_never_loads_runner_engine_or_connects_external_services():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('No network or process permitted')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('No secrets permitted')
sys.addaudithook(guard)
import aegis.lab_runner.journal_probe
assert 'aegis.lab_runner.engine' not in sys.modules
assert 'aegis.lab_runner.server' not in sys.modules
assert 'aegis.config' not in sys.modules
assert 'aegis.security' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
