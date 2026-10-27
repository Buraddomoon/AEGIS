"""Probe output against real private temporary SQLite; no daemon or source volume."""

import copy
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import journal_probe
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_probe_result as results  # noqa: E402


@pytest.fixture
def reply(journal, bundle, monkeypatch):
    monkeypatch.setattr(journal_probe, "STATE_DIRECTORY", journal[0])
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(bundle).encode())))
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    assert journal_probe.main(["--expected-sha256", digest(bundle)]) == 0
    return json.loads(output.getvalue())


def test_real_probe_output_is_bound_to_original_context_and_equal_logical_inventory(reply, bundle):
    raw = json.dumps(reply).encode()
    decoded = results.decode(raw, bundle, digest(bundle))
    assert decoded == reply
    compared = results.compare(raw, json.dumps(reply, indent=2).encode(), bundle, digest(bundle))
    assert compared["logical_inventories_match"] and compared["expected_proofs_matched"] == 1
    assert (
        compared["runtime_binding_verified"]
        is compared["activation_verified"]
        is compared["normal_operation_permitted"]
        is False
    )
    assert bundle["proofs"][0]["spec"]["marker"] not in json.dumps(compared)


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "unknown"),
        ("status", "rejected"),
        ("proof_bundle_sha256", "0" * 64),
        ("old_descriptor_sha256", "0" * 64),
        *[(key, True) for key in journal_probe.FLAGS],
    ],
)
def test_probe_reply_cannot_change_context_or_claim_activation(reply, bundle, field, value):
    reply[field] = value
    with pytest.raises(results.ActivationError, match="context_mismatch"):
        results.decode(json.dumps(reply).encode(), bundle, digest(bundle))


@pytest.mark.parametrize(
    "field,value",
    [
        ("identity_sha256", "f" * 64),
        ("inventory_sha256", "not-a-hash"),
        ("format", "unknown"),
        ("status", "unknown"),
        ("jobs_reviewed", 0),
        ("jobs_reviewed", 10001),
        ("events_reviewed", 2),
        ("events_reviewed", 100001),
        ("expected_proofs_matched", 0),
        ("expected_proofs_matched", True),
        ("additional_jobs_reviewed", 1),
        ("implicit_restart_histories", -1),
        ("implicit_restart_histories", 2),
        *[(key, True) for key in results.SNAPSHOT_FLAGS],
    ],
)
def test_snapshot_identity_counts_flags_and_hash_are_strict(reply, bundle, field, value):
    reply["snapshot"][field] = value
    with pytest.raises(results.ActivationError):
        results.decode(json.dumps(reply).encode(), bundle, digest(bundle))


@pytest.mark.parametrize("scene", ["hash", "event", "count"])
def test_after_probe_must_preserve_full_inventory_and_counts(reply, bundle, scene):
    after = copy.deepcopy(reply)
    if scene == "hash":
        after["snapshot"]["inventory_sha256"] = "f" * 64
    elif scene == "event":
        after["snapshot"]["events_reviewed"] += 1
    else:
        after["snapshot"]["jobs_reviewed"] += 1
        after["snapshot"]["additional_jobs_reviewed"] += 1
        after["snapshot"]["events_reviewed"] += 3
    with pytest.raises(results.ActivationError, match="continuity_changed"):
        results.compare(
            json.dumps(reply).encode(), json.dumps(after).encode(), bundle, digest(bundle)
        )


@pytest.mark.parametrize(
    "raw", [b"{}", b"private-sensitive-sentinel", b'{"a":1,"a":2}', b"x" * 65537]
)
def test_untrusted_or_excessive_stdout_never_becomes_a_receipt_or_leaks_diagnostics(bundle, raw):
    with pytest.raises(results.ActivationError) as error:
        results.decode(raw, bundle, digest(bundle))
    assert "private-sensitive-sentinel" not in str(error.value)


def test_missing_extra_fields_changed_bundle_or_wrong_expected_hash_are_rejected(reply, bundle):
    raw = json.dumps(reply).encode()
    with pytest.raises(results.ActivationError):
        results.decode(raw, bundle, "0" * 64)
    bundle["environment_version"] += 1
    with pytest.raises(results.ActivationError):
        results.decode(raw, bundle, digest(bundle))


def test_import_does_not_load_settings_runner_or_external_services():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('No external effects permitted')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('No secrets permitted')
sys.addaudithook(guard)
import runner_activation_probe_result
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
assert 'aegis.lab_runner.engine' not in sys.modules
assert 'aegis.lab_runner.server' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
