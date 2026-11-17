"""Fixed owned-file adapter in temporary directories, never a Lab or upstream shell."""

import hashlib
import json
import os
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import atomic_policy, continuity, engine
from aegis.lab_runner.engine import Conflict, Runner
from aegis.lab_runner.protocol import TEST_ID, BoundRequest, JobSpec, JobView, RunnerIdentity
from pydantic import ValidationError


def spec(runner):
    return JobSpec(
        test_id=atomic_policy.TEST_ID,
        job_id=uuid4(),
        laboratory_id=runner.identity.laboratory_id,
        asset_id=runner.identity.asset_id,
        runner_id=runner.identity.runner_id,
        marker="aegis-" + str(uuid4()),
        scope_hash="a" * 64,
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
    )


def bound(view):
    return BoundRequest(spec_hash=view.spec_hash, generation=view.generation)


def finish(runner, view):
    end = time.monotonic() + 7
    while runner.active is not None:
        assert time.monotonic() < end, "Unbounded supervisor"
        time.sleep(0.01)
    return runner.journal.get(view.spec.job_id)


def test_review_identity_pins_source_configuration_and_program():
    review = atomic_policy.review()
    fixture = json.loads(Path("fixtures/atomic/T1222.002.json").read_text())
    assert review["guid"] == "34ca1464-de9d-40c6-8c77-690adf36a135"
    assert review["source_commit"] == fixture["source_commit"]
    assert review["source_sha256"] == hashlib.sha256(fixture["content"].encode()).hexdigest()
    assert atomic_policy.TEST_ID == "atomic-file-permissions/v1@" + digest(review)
    assert (
        hashlib.sha256(atomic_policy.program_source().encode()).hexdigest()
        == review["program_sha256"]
    )


def test_historical_identity_rejects_atomic_without_any_intent(runner):
    with pytest.raises(Conflict, match="identidade"):
        runner.prepare(spec(runner))
    assert not list(runner.workspace.root.iterdir())
    with runner.journal.connection() as db:
        assert db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0


@pytest.mark.parametrize(
    "field",
    ["command", "path", "numeric_mode", "guid", "source_commit", "source_sha256", "program_sha256"],
)
def test_api_cannot_supply_commands_paths_or_a_new_review(runner, field):
    raw = spec(runner).model_dump(mode="json")
    raw[field] = "untrusted"
    with pytest.raises(ValidationError):
        JobSpec.model_validate(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("GUID", "0" * 36),
        ("SOURCE_COMMIT", "a" * 40),
        ("SOURCE_SHA256", "a" * 64),
        ("PROGRAM_SHA256", "a" * 64),
    ],
)
def test_review_changes_invalidate_the_selected_identity(monkeypatch, field, value):
    monkeypatch.setattr(atomic_policy, field, value)
    with pytest.raises(ValueError, match="nova identidade"):
        atomic_policy.program_source()


@pytest.mark.parametrize("runner", [atomic_policy.TEST_ID], indirect=True)
def test_fixed_effect_observes_modes_receipt_cleanup_and_no_replay(runner, monkeypatch):
    view = runner.prepare(spec(runner))
    real_popen = engine.subprocess.Popen
    calls = []

    def launch(args, **kwargs):
        calls.append(args)
        assert args[1:4] == ["-I", "-S", "-c"]
        assert hashlib.sha256(args[4].encode()).hexdigest() == atomic_policy.PROGRAM_SHA256
        assert kwargs["env"] == {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}
        assert kwargs["start_new_session"] and not kwargs.get("shell")
        with runner.journal.connection() as db:
            assert db.execute("SELECT state FROM jobs").fetchone()[0] == "RUNNING"
        return real_popen(args, **kwargs)

    monkeypatch.setattr(engine.subprocess, "Popen", launch)
    runner.start(view.spec.job_id, bound(view))
    result = finish(runner, view)
    assert result.state == "SUCCEEDED", result
    assert result.receipt.mode_before == 0o400 and result.receipt.mode_after == 0o600
    assert result.receipt.test_id == atomic_policy.TEST_ID and not result.receipt.synthetic
    assert result.receipt_sha256 == digest(result.receipt.model_dump(mode="json"))
    artifact = runner.workspace.root / view.spec.job_id.hex / "proof.marker"
    assert artifact.read_bytes() == (view.spec.marker + "\n").encode()
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert runner.start(view.spec.job_id, bound(view)).receipt == result.receipt
    proof = runner.cleanup(view.spec.job_id, bound(view))
    assert proof.cleanup_state == "CLEANED"
    assert runner.start(view.spec.job_id, bound(view)).receipt == result.receipt
    assert len(calls) == 1 and not list(runner.workspace.root.iterdir())
    runner.close()
    snapshot = continuity.review(
        runner.journal.path.parent, runner.identity, {view.spec.job_id: proof}
    )
    assert snapshot["expected_proofs_matched"] == 1 and snapshot["source_modified"] is False


@pytest.mark.parametrize("runner", [atomic_policy.TEST_ID], indirect=True)
@pytest.mark.parametrize("phase", ["prepare", "start"])
def test_program_drift_refuses_effect_and_preserves_cleanup(runner, tmp_path, monkeypatch, phase):
    job = spec(runner)
    view = runner.prepare(job) if phase == "start" else None
    altered = tmp_path / "changed.py"
    altered.write_text("raise AssertionError('must never execute')\n")
    monkeypatch.setattr(atomic_policy, "PROGRAM", altered)
    with pytest.raises(ValueError, match="revisão"):
        runner.start(job.job_id, bound(view)) if view else runner.prepare(job)
    assert not list(runner.workspace.root.iterdir())
    if view:
        assert runner.journal.get(job.job_id).state == "PREPARED"
        assert runner.cleanup(job.job_id, bound(view)).cleanup_state == "CLEANED"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "writable", "oversized"])
def test_program_source_rejects_unsafe_files(tmp_path, monkeypatch, kind):
    target = tmp_path / "program.py"
    if kind == "symlink":
        target.symlink_to(atomic_policy.PROGRAM)
    elif kind == "hardlink":
        original = tmp_path / "original.py"
        original.write_bytes(atomic_policy.PROGRAM.read_bytes())
        os.link(original, target)
    elif kind == "fifo":
        os.mkfifo(target)
    elif kind == "writable":
        target.write_bytes(atomic_policy.PROGRAM.read_bytes())
        target.chmod(0o666)
    else:
        target.write_bytes(b"x" * 16385)
    monkeypatch.setattr(atomic_policy, "PROGRAM", target)
    with pytest.raises((ValueError, OSError)):
        atomic_policy.program_source()


@pytest.mark.parametrize("runner", [atomic_policy.TEST_ID], indirect=True)
@pytest.mark.parametrize("outcome", ["CANCELLED", "TIMED_OUT"])
def test_cancel_and_lease_expiry_reap_without_replay(runner, monkeypatch, outcome):
    # A blocking child is a test-only fault injection, never a production allowlist entry.
    monkeypatch.setattr(atomic_policy, "program_source", lambda: "import time; time.sleep(60)")
    view = runner.prepare(spec(runner))
    runner.start(view.spec.job_id, bound(view))
    active = runner.active
    if outcome == "CANCELLED":
        runner.cancel(view.spec.job_id, bound(view))
    else:
        with active.lease_lock:
            active.lease_until = time.monotonic() - 1
    result = finish(runner, view)
    assert result.state == outcome and result.receipt is None
    assert active.process.returncode is not None
    assert runner.start(view.spec.job_id, bound(view)).state == outcome
    assert runner.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"


@pytest.mark.parametrize("runner", [atomic_policy.TEST_ID], indirect=True)
def test_unknown_artifact_retains_reservation_and_original_receipt(runner):
    view = runner.prepare(spec(runner))
    runner.start(view.spec.job_id, bound(view))
    result = finish(runner, view)
    unknown = runner.workspace.root / view.spec.job_id.hex / "preserve"
    unknown.write_text("unrelated")
    with pytest.raises(Conflict, match="Cleanup"):
        runner.cleanup(view.spec.job_id, bound(view))
    with pytest.raises(Conflict, match="reservado"):
        runner.prepare(spec(runner))
    assert unknown.read_text() == "unrelated"
    assert runner.journal.get(view.spec.job_id).receipt == result.receipt
    unknown.unlink()  # Test owner removes its own injection; runtime never does this.
    assert runner.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"


@pytest.mark.parametrize("runner", [atomic_policy.TEST_ID], indirect=True)
@pytest.mark.parametrize(
    "change", [{"mode_before": 0o600}, {"mode_after": 0o777}, {"test_id": TEST_ID}]
)
def test_atomic_receipts_cannot_claim_other_modes_or_test(runner, change):
    view = runner.prepare(spec(runner))
    runner.start(view.spec.job_id, bound(view))
    raw = finish(runner, view).model_dump(mode="json")
    raw["receipt"].update(change)
    with pytest.raises(ValidationError):
        JobView.model_validate(raw)


def test_restart_preserves_ambiguous_atomic_intent_without_replay(tmp_path):
    work, state = tmp_path / "work", tmp_path / "state"
    work.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    identity = RunnerIdentity(
        runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4(), tests=(atomic_policy.TEST_ID,)
    )
    first = Runner(identity, work, state)
    view = first.prepare(spec(first))
    first.journal.update(view.spec.job_id, state="RUNNING")
    first.close()
    second = Runner(identity, work, state)
    try:
        assert second.start(view.spec.job_id, bound(view)).state == "INTERRUPTED"
        assert second.active is None and not list(work.iterdir())
        assert second.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"
    finally:
        second.close()
