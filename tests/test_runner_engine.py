import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import engine
from aegis.lab_runner.engine import Conflict, Runner
from aegis.lab_runner.protocol import BoundRequest, JobSpec, RunnerIdentity


@pytest.fixture
def runner(tmp_path):
    work, state = tmp_path / "work", tmp_path / "state"
    work.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    identity = RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4())
    instance = Runner(identity, work, state)
    yield instance
    instance.close()


def prepare(runner, **changes):
    data = dict(
        runner_id=runner.identity.runner_id,
        laboratory_id=runner.identity.laboratory_id,
        asset_id=runner.identity.asset_id,
        job_id=uuid4(),
        marker="aegis-" + str(uuid4()),
        scope_hash="b" * 64,
        deadline_at=datetime.now(UTC) + timedelta(seconds=20),
    )
    data.update(changes)
    return runner.prepare(JobSpec(**data))


def bound(view):
    return BoundRequest(spec_hash=view.spec_hash, generation=view.generation)


def wait(runner, view):
    end = time.monotonic() + 7
    while time.monotonic() < end:
        active = runner.active
        if active is None:
            return runner.journal.get(view.spec.job_id)
        time.sleep(0.01)
    raise AssertionError("Supervisor did not finish within the bounded effect lifetime")


def block_program(tmp_path, monkeypatch):
    program = tmp_path / "blocking_test_fixture.py"
    # Test fixture only; no such test or command exists in the runtime allowlist/API.
    program.write_text("import time\ntime.sleep(60)\n")
    monkeypatch.setattr(engine, "MARKER_PROGRAM", program)


def test_real_fixed_child_receipt_cleanup_and_retry_fence(runner):
    view = prepare(runner)
    assert runner.start(view.spec.job_id, bound(view)).state in ("RUNNING", "SUCCEEDED")
    result = wait(runner, view)
    assert result.state == "SUCCEEDED", result
    receipt = result.receipt
    assert receipt and receipt.synthetic is False and receipt.kind == "execution_receipt"
    assert result.receipt_sha256 == digest(receipt.model_dump(mode="json"))
    assert (
        runner.workspace.read(view.spec.job_id, "proof.marker", 256)
        == (view.spec.marker + "\n").encode()
    )
    assert runner.start(view.spec.job_id, bound(view)).receipt == receipt
    cleaned = runner.cleanup(view.spec.job_id, bound(view))
    assert cleaned.cleanup_state == "CLEANED"
    assert not (runner.workspace.root / view.spec.job_id.hex).exists()
    assert runner.start(view.spec.job_id, bound(view)).receipt == receipt
    assert runner.prepare(view.spec).generation == view.generation


def test_parallel_starts_only_one_subprocess(runner, monkeypatch):
    view = prepare(runner)
    real_popen = engine.subprocess.Popen
    calls = []

    def record(*args, **kwargs):
        calls.append(args)
        assert "preexec_fn" not in kwargs
        assert kwargs["start_new_session"]
        assert not kwargs.get("shell")
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(engine.subprocess, "Popen", record)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: runner.start(view.spec.job_id, bound(view)), range(4)))
    assert wait(runner, view).state == "SUCCEEDED"
    assert len(calls) == 1


def test_identity_scope_and_generation_must_match(runner):
    with pytest.raises(Conflict, match="Identidade"):
        prepare(runner, asset_id=uuid4())
    view = prepare(runner)
    changed = view.spec.model_copy(update={"scope_hash": "c" * 64})
    with pytest.raises(Conflict, match="outro escopo"):
        runner.prepare(changed)
    with pytest.raises(Conflict, match="geração"):
        runner.start(view.spec.job_id, BoundRequest(spec_hash=view.spec_hash, generation=uuid4()))
    with pytest.raises(Conflict, match="reservado"):
        prepare(runner)


def test_cancel_terminates_and_reaps_blocked_child(runner, tmp_path, monkeypatch):
    block_program(tmp_path, monkeypatch)
    view = prepare(runner)
    runner.start(view.spec.job_id, bound(view))
    active = runner.active
    runner.cancel(view.spec.job_id, bound(view))
    result = wait(runner, view)
    assert result.state == "CANCELLED"
    assert active.process.returncode is not None
    assert runner.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"


def test_lease_loss_kills_child_even_when_sqlite_locked(runner, tmp_path, monkeypatch):
    block_program(tmp_path, monkeypatch)
    view = prepare(runner)
    runner.start(view.spec.job_id, bound(view))
    active = runner.active
    # Simulate a near-expired lease and blocked result persistence.
    with active.lease_lock:
        active.lease_until = time.monotonic() + 0.1
    with sqlite3.connect(runner.journal.path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        end = time.monotonic() + 1.5
        while active.process is None or active.process.poll() is None:
            assert time.monotonic() < end, "Journal lock delayed watchdog kill"
            time.sleep(0.01)
        assert active.process.returncode is not None
        time.sleep(0.15)  # Result transaction fails closed; no replay.
    result = wait(runner, view)
    assert result.state == "RUNNING" and result.receipt is None
    with pytest.raises(Conflict):
        runner.renew(view.spec.job_id, bound(view))
    assert runner.start(view.spec.job_id, bound(view)).state == "RUNNING"
    recovered = runner.cleanup(view.spec.job_id, bound(view))
    assert recovered.state == "INTERRUPTED" and recovered.cleanup_state == "CLEANED"


def test_expired_lease_never_renews_and_deadline_remains_fixed(runner, tmp_path, monkeypatch):
    block_program(tmp_path, monkeypatch)
    view = prepare(runner)
    runner.start(view.spec.job_id, bound(view))
    active = runner.active
    initial_deadline = active.deadline
    runner.renew(view.spec.job_id, bound(view))
    assert active.deadline == initial_deadline
    with active.lease_lock:
        active.lease_until = time.monotonic() - 1
    with pytest.raises(Conflict):
        runner.renew(view.spec.job_id, bound(view))
    assert wait(runner, view).state == "TIMED_OUT"


def test_cleanup_failure_retains_reservation_and_refuses_unknown_files(runner):
    view = prepare(runner)
    runner.start(view.spec.job_id, bound(view))
    assert wait(runner, view).state == "SUCCEEDED"
    unexpected = runner.workspace.root / view.spec.job_id.hex / "unknown"
    unexpected.write_text("preserve")
    with pytest.raises(Conflict, match="Cleanup"):
        runner.cleanup(view.spec.job_id, bound(view))
    assert unexpected.read_text() == "preserve"
    assert runner.journal.get(view.spec.job_id).cleanup_state == "FAILED"
    with pytest.raises(Conflict, match="reservado"):
        prepare(runner)
    unexpected.unlink()  # Explicit maintenance by test, never automatic deletion.
    assert runner.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"


def test_restart_marks_ambiguous_intent_without_replaying(tmp_path):
    work, state = tmp_path / "work", tmp_path / "state"
    work.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    identity = RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4())
    first = Runner(identity, work, state)
    view = prepare(first)
    first.journal.update(view.spec.job_id, state="RUNNING")
    with pytest.raises(BlockingIOError):
        Runner(identity, work, state)
    first.close()
    second = Runner(identity, work, state)
    try:
        result = second.journal.get(view.spec.job_id)
        assert result.state == "INTERRUPTED"
        assert second.start(view.spec.job_id, bound(view)).state == "INTERRUPTED"
        assert second.active is None
        assert second.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"
        rows = (
            sqlite3.connect(second.journal.path)
            .execute("SELECT action FROM events ORDER BY sequence")
            .fetchall()
        )
        assert ("PREPARED",) in rows
    finally:
        second.close()


def test_no_effect_if_durable_intent_cannot_commit(runner, monkeypatch):
    view = prepare(runner)

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("Injected commit failure")

    monkeypatch.setattr(runner.journal, "update", unavailable)
    with pytest.raises(sqlite3.OperationalError):
        runner.start(view.spec.job_id, bound(view))
    assert runner.active is None
    assert not list(runner.workspace.root.iterdir())
