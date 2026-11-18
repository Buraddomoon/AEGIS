"""Real fixed programs in pytest temporaries; no native lab or defensive sensor."""

import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from aegis.domain.contracts import Collection, Event, ExecutionContext
from aegis.domain.validation import digest, validate
from aegis.lab_runner import behavior_policy as policy
from aegis.lab_runner import engine
from aegis.lab_runner.engine import Conflict, Runner
from aegis.lab_runner.protocol import BoundRequest, JobSpec, JobView, RunnerIdentity
from pydantic import ValidationError

IDS = list(policy.TEST_IDS.values())


def spec(runner):
    return JobSpec(
        test_id=runner.identity.tests[0],
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
        assert time.monotonic() < end
        time.sleep(0.01)
    return runner.journal.get(view.spec.job_id)


@pytest.mark.parametrize("kind", policy.PROFILES)
def test_catalog_consistency_source_identity_and_mapping(kind):
    review = policy.review(kind)
    assert policy.TEST_IDS[kind] == f"linux-{kind}-canary/v1@" + digest(review)
    assert hashlib.sha256(policy.PROGRAM.read_bytes()).hexdigest() == review["program_sha256"]
    assert review["cleanup_artifacts"] == ["proof.marker", "receipt.json"]
    assert review["free_inputs"] is False and review["external_network"] is False
    assert review["technique_id"] == ("T1059.004" if kind == "shell" else None)
    if kind == "shell":
        source = json.loads(Path("fixtures/attack/enterprise.json").read_text())
        assert any(t["id"] == "T1059.004" for t in source["techniques"])
    assert policy.program_source(policy.TEST_IDS[kind]).endswith(f"main({kind!r})\n")


@pytest.mark.parametrize("runner", IDS, indirect=True)
def test_fixed_child_receipt_durable_intent_and_cleanup(runner, monkeypatch):
    job = spec(runner)
    calls = []
    launch = engine.subprocess.Popen

    def checked(args, **kwargs):
        assert runner.journal.get(job.job_id).state == "RUNNING"
        assert args == [sys.executable, "-I", "-S", "-c", policy.program_source(job.test_id)]
        assert kwargs["start_new_session"] and not kwargs.get("shell")
        calls.append(args)
        return launch(args, **kwargs)

    monkeypatch.setattr(engine.subprocess, "Popen", checked)
    view = runner.prepare(job)
    runner.start(job.job_id, bound(view))
    result = finish(runner, view)
    assert result.state == "SUCCEEDED", result
    receipt = result.receipt
    assert receipt.test_id == job.test_id and not receipt.synthetic
    assert receipt.kind == "execution_receipt" and receipt.child_exit_code == 0
    with pytest.raises(ProcessLookupError):
        os.kill(receipt.child_pid, 0)  # The helper already reaped its own child.
    expected = (job.marker + "\n").encode()
    assert receipt.artifact_bytes == 43
    assert receipt.artifact_sha256 == hashlib.sha256(expected).hexdigest()
    assert receipt.stdout_bytes == (43 if policy.kind_for(job.test_id) == "shell" else 0)
    assert result.receipt_sha256 == digest(receipt.model_dump(mode="json"))
    directory = runner.workspace.root / job.job_id.hex
    assert (directory / "proof.marker").read_bytes() == expected
    assert (directory / "proof.marker").stat().st_mode & 0o777 == 0o600
    assert runner.start(job.job_id, bound(view)).receipt == receipt
    assert runner.cleanup(job.job_id, bound(view)).cleanup_state == "CLEANED"
    assert runner.start(job.job_id, bound(view)).receipt == receipt
    assert len(calls) == 1 and not list(runner.workspace.root.iterdir())


@pytest.mark.parametrize("runner", IDS, indirect=True)
@pytest.mark.parametrize("phase", ["prepare", "start"])
def test_program_drift_refuses_before_effect(runner, monkeypatch, tmp_path, phase):
    job = spec(runner)
    view = runner.prepare(job) if phase == "start" else None
    changed = tmp_path / "changed.py"
    changed.write_bytes(policy.PROGRAM.read_bytes() + b"\n# drift\n")
    monkeypatch.setattr(policy, "PROGRAM", changed)
    with pytest.raises(ValueError, match="revisão"):
        runner.start(job.job_id, bound(view)) if view else runner.prepare(job)
    assert not list(runner.workspace.root.iterdir())
    if view:
        assert runner.cleanup(job.job_id, bound(view)).cleanup_state == "CLEANED"


@pytest.mark.parametrize("kind", policy.PROFILES)
def test_review_drift_rejects_existing_identity(kind, monkeypatch):
    profiles = copy.deepcopy(policy.PROFILES)
    profiles[kind]["behavior"] = "other-behavior"
    monkeypatch.setattr(policy, "PROFILES", profiles)
    with pytest.raises(ValueError, match="nova identidade"):
        policy.program_source(policy.TEST_IDS[kind])


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "writable", "oversized"])
def test_unsafe_program_file_refused(tmp_path, monkeypatch, kind):
    target = tmp_path / "program.py"
    if kind == "symlink":
        target.symlink_to(policy.PROGRAM)
    elif kind == "hardlink":
        original = tmp_path / "original.py"
        original.write_bytes(policy.PROGRAM.read_bytes())
        os.link(original, target)
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        target.write_bytes(b"x" * 16385 if kind == "oversized" else policy.PROGRAM.read_bytes())
        if kind == "writable":
            target.chmod(0o666)
    monkeypatch.setattr(policy, "PROGRAM", target)
    with pytest.raises((ValueError, OSError)):
        policy.program_source(IDS[0])


def blocking_source(identifier):
    # Fault injection only. The production program has no sleeping/background child.
    source = policy.program_source(identifier)
    child = "import os,time;open('child.pid','w').write(str(os.getpid()));time.sleep(60)"
    return source.replace(
        "    parent = os.getpid()",
        f"    command = [{sys.executable!r}, '-I', '-S', '-c', {child!r}]\n    parent = os.getpid()",
    )


@pytest.mark.parametrize("runner", IDS, indirect=True)
@pytest.mark.parametrize("outcome", ["CANCELLED", "TIMED_OUT"])
def test_cancel_timeout_reap_nested_child_without_replay(runner, monkeypatch, outcome):
    source = blocking_source(runner.identity.tests[0])
    monkeypatch.setattr(policy, "program_source", lambda identifier: source)
    view = runner.prepare(spec(runner))
    runner.start(view.spec.job_id, bound(view))
    active = runner.active
    pid_file = runner.workspace.root / view.spec.job_id.hex / "child.pid"
    end = time.monotonic() + 2
    while not pid_file.exists() or not pid_file.read_text():
        assert time.monotonic() < end
        time.sleep(0.01)
    pid = int(pid_file.read_text())
    if outcome == "CANCELLED":
        runner.cancel(view.spec.job_id, bound(view))
    else:
        with active.lease_lock:
            active.lease_until = time.monotonic() - 1
    result = finish(runner, view)
    assert result.state == outcome and result.receipt is None
    assert active.process.returncode is not None
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert runner.start(view.spec.job_id, bound(view)).state == outcome
    pid_file.unlink()  # The test owner removes its own injection.
    assert runner.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"


@pytest.mark.parametrize("runner", IDS, indirect=True)
def test_failed_cleanup_keeps_reservation_and_receipt(runner):
    view = runner.prepare(spec(runner))
    runner.start(view.spec.job_id, bound(view))
    result = finish(runner, view)
    unknown = runner.workspace.root / view.spec.job_id.hex / "unknown"
    unknown.write_text("preserve")
    with pytest.raises(Conflict, match="Cleanup"):
        runner.cleanup(view.spec.job_id, bound(view))
    with pytest.raises(Conflict, match="reservado"):
        runner.prepare(spec(runner))
    assert runner.journal.get(view.spec.job_id).receipt == result.receipt
    assert unknown.read_text() == "preserve"
    unknown.unlink()
    assert runner.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"


@pytest.mark.parametrize("runner", IDS, indirect=True)
@pytest.mark.parametrize(
    "change",
    [
        {"stdout_sha256": "0" * 64},
        {"child_exit_code": 1},
        {"child_pid": 0},
        {"test_id": "linux-file-marker/v1"},
    ],
)
def test_receipt_rejects_wrong_profile_output_or_child(runner, change):
    view = runner.prepare(spec(runner))
    runner.start(view.spec.job_id, bound(view))
    raw = finish(runner, view).model_dump(mode="json")
    raw["receipt"].update(change)
    with pytest.raises(ValidationError):
        JobView.model_validate(raw)


@pytest.mark.parametrize("field", ["command", "argv", "script", "env", "path"])
def test_api_cannot_supply_program_inputs(runner, field):
    raw = spec(runner).model_dump(mode="json")
    raw.update(test_id=IDS[0], **{field: "untrusted"})
    with pytest.raises(ValidationError):
        JobSpec.model_validate(raw)


@pytest.mark.parametrize("identifier", IDS)
def test_legacy_binding_does_not_authorize_new_profile(runner, identifier):
    job = spec(runner).model_copy(update={"test_id": identifier})
    with pytest.raises(Conflict, match="identidade"):
        runner.prepare(job)
    assert not list(runner.workspace.root.iterdir())


def test_mixed_profile_identity_is_refused(tmp_path):
    identity = RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4(), tests=IDS)
    with pytest.raises(ValueError, match="único perfil"):
        Runner(identity, tmp_path / "work", tmp_path / "state")


@pytest.mark.parametrize("identifier", IDS)
def test_restart_preserves_ambiguous_intent_without_effect(tmp_path, identifier):
    work, state = tmp_path / "work", tmp_path / "state"
    work.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    identity = RunnerIdentity(
        runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4(), tests=(identifier,)
    )
    first = Runner(identity, work, state)
    view = first.prepare(spec(first))
    first.journal.update(view.spec.job_id, state="RUNNING")
    first.close()
    second = Runner(identity, work, state)
    try:
        assert second.start(view.spec.job_id, bound(view)).state == "INTERRUPTED"
        assert not list(work.iterdir())
        assert second.cleanup(view.spec.job_id, bound(view)).cleanup_state == "CLEANED"
    finally:
        second.close()


@pytest.mark.parametrize("identifier", IDS)
def test_parent_death_reaps_wrapper_and_nested_child(tmp_path, identifier):
    source_file = tmp_path / "wrapper.py"
    source_file.write_text(blocking_source(identifier))
    driver = tmp_path / "driver.py"
    driver.write_text("""import json,os,subprocess,sys,time
p=subprocess.Popen([sys.executable,'-I','-S',sys.argv[1]],stdin=subprocess.PIPE,stderr=subprocess.DEVNULL)
p.stdin.write(json.dumps({'parent_pid':os.getpid(),'marker':sys.argv[2]}).encode());p.stdin.close()
print(p.pid,flush=True)
time.sleep(60)
""")
    reaper = tmp_path / "reaper.py"
    reaper.write_text("""import ctypes,os,subprocess,sys,time
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
p=subprocess.Popen([sys.executable,'-I','-S',sys.argv[1],sys.argv[2],sys.argv[3]],stdout=subprocess.PIPE,text=True)
wrapper=int(p.stdout.readline());child=None
try:
    end=time.monotonic()+3
    while not os.path.exists('child.pid') or not open('child.pid').read():
        assert time.monotonic()<end
        time.sleep(.01)
    child=int(open('child.pid').read())
    p.kill();p.wait(timeout=1)
    end=time.monotonic()+3
    while not os.waitpid(wrapper,os.WNOHANG)[0]:
        assert time.monotonic()<end
        time.sleep(.01)
    try:os.kill(child,0)
    except ProcessLookupError:pass
    else:raise AssertionError('Nested child survived or was not reaped')
finally:
    if p.poll() is None:p.kill();p.wait()
    for pid in (wrapper,child):
        if pid:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            try:os.waitpid(pid,0)
            except ChildProcessError:pass
""")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(reaper),
            str(driver),
            str(source_file),
            "aegis-" + str(uuid4()),
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=9,
    )
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("behavior", [p["behavior"] for p in policy.PROFILES.values()])
@pytest.mark.parametrize(
    "field",
    [
        "laboratory_id",
        "asset_id",
        "execution_id",
        "marker",
        "behavior",
        "rule_id",
        "synthetic",
        "timestamp",
    ],
)
def test_independent_alert_requires_full_correlation(behavior, field):
    instant = datetime.now(UTC)
    ctx = ExecutionContext(
        execution_id=str(uuid4()),
        laboratory_id=str(uuid4()),
        asset_id=str(uuid4()),
        marker="aegis-" + str(uuid4()),
        behavior=behavior,
        expected_rule="reviewed-fixture-rule",
        started_at=instant,
        ended_at=instant,
        synthetic=False,
    )
    data = dict(
        laboratory_id=ctx.laboratory_id,
        asset_id=ctx.asset_id,
        execution_id=ctx.execution_id,
        marker=ctx.marker,
        behavior=behavior,
        rule_id=ctx.expected_rule,
        synthetic=False,
        timestamp=instant,
        kind="alert",
        source="independent-fixture",
        source_id="fixture-event",
        raw={},
    )
    good = Collection(
        events=(Event(**data),), complete=True, alerts_available=True, telemetry_available=True
    )
    assert validate(ctx, good, True).outcome == "DETECTED"
    data[field] = (
        instant + timedelta(hours=1)
        if field == "timestamp"
        else True
        if field == "synthetic"
        else "unrelated"
    )
    bad = Collection(
        events=(Event(**data),), complete=True, alerts_available=True, telemetry_available=True
    )
    assert validate(ctx, bad, True).outcome != "DETECTED"
    assert validate(ctx, good, False).outcome == "EXECUTION_FAILED"
