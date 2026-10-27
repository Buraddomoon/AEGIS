"""Only temporary SQLite journals; no runner server, marker, Docker or volume."""

import hashlib
import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import continuity
from aegis.lab_runner.journal import Journal
from aegis.lab_runner.protocol import ExecutionReceipt, JobSpec, JobView, RunnerIdentity


def add_job(root, identity, state="CANCELLED"):
    spec = JobSpec(
        job_id=uuid4(),
        runner_id=identity.runner_id,
        laboratory_id=identity.laboratory_id,
        asset_id=identity.asset_id,
        marker="aegis-" + str(uuid4()),
        scope_hash="a" * 64,
        deadline_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    receipt = None
    if state == "SUCCEEDED":
        content = (spec.marker + "\n").encode()
        receipt = ExecutionReceipt(
            job_id=spec.job_id,
            runner_id=spec.runner_id,
            laboratory_id=spec.laboratory_id,
            asset_id=spec.asset_id,
            marker=spec.marker,
            scope_hash=spec.scope_hash,
            artifact_sha256=hashlib.sha256(content).hexdigest(),
            artifact_bytes=len(content),
            started_at=datetime.now(UTC),
            ended_at=datetime.now(UTC),
        )
    view = JobView(
        spec=spec,
        spec_hash=digest(spec.model_dump(mode="json")),
        generation=uuid4(),
        state=state,
        cleanup_state="CLEANED",
        reason="Fixture without an effect",
        receipt=receipt,
        receipt_sha256=digest(receipt.model_dump(mode="json")) if receipt else None,
    )
    with closing(sqlite3.connect(root / "journal.sqlite3")) as db, db:
        db.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(spec.job_id),
                spec.model_dump_json(),
                view.spec_hash,
                str(view.generation),
                state,
                "CLEANED",
                view.reason,
                receipt.model_dump_json() if receipt else None,
                view.receipt_sha256,
            ),
        )
        actions = ["PREPARED"]
        if state not in {"CANCELLED", "TIMED_OUT"}:
            actions.append("RUNNING")
        actions.extend([state, "CLEANED"])
        for action in actions:
            db.execute("INSERT INTO events(job_id,action) VALUES (?,?)", (str(spec.job_id), action))
    return view


@pytest.fixture
def journal(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    identity = RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4())
    writer = Journal(root)
    with writer.connection() as db:
        db.execute(
            "INSERT INTO metadata VALUES ('identity',?)",
            (digest(identity.model_dump(mode="json")),),
        )
    writer.close()
    proof = add_job(root, identity)
    return root, identity, {proof.spec.job_id: proof}


def edit(root, statement, parameters=()):
    with closing(sqlite3.connect(root / "journal.sqlite3")) as db, db:
        db.execute(statement, parameters)


def snapshot(root):
    return {
        file.name: (file.read_bytes(), file.stat().st_mtime_ns, file.stat().st_ctime_ns)
        for file in root.iterdir()
    }


def test_valid_snapshot_preserves_every_source_file_and_has_no_operational_permission(
    journal, monkeypatch
):
    root, identity, expected = journal
    before = snapshot(root)
    monkeypatch.setattr(Journal, "__init__", lambda *a: pytest.fail("Do not initialize source"))
    result = continuity.review(root, identity, expected)
    assert result["status"] == "snapshot_consistent_with_supplied_proofs"
    assert result["jobs_reviewed"] == result["expected_proofs_matched"] == 1
    assert result["events_reviewed"] == 3
    assert result["additional_jobs_reviewed"] == 0
    assert len(result["inventory_sha256"]) == 64
    assert all(
        result[name] is False
        for name in (
            "source_modified",
            "volume_binding_verified",
            "database_binding_verified",
            "activation_permitted",
            "normal_operation_permitted",
        )
    )
    assert snapshot(root) == before
    assert continuity.review(root, identity, expected) == result


def test_additional_standalone_jobs_and_success_receipts_are_all_reviewed(journal):
    root, identity, expected = journal
    add_job(root, identity, "SUCCEEDED")
    result = continuity.review(*journal)
    assert result["jobs_reviewed"] == 2 and result["additional_jobs_reviewed"] == 1
    assert result["events_reviewed"] == 7
    assert result["expected_proofs_matched"] == 1


def test_changed_generation_cannot_match_database_proof(journal):
    root, _, _ = journal
    edit(root, "UPDATE jobs SET generation=?", (str(uuid4()),))
    with pytest.raises(continuity.ContinuityError, match="expected_proof_mismatch"):
        continuity.review(*journal)


@pytest.mark.parametrize(
    "problem",
    [
        "spec_hash",
        "generation",
        "identity",
        "pending",
        "running",
        "cleanup_pending",
        "receipt_hash",
        "duplicate_json",
        "oversized_json",
        "wrong_id",
    ],
)
def test_job_corruption_and_ambiguity_block_without_repair(journal, problem):
    root, identity, expected = journal
    if problem == "identity":
        edit(root, "UPDATE metadata SET value=?", ("0" * 64,))
    elif problem == "pending":
        edit(root, "UPDATE jobs SET state='PREPARED'")
    elif problem == "running":
        edit(root, "UPDATE jobs SET state='RUNNING'")
    elif problem == "cleanup_pending":
        edit(root, "UPDATE jobs SET cleanup_state='PENDING'")
    elif problem == "receipt_hash":
        edit(root, "UPDATE jobs SET receipt_sha256=?", ("0" * 64,))
    elif problem == "duplicate_json":
        proof = next(iter(expected.values()))
        text = proof.spec.model_dump_json()
        edit(
            root,
            "UPDATE jobs SET spec=?",
            ('{"job_id":"' + str(proof.spec.job_id) + '",' + text[1:],),
        )
    elif problem == "oversized_json":
        edit(root, "UPDATE jobs SET spec=?", ("x" * 20000,))
    elif problem == "wrong_id":
        edit(root, "UPDATE jobs SET id=?", (str(uuid4()),))
    else:
        edit(root, f"UPDATE jobs SET {problem}=?", ("invalid",))
    before = snapshot(root)
    with pytest.raises(continuity.ContinuityError):
        continuity.review(root, identity, expected)
    assert snapshot(root) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("job_id", str(uuid4())),
        ("runner_id", str(uuid4())),
        ("marker", "wrong"),
        ("scope_hash", "0" * 64),
        ("artifact_bytes", 1),
        ("artifact_sha256", "0" * 64),
        ("started_at", "2099-01-01T00:00:00Z"),
        ("ended_at", "2099-01-01T00:00:00Z"),
    ],
)
def test_receipt_must_match_its_original_job_even_with_rehashed_content(journal, field, value):
    root, identity, _ = journal
    view = add_job(root, identity, "SUCCEEDED")
    receipt = view.receipt.model_dump(mode="json")
    receipt[field] = value
    edit(
        root,
        "UPDATE jobs SET receipt=?,receipt_sha256=? WHERE id=?",
        (json.dumps(receipt), digest(receipt), str(view.spec.job_id)),
    )
    with pytest.raises(continuity.ContinuityError, match="receipt_invalid"):
        continuity.review(*journal)


@pytest.mark.parametrize(
    "problem", ["missing", "view", "trigger", "table", "index", "version", "metadata"]
)
def test_unexpected_schema_is_rejected(journal, problem):
    root, _, _ = journal
    sql = {
        "missing": "DROP TABLE events",
        "view": "CREATE VIEW extra AS SELECT * FROM jobs",
        "trigger": "CREATE TRIGGER extra AFTER INSERT ON events BEGIN DELETE FROM jobs; END",
        "table": "CREATE TABLE extra (value TEXT)",
        "index": "CREATE INDEX extra ON jobs(state)",
        "version": "PRAGMA user_version=2",
        "metadata": "INSERT INTO metadata VALUES ('extra','value')",
    }[problem]
    edit(root, sql)
    with pytest.raises(continuity.ContinuityError):
        continuity.review(*journal)


@pytest.mark.parametrize(
    "problem",
    [
        "missing",
        "orphan",
        "negative_sequence",
        "naive_time",
        "repeated_start",
        "after_clean",
        "wrong_state",
    ],
)
def test_event_history_must_correspond_to_terminal_job(journal, problem):
    root, _, expected = journal
    identifier = str(next(iter(expected)))
    if problem == "missing":
        edit(root, "DELETE FROM events WHERE action='CANCELLED'")
    elif problem == "orphan":
        edit(root, "UPDATE events SET job_id=? WHERE sequence=1", (str(uuid4()),))
    elif problem == "negative_sequence":
        edit(root, "UPDATE events SET sequence=-1 WHERE sequence=1")
    elif problem == "naive_time":
        edit(root, "UPDATE events SET timestamp='2026-10-27T12:00:00'")
    elif problem == "repeated_start":
        edit(root, "UPDATE events SET action='PREPARED' WHERE action='CANCELLED'")
    elif problem == "after_clean":
        edit(root, "INSERT INTO events(job_id,action) VALUES (?,'RUNNING')", (identifier,))
    else:
        edit(root, "UPDATE events SET action='TIMED_OUT' WHERE action='CANCELLED'")
    with pytest.raises(continuity.ContinuityError):
        continuity.review(*journal)


def test_implicit_restart_is_explicitly_counted_and_does_not_rewrite_events(journal):
    root, identity, _ = journal
    view = add_job(root, identity, "INTERRUPTED")
    edit(
        root, "DELETE FROM events WHERE job_id=? AND action='INTERRUPTED'", (str(view.spec.job_id),)
    )
    before = snapshot(root)
    result = continuity.review(*journal)
    assert result["implicit_restart_histories"] == 1
    assert snapshot(root) == before


@pytest.mark.parametrize(
    "problem",
    [
        "missing_db",
        "missing_lock",
        "symlink",
        "hardlink",
        "fifo",
        "public_root",
        "public_file",
        "unknown",
        "oversized",
        "corrupt",
    ],
)
def test_unsafe_source_is_not_opened_as_sqlite(journal, problem, monkeypatch):
    root, _, _ = journal
    db = root / "journal.sqlite3"
    if problem == "missing_db":
        db.unlink()
    elif problem == "missing_lock":
        (root / "instance.lock").unlink()
    elif problem == "symlink":
        db.rename(root.parent / "outside")
        db.symlink_to(root.parent / "outside")
    elif problem == "hardlink":
        os.link(db, root.parent / "outside")
    elif problem == "fifo":
        db.unlink()
        os.mkfifo(db, 0o600)
    elif problem == "public_root":
        root.chmod(0o755)
    elif problem == "public_file":
        db.chmod(0o666)
    elif problem == "unknown":
        (root / "journal.sqlite3-journal").write_bytes(b"unreviewed")
    elif problem == "oversized":
        with db.open("ab") as stream:
            stream.truncate(continuity.FILES[db.name] + 1)
    else:
        db.write_bytes(b"private-sensitive-sentinel")
    monkeypatch.setattr(
        continuity.sqlite3, "connect", lambda *a, **kw: pytest.fail("unsafe input reached SQLite")
    )
    with pytest.raises(continuity.ContinuityError) as error:
        continuity.review(*journal)
    assert "private-sensitive-sentinel" not in str(error.value)


def test_live_runner_lock_blocks_review_and_is_released_on_exit(journal):
    root, _, _ = journal
    writer = Journal(root)
    try:
        with pytest.raises(continuity.ContinuityError, match="instance_busy"):
            continuity.review(*journal)
    finally:
        writer.close()
    assert continuity.review(*journal)["jobs_reviewed"] == 1


@pytest.fixture
def wal_journal(journal, tmp_path):
    root, identity, expected = journal
    target = tmp_path / "crash-copy"
    target.mkdir(mode=0o700)
    with closing(sqlite3.connect(root / "journal.sqlite3")) as db:
        db.execute("PRAGMA wal_autocheckpoint=0")
        proof = next(iter(expected.values()))
        reason = "Committed only in WAL; no effect"
        db.execute("UPDATE jobs SET reason=?", (reason,))
        db.commit()
        assert (root / "journal.sqlite3-wal").stat().st_size > 32
        for file in root.iterdir():
            (target / file.name).write_bytes(file.read_bytes())
            (target / file.name).chmod(stat.S_IMODE(file.stat().st_mode))
    proof = proof.model_copy(update={"reason": reason})
    return target, identity, {proof.spec.job_id: proof}


def test_committed_wal_is_read_and_original_shm_and_wal_never_modified(wal_journal):
    before = snapshot(wal_journal[0])
    assert continuity.review(*wal_journal)["expected_proofs_matched"] == 1
    assert snapshot(wal_journal[0]) == before
    (wal_journal[0] / "journal.sqlite3-wal").unlink()
    with pytest.raises(continuity.ContinuityError, match="expected_proof_mismatch"):
        continuity.review(*wal_journal)


@pytest.mark.parametrize("problem", ["header", "truncated", "salt", "checksum", "data"])
def test_wal_damage_never_silently_discards_committed_frames(wal_journal, problem):
    path = wal_journal[0] / "journal.sqlite3-wal"
    data = bytearray(path.read_bytes())
    if problem == "header":
        data[0] ^= 1
    elif problem == "truncated":
        data = data[:-1]
    elif problem == "salt":
        data[40] ^= 1
    elif problem == "checksum":
        data[48] ^= 1
    else:
        data[70] ^= 1
    path.write_bytes(data)
    before = snapshot(wal_journal[0])
    with pytest.raises(continuity.ContinuityError, match="wal_"):
        continuity.review(*wal_journal)
    assert snapshot(wal_journal[0]) == before


def test_no_known_proof_is_not_continuity(journal):
    with pytest.raises(continuity.ContinuityError, match="known_proofs_required"):
        continuity.review(journal[0], journal[1], {})


def test_database_expected_job_cannot_disappear_even_if_journal_remains_valid(journal):
    root, _, _ = journal
    edit(root, "DELETE FROM events")
    edit(root, "DELETE FROM jobs")
    with pytest.raises(continuity.ContinuityError, match="expected_proof_mismatch"):
        continuity.review(*journal)


def test_source_change_during_review_blocks_result(journal, monkeypatch):
    original = continuity._inspect

    def changed(*args):
        result = original(*args)
        edit(journal[0], "UPDATE jobs SET reason='changed concurrently'")
        return result

    monkeypatch.setattr(continuity, "_inspect", changed)
    with pytest.raises(continuity.ContinuityError, match="source_changed"):
        continuity.review(*journal)


def test_sqlite_authorizer_blocks_writes_attach_functions_and_unknown_pragmas(journal, monkeypatch):
    original = continuity._inspect

    def verify(db, *args):
        for statement in (
            "DELETE FROM jobs",
            "ATTACH ':memory:' AS other",
            "SELECT load_extension('bad')",
            "PRAGMA journal_mode=DELETE",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                db.execute(statement)
        return original(db, *args)

    monkeypatch.setattr(continuity, "_inspect", verify)
    assert continuity.review(*journal)["jobs_reviewed"] == 1


def test_private_scratch_is_removed_before_success(journal, tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    monkeypatch.setattr(continuity.tempfile, "tempdir", str(scratch))
    continuity.review(*journal)
    assert list(scratch.iterdir()) == []


def test_history_limits_block_without_truncated_success(journal, monkeypatch):
    monkeypatch.setattr(continuity, "MAX_EVENTS", 2)
    with pytest.raises(continuity.ContinuityError, match="history_limit"):
        continuity.review(*journal)
