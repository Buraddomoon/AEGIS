"""Disposable PostgreSQL/SQLite only. Dump writer is a fixture, never pg_dump.

These tests prove data coordination and guards, not native volume binding,
complete host-fence collection, Docker runtime or PostgreSQL dump/restore.
"""

import copy
import json
import os
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import continuity, persisted_review
from aegis.lab_runner.journal import Journal
from aegis.operations import lab_backup as snapshot
from sqlalchemy import text
from test_binding_review import binding_lab as binding_lab
from test_binding_review import history
from test_runner_journal_continuity import journal as journal
from test_runner_journal_continuity import snapshot as journal_snapshot
from test_runner_journal_continuity import wal_journal as wal_journal


@pytest.fixture
def prepared(binding_lab, pg_engine, tmp_path):
    _, descriptor = binding_lab
    history(descriptor)
    from aegis.lab_runner.protocol import RunnerIdentity

    identity = RunnerIdentity(
        **{key: descriptor[key] for key in ("runner_id", "laboratory_id", "asset_id")}
    )
    bundle = persisted_review.collect(pg_engine, identity, digest(descriptor))
    _, expected = persisted_review.expected_proofs(bundle, digest(bundle))
    root = tmp_path / "original-journal"
    root.mkdir(mode=0o700)
    writer = Journal(root)
    with writer.connection() as db:
        db.execute("INSERT INTO metadata VALUES ('identity',?)", (digest(bundle["identity"]),))
        for view in expected.values():
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(view.spec.job_id),
                    view.spec.model_dump_json(),
                    view.spec_hash,
                    str(view.generation),
                    view.state,
                    view.cleanup_state,
                    view.reason,
                    None,
                    None,
                ),
            )
            for action in ("PREPARED", "CANCELLED", "CLEANED"):
                writer.event(db, view.spec.job_id, action)
    writer.close()
    with pg_engine.connect() as db:
        revision = db.scalar(text("SELECT version_num FROM alembic_version"))
        schema = db.scalar(text("SELECT current_schema()"))
    context = snapshot.Context(
        project="aegis-linux-lab",
        source_commit="a" * 40,
        identity=identity,
        descriptor_sha256=digest(descriptor),
        descriptor=descriptor,
        server_ca_sha256=descriptor["server_ca_sha256"],
        client_cert_sha256=descriptor["client_cert_sha256"],
        images=snapshot.Images(
            **{key: "sha256:" + "d" * 64 for key in ("application", "runner", "postgres", "redis")}
        ),
        schema_revision=revision,
        database_schema=schema,
        environment_version=bundle["environment_version"],
    )
    return (
        pg_engine,
        root,
        context,
        {"consumed": b'{"state":"CONSUMED"}\n', "expired": b'{"state":"EXPIRED"}\n'},
        tmp_path / "bundle",
    )


def fixture_dump(snapshot_id, stream):
    assert snapshot_id and "'" not in snapshot_id
    stream.write(b"PGDMP-fixture-not-a-real-archive")


def create(prepared, dump=fixture_dump):
    return snapshot.create(*prepared, dump)


def test_coordinated_private_bundle_preserves_source_and_has_no_operational_permission(prepared):
    engine, root, context, fences, folder = prepared
    before = journal_snapshot(root)
    original_fences = copy.deepcopy(fences)
    with engine.connect() as conn:
        before_db = snapshot.backup.inventory(
            lambda sql: conn.execute(text(sql)).scalars(),
            conn.scalar(text("SELECT current_schema()")),
        )
    manifest = create(prepared)
    assert snapshot.inspect(folder, digest(manifest)) == manifest
    assert journal_snapshot(root) == before and fences == original_fences
    assert json.loads((folder / "context.json").read_bytes()) == context.model_dump(mode="json")
    for name, value in fences.items():
        assert (folder / "fences" / (name + ".json")).read_bytes() == value
    with engine.connect() as conn:
        assert before_db == snapshot.backup.inventory(
            lambda sql: conn.execute(text(sql)).scalars(),
            conn.scalar(text("SELECT current_schema()")),
        )
    for file in folder.rglob("*"):
        assert file.stat().st_mode & 0o777 == (0o700 if file.is_dir() else 0o600)
    assert manifest["status"] == "data_snapshot_created_not_restored"
    assert all(
        value is False for key, value in manifest.items() if key.endswith(("verified", "permitted"))
    )
    assert "Fixture only" not in json.dumps(manifest)  # No job contents in manifest.


def test_dump_writer_imports_the_same_live_snapshot_and_cannot_write(prepared):
    engine, _, _, _, _ = prepared
    seen = []

    def dump(snapshot_id, stream):
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            conn.execute(text("SET TRANSACTION SNAPSHOT '" + snapshot_id + "'"))
            seen.append(conn.scalar(text("SHOW transaction_read_only")))
            assert conn.scalar(text("SELECT count(*) FROM runner_dispatches")) == 1
        fixture_dump(snapshot_id, stream)

    create(prepared, dump)
    assert seen == ["on"]


def test_concurrent_database_change_during_dump_refuses_publication(prepared):
    engine, _, _, _, folder = prepared

    def dump(snapshot_id, stream):
        with engine.begin() as writer:
            writer.execute(text("UPDATE users SET active=false WHERE username='viewer'"))
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as reader:
            reader.execute(text("SET TRANSACTION SNAPSHOT '" + snapshot_id + "'"))
            assert reader.scalar(text("SELECT active FROM users WHERE username='viewer'"))
        fixture_dump(snapshot_id, stream)

    with pytest.raises(snapshot.SnapshotError):
        create(prepared, dump)
    assert not (folder / "manifest.json").exists()
    assert (folder / "database.dump").exists()  # Private failed copy is preserved.


@pytest.mark.parametrize(
    "problem",
    [
        "pending",
        "dispatch",
        "cleanup",
        "authorized",
        "reservation",
        "schema",
        "environment",
        "identity",
    ],
)
def test_unresolved_effect_or_context_blocks_before_dump(prepared, problem):
    engine, root, context, fences, folder = prepared
    statements = {
        "pending": "UPDATE campaign_runs SET state='QUEUED'",
        "dispatch": "UPDATE runner_dispatches SET generation='" + str(uuid4()) + "'",
        "cleanup": "DELETE FROM runner_cleanups",
        "authorized": "UPDATE laboratories SET authorized=true WHERE kind='linux'",
        "reservation": "UPDATE laboratories SET active_run_id=(SELECT id FROM campaign_runs LIMIT 1) WHERE kind='linux'",
    }
    if problem in statements:
        with engine.begin() as conn:
            conn.execute(text(statements[problem]))
    else:
        context = context.model_copy(
            update={
                "schema_revision": "0" * 12 if problem == "schema" else context.schema_revision,
                "environment_version": context.environment_version + (problem == "environment"),
                "descriptor_sha256": "0" * 64
                if problem == "identity"
                else context.descriptor_sha256,
            }
        )
    before = journal_snapshot(root)
    with pytest.raises(snapshot.SnapshotError):
        snapshot.create(
            engine,
            root,
            context,
            fences,
            folder,
            lambda *_: pytest.fail("No dump after blocked review"),
        )
    assert journal_snapshot(root) == before
    assert not (folder / "manifest.json").exists()


@pytest.mark.parametrize("problem", ["exception", "partial", "journal_change"])
def test_failed_or_partial_dump_never_publishes_success(prepared, problem):
    _, root, _, _, folder = prepared

    def dump(snapshot_id, stream):
        if problem == "exception":
            raise RuntimeError("private-secret-must-not-be-echoed")
        if problem == "partial":
            stream.write(b"partial")
            return
        fixture_dump(snapshot_id, stream)
        with (root / "journal.sqlite3").open("ab") as changed:
            changed.write(b"altered")

    with pytest.raises(snapshot.SnapshotError) as error:
        create(prepared, dump)
    assert "private-secret" not in str(error.value)
    assert not (folder / "manifest.json").exists()


@pytest.mark.parametrize(
    "problem",
    [
        "dump",
        "fence",
        "extra",
        "missing",
        "symlink",
        "hardlink",
        "public",
        "hash",
        "flag",
        "version",
        "duplicate_json",
        "directory",
    ],
)
def test_changed_or_unsafe_bundle_is_rejected_without_repair(prepared, problem):
    _, _, _, _, folder = prepared
    manifest = create(prepared)
    pinned = digest(manifest)
    target = folder / "database.dump"
    if problem == "dump":
        target.write_bytes(b"PGDMP-corrupted")
    elif problem == "fence":
        (folder / "fences/expired.json").write_bytes(b"deleted-fence")
    elif problem == "extra":
        (folder / "journal/unexpected").touch()
    elif problem == "missing":
        (folder / "journal/instance.lock").unlink()
    elif problem == "symlink":
        target.unlink()
        target.symlink_to(folder / "proofs.json")
    elif problem == "hardlink":
        os.link(target, folder.parent / "linked")
    elif problem == "public":
        target.chmod(0o644)
    elif problem == "directory":
        (folder / "journal").chmod(0o755)
    elif problem == "hash":
        pinned = "0" * 64
    elif problem == "duplicate_json":
        path = folder / "manifest.json"
        path.write_text('{"format":"duplicate",' + path.read_text()[1:])
    else:
        manifest["restore_verified" if problem == "flag" else "format"] = (
            True if problem == "flag" else "unknown/2"
        )
        (folder / "manifest.json").write_text(json.dumps(manifest))
        pinned = digest(manifest)
    before = {
        p: (p.lstat().st_mode, p.lstat().st_size, p.lstat().st_mtime_ns) for p in folder.rglob("*")
    }
    with pytest.raises(snapshot.SnapshotError):
        snapshot.inspect(folder, pinned)
    assert before == {
        p: (p.lstat().st_mode, p.lstat().st_size, p.lstat().st_mtime_ns) for p in folder.rglob("*")
    }


def test_existing_destination_is_never_adopted(prepared):
    folder = prepared[-1]
    folder.mkdir(mode=0o700)
    sentinel = folder / "owned-by-another-attempt"
    sentinel.write_bytes(b"preserve")
    with pytest.raises(snapshot.SnapshotError):
        create(prepared)
    assert list(folder.iterdir()) == [sentinel]


def test_capture_returns_exact_bytes_and_review_while_preserving_original(journal):
    before = journal_snapshot(journal[0])
    result, contents = continuity.capture(*journal)
    assert contents == {name: value[0] for name, value in before.items()}
    assert result == continuity.review(*journal)
    assert journal_snapshot(journal[0]) == before


def test_capture_preserves_committed_wal_and_shm_bytes_in_a_new_private_copy(wal_journal, tmp_path):
    before = journal_snapshot(wal_journal[0])
    result, contents = continuity.capture(*wal_journal)
    assert contents == {name: record[0] for name, record in before.items()}
    assert len(contents["journal.sqlite3-wal"]) > 32
    target = tmp_path / "captured"
    target.mkdir(mode=0o700)
    for name, data in contents.items():
        snapshot.vault.write_private(target / name, data)
    assert continuity.review(target, *wal_journal[1:]) == result
    assert journal_snapshot(wal_journal[0]) == before
    (target / "journal.sqlite3-wal").unlink()
    with pytest.raises(continuity.ContinuityError):
        continuity.review(target, *wal_journal[1:])


def test_persisted_proofs_import_the_exporters_snapshot_not_a_later_cleanup(prepared):
    engine, _, context, _, _ = prepared
    with engine.connect().execution_options(isolation_level="REPEATABLE READ") as source:
        source.execute(text("SET TRANSACTION READ ONLY"))
        snapshot_id = source.scalar(text("SELECT pg_export_snapshot()"))
        before = persisted_review.collect(
            engine, context.identity, context.descriptor_sha256, snapshot_id=snapshot_id
        )
        with engine.begin() as writer:
            writer.execute(text("DELETE FROM runner_cleanups"))
        imported = persisted_review.collect(
            engine, context.identity, context.descriptor_sha256, snapshot_id=snapshot_id
        )
        assert snapshot._stable_proofs(before) == snapshot._stable_proofs(imported)
        with pytest.raises(continuity.ContinuityError, match="blocked"):
            persisted_review.collect(engine, context.identity, context.descriptor_sha256)


def test_public_descriptor_cannot_mix_pki_or_smuggle_a_credential(prepared):
    context = prepared[2].model_dump(mode="json")
    for problem in ("private_key", "pki", "url", "asset"):
        changed = copy.deepcopy(context)
        descriptor = changed["descriptor"]
        if problem == "private_key":
            descriptor["private_key"] = "not-allowed"
        elif problem == "pki":
            descriptor["client_cert_sha256"] = "0" * 64
        elif problem == "url":
            descriptor["url"] = "https://user:secret@127.0.0.1:8443"
        else:
            descriptor["asset_id"] = str(uuid4())
        changed["descriptor_sha256"] = digest(descriptor)
        with pytest.raises(ValueError):
            snapshot.Context.model_validate_json(json.dumps(changed))


@pytest.mark.parametrize(
    "name,data", [("../escape", b"{}"), ("bad/name", b"{}"), ("empty", b""), ("text", "not-bytes")]
)
def test_fence_input_is_bounded_opaque_and_never_interpreted(prepared, name, data):
    engine, root, context, _, folder = prepared
    with pytest.raises(snapshot.SnapshotError, match="fences_invalid"):
        snapshot.create(engine, root, context, {name: data}, folder, fixture_dump)
    assert not folder.exists()


def test_failed_private_publication_preserves_source_and_no_manifest(prepared, monkeypatch):
    root, folder = prepared[1], prepared[-1]
    before = journal_snapshot(root)
    original = snapshot.vault.write_private

    def interrupted(path, content):
        if path.name == "proofs.json":
            raise OSError("simulated durable write failure")
        return original(path, content)

    monkeypatch.setattr(snapshot.vault, "write_private", interrupted)
    with pytest.raises(snapshot.SnapshotError):
        create(prepared)
    assert not (folder / "manifest.json").exists()
    assert journal_snapshot(root) == before


@pytest.mark.parametrize("value", ["'; SELECT 1 --", "", "x" * 129, "not-a-snapshot", 123, True])
def test_snapshot_id_rejects_sql_input_before_connect(value):
    class ForbiddenEngine:
        def connect(self):
            pytest.fail("Invalid snapshot must not connect")

    from aegis.lab_runner.protocol import RunnerIdentity

    with pytest.raises(continuity.ContinuityError, match="inputs_invalid"):
        persisted_review.collect(
            ForbiddenEngine(),
            RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4()),
            "a" * 64,
            snapshot_id=value,
        )
