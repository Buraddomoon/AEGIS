"""Explicit #116 acceptance: complete schema, real CLI apply and real restores.

Only new PostgreSQL containers in tmpfs/network=none and private test files.
Excluded from automatic pytest/CI collection; never opens a human database.
"""

import io
import json
import os
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aegis import models
from aegis.domain.validation import digest
from aegis.operations import backup, retention, vault
from aegis.operations import retention_store as store
from alembic import command
from alembic.config import Config
from sqlalchemy import ARRAY

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import demo_backup as native  # noqa: E402
import history_retention as cli  # noqa: E402


@contextmanager
def offline_source():
    image = (
        native.docker("image", "inspect", "postgres:17-alpine", "--format", "{{.Id}}")
        .decode()
        .strip()
    )
    token = uuid.uuid4().hex
    name = "aegis-recovery-" + token
    try:
        native.docker(
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            native.LABEL + "=" + token,
            "--network=none",
            "--read-only",
            "--security-opt=no-new-privileges:true",
            "--memory=256m",
            "--cpus=1",
            "--pids-limit=128",
            "--tmpfs",
            "/var/lib/postgresql/data:rw,noexec,nosuid,size=256m",
            "--tmpfs",
            "/var/run/postgresql:rw,noexec,nosuid,size=16m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_DB=aegis_restore",
            image,
        )
        native.docker("start", name)
        for _attempt in range(60):
            try:
                if native.docker("exec", name, "cat", "/proc/1/comm").strip() == b"postgres":
                    native.docker(
                        "exec", name, "pg_isready", "-U", "postgres", "-d", "aegis_restore"
                    )
                    break
            except native.BackupError:
                pass
            time.sleep(0.25)
        else:
            raise AssertionError("Disposable source did not become ready")
        yield name, image
    finally:
        assert native.remove_clone(name, token) == "removed"
    assert not native.docker("ps", "-aq", "--filter", "label=" + native.LABEL + "=" + token).strip()


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def fixture_insert(model, **values):
    """Render only program-owned fixture values using current model defaults.

    No caller SQL, imported data, adapters, live ORM session or trigger bypass.
    The real current Alembic schema still enforces every type/FK/constraint.
    """
    table = model.__table__
    row = dict(values)
    for column in table.columns:
        if column.name not in row and column.default is not None:
            default = column.default
            row[column.name] = default.arg(None) if default.is_callable else default.arg
    encoded = []
    for name, value in row.items():
        if value is None:
            literal = "NULL"
        elif isinstance(value, bool):
            literal = "true" if value else "false"
        elif isinstance(value, int):
            literal = str(value)
        elif isinstance(value, (dict, list)):
            literal = quote("{}" if isinstance(table.c[name].type, ARRAY) else json.dumps(value))
        else:
            literal = quote(value.isoformat() if isinstance(value, datetime) else value)
        encoded.append(literal)
    columns = ",".join(backup.identifier(name) for name in row)
    return (
        f"INSERT INTO {backup.identifier(table.name)} ({columns}) VALUES ({','.join(encoded)});",
        row,
    )


def complete_fixture():
    """Synthetic relational history, no worker, start, scheduler or claimed alert."""
    statements = []
    stamp = datetime.now(UTC)
    scope = {"synthetic": True, "fixture": "retention-116", "version": 1}
    scope_hash = digest(scope)

    def add(model, **values):
        sql, row = fixture_insert(model, **values)
        statements.append(sql)
        return row["id"]

    actor = add(
        models.User,
        username="retention-fixture",
        password_hash="invalid-no-login-fixture",
        role="administrator",
        active=False,
    )
    lab = add(
        models.Laboratory,
        name="Retention fixture",
        description="Synthetic history only",
        owner="Disposable fixture",
        isolation="network=none; no executor",
        authorized=False,
    )
    asset = add(
        models.Asset,
        laboratory_id=lab,
        name="fixture",
        platform="Synthetic",
        external_id="fixture-only",
        synthetic=True,
    )
    test = add(
        models.TestDefinition,
        id="retention-fixture",
        name="Fixture",
        description="No executor",
        behavior="fixture-only",
        cleanup="No effect",
        prerequisites="Never dispatched",
        expected_rule="",
        demo_outcome="INCONCLUSIVE",
    )
    campaign = add(
        models.Campaign,
        name="Fixture",
        objective="Preserve full history",
        laboratory_id=lab,
        asset_id=asset,
        created_by=actor,
    )
    statements.append(f"INSERT INTO campaign_tests VALUES ({quote(campaign)},{quote(test)});")
    schedule = add(
        models.Schedule,
        campaign_id=campaign,
        laboratory_id=lab,
        created_by=actor,
        state="EXHAUSTED",
        scope=scope,
        scope_hash=scope_hash,
        plan_hash=scope_hash,
        interval_seconds=60,
        max_occurrences=2,
        occurrences_count=2,
        max_duration_seconds=60,
        starts_at=stamp - timedelta(minutes=2),
        ends_at=stamp + timedelta(hours=1),
        next_due_at=stamp,
    )
    grant = add(
        models.ScheduleAuthorization,
        schedule_id=schedule,
        approved_by=actor,
        plan_hash=scope_hash,
        expires_at=stamp + timedelta(hours=1),
    )
    runs, reports = [], []
    for index in range(2):
        run = add(
            models.CampaignRun,
            campaign_id=campaign,
            laboratory_id=lab,
            requested_by=actor,
            schedule_id=schedule,
            idempotency_key=f"fixture-{index}",
            state="CANCELLED",
            scope=scope,
            scope_hash=scope_hash,
            synthetic=True,
            ended_at=stamp,
        )
        runs.append(run)
        add(
            models.Approval,
            run_id=run,
            approved_by=actor,
            schedule_authorization_id=grant,
            scope_hash=scope_hash,
            expires_at=stamp + timedelta(hours=1),
            max_duration_seconds=60,
        )
        occurrence = add(
            models.ScheduleOccurrence,
            schedule_id=schedule,
            authorization_id=grant,
            scheduled_for=stamp - timedelta(seconds=120 - index * 60),
            run_id=run,
            status="QUEUED",
            reason="Fixture; no scheduler or execution",
        )
        document = {
            **scope,
            "run_id": run,
            "previous_run_id": runs[0] if index else None,
            "context_version": "fixture/1",
        }
        reports.append(
            add(
                models.ScheduledReport,
                schedule_id=schedule,
                authorization_id=grant,
                occurrence_id=occurrence,
                run_id=run,
                previous_run_id=runs[0] if index else None,
                kind="COMPARISON" if index else "BASELINE",
                state="READY",
                attempts=1,
                document=document,
                document_sha256=digest(document),
                generated_at=stamp,
            )
        )
    execution = add(
        models.TestExecution,
        run_id=runs[0],
        test_id=test,
        asset_id=asset,
        state="CANCELLED",
        marker="fixture-only-no-marker-executed",
        synthetic=True,
        executed=False,
        ended_at=stamp,
    )
    raw = {**scope, "execution_id": execution, "observation": "fixture-not-defensive-telemetry"}
    event = add(
        models.TelemetryEvent,
        execution_id=execution,
        source_id="fixture-event",
        source="fixture",
        timestamp=stamp,
        kind="telemetry",
        synthetic=True,
        raw=raw,
        sha256=digest(raw),
    )
    result = add(
        models.ValidationResult,
        execution_id=execution,
        outcome="INCONCLUSIVE",
        reason="Synthetic archival fixture; no detection claim",
        logic_version="fixture/1",
        synthetic=True,
        collection_complete=False,
        telemetry_available=False,
        alerts_available=False,
    )
    add(
        models.DetectionEvidence,
        result_id=result,
        event_id=event,
        reason="Fixture relation only; not a correlated alert",
    )
    add(models.RunnerReceipt, execution_id=execution, content=scope, sha256=digest(scope))
    add(models.RunnerCleanup, execution_id=execution, content=scope, sha256=digest(scope))
    rule = add(models.DetectionRule, title="Fixture", sigma_id=str(uuid.uuid4()))
    add(
        models.RuleVersion,
        rule_id=rule,
        version=1,
        content="fixture-only",
        sha256=digest("fixture-only"),
        techniques=[],
        created_by=actor,
    )
    return "\n".join(statements), {
        "actor": actor,
        "runs": runs,
        "reports": reports,
        "event": event,
        "result": result,
    }


def source_snapshot(workspace, identifier, name, image, expected, created):
    folder = workspace / identifier
    folder.mkdir(mode=0o700)
    fd = os.open(folder / "database.dump", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        native.docker(
            "exec",
            name,
            "pg_dump",
            "-U",
            "postgres",
            "-d",
            "aegis_restore",
            "--format=custom",
            "--schema=public",
            "--no-owner",
            "--no-privileges",
            stdout=output,
        )
        output.flush()
        os.fsync(output.fileno())
    with vault.private_file(folder / "database.dump") as stream:
        dump_sha = vault.hash_stream(stream)
    vault.write_json(
        folder / "manifest.json",
        {
            "format": backup.FORMAT,
            "id": identifier,
            "created_at": created.isoformat(),
            "source": {"postgres_major": 17, "image_id": image},
            "inventory": expected,
            "dump_sha256": dump_sha,
            "fixture": "synthetic-aged-metadata-not-human-history",
        },
    )
    return folder


def test_full_schema_cli_apply_keeps_hold_minimum_source_and_recoverable_history(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "private"
    vault.private_directory(workspace)
    monkeypatch.setattr(native, "ROOT", workspace)
    root = workspace / "retention"
    identifiers = ["20260901T000000Z-" + uuid.uuid4().hex for _ in range(9)]
    policy = {
        "format": retention.POLICY_FORMAT,
        "retain_days": 30,
        "minimum_snapshots": 7,
        "legal_holds": [identifiers[8]],
    }
    store.initialize(root, policy)
    key = vault.generate_key(workspace / "keys")

    def invoke(*args):
        monkeypatch.setattr(sys, "argv", ["history_retention.py", "--store", str(root), *args])
        cli.main()  # Real fixed restore coordinator; no mocked restore/network/SQL.
        return json.loads(capsys.readouterr().out)

    with offline_source() as (name, image):
        sql = io.StringIO()
        command.upgrade(Config("alembic.ini", output_buffer=sql), "head", sql=True)

        def query(statement):
            return native.psql(name, statement, database="aegis_restore", user="postgres")

        list(query(sql.getvalue()))
        data, relations = complete_fixture()
        list(query(data))
        sources, originals, envelopes = {}, {}, {}
        for index, identifier in enumerate(identifiers):
            statement, _ = fixture_insert(
                models.AuditEvent,
                actor_id=relations["actor"],
                action="retention.fixture",
                resource_id=str(index),
                details={"synthetic": True, "fixture": True, "snapshot": index},
            )
            list(query(statement))
            expected = backup.inventory(query)
            folder = source_snapshot(
                workspace,
                identifier,
                name,
                image,
                expected,
                datetime.now(UTC) - timedelta(days=40 + index),
            )
            sources[identifier] = folder
            originals[identifier] = store.files(folder)
            invoke("enroll", "--source", str(folder))
            envelope = invoke("archive", identifier, "--recipient", key["recipient"])
            envelopes[identifier] = envelope
            verified = invoke(
                "verify",
                envelope["id"],
                "--expected-sha256",
                envelope["ciphertext_sha256"],
                "--keys",
                str(workspace / "keys"),
                "--key-id",
                key["key_id"],
            )
            assert verified["recovery"]["tables"] == len(models.Base.metadata.tables) + 1 == 36
            assert verified["recovery"]["clone_removed"] is True
        before = backup.inventory(query)
        assert before["tables"]["scheduled_reports"]["rows"] == 2
        assert before["tables"]["detection_evidence"]["rows"] == 1
        assert before["tables"]["runner_receipts"]["rows"] == 1
        assert before["structure"]["triggers"]["rows"] > 0
        plan = invoke("plan")
        candidates = [row["id"] for row in plan["members"] if row["action"] != "keep"]
        assert candidates == [identifiers[7]]
        plan_path = workspace / "plan.json"
        vault.write_json(plan_path, plan)
        dry = invoke(
            "apply", "--plan", str(plan_path), "--expected-sha256", plan["sha256"], "--dry-run"
        )
        assert dry["candidate_ids"] == candidates and dry["deletion_performed"] is False
        # A hold added after review must refuse before any intent or deletion.
        original_policy = (root / "policy.json").read_bytes()
        (root / "policy.json").write_text(json.dumps({**policy, "legal_holds": candidates}))
        with pytest.raises(SystemExit):
            invoke(
                "apply", "--plan", str(plan_path), "--expected-sha256", plan["sha256"], "--dry-run"
            )
        assert len(list((root / "snapshots").iterdir())) == 9
        assert not list((root / "receipts").iterdir())
        (root / "policy.json").write_bytes(original_policy)
        plan_path.unlink()  # Only this test's private review artifact; no consumed plan.
        plan = invoke("plan")
        vault.write_json(plan_path, plan)
        approval_path = workspace / "fixture-approval.json"
        vault.write_json(
            approval_path,
            {
                "format": "aegis-history-retention-approval/1",
                "store_id": plan["store_id"],
                "plan_sha256": plan["sha256"],
                "decision": "approve_enrolled_plaintext_removal",
                "approved_by": "native-disposable-fixture-not-human-authorization",
                "approved_at": datetime.now(UTC).isoformat(),
                "expires_at": plan["expires_at"],
            },
        )
        protected = {
            str(path): path.read_bytes()
            for path in (root / "archives").rglob("*")
            if path.is_file()
        }
        original_bytes = sum(
            store.files(root / "snapshots" / identifier)[name]["bytes"]
            for identifier in identifiers
            for name in store.files(root / "snapshots" / identifier)
        )
        result = invoke(
            "apply",
            "--plan",
            str(plan_path),
            "--expected-sha256",
            plan["sha256"],
            "--authorization",
            str(approval_path),
            "--keys",
            str(workspace / "keys"),
            "--key-id",
            key["key_id"],
            "--confirm-remove-copies",
        )
        assert result["status"] == "applied" and result["removed_ids"] == candidates
        assert (
            len(result["fresh_restores"]) == 1
            and result["fresh_restores"][0]["recovery"]["clone_removed"] is True
        )
        assert not (root / "snapshots" / candidates[0]).exists()
        assert len(list((root / "snapshots").iterdir())) == 8
        assert (root / "snapshots" / identifiers[8]).is_dir()  # Legal hold beyond minimum.
        assert protected == {
            str(path): path.read_bytes()
            for path in (root / "archives").rglob("*")
            if path.is_file()
        }
        assert all(
            store.files(folder) == originals[identifier] for identifier, folder in sources.items()
        )
        assert before == backup.inventory(query)  # All database rows and guards unchanged.
        remaining = invoke("plan")
        assert all(row["action"] == "keep" for row in remaining["members"])
        remaining_bytes = sum(row["bytes"] for row in remaining["members"])
        assert original_bytes - remaining_bytes == plan["candidate_bytes"] > 0
        with pytest.raises(SystemExit):
            invoke(
                "apply",
                "--plan",
                str(plan_path),
                "--expected-sha256",
                plan["sha256"],
                "--authorization",
                str(approval_path),
                "--keys",
                str(workspace / "keys"),
                "--key-id",
                key["key_id"],
                "--confirm-remove-copies",
            )
        audit = store.read_json(root / "receipts" / (plan["sha256"] + "-result.json"))
        assert audit["status"] == "applied" and audit["removed_ids"] == candidates
        # Recover the deleted copy's complete database again, with no plaintext fallback.
        envelope = envelopes[candidates[0]]
        recovered = invoke(
            "verify",
            envelope["id"],
            "--expected-sha256",
            envelope["ciphertext_sha256"],
            "--keys",
            str(workspace / "keys"),
            "--key-id",
            key["key_id"],
        )
        assert (
            recovered["recovery"]["tables"] == 36 and recovered["recovery"]["clone_removed"] is True
        )
        assert not list((root / "work").iterdir())
        print(
            json.dumps(
                {
                    "status": "FULL_SCHEMA_RETENTION_VERIFIED",
                    "synthetic": True,
                    "tables": 36,
                    "migration": before["migration"],
                    "snapshots_verified": 9,
                    "plaintext_copies_removed": 1,
                    "plaintext_copies_remaining": 8,
                    "legal_hold_preserved": True,
                    "removed_bytes": original_bytes - remaining_bytes,
                    "source_database_identical": True,
                    "protected_archives_identical": True,
                    "restore_after_removal_verified": True,
                    "rows": sum(item["rows"] for item in before["tables"].values()),
                }
            )
        )
