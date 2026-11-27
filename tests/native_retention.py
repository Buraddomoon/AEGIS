"""Explicit real PostgreSQL fixture. Never starts Linux/Wazuh or opens originals.

Run only with make test-retention-native-fixture; excluded from default pytest.
Source and restore are fresh offline PostgreSQL17 with tmpfs and no host mounts.
"""

import hashlib
import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aegis.domain.validation import digest
from aegis.operations import backup, retention, vault
from aegis.operations import retention_store as store

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import demo_backup as native  # noqa: E402
import history_retention as cli  # noqa: E402


def test_real_dump_encrypted_roundtrip_with_relations_and_snapshot_bytes(tmp_path, monkeypatch):
    workspace = tmp_path / "private"
    vault.private_directory(workspace)
    monkeypatch.setattr(native, "ROOT", workspace)
    image = (
        native.docker("image", "inspect", "postgres:17-alpine", "--format", "{{.Id}}")
        .decode()
        .strip()
    )
    token = uuid.uuid4().hex
    name = "aegis-recovery-" + token
    identifier = "20260901T000000Z-" + uuid.uuid4().hex
    source = workspace / identifier
    source.mkdir(mode=0o700)
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
            raise AssertionError("Disposable PostgreSQL not ready")
        scope = {"synthetic": True, "provenance": "native_disposable_fixture", "version": 7}
        raw = {"synthetic": True, "marker": "fixture-only-no-executor", "rule": "fixture"}
        # Nonempty relational fixture, including frozen snapshot, audit and receipt.
        sql = f"""
        CREATE TABLE alembic_version(version_num varchar(32) PRIMARY KEY);
        INSERT INTO alembic_version VALUES ('retention-fixture-not-app-schema');
        CREATE TABLE campaign_runs(id text PRIMARY KEY, scope jsonb NOT NULL, scope_hash text NOT NULL, synthetic boolean NOT NULL);
        CREATE TABLE test_executions(id text PRIMARY KEY, run_id text NOT NULL REFERENCES campaign_runs, synthetic boolean NOT NULL);
        CREATE TABLE telemetry_events(id text PRIMARY KEY, execution_id text NOT NULL REFERENCES test_executions, raw jsonb NOT NULL, sha256 text NOT NULL, synthetic boolean NOT NULL);
        CREATE TABLE validation_results(id text PRIMARY KEY, execution_id text NOT NULL REFERENCES test_executions, outcome text NOT NULL, synthetic boolean NOT NULL);
        CREATE TABLE detection_evidence(id text PRIMARY KEY, result_id text NOT NULL REFERENCES validation_results, event_id text NOT NULL REFERENCES telemetry_events);
        CREATE TABLE runner_receipts(id text PRIMARY KEY, execution_id text NOT NULL REFERENCES test_executions, content jsonb NOT NULL);
        CREATE TABLE audit_events(id text PRIMARY KEY, details jsonb NOT NULL);
        CREATE TABLE scheduled_reports(id text PRIMARY KEY, run_id text NOT NULL REFERENCES campaign_runs, previous_run_id text REFERENCES campaign_runs, document jsonb NOT NULL, document_sha256 text NOT NULL);
        INSERT INTO campaign_runs VALUES ('r1','{json.dumps(scope)}','{digest(scope)}',true),('r2','{json.dumps(scope)}','{digest(scope)}',true);
        INSERT INTO test_executions VALUES ('x1','r1',true);
        INSERT INTO telemetry_events VALUES ('e1','x1','{json.dumps(raw)}','{digest(raw)}',true);
        INSERT INTO validation_results VALUES ('v1','x1','INCONCLUSIVE',true);
        INSERT INTO detection_evidence VALUES ('d1','v1','e1');
        INSERT INTO runner_receipts VALUES ('receipt1','x1','{{"synthetic":true,"version":"fixture/1"}}');
        INSERT INTO audit_events VALUES ('audit1','{{"synthetic":true,"provenance":"fixture"}}');
        INSERT INTO scheduled_reports VALUES ('report1','r2','r1','{json.dumps(scope)}','{digest(scope)}');
        CREATE FUNCTION preserve_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable fixture history'; END; $$;
        CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON detection_evidence FOR EACH ROW EXECUTE FUNCTION preserve_history();
        CREATE TRIGGER reports_immutable BEFORE UPDATE OR DELETE ON scheduled_reports FOR EACH ROW EXECUTE FUNCTION preserve_history();
        """

        def query(sql):
            return native.psql(name, sql, database="aegis_restore", user="postgres")

        list(query(sql))
        expected = backup.inventory(query)
        dump = source / "database.dump"
        fd = os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        with vault.private_file(dump) as stream:
            dump_sha = vault.hash_stream(stream)
        vault.write_json(
            source / "manifest.json",
            {
                "format": backup.FORMAT,
                "id": identifier,
                "created_at": (datetime.now(UTC) - timedelta(days=40)).isoformat(),
                "source": {"postgres_major": 17, "image_id": image},
                "inventory": expected,
                "dump_sha256": dump_sha,
            },
        )
        vault.write_json(
            source / ("verification-" + token + ".json"),
            {"synthetic": True, "fixture": "historical receipt unchanged", "scope": scope},
        )
        original_files = store.files(source)
        root = workspace / "retention"
        store.initialize(
            root,
            {
                "format": retention.POLICY_FORMAT,
                "retain_days": 30,
                "minimum_snapshots": 7,
                "legal_holds": [],
            },
        )
        store.enroll(root, source)
        key = vault.generate_key(workspace / "keys")
        identity = vault.load_key(workspace / "keys", key["key_id"])
        envelope = store.archive(root, identifier, key["recipient"])
        seen = []

        def restore(backup_id, folder):
            before = store.files(folder)
            assert {k: v for k, v in before.items() if k != "enrollment.json"} == original_files
            result = cli.restore(backup_id, folder)
            assert all(store.files(folder)[k] == v for k, v in before.items())
            seen.append(result)
            return result

        result = store.verify(
            root, envelope["id"], envelope["ciphertext_sha256"], identity, restore
        )
        assert result["status"] == "restore_verified" and len(seen) == 1
        assert result["recovery"]["tables"] == 9 and result["recovery"]["rows"] == 10
        assert expected == backup.inventory(query)
        assert store.files(source) == original_files
        assert list((root / "work").iterdir()) == []
        assert store.build_plan(root)["members"][0]["restore_verified"] is True
        assert hashlib.sha256((source / "database.dump").read_bytes()).hexdigest() == dump_sha
    finally:
        assert native.remove_clone(name, token) == "removed"
    assert not native.docker("ps", "-aq", "--filter", "label=" + native.LABEL + "=" + token).strip()
