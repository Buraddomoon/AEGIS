"""Explicit operator fixture: real pg_dump/restore, no historical Lab volumes.

Run via make test-lab-recovery-native-fixture. Not an automatic lab/CI startup.
Shared PG/Redis fixtures remain sequential; only a new isolated PG is started.
"""

import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from aegis.domain.validation import digest
from aegis.operations import lab_archive, vault
from aegis.operations import lab_backup as snapshot
from sqlalchemy import create_engine, text
from test_binding_review import binding_lab as binding_lab  # noqa: F401
from test_lab_backup import prepared as prepared  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import lab_recovery_runtime as runtime  # noqa: E402
import lab_recovery_transport as transport  # noqa: E402


def test_real_dump_restores_in_fresh_offline_cluster_and_cleans_every_resource(prepared):
    engine, journal, context, fences, _ = prepared
    root = Path(__file__).resolve().parents[1] / ".local/lab-recovery-fixtures"
    vault.private_directory(root)
    folder = root / uuid4().hex
    snapshot._new(folder)
    containers = (
        transport.run(
            [
                "ps",
                "-q",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project=aegis",
                "--filter",
                "label=com.docker.compose.service=db",
            ]
        )
        .decode()
        .split()
    )
    assert len(containers) == 1
    container = containers[0]
    image = transport.run(["inspect", "--format", "{{.Image}}", container]).decode().strip()
    context = context.model_copy(
        update={"images": context.images.model_copy(update={"postgres": image})}
    )
    with engine.connect() as conn:
        expected = snapshot.backup.inventory(
            lambda sql: conn.execute(text(sql)).scalars(), context.database_schema
        )
        cluster = conn.scalar(text("SELECT system_identifier::text FROM pg_control_system()"))
    actual_cluster = (
        transport.run(
            [
                "exec",
                container,
                "/usr/local/bin/psql",
                "-X",
                "-qAt",
                "-U",
                "aegis",
                "-d",
                "aegis",
                "-c",
                "SELECT system_identifier::text FROM pg_control_system()",
            ]
        )
        .decode()
        .strip()
    )
    assert cluster == actual_cluster

    def dump(snapshot_id, stream):
        assert context.database_schema.startswith("aegis_test_")
        transport.run(
            [
                "exec",
                container,
                "/usr/local/bin/pg_dump",
                "-U",
                "aegis",
                "-d",
                "aegis",
                "--format=custom",
                "--schema=" + context.database_schema,
                "--no-owner",
                "--no-privileges",
                "--snapshot=" + snapshot_id,
            ],
            output=stream,
            maximum=snapshot.MAX_DUMP,
            timeout=120,
        )

    manifest = snapshot.create(engine, journal, context, fences, folder / "bundle", dump)
    operation = runtime.Operation(folder / "operation", digest(manifest))
    vault.write_json(folder / "begin.json", {"begin_sha256": digest(operation.events[0])})
    restored = None
    try:
        properties = runtime.database_properties(engine)
        restored = runtime.restore(
            operation, folder / "bundle", digest(manifest), image, properties
        )
        assert restored["inventory_sha256"] == digest(expected)
        assert restored["normal_operation_permitted"] is False
        operation.remove("restore")
        archive_hashes = []
        for role in ("cold-first", "cold-second"):
            operation.create(
                role,
                image,
                "/bin/tar",
                ["-C", runtime.DATA, "-cf", "-", "."],
                [runtime.mount(operation.workspace / "restore/data", runtime.DATA, readonly=True)],
            )
            target = folder / (role + ".tar")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                operation.start(role, output=stream, maximum=lab_archive.MAX_ARCHIVE, attached=True)
                stream.flush()
                os.fsync(stream.fileno())
            operation.remove(role)
            with snapshot.vault.private_file(target, maximum=lab_archive.MAX_ARCHIVE) as stream:
                archive_hashes.append(snapshot.vault.hash_stream(stream))
        assert archive_hashes[0] == archive_hashes[1]
        cold_root = runtime.postgres_files(operation, "cold-source")
        physical = lab_archive.extract(folder / "cold-first.tar", cold_root / "data")
        assert not (cold_root / "data/postmaster.pid").exists()
        operation.create(
            "cold-control",
            image,
            "/usr/local/bin/pg_controldata",
            [runtime.DATA],
            [runtime.mount(cold_root / "data", runtime.DATA, readonly=True)],
        )
        control = io.BytesIO()
        operation.start("cold-control", output=control, attached=True)
        assert re.search(rb"Database cluster state:\s+shut down\s*\n", control.getvalue())
        operation.remove("cold-control")
        cold = runtime.start_postgres(operation, "cold-source", image, cold_root, fresh=False)
        cold.dispose()
        cold = create_engine(
            cold.url.set(database="aegis_restore"),
            connect_args={
                "options": "-csearch_path=" + context.database_schema + " -ctimezone=UTC"
            },
        )
        try:
            assert runtime.database_properties(cold) == properties
            with cold.connect() as connection:
                copied = snapshot.backup.inventory(
                    lambda sql: connection.execute(text(sql)).scalars(), context.database_schema
                )
            snapshot.backup.compare(expected, copied)

            def cold_dump(snapshot_id, stream):
                operation.execute(
                    "cold-source",
                    "/usr/local/bin/pg_dump",
                    [
                        "-h",
                        "/socket",
                        "-U",
                        "aegis",
                        "-d",
                        "aegis_restore",
                        "--format=custom",
                        "--schema=" + context.database_schema,
                        "--no-owner",
                        "--no-privileges",
                        "--snapshot=" + snapshot_id,
                    ],
                    output=stream,
                    maximum=snapshot.MAX_DUMP,
                )

            cold_manifest = snapshot.create(
                cold, journal, context, fences, folder / "cold-bundle", cold_dump
            )
        finally:
            cold.dispose()
    finally:
        operation.cleanup()
    with engine.connect() as conn:
        snapshot.backup.compare(
            expected,
            snapshot.backup.inventory(
                lambda sql: conn.execute(text(sql)).scalars(), context.database_schema
            ),
        )
    assert operation.workspace is not None and not operation.workspace.exists()
    assert all(not operation.names(spec["name"]) for spec in operation.resources.values())
    receipt = {
        "format": "aegis-lab-recovery-native-fixture/3",
        "status": "VERIFIED",
        "synthetic": True,
        "source": "disposable_test_schema_in_existing_development_pg",
        "historical_volumes_opened": False,
        "database_image": image,
        "schema_revision": context.schema_revision,
        "snapshot_sha256": digest(manifest),
        "restored": restored,
        "database_properties": properties,
        "cold_archives_equal": True,
        "cold_archive_sha256": archive_hashes[0],
        "physical_inventory_sha256": physical["sha256"],
        "cold_reopened_inventory_sha256": digest(copied),
        "cold_manifest_sha256": digest(cold_manifest),
        "cleanup_verified": True,
        "normal_operation_permitted": False,
        "tool_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True
        ).strip(),
        "tool_sources_sha256": digest(
            {
                name: hashlib.sha256(
                    (Path(__file__).resolve().parents[1] / name).read_bytes()
                ).hexdigest()
                for name in (
                    "scripts/lab_recovery_runtime.py",
                    "scripts/lab_recovery_transport.py",
                    "apps/api/aegis/operations/lab_archive.py",
                    "apps/api/aegis/operations/lab_backup.py",
                    "tests/native_lab_recovery.py",
                )
            }
        ),
    }
    vault.write_json(folder / "verified.json", receipt)
    print(
        json.dumps(
            {"fixture_id": folder.name, "status": "VERIFIED", "receipt_sha256": digest(receipt)}
        )
    )
