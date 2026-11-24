"""Host-only historical Linux/Wazuh cold backup and quarantined restore.

Prepare reads metadata only. Run requires a specific reviewed authorization;
the CLI assertion is not independent human authentication. No original RW mount,
normal runner/worker/SIEM, marker, migration, network creation or cutover exists.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import lab_recovery_runtime as runtime
import lab_recovery_transport as transport
from aegis.domain.validation import digest
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.operations import lab_archive, vault
from aegis.operations import lab_backup as snapshot
from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "aegis-lab-cold-recovery-plan/1"
PROFILES = {"linux": "aegis-linux-lab", "wazuh": "aegis-wazuh-lab"}
SCOPE = {
    "original_mounts": "read_only_nocopy",
    "original_database_started": False,
    "fresh_restore_clusters": 2,
    "new_marker": False,
    "cutover": False,
    "normal_operation_permitted": False,
    "retention_deletion": False,
    "host_records_include_private_pki_and_environment": True,
    "maximum_container_memory": runtime.MEMORY,
    "maximum_seconds": 900,
    "minimum_available_memory": 1536 * 1024**2,
    "minimum_free_disk": 4 * 1024**3,
}
VOLUME_FORMAT = (
    '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
    '"options":{{json .Options}},"created_at":{{json .CreatedAt}},'
    '"project":{{json (index .Labels "com.docker.compose.project")}},'
    '"volume":{{json (index .Labels "com.docker.compose.volume")}}}'
)
IMAGE_FORMAT = '{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},"volumes":{{json .Config.Volumes}}}'
SOURCE_FILES = (
    "scripts/lab_recovery.py",
    "scripts/lab_recovery_runtime.py",
    "scripts/lab_recovery_transport.py",
    "apps/api/aegis/operations/lab_archive.py",
    "apps/api/aegis/operations/lab_backup.py",
    "apps/api/aegis/lab_runner/continuity.py",
    "apps/api/aegis/lab_runner/persisted_review.py",
    "requirements.lock",
    "pyproject.toml",
)


def directories():
    for path in (
        ROOT / ".local",
        ROOT / ".local/lab-recovery",
        ROOT / ".local/lab-recovery/plans",
        ROOT / ".local/lab-recovery/operations",
    ):
        vault.private_directory(path)
    return ROOT / ".local/lab-recovery"


def source_hash():
    files = set(SOURCE_FILES) | {
        str(path.relative_to(ROOT)) for path in (ROOT / "apps/api/aegis").rglob("*.py")
    }
    return digest(
        {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(files)}
    )


def roots():
    result = {"primary": ROOT / ".local"}
    legacy = Path.home() / "codes/aegis/.local"
    if legacy.exists() and legacy != result["primary"]:
        result["legacy"] = legacy
    return result


def daemon():
    return snapshot._json(
        transport.run(
            [
                "info",
                "--format",
                '{"id":{{json .ID}},"os":{{json .OSType}},"arch":{{json .Architecture}}}',
            ]
        )
    )


def volume(name, project, suffix):
    item = snapshot._json(transport.run(["volume", "inspect", "--format", VOLUME_FORMAT, name]))
    if (
        item["name"] != name
        or item["driver"] != "local"
        or item["scope"] != "local"
        or item["options"] not in (None, {})
        or item["project"] != project
        or item["volume"] != suffix
    ):
        raise snapshot.SnapshotError("recovery_original_volume_identity")
    return item


def quiescent(expected=None, operation=None):
    result = {}
    own = (
        {}
        if operation is None
        else {spec["id"]: spec for spec in operation.resources.values() if spec["id"] is not None}
    )
    for project in PROFILES.values():
        if transport.run(
            [
                "ps",
                "-a",
                "--no-trunc",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + project,
            ]
        ).strip():
            raise snapshot.SnapshotError("recovery_original_project_in_use")
        for suffix in ("postgres-data", "journal"):
            name = project + "_" + suffix
            result[name] = volume(name, project, suffix)
            consumers = (
                transport.run(["ps", "-a", "--no-trunc", "-q", "--filter", "volume=" + name])
                .decode()
                .split()
            )
            for identifier in consumers:
                if identifier not in own or not any(
                    m["type"] == "volume" and m["source"] == name and m["readonly"]
                    for m in own[identifier]["mounts"]
                ):
                    raise snapshot.SnapshotError("recovery_original_consumer_present")
            if expected is not None and result[name] != expected[name]:
                raise snapshot.SnapshotError("recovery_original_metadata_changed")
    return result


def image_metadata(images):
    result = {}
    for name, values in images.items():
        if name not in PROFILES:
            raise snapshot.SnapshotError("recovery_profile_unknown")
        parsed = snapshot.Images.model_validate(values)
        result[name] = {}
        for role, identifier in parsed.model_dump().items():
            item = snapshot._json(
                transport.run(["image", "inspect", "--format", IMAGE_FORMAT, identifier])
            )
            if (
                item["id"] != identifier
                or item["os"] != "linux"
                or item["arch"] not in {"amd64", "arm64"}
            ):
                raise snapshot.SnapshotError("recovery_local_image_identity")
            if role == "postgres" and set(item["volumes"] or {}) != {runtime.DATA}:
                raise snapshot.SnapshotError("recovery_postgres_declared_volumes")
            result[name][role] = item
    if set(result) != set(PROFILES):
        raise snapshot.SnapshotError("recovery_both_historical_profiles_required")
    return result


def prepare(images):
    base = directories()
    if (
        subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip()
        or subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT).strip() != b"main"
    ):
        raise snapshot.SnapshotError("recovery_clean_committed_source_required")
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    inventory = quiescent()
    metadata = image_metadata(images)
    records = lab_archive.record_paths(roots())
    identifier = uuid4().hex
    plan = {
        "format": FORMAT,
        "id": identifier,
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=24)).isoformat(),
        "source_commit": source_commit,
        "coordinator_sha256": source_hash(),
        "daemon": daemon(),
        "original_volumes": inventory,
        "images": images,
        "image_metadata": metadata,
        "host_roots": {k: str(v) for k, v in roots().items()},
        "host_records": records,
        "scope": dict(SCOPE),
    }
    folder = base / "plans" / identifier
    snapshot._new(folder)
    vault.write_json(folder / "plan.json", plan)
    return plan


def load(identifier, expected_hash, *, expired=False):
    if not re.fullmatch(r"[a-f0-9]{32}", identifier) or not re.fullmatch(
        r"[a-f0-9]{64}", expected_hash
    ):
        raise snapshot.SnapshotError("recovery_plan_identifiers")
    folder = ROOT / ".local/lab-recovery/plans" / identifier
    snapshot._directory(folder)
    plan = snapshot._json(snapshot._read(folder / "plan.json", 16 * 1024**2))
    if digest(plan) != expected_hash or plan["format"] != FORMAT or plan["id"] != identifier:
        raise snapshot.SnapshotError("recovery_plan_integrity")
    if set(plan["scope"]) != set(SCOPE) or any(
        type(plan["scope"][k]) is not type(v) or plan["scope"][k] != v for k, v in SCOPE.items()
    ):
        raise snapshot.SnapshotError("recovery_scope_profile_changed")
    if not expired and (
        datetime.fromisoformat(plan["expires_at"]) <= datetime.now(UTC)
        or plan["coordinator_sha256"] != source_hash()
    ):
        raise snapshot.SnapshotError("recovery_plan_expired_or_code_changed")
    return folder, plan


@contextmanager
def lock():
    base = directories()
    fd = os.open(
        base / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_size
            or info.st_mode & 0o077
        ):
            raise snapshot.SnapshotError("recovery_lock_unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def recheck(plan, operation=None):
    if datetime.fromisoformat(plan["expires_at"]) <= datetime.now(UTC):
        raise snapshot.SnapshotError("recovery_plan_expired")
    if plan["coordinator_sha256"] != source_hash():
        raise snapshot.SnapshotError("recovery_code_changed")
    if daemon() != plan["daemon"] or image_metadata(plan["images"]) != plan["image_metadata"]:
        raise snapshot.SnapshotError("recovery_daemon_or_images_changed")
    if (
        plan["host_roots"] != {k: str(v) for k, v in roots().items()}
        or lab_archive.record_paths(roots()) != plan["host_records"]
    ):
        raise snapshot.SnapshotError("recovery_host_records_changed")
    return quiescent(plan["original_volumes"], operation)


def cold_archive(operation, role, name, image, target, plan):
    recheck(plan, operation)
    uid = "70:70" if name.endswith("_postgres-data") else "10001:10001"
    operation.create(
        role,
        image,
        "/bin/tar",
        ["-C", "/source", "-cf", "-", "."],
        [runtime.mount(name, "/source", readonly=True, kind="volume")],
        user=uid,
        memory=128 * 1024**2,
    )
    recheck(plan, operation)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        operation.start(role, output=stream, maximum=lab_archive.MAX_ARCHIVE, attached=True)
        stream.flush()
        os.fsync(stream.fileno())
    recheck(plan, operation)
    operation.remove(role)
    with vault.private_file(target, maximum=lab_archive.MAX_ARCHIVE) as stream:
        result = {
            "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
            "bytes": target.stat().st_size,
        }
    operation.event("cold_archive", {"role": role, "source_volume": name, **result})
    return result


def context_from_copy(engine, project, images, source_commit):
    with engine.connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        rows = (
            conn.execute(
                text(
                    "SELECT b.laboratory_id,b.configuration_hash,l.environment_version FROM linux_lab_bindings b JOIN laboratories l ON l.id=b.laboratory_id"
                )
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            raise snapshot.SnapshotError("recovery_exact_original_binding_required")
        binding = rows[0]
        scopes = conn.scalars(
            text("SELECT scope FROM campaign_runs WHERE laboratory_id=:lab ORDER BY id LIMIT 1001"),
            {"lab": binding["laboratory_id"]},
        ).all()
        if len(scopes) > 1000:
            raise snapshot.SnapshotError("recovery_scope_history_limit")
        descriptors = [
            s["runner"]
            for s in scopes
            if isinstance(s, dict)
            and isinstance(s.get("runner"), dict)
            and digest(s["runner"]) == binding["configuration_hash"]
        ]
        if not descriptors or any(value != descriptors[0] for value in descriptors):
            raise snapshot.SnapshotError("recovery_current_descriptor_missing")
        descriptor = descriptors[0]
        revision = conn.scalars(text("SELECT version_num FROM alembic_version")).all()
        if revision != ["b7f3c2d91a06"]:
            raise snapshot.SnapshotError("recovery_historical_b7_profile_required")
        if conn.scalar(text("SELECT count(*) FROM pg_tables WHERE schemaname='public'")) != 33:
            raise snapshot.SnapshotError("recovery_historical_b7_table_count_mismatch")
    return snapshot.Context(
        project=project,
        source_commit=source_commit,
        identity=RunnerIdentity(
            **{k: descriptor[k] for k in ("runner_id", "laboratory_id", "asset_id")}
        ),
        descriptor=descriptor,
        descriptor_sha256=digest(descriptor),
        server_ca_sha256=descriptor["server_ca_sha256"],
        client_cert_sha256=descriptor["client_cert_sha256"],
        images=snapshot.Images.model_validate(images),
        database_schema="public",
        schema_revision=revision[0],
        environment_version=binding["environment_version"],
    )


def profile(folder, key, plan, host_inventory, deadline):
    operation = runtime.Operation(folder, digest(plan), deadline=deadline)
    operation.before_effect = lambda: recheck(plan, operation)
    vault.write_json(
        folder.parent / (key + "-begin.json"), {"begin_sha256": digest(operation.events[0])}
    )
    project, images = PROFILES[key], plan["images"][key]
    image = images["postgres"]
    result = None
    try:
        database = folder / "database-cold.tar"
        journal = folder / "journal-cold.tar"
        before_db = cold_archive(
            operation, "database-before", project + "_postgres-data", image, database, plan
        )
        before_journal = cold_archive(
            operation, "journal-before", project + "_journal", image, journal, plan
        )
        root = runtime.postgres_files(operation, "source")
        physical = lab_archive.extract(database, root / "data")
        if (root / "data/postmaster.pid").exists() or (
            root / "data/PG_VERSION"
        ).read_bytes().strip() != b"17":
            raise snapshot.SnapshotError("recovery_stopped_postgres17_required")
        check_role = "cold-control"
        operation.create(
            check_role,
            image,
            "/usr/local/bin/pg_controldata",
            [runtime.DATA],
            runtime.postgres_mounts(root),
        )
        control = __import__("io").BytesIO()
        operation.start(check_role, output=control, attached=True)
        if not re.search(rb"Database cluster state:\s+shut down\s*\n", control.getvalue()):
            raise snapshot.SnapshotError("recovery_cold_cluster_not_cleanly_stopped")
        operation.remove(check_role)
        journal_root = operation.scratch() / "journal"
        snapshot._new(journal_root)
        lab_archive.extract(journal, journal_root)
        engine = runtime.start_postgres(operation, "source", image, root, fresh=False)
        try:
            context = context_from_copy(engine, project, images, plan["source_commit"])
            properties = runtime.database_properties(engine)
            vault.write_json(folder / "database-properties.json", properties)
            certificate_hashes = {
                item["sha256"]
                for name, item in host_inventory["files"].items()
                if name.endswith(".crt") and item["kind"] == "file"
            }
            if not {context.server_ca_sha256, context.client_cert_sha256} <= certificate_hashes:
                raise snapshot.SnapshotError("recovery_public_pki_not_preserved")

            def dump(snapshot_id, stream):
                operation.execute(
                    "source",
                    "/usr/local/bin/pg_dump",
                    [
                        "-h",
                        "/socket",
                        "-U",
                        "aegis",
                        "-d",
                        "aegis",
                        "--format=custom",
                        "--schema=public",
                        "--no-owner",
                        "--no-privileges",
                        "--lock-wait-timeout=10s",
                        "--snapshot=" + snapshot_id,
                    ],
                    output=stream,
                    maximum=snapshot.MAX_DUMP,
                )

            data_manifest = snapshot.create(
                engine,
                journal_root,
                context,
                {
                    "host-custody": json.dumps(
                        {"inventory_sha256": digest(host_inventory), "plan_sha256": digest(plan)},
                        sort_keys=True,
                    ).encode()
                },
                folder / "data",
                dump,
            )
        finally:
            engine.dispose()
        operation.remove("source")
        restored = runtime.restore(
            operation, folder / "data", digest(data_manifest), image, properties
        )
        operation.remove("restore")
        after_db = cold_archive(
            operation,
            "database-after",
            project + "_postgres-data",
            image,
            folder / "database-after.tar",
            plan,
        )
        after_journal = cold_archive(
            operation,
            "journal-after",
            project + "_journal",
            image,
            folder / "journal-after.tar",
            plan,
        )
        if before_db != after_db or before_journal != after_journal:
            raise snapshot.SnapshotError("recovery_original_bytes_changed")
        result = {
            "format": "aegis-lab-cold-recovery-result/1",
            "project": project,
            "original_database_archive": before_db,
            "original_journal_archive": before_journal,
            "physical_inventory_sha256": physical["sha256"],
            "data_manifest_sha256": digest(data_manifest),
            "database_properties_sha256": digest(properties),
            "restore": restored,
            "originals_read_only": True,
            "original_bytes_before_after_equal": True,
            "normal_operation_permitted": False,
            "synthetic": False,
        }
    finally:
        operation.cleanup()
    # No success receipt before cleanup and a final metadata/quiescence recheck.
    recheck(plan)
    vault.write_json(folder / "verified.json", {**result, "cleanup_verified": True})
    return {**result, "cleanup_verified": True}


def run(identifier, expected_hash, authorized_hash, confirm):
    if confirm is not True or authorized_hash != expected_hash:
        raise snapshot.SnapshotError("recovery_specific_authorization_required")
    runtime.check_environment()
    with lock():
        plan_folder, plan = load(identifier, expected_hash)
        if (plan_folder / "requested.json").exists() or (
            plan_folder / "requested.json"
        ).is_symlink():
            raise snapshot.SnapshotError("recovery_plan_consumed_no_replay")
        base = directories()
        for previous in (base / "operations").iterdir():
            if not (previous / "closed.json").exists():
                raise snapshot.SnapshotError("recovery_prior_cleanup_unresolved")
        recheck(plan)
        memory = next(
            int(line.split()[1]) * 1024
            for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemAvailable:")
        )
        disk = os.statvfs(base)
        if (
            memory < plan["scope"]["minimum_available_memory"]
            or disk.f_bavail * disk.f_frsize < plan["scope"]["minimum_free_disk"]
        ):
            raise snapshot.SnapshotError("recovery_host_budget_insufficient")
        run_id = uuid4().hex
        destination = base / "operations" / run_id
        snapshot._new(destination)
        begin = {
            "format": "aegis-lab-recovery-begin/1",
            "run_id": run_id,
            "plan_sha256": expected_hash,
        }
        vault.write_json(destination / "begin.json", begin)
        vault.write_json(
            plan_folder / "requested.json",
            {
                "run_id": run_id,
                "plan_sha256": expected_hash,
                "begin_sha256": digest(begin),
                "at": datetime.now(UTC).isoformat(),
            },
        )
        deadline = time.monotonic() + 900
        try:
            custody = lab_archive.capture_records(
                roots(), plan["host_records"], destination / "host-custody"
            )
            results = {
                key: profile(destination / key, key, plan, custody, deadline) for key in PROFILES
            }
            lab_archive.verify_records(destination / "host-custody", digest(custody))
            recheck(plan)
        except BaseException:
            cleaned = False
            try:
                cleanup_run(destination, digest(begin))
                cleaned = True
            except Exception:
                pass
            vault.write_json(
                destination / "failed.json",
                {
                    "status": "UNCONFIRMED",
                    "cleanup_verified": cleaned,
                    "normal_operation_permitted": False,
                },
            )
            raise
        receipt = {
            "format": "aegis-lab-recovery-receipt/1",
            "run_id": run_id,
            "plan_sha256": expected_hash,
            "status": "COLD_BACKUP_RESTORE_VERIFIED",
            "profiles": results,
            "host_custody_sha256": digest(custody),
            "cleanup_verified": True,
            "normal_operation_permitted": False,
            "new_marker": False,
            "cutover": False,
            "retention_deletion": False,
            "synthetic": False,
        }
        vault.write_json(destination / "verified.json", receipt)
        vault.write_json(
            destination / "closed.json",
            {"receipt_sha256": digest(receipt), "cleanup_verified": True},
        )
        return receipt


def cleanup_run(destination, begin_hash):
    snapshot._directory(destination)
    begin = snapshot._json(snapshot._read(destination / "begin.json", 65536))
    if digest(begin) != begin_hash or begin["run_id"] != destination.name:
        raise snapshot.SnapshotError("recovery_cleanup_begin_mismatch")
    for key in reversed(PROFILES):
        folder = destination / key
        if not folder.exists():
            continue
        marker = destination / (key + "-begin.json")
        if not marker.exists():
            # No effect is issued before this durable marker. Refuse any evidence
            # of a later request rather than guessing a partly written history.
            events = list(folder.glob("[0-9][0-9][0-9][0-9].json"))
            if len(events) > 1:
                raise snapshot.SnapshotError("recovery_cleanup_child_begin_missing")
            continue
        pin = snapshot._json(snapshot._read(marker, 65536))["begin_sha256"]
        operation = runtime.Operation.load_cleanup(folder, pin)
        if operation.plan_hash != begin["plan_sha256"]:
            raise snapshot.SnapshotError("recovery_cleanup_plan_mismatch")
        operation.cleanup()
    if not (destination / "closed.json").exists():
        vault.write_json(
            destination / "closed.json",
            {
                "status": "CLEANED_WITHOUT_VERIFIED_RESTORE",
                "cleanup_verified": True,
                "normal_operation_permitted": False,
            },
        )
    return {"status": "CLEANED", "run_id": destination.name, "normal_operation_permitted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--images", type=Path, required=True)
    execution = commands.add_parser("run")
    execution.add_argument("--plan-id", required=True)
    execution.add_argument("--plan-sha256", required=True)
    execution.add_argument("--authorized-plan-sha256", required=True)
    execution.add_argument("--confirm-original-volume-read-only", action="store_true")
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--run-id", required=True)
    cleanup.add_argument("--begin-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            images = snapshot._json(snapshot._read(args.images, 65536))
            plan = prepare(images)
            output = {
                "status": "PREPARED_NOT_AUTHORIZED",
                "plan_id": plan["id"],
                "plan_sha256": digest(plan),
                "host_files": len(plan["host_records"]),
                "host_bytes": sum(v.get("bytes", 0) for v in plan["host_records"].values()),
            }
        elif args.command == "run":
            receipt = run(
                args.plan_id,
                args.plan_sha256,
                args.authorized_plan_sha256,
                args.confirm_original_volume_read_only,
            )
            output = {
                "status": receipt["status"],
                "run_id": receipt["run_id"],
                "receipt_sha256": digest(receipt),
                "normal_operation_permitted": False,
            }
        else:
            if not re.fullmatch(r"[a-f0-9]{32}", args.run_id):
                raise snapshot.SnapshotError("recovery_cleanup_run_id")
            with lock():
                output = cleanup_run(
                    ROOT / ".local/lab-recovery/operations" / args.run_id, args.begin_sha256
                )
        print(json.dumps(output, sort_keys=True))
        return 0
    except Exception:
        print(
            json.dumps(
                {
                    "status": "UNCONFIRMED",
                    "normal_operation_permitted": False,
                    "detail": "Review private records; no sensitive diagnostics displayed.",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
