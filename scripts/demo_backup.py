"""Private default-Demo backups and restoration into a disposable offline clone.

No restore destination, Docker endpoint or Compose project is configurable. This
host-side operator tool must never be exposed as an application API.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from aegis.config import settings
from aegis.operations.backup import FORMAT, compare, inventory, retention_plan
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

ROOT = Path(__file__).resolve().parents[1]
BACKUPS = ROOT / ".local" / "backups"
LABEL = "io.aegis.recovery"


class BackupError(RuntimeError):
    pass


def docker(*args, stdin=None, stdout=subprocess.PIPE, timeout=300):
    # Use the Unix socket only, ignoring Docker contexts and remote env overrides.
    try:
        result = subprocess.run(
            ["docker", "--host", "unix:///var/run/docker.sock", *args],
            stdin=stdin,
            stdout=stdout,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        # Diagnostics stay private: PostgreSQL errors may contain row values.
        directory = ROOT / ".local" / "recovery-errors"
        private_directory(ROOT / ".local")
        private_directory(directory)
        path = directory / (uuid.uuid4().hex + ".log")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as log:
            log.write(error.stderr or b"")
        raise BackupError(f"Docker {args[0]} failed; private diagnostic {path.name}") from None
    except (subprocess.SubprocessError, OSError):
        # SQL/stdout/stderr can contain sensitive rows, never echo them.
        raise BackupError("Docker operation failed; no sensitive output displayed") from None
    return result.stdout


def psql(container, sql, database="aegis", user="aegis"):
    # Large output goes to a private temporary file rather than RAM.
    with tempfile.TemporaryFile() as output:
        docker(
            "exec",
            container,
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            user,
            "-d",
            database,
            "-c",
            "SET timezone='UTC'; SET statement_timeout='60s'; " + sql,
            stdout=output,
        )
        output.seek(0)
        for row in output:
            yield row.decode().rstrip("\n")


def source():
    containers = (
        docker(
            "ps",
            "--filter",
            "label=com.docker.compose.project=aegis",
            "--filter",
            "label=com.docker.compose.service=db",
            "-q",
        )
        .decode()
        .split()
    )
    if len(containers) != 1:
        raise BackupError("Exactly one running default Demo database is required")
    container = containers[0]
    image = docker("inspect", "--format", "{{.Image}}", container).decode().strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise BackupError("Unrecognized source image ID")
    return container, image


def private_directory(path):
    if path.is_symlink():
        raise BackupError("Symlink backup directory refused")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise BackupError("Backup directories must be owned by this user and mode0700")


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, ensure_ascii=False, sort_keys=True, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def backup():
    private_directory(ROOT / ".local")
    private_directory(BACKUPS)
    container, image = source()
    # Do not allow an operator's remote DATABASE_URL to be queried accidentally.
    url = make_url(settings().database_url)
    if (
        url.host not in {"localhost", "127.0.0.1"}
        or url.port != 18782
        or url.database != "aegis"
        or url.username != "aegis"
        or url.query
    ):
        raise BackupError("Backup requires default local Demo administrative DATABASE_URL")
    identifier = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex
    destination = BACKUPS / identifier
    private_directory(destination)
    engine = create_engine(url, isolation_level="REPEATABLE READ")
    try:
        with engine.connect() as connection, connection.begin():
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL timezone='UTC'"))
            connection.execute(text("SET LOCAL statement_timeout='60s'"))
            cluster = connection.execute(
                text("SELECT system_identifier::text FROM pg_control_system()")
            ).scalar_one()
            local_cluster = list(
                psql(container, "SELECT system_identifier::text FROM pg_control_system()")
            )
            if local_cluster != [cluster]:
                raise BackupError("Local URL and Demo container refer to different clusters")
            major = int(connection.execute(text("SHOW server_version_num")).scalar_one()) // 10000
            if major != 17:
                raise BackupError("Only PostgreSQL17 has been reviewed")
            snapshot = connection.execute(text("SELECT pg_export_snapshot()")).scalar_one()
            expected = inventory(lambda sql: connection.execute(text(sql)).scalars().yield_per(100))
            dump = destination / "database.dump"
            fd = os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                docker(
                    "exec",
                    container,
                    "pg_dump",
                    "-U",
                    "aegis",
                    "-d",
                    "aegis",
                    "--format=custom",
                    "--schema=public",
                    "--no-owner",
                    "--no-privileges",
                    "--lock-wait-timeout=10s",
                    "--snapshot=" + snapshot,
                    stdout=stream,
                )
                stream.flush()
                os.fsync(stream.fileno())
        manifest = {
            "format": FORMAT,
            "id": identifier,
            "created_at": datetime.now(UTC).isoformat(),
            "source": {
                "project": "aegis",
                "database": "aegis",
                "schema": "public",
                "image_id": image,
                "postgres_major": major,
            },
            "dump_sha256": file_hash(dump),
            "inventory": expected,
            "scope": "database_only_no_roles_secrets_redis_or_runner_journals",
        }
        write_json(destination / "manifest.json", manifest)
        return manifest
    finally:
        engine.dispose()


def load_backup(identifier):
    if not re.fullmatch(r"\d{8}T\d{6}Z-[a-f0-9]{32}", identifier):
        raise BackupError("Invalid backup ID")
    private_directory(ROOT / ".local")
    private_directory(BACKUPS)
    folder = BACKUPS / identifier
    if not folder.is_dir():
        raise BackupError("Backup not found")
    private_directory(folder)
    for name in ("manifest.json", "database.dump"):
        path = folder / name
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise BackupError("Backup files must be private regular files owned by this user")
    manifest = json.loads((folder / "manifest.json").read_text())
    if (
        manifest.get("format") != FORMAT
        or manifest.get("id") != identifier
        or manifest.get("dump_sha256") != file_hash(folder / "database.dump")
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", manifest["source"]["image_id"])
        or manifest["source"].get("postgres_major") != 17
    ):
        raise BackupError("Backup metadata or archive integrity check failed")
    return folder, manifest


def rehearse(identifier):
    folder, manifest = load_backup(identifier)
    token = uuid.uuid4().hex
    name = "aegis-recovery-" + token
    started = time.monotonic()
    created = False
    verified = False
    try:
        # Image must already exist locally. No network, ports, bind mounts,
        # persistent volumes, API, Redis, worker, scheduler or SIEM credentials.
        docker(
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            LABEL + "=" + token,
            "--network=none",
            "--read-only",
            "--security-opt=no-new-privileges:true",
            "--memory=768m",
            "--cpus=1",
            "--pids-limit=128",
            "--tmpfs",
            "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g",
            "--tmpfs",
            "/var/run/postgresql:rw,noexec,nosuid,size=16m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_DB=aegis_restore",
            manifest["source"]["image_id"],
        )
        created = True
        docker("start", name)
        for _ in range(60):
            try:
                if docker("exec", name, "cat", "/proc/1/comm", timeout=5).strip() != b"postgres":
                    time.sleep(0.25)
                    continue
                docker(
                    "exec", name, "pg_isready", "-U", "postgres", "-d", "aegis_restore", timeout=5
                )
                break
            except BackupError:
                time.sleep(0.25)
        else:
            raise BackupError("Isolated PostgreSQL did not become ready")
        # initdb creates an empty public schema; this dump recreates it. Only
        # remove that empty schema in our new offline clone, without CASCADE.
        list(psql(name, "DROP SCHEMA public", database="aegis_restore", user="postgres"))
        with (folder / "database.dump").open("rb") as stream:
            docker(
                "exec",
                "-i",
                name,
                "pg_restore",
                "-U",
                "postgres",
                "-d",
                "aegis_restore",
                "--single-transaction",
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                stdin=stream,
            )
        restored = inventory(lambda sql: psql(name, sql, database="aegis_restore", user="postgres"))
        compare(manifest["inventory"], restored)
        verified = True
    finally:
        if created:
            actual = (
                docker("inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name)
                .decode()
                .strip()
            )
            if actual != token:
                raise BackupError("Clone ownership mismatch; cleanup refused")
            docker("rm", "--force", name, timeout=30)
        # A failed cleanup produces no success receipt. The backup itself remains.
    receipt = {
        "format": FORMAT,
        "backup_id": identifier,
        "dump_sha256": manifest["dump_sha256"],
        "status": "verified" if verified else "failed",
        "verified_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "clone_removed": True,
        "network": "none",
        "application_started": False,
        "tables": len(restored["tables"]),
        "rows": sum(item["rows"] for item in restored["tables"].values()),
        "limitations": [
            "No failover or application restart tested",
            "No RPO/RTO guarantee",
            "No roles, secrets, Redis or runner journals backed up",
        ],
    }
    write_json(folder / ("verification-" + token + ".json"), receipt)
    return receipt


def plan():
    records = []
    if BACKUPS.is_symlink():
        raise BackupError("Symlink backup directory refused")
    if BACKUPS.exists():
        for folder in sorted(BACKUPS.iterdir()):
            if folder.is_dir() and (folder / "manifest.json").exists():
                _, manifest = load_backup(folder.name)
                records.append(manifest)
    return {"deletion_performed": False, "plan": retention_plan(records, datetime.now(UTC))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("create")
    verify = subparsers.add_parser("verify")
    verify.add_argument("backup_id")
    subparsers.add_parser("retention-plan")
    args = parser.parse_args()
    try:
        if args.action == "create":
            manifest = backup()
            output = {
                "id": manifest["id"],
                "dump_sha256": manifest["dump_sha256"],
                "status": "created_not_yet_verified",
                "private_path": str(BACKUPS / manifest["id"]),
            }
        elif args.action == "verify":
            output = rehearse(args.backup_id)
        else:
            output = plan()
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except BackupError as error:
        raise SystemExit(
            str(error) + "; source unchanged. No sensitive details displayed."
        ) from None
    except (ValueError, KeyError, OSError, SQLAlchemyError):
        raise SystemExit(
            "Backup/recovery failed; source unchanged. Review private files and clone status; no sensitive details displayed."
        ) from None


if __name__ == "__main__":
    main()
