"""Private default-Demo backups and restoration into a disposable offline clone.

No restore destination, Docker endpoint or Compose project is configurable. This
host-side operator tool must never be exposed as an application API.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from aegis.config import settings
from aegis.operations import reconciliation
from aegis.operations.backup import FORMAT, INVENTORY_FORMAT, compare, inventory, retention_plan
from aegis.operations.recovery import LARGE_OBJECT_FUNCTIONS
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

ROOT = Path(__file__).resolve().parents[1]
BACKUPS = ROOT / ".local" / "backups"
LABEL = "io.aegis.recovery"
APPLICATION_IMAGE = "aegis-recovery-local:0.2"


class BackupError(RuntimeError):
    pass


def docker(*args, stdin=None, stdout=subprocess.PIPE, timeout=300):
    # Use the Unix socket only, ignoring Docker contexts and remote env overrides.
    try:
        # An empty CLI config also prevents injection of global proxy credentials.
        with tempfile.TemporaryDirectory(prefix="aegis-docker-") as config:
            result = subprocess.run(
                ["docker", "--config", config, "--host", "unix:///var/run/docker.sock", *args],
                env={"PATH": os.defpath, "LANG": "C.UTF-8"},
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
    sync_directory(path)
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, ensure_ascii=False, sort_keys=True, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    sync_directory(path.parent)


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
            if connection.execute(text("SELECT current_database()")).scalar_one() != "aegis":
                raise BackupError("Unexpected source database")
            transaction_at = connection.execute(text("SELECT CURRENT_TIMESTAMP")).scalar_one()
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
            expected = inventory(
                lambda sql: connection.execute(
                    text(sql), execution_options={"yield_per": 100}
                ).scalars()
            )
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
            "created_at": transaction_at.isoformat(),
            "dump_completed_at": datetime.now(UTC).isoformat(),
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


def load_backup(identifier, *, require_current_inventory=True):
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
        require_current_inventory
        and manifest.get("inventory", {}).get("format") != INVENTORY_FORMAT
    ):
        raise BackupError(
            "Unsupported inventory format; create a new backup without rewriting history"
        )
    if (
        manifest.get("format") != FORMAT
        or manifest.get("id") != identifier
        or manifest.get("dump_sha256") != file_hash(folder / "database.dump")
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", manifest["source"]["image_id"])
        or manifest["source"].get("postgres_major") != 17
    ):
        raise BackupError("Backup metadata or archive integrity check failed")
    return folder, manifest


def remove_clone(name, token):
    names = (
        docker("ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}")
        .decode()
        .split()
    )
    if not names:
        return "observed_absent"
    if names != [name]:
        raise BackupError("Unexpected clone names; cleanup refused")
    actual = (
        docker("inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name)
        .decode()
        .strip()
    )
    if actual != token:
        raise BackupError("Clone ownership mismatch; cleanup refused")
    docker("rm", "--force", name, timeout=30)
    return "removed"


def application_image():
    image = docker("image", "inspect", APPLICATION_IMAGE, "--format", "{{.Id}}").decode().strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise BackupError("Recovery application image must already exist locally")
    return image


def prepare_reader(name, password):
    # All changes below are restricted to the newly restored disposable clone.
    # SQL containing an ephemeral secret goes over stdin, never process arguments.
    sql = f"""
    CREATE ROLE aegis_recovery LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS PASSWORD '{password}';
    ALTER ROLE aegis_recovery SET default_transaction_read_only=on;
    REVOKE ALL ON DATABASE aegis_restore FROM PUBLIC;
    GRANT CONNECT ON DATABASE aegis_restore TO aegis_recovery;
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO aegis_recovery;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO aegis_recovery;
    REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
    DO $block$
    DECLARE signature text;
    BEGIN
      FOR signature IN {LARGE_OBJECT_FUNCTIONS} LOOP
        EXECUTE 'REVOKE EXECUTE ON FUNCTION ' || signature || ' FROM PUBLIC';
      END LOOP;
    END $block$;
    """
    # password is generated internally as hex; no user-supplied SQL interpolation.
    if not re.fullmatch(r"[a-f0-9]{64}", password):
        raise BackupError("Invalid ephemeral password")
    with tempfile.TemporaryFile() as stream:
        stream.write(sql.encode())
        stream.seek(0)
        docker(
            "exec",
            "-i",
            name,
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "aegis_restore",
            stdin=stream,
        )
    hba = (
        "local all postgres trust\nlocal all all reject\n"
        "host aegis_restore aegis_recovery 127.0.0.1/32 scram-sha-256\n"
        "host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
    )
    with tempfile.TemporaryFile() as stream:
        stream.write(hba.encode())
        stream.seek(0)
        docker(
            "exec",
            "-i",
            name,
            "sh",
            "-c",
            "cat > /var/lib/postgresql/data/pg_hba.conf",
            stdin=stream,
        )
    if list(psql(name, "SELECT pg_reload_conf()", database="aegis_restore", user="postgres")) != [
        "t"
    ]:
        raise BackupError("Isolated database authentication reload failed")


def boot_application(
    database_name, token, image, intents, cleanup_state=None, *, reconciliation_hash=None
):
    if reconciliation_hash is not None and (
        not re.fullmatch(r"[a-f0-9]{64}", reconciliation_hash)
        or not re.fullmatch(r"[a-f0-9]{32}", token)
    ):
        raise BackupError("Invalid reconciliation identity/hash")
    cleanup_state = cleanup_state if cleanup_state is not None else {}
    name = "aegis-recovery-api-" + token
    password = secrets.token_hex(32)
    access_token = secrets.token_hex(32)
    prepare_reader(database_name, password)
    write_json(
        intents / (token + "-api.json"),
        {
            "clone_name": name,
            "ownership_token": token,
            "image_id": image,
            "database_clone": database_name,
            "intent_at": datetime.now(UTC).isoformat(),
        },
    )
    cleanup_state["attempted"] = True
    try:
        # Private env file survives only the create call; it is never an image layer.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as env:
            env.write("OPERATING_MODE=recovery\n")
            env.write(
                "DATABASE_URL=postgresql+psycopg://aegis_recovery:"
                + password
                + "@127.0.0.1:5432/aegis_restore\n"
            )
            env.write("RECOVERY_ACCESS_TOKEN=" + access_token + "\n")
            if reconciliation_hash is not None:
                env.write("RECOVERY_RECONCILIATION_ID=" + token + "\n")
                env.write("RECOVERY_RECONCILIATION_HASH=" + reconciliation_hash + "\n")
            env.flush()
            docker(
                "create",
                "--pull=never",
                "--name",
                name,
                "--label",
                LABEL + "=" + token,
                "--network=container:" + database_name,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--user=10001:10001",
                "--memory=384m",
                "--cpus=1",
                "--pids-limit=64",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--env-file",
                env.name,
                image,
                "uvicorn",
                "aegis.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--no-proxy-headers",
                "--no-access-log",
            )
        docker("start", name)
        with (ROOT / "scripts/recovery_probe.py").open("rb") as probe:
            result = json.loads(docker("exec", "-i", name, "python", "-", stdin=probe, timeout=120))
        if (
            result.get("review", {}).get("format") != "aegis-recovery-review/1"
            or result["review"].get("normal_operation_permitted") is not False
            or result["review"].get("reconciliation_applied")
            is not (reconciliation_hash is not None)
            or result.get("entrypoints_blocked") != 5
            or result.get("database_write_probes_denied") != 4
            or result.get("administrative_tcp_denied") is not True
            or result["review"].get("database_read_only") is not True
            or result["review"].get("quarantined") is not True
        ):
            raise BackupError("Recovery application assertions failed")
        if reconciliation_hash is not None and (
            result["review"].get("reconciliation_identity") != token
            or result["review"].get("reconciliation_plan_sha256") != reconciliation_hash
        ):
            raise BackupError("Recovery application reconciliation binding failed")
    finally:
        cleanup = remove_clone(name, token)
        cleanup_state["confirmed"] = True
        write_json(
            intents / (token + "-api-cleanup.json"),
            {
                "clone_name": name,
                "state": cleanup,
                "at": datetime.now(UTC).isoformat(),
            },
        )
    return result


def clone_reconciliation(name, token, intents):
    """A host-only transaction, always on this rehearsal's new offline clone."""
    if not re.fullmatch(r"[a-f0-9]{32}", token) or name != "aegis-recovery-" + token:
        raise BackupError("Reconciliation clone identity refused")

    def check_clone():
        projection = (
            docker(
                "inspect",
                "--format",
                "{{.HostConfig.NetworkMode}}|{{len .Mounts}}|{{len .HostConfig.Binds}}|"
                '{{len .HostConfig.PortBindings}}|{{index .Config.Labels "' + LABEL + '"}}',
                name,
            )
            .decode()
            .strip()
        )
        if projection != "none|0|0|0|" + token:
            raise BackupError(
                "Reconciliation requires the owned offline clone without mounts/ports"
            )

    def sql_json(statement):
        check_clone()
        with tempfile.TemporaryFile() as stream:
            stream.write(statement.encode())
            stream.seek(0)
            return json.loads(
                docker(
                    "exec",
                    "-i",
                    name,
                    "psql",
                    "-X",
                    "-qAt",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    "postgres",
                    "-d",
                    "aegis_restore",
                    stdin=stream,
                )
            )

    plan = sql_json(
        "BEGIN READ ONLY; SET LOCAL timezone='UTC'; SET LOCAL statement_timeout='60s'; "
        + reconciliation.plan_sql()
        + "; COMMIT;"
    )
    if plan.get("format") != reconciliation.FORMAT:
        raise BackupError("Unsupported reconciliation plan")
    write_json(intents / (token + "-reconciliation-plan.json"), plan)
    if any(plan["blockers"].values()):
        raise BackupError("Recovered work requires manual review; reconciliation not applied")
    result = sql_json(reconciliation.apply_sql(plan["snapshot_sha256"], token))
    if (
        result.get("format") != reconciliation.FORMAT
        or result.get("plan_sha256") != plan["snapshot_sha256"]
        or result.get("reconciliation_applied") is not True
        or result.get("normal_operation_permitted") is not False
        or result.get("external_cleanup_performed") is not False
    ):
        raise BackupError("Reconciliation assertions failed")
    write_json(intents / (token + "-reconciliation-applied.json"), result)
    return result


def compare_reconciled(original, reconciled):
    """Only explicit operational tables may change; SQL also checks columns."""
    if (
        original["migration"] != reconciled["migration"]
        or original["structure"] != reconciled["structure"]
        or original["tables"].keys() != reconciled["tables"].keys()
    ):
        raise BackupError("Reconciliation changed protected schema")
    allowed = set(reconciliation.MUTABLE) | {"sessions", "audit_events", "execution_steps"}
    for table in original["tables"].keys() - allowed:
        if original["tables"][table] != reconciled["tables"][table]:
            raise BackupError("Reconciliation changed protected history")


def rehearse(identifier, *, application=False, reconcile_demo=False):
    if reconcile_demo and not application:
        raise BackupError("Reconciliation requires quarantined application verification")
    folder, manifest = load_backup(identifier)
    image = application_image() if application else None
    token = uuid.uuid4().hex
    name = "aegis-recovery-" + token
    started = time.monotonic()
    attempted = False
    verified = False
    application_cleanup = {"attempted": False, "confirmed": False}
    intents = ROOT / ".local" / "recovery-intents"
    private_directory(intents)
    write_json(
        intents / (token + ".json"),
        {
            "clone_name": name,
            "ownership_token": token,
            "backup_id": identifier,
            "image_id": manifest["source"]["image_id"],
            "intent_at": datetime.now(UTC).isoformat(),
        },
    )
    try:
        # Image must already exist locally. No network, ports, bind mounts,
        # persistent volumes, API, Redis, worker, scheduler or SIEM credentials.
        attempted = True
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
        if reconcile_demo:
            reconciliation_result = clone_reconciliation(name, token, intents)
            reconciled = inventory(
                lambda sql: psql(name, sql, database="aegis_restore", user="postgres")
            )
            compare_reconciled(restored, reconciled)
            restored = reconciled
        if application:
            if reconcile_demo:
                application_result = boot_application(
                    name,
                    token,
                    image,
                    intents,
                    application_cleanup,
                    reconciliation_hash=reconciliation_result["plan_sha256"],
                )
            else:
                application_result = boot_application(
                    name, token, image, intents, application_cleanup
                )
            # ACLs changed in the clone, but no restored rows/structure may change.
            after = inventory(
                lambda sql: psql(name, sql, database="aegis_restore", user="postgres")
            )
            compare(restored, after)
        verified = True
    finally:
        if attempted:
            if application_cleanup["attempted"] and not application_cleanup["confirmed"]:
                cleanup = "retained_api_cleanup_unconfirmed"
            else:
                cleanup = remove_clone(name, token)
            write_json(
                intents / (token + "-cleanup.json"),
                {
                    "clone_name": name,
                    "state": cleanup,
                    "at": datetime.now(UTC).isoformat(),
                },
            )
        # A failed cleanup produces no success receipt. The backup itself remains.
    receipt = {
        "format": FORMAT,
        "inventory_format": INVENTORY_FORMAT,
        "structure_comparison": manifest["inventory"].get("structure_comparison"),
        "backup_id": identifier,
        "dump_sha256": manifest["dump_sha256"],
        "status": "verified" if verified else "failed",
        "verified_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "clone_removed": True,
        "network": "none",
        "application_started": application,
        "tables": len(restored["tables"]),
        "rows": sum(item["rows"] for item in restored["tables"].values()),
        "limitations": [
            "No failover or application restart tested",
            "No RPO/RTO guarantee",
            "No roles, secrets, Redis or runner journals backed up",
        ],
    }
    if application:
        receipt.update(application_image_id=image, application=application_result)
        receipt["limitations"][0] = (
            "Quarantined API only; no normal operation, reconciliation or failover"
        )
    prefix = "application-verification-" if application else "verification-"
    if reconcile_demo:
        receipt.update(
            reconciliation=reconciliation_result,
            original_inventory_matched=True,
            protected_history_unchanged=True,
            snapshot_rows=sum(item["rows"] for item in manifest["inventory"]["tables"].values()),
        )
        receipt["limitations"][0] = (
            "Offline Demo reconciliation and quarantined API only; no normal restart or failover"
        )
        prefix = "demo-reconciliation-verification-"
    write_json(folder / (prefix + token + ".json"), receipt)
    return receipt


def plan():
    records = []
    unsupported = set()
    if BACKUPS.is_symlink():
        raise BackupError("Symlink backup directory refused")
    if BACKUPS.exists():
        for folder in sorted(BACKUPS.iterdir()):
            if folder.is_dir() and (folder / "manifest.json").exists():
                _, manifest = load_backup(folder.name, require_current_inventory=False)
                records.append(manifest)
                if manifest.get("inventory", {}).get("format") != INVENTORY_FORMAT:
                    unsupported.add(manifest["id"])
    result = retention_plan(records, datetime.now(UTC))
    for entry in result:
        if entry["id"] in unsupported:
            entry.update(action="keep", reason="unsupported_inventory_preserved")
    return {"deletion_performed": False, "plan": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("create")
    verify = subparsers.add_parser("verify")
    verify.add_argument("backup_id")
    application = subparsers.add_parser("verify-application")
    application.add_argument("backup_id")
    reconcile = subparsers.add_parser("reconcile-demo")
    reconcile.add_argument("backup_id")
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
        elif args.action == "verify-application":
            output = rehearse(args.backup_id, application=True)
        elif args.action == "reconcile-demo":
            output = rehearse(args.backup_id, application=True, reconcile_demo=True)
        else:
            output = plan()
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except BackupError as error:
        raise SystemExit(
            str(error) + "; source unchanged. No sensitive details displayed."
        ) from None
    except (ValueError, KeyError, TypeError, AttributeError, OSError, SQLAlchemyError):
        raise SystemExit(
            "Backup/recovery failed; source unchanged. Review private files and clone status; no sensitive details displayed."
        ) from None


if __name__ == "__main__":
    main()
