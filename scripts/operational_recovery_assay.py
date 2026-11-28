"""Approved two-VM Demo rehearsal; accepts no human backup or original volume.

prepare builds dedicated images only; wait binds later human approval to them.
source creates a synthetic origin and exports its fenced snapshot plus images.
destination consumes only that authenticated same-run artifact, on another VM.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import demo_backup as native
import httpx
import pyrage
from aegis.operations import operational_recovery as contract
from aegis.operations import reconciliation, vault
from aegis.operations.backup import FORMAT, compare, inventory
from aegis.operations.recovery import required_revision
from recovery_cycle_runtime import REDIS_COMMAND

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".local/recovery29-private"
PUBLIC = ROOT / ".local/recovery29-public"
TRANSFER = ROOT / ".local/recovery29-transfer"


def now():
    return datetime.now(UTC).isoformat()


def context():
    values = [
        os.environ.get(key, "")
        for key in (
            "GITHUB_RUN_ID",
            "GITHUB_ACTOR",
            "GITHUB_SHA",
        )
    ]
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "Buraddomoon/AEGIS"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or sys.platform != "linux"
        or not re.fullmatch(r"[1-9][0-9]{5,19}", values[0])
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", values[1])
        or not re.fullmatch(r"[a-f0-9]{40}", values[2])
    ):
        raise ValueError("Fresh manual main hosted run required")
    for folder in (ROOT / ".local", PRIVATE, PUBLIC, TRANSFER):
        native.private_directory(folder)
    return values


def host():
    return contract.fingerprint(Path("/proc/sys/kernel/random/boot_id").read_text().strip())


def image(reference):
    value = json.loads(
        native.docker(
            "image",
            "inspect",
            reference,
            "--format",
            '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}}}',
        )
    )
    return contract.image(value)


def output(key, value):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(key + "=" + value + "\n")


@contextmanager
def incoming(path, maximum):
    # download-artifact restores ordinary modes. Establish privacy on the same
    # no-follow FD, after checking ownership/type, never chmod a supplied link.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or not 0 < info.st_size <= maximum
        ):
            raise ValueError("Incoming artifact file refused")
        os.fchmod(stream.fileno(), 0o600)
        yield stream


def load_plan():
    plan = json.loads((PUBLIC / "proposal.json").read_text())
    contract.validate_plan(plan)
    run, actor, commit = context()
    if (plan["workflow_run"], plan["approved_by"], plan["source_commit"]) != (run, actor, commit):
        raise ValueError("Plan/source identity drift")
    return plan


def prepare():
    run, actor, commit = context()
    recipient = str(pyrage.x25519.Recipient.from_str(os.environ["RECOVERY29_RECIPIENT"]))
    tag = "aegis-recovery29:" + run + "-" + commit[:12]
    native.docker("pull", "postgres:17-alpine", timeout=240)
    native.docker("pull", "redis:8-alpine", timeout=240)
    native.docker("build", "--pull=false", "-t", tag, str(ROOT), timeout=900)
    prepared_at = datetime.now(UTC)
    plan = {
        "format": contract.FORMAT,
        "profile": contract.PROFILE,
        "workflow_run": run,
        "source_commit": commit,
        "approved_by": actor,
        "prepared_at": prepared_at.isoformat(),
        "expires_at": (prepared_at + timedelta(minutes=45)).isoformat(),
        "recipient": recipient,
        "source_host": host(),
        "schema": required_revision(),
        "destination": "fresh-ubuntu-24.04-job-destination-same-workflow",
        "secret_name": "AEGIS_RECOVERY29_" + run,
        "images": {
            "application": image(tag),
            "postgres": image("postgres:17-alpine"),
            "redis": image("redis:8-alpine"),
        },
        "budget": {
            "source_normal_api": 1,
            "source_worker": 0,
            "destination_restores": 3,
            "destination_runs": 1,
            "destination_synthetic_tests": 4,
            "originals": False,
            "external_targets": False,
            "persistent_service": False,
            "encrypted_artifact_days": 1,
            "maximum_bytes": contract.MAX_BYTES,
        },
    }
    contract.validate_plan(plan)
    native.write_json(PUBLIC / "proposal.json", plan)
    output("plan_sha", contract.fingerprint(plan))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
        stream.write(
            "# Recovery29 exact proposal\n\n"
            + contract.fingerprint(plan)
            + "\n\nOnly fresh synthetic origin and destination VMs. No originals.\n\n```text\n"
            + contract.approval_text(plan)
            + "\n```\n"
        )
    print(
        json.dumps(
            {"status": "PREPARED_NO_RUNTIME_CONTAINERS", "plan_sha": contract.fingerprint(plan)}
        )
    )


def comments():
    with httpx.Client(
        timeout=15,
        trust_env=False,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        },
    ) as client:
        result = []
        for page in range(1, 21):
            response = client.get(
                "https://api.github.com/repos/Buraddomoon/AEGIS/issues/121/comments",
                params={"per_page": 100, "page": page},
            )
            response.raise_for_status()
            batch = response.json()
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise ValueError("Approval history bound exceeded")


def wait():
    plan = load_plan()
    while datetime.now(UTC) < contract.timestamp(plan["expires_at"]) - timedelta(minutes=20):
        for comment in comments():
            if contract.approved(comment, plan, datetime.now(UTC)):
                native.write_json(PRIVATE / "authorization.json", {"comment_id": comment["id"]})
                print("EXACT_PACKAGE_APPROVED")
                return
        time.sleep(20)
    raise ValueError("Approval expired without source effects")


def authorized(plan):
    receipt = json.loads((PRIVATE / "authorization.json").read_text())
    if not any(
        c["id"] == receipt["comment_id"] and contract.approved(c, plan, datetime.now(UTC))
        for c in comments()
    ):
        raise ValueError("Current exact approval absent")


def create(name, token, image_id, command, *, network, environment=None, memory="384m", tmpfs=()):
    native.write_json(
        PRIVATE / (name + "-intent.json"),
        {
            "name": name,
            "token": token,
            "image_id": image_id,
            "intent_at": now(),
        },
    )
    with tempfile.NamedTemporaryFile(mode="w") as env:
        for key, value in (environment or {}).items():
            if "\n" in value:
                raise ValueError("Environment newline refused")
            env.write(key + "=" + value + "\n")
        env.flush()
        native.docker(
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            native.LABEL + "=" + token,
            "--network=" + network,
            "--read-only",
            "--security-opt=no-new-privileges:true",
            "--cpus=1",
            "--memory=" + memory,
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            *[arg for mount in tmpfs for arg in ("--tmpfs", mount)],
            "--env-file",
            env.name,
            "-i",
            image_id,
            *command,
        )


def remove(name, token):
    result = native.remove_clone(name, token)
    native.write_json(PRIVATE / (name + "-cleanup.json"), {"state": result, "at": now()})


def assert_absent():
    if native.docker(
        "ps", "-a", "--filter", "label=" + native.LABEL, "--format", "{{.Names}}"
    ).strip():
        raise ValueError("Recovery resource remains; no success receipt")


def query(name, sql):
    return native.psql(name, sql, database="aegis_restore", user="postgres")


def program_input(program, *args, timeout=180):
    with tempfile.TemporaryFile() as stream:
        stream.write(program.encode())
        stream.seek(0)
        return native.docker(*args, stdin=stream, timeout=timeout)


def fixture_program(app_password, account_password):
    # Reuse the nonempty historical fixture: READY/FAILED/PENDING reports,
    # queued work, old sessions, reservation and active schedule/grant.
    fixture = (ROOT / "tests/recovery_report_fixtures.py").read_text()
    return (
        fixture
        + f"""
from alembic import command
from alembic.config import Config
from aegis import db as database
from aegis.seed import seed
from aegis.security import hasher
from aegis.operations.runtime_grants import RUNTIME_PERMISSIONS
from sqlalchemy import text
command.upgrade(Config("alembic.ini"), "head")
with database.session_factory()() as db:
    seed(db)
    create_report_fixture(db)
    db.add(User(username="recovery29-origin", role="administrator", password_hash=hasher.hash({account_password!r})))
    db.commit()
with database.engine().begin() as c:
    c.execute(text("CREATE ROLE aegis_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{app_password}'"))
    c.execute(text("GRANT CONNECT ON DATABASE aegis_restore TO aegis_app"))
    for statement in RUNTIME_PERMISSIONS:
        c.execute(text(statement))
print("SYNTHETIC_ORIGIN_INITIALIZED")
"""
    )


def source_probe(password):
    return f"""
import httpx,time
with httpx.Client(base_url="http://127.0.0.1:8080",trust_env=False,timeout=3) as c:
    for attempt in range(80):
        try:
            if c.get("/api/v1/health/ready").status_code==200: break
        except httpx.HTTPError: pass
        time.sleep(.25)
    else: raise ValueError("Source API unavailable")
    assert c.get("/").status_code==200
    r=c.post("/api/v1/auth/login",json={{"username":"recovery29-origin","password":{password!r}}},headers={{"x-aegis-request":"browser"}})
    assert r.status_code==200
    c.headers["x-csrf-token"]=r.json()["csrf_token"]
    assert c.get("/api/v1/coverage").status_code==200
    assert c.post("/api/v1/auth/logout").status_code==204
print("SOURCE_NORMAL_LOGIN_AND_SPA_VERIFIED_NO_WORKER")
"""


def source():
    plan = load_plan()
    authorized(plan)
    if host() != plan["source_host"]:
        raise ValueError("Prepared source host changed")
    native.write_json(PRIVATE / "source-attempt.json", {"at": now()})  # exclusive one-attempt fence
    assert_absent()
    token = uuid4().hex
    db = "aegis-recovery-" + token
    helper = "aegis-recovery29-helper-" + token
    api = "aegis-recovery29-api-" + token
    redis = "aegis-recovery29-redis-" + token
    images = {key: value["id"] for key, value in plan["images"].items()}
    for value in plan["images"].values():
        if image(value["id"]) != value:
            raise ValueError("Prepared image drift")
    password, app_password, redis_password = (secrets.token_hex(32) for _ in range(3))
    owned = []
    folder = PRIVATE / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + token)
    native.private_directory(folder)
    try:
        owned.append(db)
        # PostgreSQL entrypoint needs its normal root capabilities for tmpfs setup.
        native.write_json(PRIVATE / (db + "-intent.json"), {"token": token, "at": now()})
        native.docker(
            "create",
            "--pull=never",
            "--name",
            db,
            "--label",
            native.LABEL + "=" + token,
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
            images["postgres"],
        )
        native.docker("start", db)
        for _ in range(80):
            try:
                if native.docker("exec", db, "cat", "/proc/1/comm").strip() == b"postgres":
                    list(query(db, "SELECT 1"))
                    break
            except native.BackupError:
                pass
            time.sleep(0.25)
        else:
            raise ValueError("Origin PostgreSQL unavailable")
        owned.append(helper)
        create(
            helper,
            token,
            images["application"],
            ["python", "-"],
            network="container:" + db,
            environment={
                "DATABASE_URL": "postgresql+psycopg://postgres@127.0.0.1:5432/aegis_restore"
            },
            memory="512m",
        )
        program_input(fixture_program(app_password, password), "start", "-a", "-i", helper)
        remove(helper, token)
        owned.remove(helper)
        native.configure_clone_hba(db, "aegis_app")
        owned.append(redis)
        create(
            redis,
            token,
            images["redis"],
            ["/bin/sh", "-c", REDIS_COMMAND],
            network="container:" + db,
            memory="128m",
            environment={"RECOVERY_REDIS_PASSWORD": redis_password},
            tmpfs=("/data:rw,noexec,nosuid,size=16m",),
        )
        native.docker("start", redis)
        owned.append(api)
        create(
            api,
            token,
            images["application"],
            [
                "uvicorn",
                "aegis.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--no-proxy-headers",
                "--no-access-log",
            ],
            network="container:" + db,
            environment={
                "OPERATING_MODE": "normal",
                "PUBLIC_ORIGIN": "http://127.0.0.1:8080",
                "DATABASE_URL": "postgresql+psycopg://aegis_app:"
                + app_password
                + "@127.0.0.1:5432/aegis_restore",
                "REDIS_URL": "redis://:" + redis_password + "@127.0.0.1:6379/0",
            },
        )
        native.docker("start", api)
        program_input(source_probe(password), "exec", "-i", api, "python", "-", timeout=90)
        fenced_at = now()
        native.docker("stop", "--time=10", api, timeout=25)
        remove(api, token)
        owned.remove(api)
        remove(redis, token)
        owned.remove(redis)
        snapshot_at = now()
        expected = inventory(lambda statement: query(db, statement))
        if expected["migration"] != [plan["schema"]]:
            raise ValueError("Origin schema mismatch")
        source_plan = native.clone_json(db, token, reconciliation.plan_sql())
        if any(source_plan["blockers"].values()) or not all(
            source_plan["counts"][key] > 0
            for key in (
                "sessions",
                "active_users",
                "pending_demo_runs",
                "resumable_schedules",
                "unrevoked_grants",
                "pending_scheduled_reports",
            )
        ):
            raise ValueError("Nonempty recovery fences not present")
        with (folder / "database.dump").open("xb") as stream:
            native.docker(
                "exec",
                db,
                "pg_dump",
                "-U",
                "postgres",
                "-d",
                "aegis_restore",
                "--format=custom",
                "--schema=public",
                "--no-owner",
                "--no-privileges",
                stdout=stream,
            )
            stream.flush()
            os.fsync(stream.fileno())
        (folder / "database.dump").chmod(0o600)
        compare(expected, inventory(lambda statement: query(db, statement)))
        native.write_json(
            folder / "manifest.json",
            {
                "format": FORMAT,
                "id": folder.name,
                "created_at": snapshot_at,
                "source": {"postgres_major": 17, "image_id": images["postgres"]},
                "dump_sha256": native.file_hash(folder / "database.dump"),
                "inventory": expected,
            },
        )
    finally:
        for name in reversed(owned):
            remove(name, token)
    assert_absent()
    with (folder / "images.tar").open("xb") as stream:
        native.docker("image", "save", *images.values(), stdout=stream, timeout=240)
    (folder / "images.tar").chmod(0o600)
    native.write_json(
        folder / "bundle.json",
        {
            "format": contract.FORMAT,
            "synthetic": True,
            "plan_sha": contract.fingerprint(plan),
            "source_fenced_at": fenced_at,
            "snapshot_at": snapshot_at,
            "files": {
                name: native.file_hash(folder / name)
                for name in ("manifest.json", "database.dump", "images.tar")
            },
        },
    )
    package = PRIVATE / "transport.tar.gz"
    with tarfile.open(package, "x:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(contract.FILES):
            archive.add(folder / name, arcname=name, recursive=False)
    package.chmod(0o600)
    if package.stat().st_size > contract.MAX_BYTES:
        raise ValueError("Transport exceeds approved size")
    with package.open("rb") as source_file, (TRANSFER / "bundle.age").open("xb") as encrypted:
        pyrage.encrypt_io(
            source_file, encrypted, [pyrage.x25519.Recipient.from_str(plan["recipient"])]
        )
    (TRANSFER / "bundle.age").chmod(0o600)
    envelope = {
        "format": contract.FORMAT,
        "synthetic": True,
        "source_cleaned": True,
        "plan": plan,
        "ciphertext_sha256": native.file_hash(TRANSFER / "bundle.age"),
        "ciphertext_bytes": (TRANSFER / "bundle.age").stat().st_size,
    }
    native.write_json(TRANSFER / "envelope.json", envelope)
    native.write_json(
        PUBLIC / "source.json",
        {
            "status": "SYNTHETIC_SOURCE_FENCED_EXPORTED_CLEANED",
            "plan_sha": contract.fingerprint(plan),
            "source_host": host(),
            "tables": len(expected["tables"]),
            "rows": sum(t["rows"] for t in expected["tables"].values()),
            "source_normal_login_verified": True,
            "source_workers": 0,
        },
    )
    output("envelope_sha", contract.fingerprint(envelope))
    print("SOURCE_EXPORTED_ENCRYPTED_AND_CLEANED")


class LimitedWriter:
    def __init__(self, stream):
        self.stream, self.count = stream, 0

    def write(self, value):
        self.count += len(value)
        if self.count > contract.MAX_BYTES:
            raise ValueError("Decrypted size exceeded")
        return self.stream.write(value)

    def flush(self):
        self.stream.flush()


def destination():
    run, _, commit = context()
    with incoming(TRANSFER / "envelope.json", 1024 * 1024) as stream:
        envelope = json.load(stream)
    contract.validate_envelope(
        envelope,
        expected_hash=os.environ["RECOVERY29_ENVELOPE_SHA"],
        plan_hash=os.environ["RECOVERY29_PLAN_SHA"],
        run=run,
        source_commit=commit,
        host=host(),
    )
    plan = envelope["plan"]
    identity = pyrage.x25519.Identity.from_str(os.environ.pop("RECOVERY29_IDENTITY"))
    if str(identity.to_public()) != plan["recipient"] or datetime.now(UTC) >= contract.timestamp(
        plan["expires_at"]
    ):
        raise ValueError("Destination key or deadline refused")
    native.write_json(PRIVATE / "destination-attempt.json", {"at": now()})
    assert_absent()
    archive_path = PRIVATE / "authenticated.tar.gz"
    cipher = TRANSFER / "bundle.age"
    with incoming(cipher, contract.MAX_BYTES) as stream:
        if (
            os.fstat(stream.fileno()).st_size != envelope["ciphertext_bytes"]
            or vault.hash_stream(stream) != envelope["ciphertext_sha256"]
        ):
            raise ValueError("Ciphertext integrity mismatch")
        stream.seek(0)
        with archive_path.open("xb") as plaintext:
            pyrage.decrypt_io(stream, LimitedWriter(plaintext), [identity])
        stream.seek(0)
        if vault.hash_stream(stream) != envelope["ciphertext_sha256"]:
            raise ValueError("Ciphertext changed during authentication")
    archive_path.chmod(0o600)
    identity = None
    folder = PRIVATE / "authenticated"
    native.private_directory(folder)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = []
        for member in archive:
            members.append(member)
            if len(members) > len(contract.FILES):
                raise ValueError("Extra archive entry")
        contract.validate_members(members)
        for member in members:
            with (
                archive.extractfile(member) as entry_stream,
                (folder / member.name).open("xb") as outgoing,
            ):
                shutil.copyfileobj(entry_stream, outgoing, 1024 * 1024)
            (folder / member.name).chmod(0o600)
    bundle = json.loads((folder / "bundle.json").read_text())
    if (
        bundle["format"] != contract.FORMAT
        or bundle["synthetic"] is not True
        or bundle["plan_sha"] != contract.fingerprint(plan)
    ):
        raise ValueError("Decrypted identity mismatch")
    if set(bundle["files"]) != contract.FILES - {"bundle.json"}:
        raise ValueError("Decrypted file inventory mismatch")
    for name, expected_hash in bundle["files"].items():
        if native.file_hash(folder / name) != expected_hash:
            raise ValueError("Decrypted file drift")
    # Image archives were saved by ID, with no tag to overwrite on the new host.
    with vault.private_file(folder / "images.tar", maximum=contract.MAX_BYTES) as stream:
        if vault.hash_stream(stream) != bundle["files"]["images.tar"]:
            raise ValueError("Image archive FD drift")
        stream.seek(0)
        with tarfile.open(fileobj=stream) as archive:
            manifest = json.load(archive.extractfile("manifest.json"))
            if len(manifest) != 3 or any(item.get("RepoTags") for item in manifest):
                raise ValueError("Tagged image transport refused")
            ids = {
                "sha256:" + hashlib.sha256(archive.extractfile(item["Config"]).read()).hexdigest()
                for item in manifest
            }
            if ids != {item["id"] for item in plan["images"].values()}:
                raise ValueError("Image archive identity mismatch")
        stream.seek(0)
        native.docker("image", "load", stdin=stream, timeout=240)
    for value in plan["images"].values():
        if image(value["id"]) != value:
            raise ValueError("Loaded image drift")
    # Only a previously absent tag may be introduced for the legacy closed selector.
    existing = (
        native.docker("image", "ls", "--no-trunc", "--format", "{{.ID}}", "redis:8-alpine")
        .decode()
        .split()
    )
    redis_id = plan["images"]["redis"]["id"]
    if existing and existing != [redis_id]:
        raise ValueError("Destination Redis tag conflict; preserved")
    if not existing:
        native.docker("image", "tag", redis_id, "redis:8-alpine")
    native.APPLICATION_IMAGE = plan["images"]["application"]["id"]
    backup_id = json.loads((folder / "manifest.json").read_text())["id"]
    quarantine = native.rehearse(backup_id, application=True, _archive_folder=folder)
    assert_absent()
    original_reconcile = native.clone_reconciliation

    class ExpectedRollback(Exception):
        pass

    def rollback(name, token, intents):
        before = inventory(lambda statement: query(name, statement))
        current = native.clone_json(name, token, reconciliation.plan_sql())
        stale = "0" * 64 if current["snapshot_sha256"] != "0" * 64 else "1" * 64
        try:
            native.clone_json(name, token, reconciliation.apply_sql(stale, token))
        except native.BackupError:
            compare(before, inventory(lambda statement: query(name, statement)))
            raise ExpectedRollback() from None
        raise ValueError("Stale reconciliation unexpectedly applied")

    native.clone_reconciliation = rollback
    try:
        try:
            native.rehearse(
                backup_id, application=True, reconcile_demo=True, _archive_folder=folder
            )
        except ExpectedRollback:
            pass
        else:
            raise ValueError("Rollback exercise did not refuse")
    finally:
        native.clone_reconciliation = original_reconcile
    assert_absent()
    docker = native.docker
    accepted = []

    def observed_docker(*args, **kwargs):
        result = docker(*args, **kwargs)
        if "aegis.operations.recovery_cycle_probe" in args:
            accepted.append(now())
        return result

    native.docker = observed_docker
    try:
        cycle = native.rehearse(
            backup_id,
            application=True,
            reconcile_demo=True,
            demo_cycle=True,
            _archive_folder=folder,
        )
    finally:
        native.docker = docker
    assert_absent()
    if len(accepted) != 1 or not cycle["demo_cycle"]["closure"]["historical_rows_unchanged"]:
        raise ValueError("Destination flow unconfirmed")
    proof = {
        "format": contract.FORMAT,
        "status": "TWO_HOST_DEMO_RECOVERY_VERIFIED_CLEANED",
        "synthetic": True,
        "plan_sha": contract.fingerprint(plan),
        "source_commit": commit,
        "source_host": plan["source_host"],
        "destination_host": host(),
        "images": plan["images"],
        "schema": plan["schema"],
        "snapshot_rows": cycle["snapshot_rows"],
        "tables": cycle["tables"],
        "quarantine_verified": quarantine["application"]["review"]["quarantined"],
        "rollback_without_row_change": True,
        "old_work_not_replayed": True,
        "destination_runs": 1,
        "destination_synthetic_tests": 4,
        "protected_history_unchanged": True,
        "normal_destination_flow_verified": True,
        "runtime_credentials_fresh": True,
        "cleanup_confirmed": True,
        **contract.timing(bundle["source_fenced_at"], bundle["snapshot_at"], accepted[0]),
        "limits": [
            "Synthetic fixture origin; no human backup or original service cutover",
            "Cold quiesced snapshot; no unplanned-loss RPO or SLA guarantee",
            "Hosted provider UTC clocks; no external endpoint/TLS or continuous service",
        ],
    }
    # Authenticated plaintext and key are not retained as transport artifacts.
    for path in folder.iterdir():
        path.unlink()
    folder.rmdir()
    archive_path.unlink()
    native.write_json(PUBLIC / "destination.json", proof)
    print(json.dumps(proof))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "wait", "source", "destination"))
    action = parser.parse_args().action
    try:
        globals()[action]()
    except Exception as error:
        # Raw database/build errors stay in host-only private diagnostics.
        if PUBLIC.is_dir() and not (PUBLIC / (action + "-failure.json")).exists():
            native.write_json(
                PUBLIC / (action + "-failure.json"),
                {
                    "status": "FAILED_NOT_VERIFIED",
                    "stage": action,
                    "error_class": type(error).__name__,
                },
            )
        raise SystemExit(
            "Recovery29 stage failed; private diagnostics retained, no success claim"
        ) from None


if __name__ == "__main__":
    main()
