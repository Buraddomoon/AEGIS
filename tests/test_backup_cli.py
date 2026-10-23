"""CLI safety checks; Docker mutations are mocked here, actual rehearsal is opt-in."""

import importlib.util
import json
import os
from pathlib import Path

import pytest
from aegis.operations.backup import FORMAT, INVENTORY_FORMAT

SPEC = importlib.util.spec_from_file_location(
    "demo_backup", Path(__file__).resolve().parents[1] / "scripts/demo_backup.py"
)
backup_cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup_cli)
ID = "20261022T210000Z-" + "a" * 32


@pytest.fixture
def archive(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_cli, "ROOT", tmp_path)
    monkeypatch.setattr(backup_cli, "BACKUPS", tmp_path / ".local/backups")
    backup_cli.private_directory(tmp_path / ".local")
    backup_cli.private_directory(backup_cli.BACKUPS)
    folder = backup_cli.BACKUPS / ID
    backup_cli.private_directory(folder)
    dump = folder / "database.dump"
    fd = os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(b"PGDMP-test-fixture-never-restored")
    manifest = {
        "format": FORMAT,
        "id": ID,
        "created_at": "2026-10-22T21:00:00+00:00",
        "dump_sha256": backup_cli.file_hash(dump),
        "source": {"image_id": "sha256:" + "b" * 64, "postgres_major": 17},
        "inventory": {
            "format": INVENTORY_FORMAT,
            "tables": {"test": {"rows": 4}},
            "migration": ["test"],
        },
    }
    backup_cli.write_json(folder / "manifest.json", manifest)
    return folder, manifest


@pytest.mark.parametrize("value", ["../../etc", "", ID + "/..", "--other-database"])
def test_invalid_backup_id_rejected_before_docker(value, monkeypatch):
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: pytest.fail("Docker called"))
    with pytest.raises(backup_cli.BackupError, match="Invalid"):
        backup_cli.load_backup(value)


@pytest.mark.parametrize("mutation", ["tamper", "public", "symlink", "manifest-id"])
def test_unsafe_or_changed_archive_never_starts_container(archive, monkeypatch, mutation):
    folder, manifest = archive
    if mutation == "tamper":
        (folder / "database.dump").write_bytes(b"changed")
    elif mutation == "public":
        (folder / "database.dump").chmod(0o644)
    elif mutation == "manifest-id":
        manifest["id"] = "other"
        (folder / "manifest.json").write_text(json.dumps(manifest))
    else:
        (folder / "database.dump").unlink()
        (folder / "database.dump").symlink_to(folder / "manifest.json")
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: pytest.fail("Docker called"))
    with pytest.raises(backup_cli.BackupError):
        backup_cli.rehearse(ID)


@pytest.mark.parametrize(
    "fail_stage",
    [
        None,
        "create-before",
        "create-after",
        "start",
        "restore",
        "inventory",
        "cleanup",
        "ownership",
    ],
)
def test_rehearsal_is_offline_owned_and_never_emits_false_success(archive, monkeypatch, fail_stage):
    folder, manifest = archive
    calls = []
    owned = None
    exists = False
    clone_name = None

    def docker(*args, **kwargs):
        nonlocal owned, exists, clone_name
        calls.append(args)
        if args[0] == "create":
            if fail_stage == "create-before":
                raise backup_cli.BackupError("Injected failure before create")
            exists = True
            clone_name = args[args.index("--name") + 1]
            owned = args[args.index("--label") + 1].split("=", 1)[1]
            if fail_stage == "create-after":
                raise backup_cli.BackupError("Injected ambiguous create response")
        if args[0] == "ps":
            return clone_name.encode() if exists else b""
        if args[0] == "inspect":
            return ("wrong" if fail_stage == "ownership" else owned).encode()
        if args[0] == "exec" and "cat" in args:
            return b"postgres\n"
        if (
            (fail_stage == "restore" and "pg_restore" in args)
            or (fail_stage == "start" and args[0] == "start")
            or (fail_stage == "cleanup" and args[0] == "rm")
        ):
            raise backup_cli.BackupError("Injected failure")
        return b""

    def restored(*args, **kwargs):
        if fail_stage == "inventory":
            raise ValueError("Different data")
        return manifest["inventory"]

    monkeypatch.setattr(backup_cli, "docker", docker)
    monkeypatch.setattr(backup_cli, "inventory", restored)
    if fail_stage:
        with pytest.raises((backup_cli.BackupError, ValueError)):
            backup_cli.rehearse(ID)
        assert not list(folder.glob("verification-*.json"))
    else:
        result = backup_cli.rehearse(ID)
        assert result["status"] == "verified" and result["clone_removed"]
        assert result["network"] == "none" and not result["application_started"]
        assert len(list(folder.glob("verification-*.json"))) == 1
    create = calls[0]
    assert create[0] == "create"
    assert "--network=none" in create and "--read-only" in create
    assert "--pull=never" in create
    assert create[-1] == manifest["source"]["image_id"]
    assert not any(arg in create for arg in ("-p", "--publish", "--volume", "-v", "--mount"))
    removed = [c for c in calls if c[0] == "rm"]
    assert bool(removed) == (fail_stage not in {"ownership", "create-before"})
    assert all(c[-1].startswith("aegis-recovery-") for c in removed)
    assert (folder / "database.dump").is_file()


def test_private_json_is_exclusive_and_retention_never_deletes(archive):
    folder, manifest = archive
    with pytest.raises(FileExistsError):
        backup_cli.write_json(folder / "manifest.json", {})
    result = backup_cli.plan()
    assert not result["deletion_performed"]
    assert result["plan"][0]["id"] == ID
    assert (folder / "database.dump").is_file()


def test_symlink_backup_root_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(backup_cli.BackupError, match="Symlink"):
        backup_cli.private_directory(link)


def test_docker_config_and_environment_cannot_inherit_proxy_secrets(monkeypatch):
    import subprocess

    calls = []

    def run(args, **kwargs):
        config = Path(args[args.index("--config") + 1])
        assert config.is_dir() and list(config.iterdir()) == []
        assert args[args.index("--host") + 1] == "unix:///var/run/docker.sock"
        assert kwargs["env"] == {"PATH": os.defpath, "LANG": "C.UTF-8"}
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=b"local-only", stderr=b"")

    monkeypatch.setenv("HTTP_PROXY", "http://private-proxy.invalid")
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.invalid")
    monkeypatch.setattr(backup_cli.subprocess, "run", run)
    assert backup_cli.docker("ps", "-q") == b"local-only"
    assert len(calls) == 1
    assert not Path(calls[0][calls[0].index("--config") + 1]).exists()


def test_json_publication_syncs_parent_and_refuses_replacement(archive, monkeypatch):
    folder, _ = archive
    synced = []
    monkeypatch.setattr(backup_cli, "sync_directory", synced.append)
    backup_cli.write_json(folder / "durable-test.json", {"ok": True})
    assert synced == [folder]
    with pytest.raises(FileExistsError):
        backup_cli.write_json(folder / "durable-test.json", {})


def test_legacy_inventory_is_refused_before_docker(archive, monkeypatch):
    folder, manifest = archive
    del manifest["inventory"]["format"]
    (folder / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: pytest.fail("Docker called"))
    with pytest.raises(backup_cli.BackupError, match="inventory format"):
        backup_cli.rehearse(ID)


def test_retention_preserves_legacy_inventory_without_rewriting_it(archive):
    folder, manifest = archive
    del manifest["inventory"]["format"]
    path = folder / "manifest.json"
    path.write_text(json.dumps(manifest))
    before = path.read_bytes()
    result = backup_cli.plan()
    assert result["plan"][0]["reason"] == "unsupported_inventory_preserved"
    assert result["plan"][0]["action"] == "keep"
    assert not result["deletion_performed"] and path.read_bytes() == before


@pytest.mark.parametrize(
    "fail_stage", [None, "create-before", "create-after", "start", "probe", "cleanup", "ownership"]
)
@pytest.mark.parametrize("reconciled", [False, True])
def test_application_clone_cleanup_and_secret_handling(
    archive, monkeypatch, fail_stage, reconciled
):
    _, manifest = archive
    intents = backup_cli.ROOT / ".local/recovery-intents"
    backup_cli.private_directory(intents)
    scripts = backup_cli.ROOT / "scripts"
    scripts.mkdir()
    (scripts / "recovery_probe.py").write_bytes(b"# never executed by this mocked Docker test")
    token = "c" * 32
    name = "aegis-recovery-api-" + token
    exists = False
    calls = []
    env_path = None
    valid = {
        "review": {
            "format": "aegis-recovery-review/1",
            "normal_operation_permitted": False,
            "reconciliation_applied": reconciled,
            "reconciliation_identity": token if reconciled else None,
            "reconciliation_plan_sha256": "d" * 64 if reconciled else None,
            "quarantined": True,
            "database_read_only": True,
        },
        "entrypoints_blocked": 5,
        "database_write_probes_denied": 4,
        "administrative_tcp_denied": True,
    }

    def docker(*args, **kwargs):
        nonlocal exists, env_path
        calls.append(args)
        if args[0] == "create":
            env_path = Path(args[args.index("--env-file") + 1])
            assert env_path.stat().st_mode & 0o777 == 0o600
            contents = env_path.read_text()
            assert "OPERATING_MODE=recovery" in contents and "RECOVERY_ACCESS_TOKEN=" in contents
            assert "WAZUH" not in contents and "RUNNER" not in contents
            assert ("RECOVERY_RECONCILIATION_ID=" + token in contents) == reconciled
            assert ("RECOVERY_RECONCILIATION_HASH=" + "d" * 64 in contents) == reconciled
            assert not any(
                "DATABASE_URL=" in arg or "RECOVERY_ACCESS_TOKEN=" in arg for arg in args
            )
            if fail_stage == "create-before":
                raise backup_cli.BackupError("before")
            exists = True
            if fail_stage == "create-after":
                raise backup_cli.BackupError("ambiguous create")
        if args[0] == "start" and fail_stage == "start":
            raise backup_cli.BackupError("start")
        if args[0] == "exec":
            if fail_stage == "probe":
                raise backup_cli.BackupError("probe")
            return json.dumps(valid).encode()
        if args[0] == "ps":
            return name.encode() if exists else b""
        if args[0] == "inspect":
            return ("wrong" if fail_stage == "ownership" else token).encode()
        if args[0] == "rm" and fail_stage == "cleanup":
            raise backup_cli.BackupError("cleanup")
        return b""

    monkeypatch.setattr(backup_cli, "docker", docker)
    monkeypatch.setattr(backup_cli, "prepare_reader", lambda *a: None)
    if fail_stage:
        with pytest.raises(backup_cli.BackupError):
            backup_cli.boot_application(
                "aegis-recovery-" + token,
                token,
                manifest["source"]["image_id"],
                intents,
                reconciliation_hash="d" * 64 if reconciled else None,
            )
    else:
        assert (
            backup_cli.boot_application(
                "aegis-recovery-" + token,
                token,
                manifest["source"]["image_id"],
                intents,
                reconciliation_hash="d" * 64 if reconciled else None,
            )
            == valid
        )
    create = calls[0]
    assert "--network=container:aegis-recovery-" + token in create
    assert "--pull=never" in create and "--cap-drop=ALL" in create and "--read-only" in create
    assert "--user=10001:10001" in create
    assert not any(arg in create for arg in ("-p", "--publish", "--volume", "--mount"))
    assert env_path is not None and not env_path.exists()
    intent = (intents / (token + "-api.json")).read_text()
    assert "RECOVERY_ACCESS_TOKEN" not in intent and "DATABASE_URL" not in intent
    assert ("rm" in [c[0] for c in calls]) == (fail_stage not in {"ownership", "create-before"})


def test_application_image_must_be_local_and_have_an_immutable_id(monkeypatch):
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: b"unexpected tag")
    with pytest.raises(backup_cli.BackupError, match="image"):
        backup_cli.application_image()


def test_reader_authentication_replaces_trust_and_does_not_put_secret_in_arguments(monkeypatch):
    calls = []
    inputs = []
    password = "d" * 64

    def docker(*args, **kwargs):
        calls.append(args)
        inputs.append(kwargs["stdin"].read())
        return b""

    monkeypatch.setattr(backup_cli, "docker", docker)
    monkeypatch.setattr(backup_cli, "psql", lambda *a, **kw: iter(["t"]))
    backup_cli.prepare_reader("aegis-recovery-test", password)
    assert all(password not in " ".join(args) for args in calls)
    assert password.encode() in inputs[0]
    hba = inputs[1].decode()
    assert "scram-sha-256" in hba and "host all all 0.0.0.0/0 reject" in hba
    assert "local all postgres trust" in hba
    assert "host all all trust" not in hba
    with pytest.raises(backup_cli.BackupError, match="password"):
        backup_cli.prepare_reader("aegis-recovery-test", "user-supplied' SQL")


@pytest.mark.parametrize("failure", [None, "boot", "changed-data"])
def test_recovered_application_receipt_requires_boot_and_unchanged_data(
    archive, monkeypatch, failure
):
    folder, manifest = archive
    calls = []
    inventory_calls = 0
    monkeypatch.setattr(backup_cli, "application_image", lambda: "sha256:" + "e" * 64)
    monkeypatch.setattr(backup_cli, "remove_clone", lambda *a: "removed")

    def docker(*args, **kwargs):
        calls.append(args)
        return b"postgres\n" if "cat" in args else b""

    def inventory(*args):
        nonlocal inventory_calls
        inventory_calls += 1
        if failure == "changed-data" and inventory_calls == 2:
            return {**manifest["inventory"], "migration": ["tampered"]}
        return manifest["inventory"]

    def boot(*args):
        if failure == "boot":
            raise backup_cli.BackupError("Application cleanup or boot failed")
        return {"review": {"normal_operation_permitted": False}}

    monkeypatch.setattr(backup_cli, "docker", docker)
    monkeypatch.setattr(backup_cli, "inventory", inventory)
    monkeypatch.setattr(backup_cli, "boot_application", boot)
    if failure:
        with pytest.raises((backup_cli.BackupError, ValueError)):
            backup_cli.rehearse(ID, application=True)
        assert not list(folder.glob("*verification-*.json"))
    else:
        receipt = backup_cli.rehearse(ID, application=True)
        assert receipt["application_started"] and receipt["clone_removed"]
        assert receipt["application_image_id"] == "sha256:" + "e" * 64
        assert len(list(folder.glob("application-verification-*.json"))) == 1
        assert inventory_calls == 2


def test_database_retained_when_application_cleanup_is_not_confirmed(archive, monkeypatch):
    folder, manifest = archive
    monkeypatch.setattr(backup_cli, "application_image", lambda: "sha256:" + "e" * 64)
    monkeypatch.setattr(backup_cli, "inventory", lambda *a: manifest["inventory"])
    monkeypatch.setattr(
        backup_cli, "remove_clone", lambda *a: pytest.fail("Database removed before API")
    )
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: b"postgres\n" if "cat" in a else b"")

    def unconfirmed(database, token, image, intents, state):
        state["attempted"] = True
        raise backup_cli.BackupError("API cleanup failed or was interrupted")

    monkeypatch.setattr(backup_cli, "boot_application", unconfirmed)
    with pytest.raises(backup_cli.BackupError, match="cleanup"):
        backup_cli.rehearse(ID, application=True)
    assert not list(folder.glob("*verification-*.json"))
    results = list((backup_cli.ROOT / ".local/recovery-intents").glob("*-cleanup.json"))
    assert len(results) == 1
    assert json.loads(results[0].read_text())["state"] == "retained_api_cleanup_unconfirmed"


@pytest.mark.parametrize(
    "projection", ["host|0|0|0|", "none|1|0|0|", "none|0|1|0|", "none|0|0|1|", "none|0|0|0|wrong"]
)
def test_reconciliation_refuses_wrong_ownership_network_mounts_or_ports(
    tmp_path, monkeypatch, projection
):
    token = "a" * 32
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        assert args[0] == "inspect"
        return (projection + (token if projection.endswith("|") else "")).encode()

    monkeypatch.setattr(backup_cli, "docker", docker)
    with pytest.raises(backup_cli.BackupError, match="owned offline"):
        backup_cli.clone_reconciliation("aegis-recovery-" + token, token, tmp_path)
    assert len(calls) == 1 and not list(tmp_path.iterdir())


def test_reconciliation_identity_refused_before_any_io(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: pytest.fail("Docker called"))
    for name, token in [("aegis-db-1", "a" * 32), ("aegis-recovery-../", "../")]:
        with pytest.raises(backup_cli.BackupError, match="identity"):
            backup_cli.clone_reconciliation(name, token, tmp_path)


@pytest.mark.parametrize("failure", [None, "blocked", "apply", "result", "ownership-drift"])
def test_clone_reconciliation_uses_stdin_records_plan_and_never_reports_false_apply(
    tmp_path, monkeypatch, failure
):
    token = "a" * 32
    plan = {
        "format": backup_cli.reconciliation.FORMAT,
        "snapshot_sha256": "b" * 64,
        "blockers": {"unsafe": int(failure == "blocked")},
        "counts": {},
    }
    result = {
        "format": backup_cli.reconciliation.FORMAT,
        "plan_sha256": "b" * 64,
        "reconciliation_applied": True,
        "normal_operation_permitted": False,
        "external_cleanup_performed": False,
    }
    calls = []
    inputs = []
    inspections = 0

    def docker(*args, **kwargs):
        nonlocal inspections
        calls.append(args)
        if args[0] == "inspect":
            inspections += 1
            return (
                ("host" if failure == "ownership-drift" and inspections > 1 else "none").encode()
                + b"|0|0|0|"
                + token.encode()
            )
        assert args[:3] == ("exec", "-i", "aegis-recovery-" + token)
        assert "-d" in args and args[args.index("-d") + 1] == "aegis_restore"
        assert "-c" not in args
        inputs.append(kwargs["stdin"].read().decode())
        if len(inputs) == 1:
            assert "BEGIN READ ONLY" in inputs[-1]
            return json.dumps(plan).encode()
        if failure == "apply":
            raise backup_cli.BackupError("Commit outcome unavailable")
        return json.dumps({**result, "normal_operation_permitted": failure == "result"}).encode()

    monkeypatch.setattr(backup_cli, "docker", docker)
    if failure:
        with pytest.raises(backup_cli.BackupError):
            backup_cli.clone_reconciliation("aegis-recovery-" + token, token, tmp_path)
        assert not list(tmp_path.glob("*-reconciliation-applied.json"))
    else:
        assert backup_cli.clone_reconciliation("aegis-recovery-" + token, token, tmp_path) == result
        assert len(list(tmp_path.glob("*-reconciliation-applied.json"))) == 1
    assert len(list(tmp_path.glob("*-reconciliation-plan.json"))) == 1
    assert len(inputs) == (1 if failure in {"blocked", "ownership-drift"} else 2)
    if len(inputs) == 2:
        assert "ACCESS EXCLUSIVE MODE NOWAIT" in inputs[1]


def test_reconciliation_requires_application_verification_before_io(monkeypatch):
    monkeypatch.setattr(backup_cli, "load_backup", lambda *a: pytest.fail("Archive read"))
    with pytest.raises(backup_cli.BackupError, match="requires"):
        backup_cli.rehearse(ID, reconcile_demo=True)


@pytest.mark.parametrize("failure", [None, "apply", "protected-history", "api-cleanup"])
def test_reconciliation_receipt_requires_history_api_and_cleanup(archive, monkeypatch, failure):
    folder, manifest = archive
    original = manifest["inventory"]
    original["structure"] = {"schema": "hash"}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    called = []
    monkeypatch.setattr(backup_cli, "application_image", lambda: "sha256:" + "e" * 64)
    monkeypatch.setattr(backup_cli, "docker", lambda *a, **kw: b"postgres\n" if "cat" in a else b"")
    monkeypatch.setattr(backup_cli, "inventory", lambda *a: original)
    monkeypatch.setattr(
        backup_cli, "remove_clone", lambda *a: called.append("remove-db") or "removed"
    )

    def apply(*a):
        called.append("apply")
        if failure == "apply":
            raise backup_cli.BackupError("Reconciliation failed")
        return {
            "reconciliation_applied": True,
            "normal_operation_permitted": False,
            "plan_sha256": "b" * 64,
        }

    def compare(*a):
        called.append("check-history")
        if failure == "protected-history":
            raise backup_cli.BackupError("Protected history changed")

    def boot(database, token, image, intents, state, *, reconciliation_hash):
        called.append("boot")
        assert reconciliation_hash == "b" * 64
        state["attempted"] = True
        if failure == "api-cleanup":
            raise backup_cli.BackupError("Cleanup uncertain")
        state["confirmed"] = True
        return {"review": {"reconciliation_applied": True, "normal_operation_permitted": False}}

    monkeypatch.setattr(backup_cli, "clone_reconciliation", apply)
    monkeypatch.setattr(backup_cli, "compare_reconciled", compare)
    monkeypatch.setattr(backup_cli, "boot_application", boot)
    if failure:
        with pytest.raises(backup_cli.BackupError):
            backup_cli.rehearse(ID, application=True, reconcile_demo=True)
        assert not list(folder.glob("*verification-*.json"))
    else:
        result = backup_cli.rehearse(ID, application=True, reconcile_demo=True)
        assert result["reconciliation"]["reconciliation_applied"]
        assert result["clone_removed"]
        assert len(list(folder.glob("demo-reconciliation-verification-*.json"))) == 1
        assert called == ["apply", "check-history", "boot", "remove-db"]
    assert ("remove-db" in called) == (failure != "api-cleanup")


@pytest.mark.parametrize("change", ["evidence", "schema", "table-set"])
def test_post_reconciliation_inventory_refuses_protected_changes(change):
    original = {
        "migration": ["head"],
        "structure": {"sql": "hash"},
        "tables": {"users": {"hash": "old"}, "telemetry_events": {"hash": "evidence"}},
    }
    import copy

    after = copy.deepcopy(original)
    if change == "schema":
        after["structure"]["sql"] = "different"
    elif change == "table-set":
        after["tables"]["unknown"] = {}
    else:
        after["tables"]["telemetry_events"]["hash"] = "tampered"
    with pytest.raises(backup_cli.BackupError, match="protected"):
        backup_cli.compare_reconciled(original, after)


def test_invalid_reconciliation_binding_refused_before_reader_provision(monkeypatch):
    monkeypatch.setattr(backup_cli, "prepare_reader", lambda *a: pytest.fail("Database changed"))
    with pytest.raises(backup_cli.BackupError, match="identity/hash"):
        backup_cli.boot_application(
            "unused", "a" * 32, "unused", None, reconciliation_hash="../invalid"
        )
