"""CLI safety checks; Docker mutations are mocked here, actual rehearsal is opt-in."""

import importlib.util
import json
import os
from pathlib import Path

import pytest
from aegis.operations.backup import FORMAT

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
        "inventory": {"tables": {"test": {"rows": 4}}, "migration": ["test"]},
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
    "fail_stage", [None, "start", "restore", "inventory", "cleanup", "ownership"]
)
def test_rehearsal_is_offline_owned_and_never_emits_false_success(archive, monkeypatch, fail_stage):
    folder, manifest = archive
    calls = []
    owned = None

    def docker(*args, **kwargs):
        nonlocal owned
        calls.append(args)
        if args[0] == "create":
            owned = args[args.index("--label") + 1].split("=", 1)[1]
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
    assert bool(removed) == (fail_stage != "ownership")
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
