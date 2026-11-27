"""Temporary private files and real age encryption; never original backups/Labs."""

import hashlib
import json
import os
from datetime import timedelta

import pytest
from aegis.operations import backup, vault
from aegis.operations import retention_store as s
from test_retention_policy import AT, POLICY

ID = "20260901T000000Z-" + "a" * 32


def source_at(root, identifier=ID, number=0):
    folder = root / identifier
    folder.mkdir(mode=0o700)
    # Explicit fixture; not a native PostgreSQL dump or claimed real execution.
    data = json.dumps(
        {
            "synthetic": True,
            "scope_hash": "historical",
            "version": number,
            "evidence_event_id": "original-event",
        }
    ).encode()
    vault.write_private(folder / "database.dump", data)
    manifest = {
        "format": backup.FORMAT,
        "id": identifier,
        "created_at": (AT - timedelta(days=40 + number)).isoformat(),
        "dump_sha256": hashlib.sha256(data).hexdigest(),
        "source": {"image_id": "sha256:" + "b" * 64, "postgres_major": 17},
        "inventory": {
            "format": backup.INVENTORY_FORMAT,
            "migration": ["fixture-version"],
            "tables": {
                "scheduled_reports": {
                    "rows": number + 1,
                    "sha256": hashlib.sha256(data).hexdigest(),
                },
                "telemetry_events": {"rows": 1, "sha256": "c" * 64},
            },
        },
    }
    vault.write_json(folder / "manifest.json", manifest)
    vault.write_json(
        folder / ("verification-" + "d" * 32 + ".json"),
        {"historical": True, "synthetic": True, "provenance": "fixture", "version": "unchanged"},
    )
    return folder


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "store"
    s.initialize(root, POLICY)
    source = source_at(tmp_path)
    s.enroll(root, source)
    key = vault.generate_key(tmp_path / "keys")
    identity = vault.load_key(tmp_path / "keys", key["key_id"])
    return root, source, key, identity


def restore_fixture(identifier, folder):
    """Transport fixture, explicitly distinct from native restore evidence."""
    manifest = s.read_json(folder / "manifest.json")
    return {
        "status": "verified",
        "backup_id": identifier,
        "dump_sha256": manifest["dump_sha256"],
        "inventory_format": backup.INVENTORY_FORMAT,
        "clone_removed": True,
        "network": "none",
        "application_started": False,
    }


def archived(store):
    root, _, key, identity = store
    envelope = s.archive(root, ID, key["recipient"])
    s.verify(root, envelope["id"], envelope["ciphertext_sha256"], identity, restore_fixture)
    return envelope


def test_enrollment_and_authenticated_roundtrip_preserve_every_member_and_original(store):
    root, original, key, identity = store
    before = s.files(original)
    envelope = archived(store)
    with s.restored_files(root, envelope["id"], envelope["ciphertext_sha256"], identity) as (
        folder,
        _,
    ):
        observed = s.files(folder)
        assert {k: v for k, v in observed.items() if k != "enrollment.json"} == before
        assert s.read_json(folder / "manifest.json") == s.read_json(original / "manifest.json")
        assert s.read_json(folder / ("verification-" + "d" * 32 + ".json"))["synthetic"] is True
        assert (folder / "database.dump").read_bytes() == (original / "database.dump").read_bytes()
    assert not folder.exists()
    assert not list((root / "work").iterdir())
    assert s.files(original) == before
    value = s.build_plan(root, at=AT.isoformat())
    member = value["members"][0]
    assert member["restore_verified"] and member["complete"]
    assert member["categories"]["reports"]["rows"] == 1
    assert value["distinct_verified_snapshots"] == 1
    assert key["key_id"] not in json.dumps(value)


@pytest.mark.parametrize("change", ["ciphertext", "envelope", "wrong_key", "wrong_hash"])
def test_tamper_or_wrong_key_never_releases_plaintext_or_deletes(store, tmp_path, change):
    root, original, key, identity = store
    envelope = s.archive(root, ID, key["recipient"])
    expected = envelope["ciphertext_sha256"]
    if change == "ciphertext":
        path = root / "archives" / envelope["id"] / "bundle.age"
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 1
        path.write_bytes(data)
    elif change == "envelope":
        path = root / "archives" / envelope["id"] / "envelope.json"
        value = s.read_json(path)
        value["files"]["database.dump"]["sha256"] = "0" * 64
        path.write_text(json.dumps(value))
    elif change == "wrong_key":
        other = vault.generate_key(tmp_path / "other-keys")
        identity = vault.load_key(tmp_path / "other-keys", other["key_id"])
    else:
        expected = "0" * 64
    with pytest.raises((ValueError, vault.crypto().DecryptError)):
        with s.restored_files(root, envelope["id"], expected, identity):
            pytest.fail("Tampered content exposed")
    assert list((root / "work").iterdir()) == []
    assert (original / "database.dump").exists()
    assert not list((root / "archives" / envelope["id"]).glob("verification-*"))


def test_failed_restore_or_cleanup_produces_no_success_receipt(store):
    root, _, key, identity = store
    envelope = s.archive(root, ID, key["recipient"])
    for field, value in [
        ("clone_removed", False),
        ("network", "default"),
        ("backup_id", "other"),
        ("dump_sha256", "0" * 64),
    ]:

        def failed(identifier, folder, field=field, value=value):
            return {**restore_fixture(identifier, folder), field: value}

        with pytest.raises(ValueError, match="cleanup"):
            s.verify(root, envelope["id"], envelope["ciphertext_sha256"], identity, failed)
    assert not list((root / "archives" / envelope["id"]).glob("verification-*"))
    assert not s.build_plan(root)["members"][0]["restore_verified"]


def test_private_staging_cleanup_failure_blocks_success_receipt(store, monkeypatch):
    root, _, key, identity = store
    envelope = s.archive(root, ID, key["recipient"])
    real = s.tempfile.TemporaryDirectory

    class FailedCleanup:
        def __init__(self, *args, **kwargs):
            self.inner = real(*args, **kwargs)

        def __enter__(self):
            return self.inner.__enter__()

        def __exit__(self, *args):
            self.inner.__exit__(*args)
            raise OSError("fixture cleanup not confirmed")

    monkeypatch.setattr(s.tempfile, "TemporaryDirectory", FailedCleanup)
    with pytest.raises(OSError, match="cleanup"):
        s.verify(root, envelope["id"], envelope["ciphertext_sha256"], identity, restore_fixture)
    assert not list((root / "archives" / envelope["id"]).glob("verification-*"))


def test_incomplete_unverified_unknown_formats_and_source_drift_are_preserved(store):
    root, _, *_ = store
    incomplete = root / "snapshots" / ("20260901T000000Z-" + "e" * 32)
    incomplete.mkdir(mode=0o700)
    vault.write_private(incomplete / "database.dump", b"interrupted")
    value = s.build_plan(root)
    assert all(x["action"] == "keep" for x in value["members"])
    assert not value["members"][1]["complete"]
    manifest_path = root / "snapshots" / ID / "manifest.json"
    data = s.read_json(manifest_path)
    data["inventory"]["format"] = "unknown/99"
    manifest_path.write_text(json.dumps(data))
    assert not s.build_plan(root)["members"][0]["complete"]


@pytest.mark.parametrize("change", ["symlink", "hardlink", "fifo", "public", "extra"])
def test_unsafe_source_files_are_refused_before_enrollment(tmp_path, change):
    root = tmp_path / "store"
    s.initialize(root, POLICY)
    source = source_at(tmp_path)
    target = source / "database.dump"
    if change == "symlink":
        target.unlink()
        target.symlink_to(source / "manifest.json")
    elif change == "hardlink":
        os.link(target, tmp_path / "another")
    elif change == "fifo":
        target.unlink()
        os.mkfifo(target, 0o600)
    elif change == "public":
        target.chmod(0o644)
    else:
        vault.write_private(source / "unrelated.txt", b"preserve")
    with pytest.raises((ValueError, vault.VaultError)):
        s.enroll(root, source)
    assert not list((root / "snapshots").iterdir())


def test_cannot_adopt_existing_directory_or_use_concurrent_store(store):
    root, original, *_ = store
    with pytest.raises(FileExistsError):
        s.initialize(root, POLICY)
    with s.locked(root):
        with pytest.raises(ValueError, match="busy"):
            s.build_plan(root)
    with pytest.raises(FileExistsError):
        s.enroll(root, original)


@pytest.mark.parametrize("change", ["escape", "symlink", "duplicate", "missing", "index"])
def test_authenticated_but_invalid_archive_structure_is_refused(store, change):
    import io
    import tarfile

    root, _, key, identity = store
    envelope = s.archive(root, ID, key["recipient"])
    index = {k: envelope[k] for k in ("format", "store_id", "id", "backup_id", "files")}
    if change == "index":
        index["backup_id"] = "unrelated"
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        data = json.dumps(index).encode()
        entry = tarfile.TarInfo("archive-index.json")
        entry.size = len(data)
        tar.addfile(entry, io.BytesIO(data))
        if change == "duplicate":
            tar.addfile(entry, io.BytesIO(data))
        for name in envelope["files"]:
            if change == "missing" and name == "database.dump":
                continue
            entry = tarfile.TarInfo("../escape" if change == "escape" else name)
            if change == "symlink" and name == "database.dump":
                entry.type, entry.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tar.addfile(entry)
            else:
                data = (root / "snapshots" / ID / name).read_bytes()
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
    plain.seek(0)
    target = root / "archives" / envelope["id"]
    with (target / "bundle.age").open("wb") as output:
        vault.crypto().encrypt_io(
            plain, output, [vault.crypto().x25519.Recipient.from_str(key["recipient"])]
        )
    with vault.private_file(target / "bundle.age") as stream:
        envelope["ciphertext_sha256"] = vault.hash_stream(stream)
        envelope["ciphertext_bytes"] = os.fstat(stream.fileno()).st_size
    (target / "envelope.json").write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="archive|Archive"):
        with s.restored_files(root, envelope["id"], envelope["ciphertext_sha256"], identity):
            pytest.fail("Unsafe authenticated archive exposed")
    assert not (root / "work" / "escape").exists()
    assert not list((root / "work").iterdir())
