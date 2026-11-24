"""Private cold archives and custody records; temporary files only."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from aegis.operations import lab_archive as archive
from aegis.operations import lab_backup as snapshot


def tar_archive(tmp_path, members):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w", format=tarfile.USTAR_FORMAT) as writer:
        for name, kind, data in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(data)
            elif kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = data.decode()
            writer.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    target = tmp_path / "archive.tar"
    snapshot.vault.write_private(target, content.getvalue())
    destination = tmp_path / "extracted"
    destination.mkdir(mode=0o700)
    return target, destination


def test_cold_copy_extraction_preserves_bytes_in_private_new_files(tmp_path):
    source, target = tar_archive(
        tmp_path,
        [
            ("./", tarfile.DIRTYPE, b""),
            ("./global", tarfile.DIRTYPE, b""),
            ("./global/pg_control", tarfile.REGTYPE, b"private-bytes"),
        ],
    )
    original = source.read_bytes()
    result = archive.extract(source, target)
    assert (target / "global/pg_control").read_bytes() == b"private-bytes"
    assert source.read_bytes() == original
    assert result["bytes"] == len(b"private-bytes")
    assert all(
        p.stat().st_mode & 0o777 == (0o700 if p.is_dir() else 0o600) for p in target.rglob("*")
    )


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("a/../../escape", tarfile.REGTYPE),
        ("link", tarfile.SYMTYPE),
        ("hardlink", tarfile.LNKTYPE),
        ("pipe", tarfile.FIFOTYPE),
        ("device", tarfile.CHRTYPE),
    ],
)
def test_cold_archive_never_follows_links_or_escapes(tmp_path, name, kind):
    source, target = tar_archive(tmp_path, [(name, kind, b"../outside")])
    with pytest.raises(snapshot.SnapshotError):
        archive.extract(source, target)
    assert not (tmp_path / "escape").exists()


def test_duplicate_cold_entries_and_existing_destinations_are_not_adopted(tmp_path):
    source, target = tar_archive(
        tmp_path, [("a", tarfile.REGTYPE, b"one"), ("a", tarfile.REGTYPE, b"two")]
    )
    with pytest.raises(snapshot.SnapshotError, match="entry"):
        archive.extract(source, target)
    assert (target / "a").read_bytes() == b"one"
    with pytest.raises(snapshot.SnapshotError, match="new_directory"):
        archive.extract(source, target)


def test_host_record_plan_only_stats_then_copies_expired_and_consumed_fences(tmp_path, monkeypatch):
    root = tmp_path / ".local"
    root.mkdir(mode=0o700)
    (root / "pki-plans").mkdir(mode=0o700)
    snapshot.vault.write_private(root / "pki-plans/expired.json", b'{"state":"EXPIRED"}')
    snapshot.vault.write_private(root / "pki-plans/consumed.json", b'{"state":"CONSUMED"}')
    snapshot.vault.write_private(tmp_path / ".env", b"EXAMPLE_PRIVATE=fixture-value\n")
    outside = tmp_path / "outside"
    snapshot.vault.write_private(outside, b"must-not-be-followed")
    (root / "pki-plans/link.key").symlink_to(outside)
    (root / "unrelated").mkdir()
    (root / "unrelated/other-project.json").write_text("preserve-other-project")
    roots = {"primary": root}
    with monkeypatch.context() as scope:
        scope.setattr(
            Path, "read_bytes", lambda *_: pytest.fail("Prepare must not read private bytes")
        )
        planned = archive.record_paths(roots)
    assert "fixture-value" not in json.dumps(planned)
    assert not any("unrelated" in name for name in planned)
    before = {p: (p.lstat().st_mtime_ns, p.lstat().st_ctime_ns) for p in root.rglob("*")}
    result = archive.capture_records(roots, planned, tmp_path / "custody")
    assert archive.verify_records(tmp_path / "custody", digest(result)) == result
    assert set(p.name for p in (tmp_path / "custody").iterdir()) == {
        "records.tar",
        "inventory.json",
    }
    with tarfile.open(tmp_path / "custody/records.tar") as packed:
        contents = [packed.extractfile(v["stored_as"]).read() for v in result["files"].values()]
    assert b'{"state":"EXPIRED"}' in contents and b'{"state":"CONSUMED"}' in contents
    assert b"must-not-be-followed" not in contents
    assert before == {p: (p.lstat().st_mtime_ns, p.lstat().st_ctime_ns) for p in root.rglob("*")}
    (tmp_path / "custody/records.tar").write_bytes(b"corrupted")
    with pytest.raises(snapshot.SnapshotError, match="integrity"):
        archive.verify_records(tmp_path / "custody", digest(result))


def test_retained_loose_custody_still_verifies_without_rewriting_it(tmp_path):
    name, data = "primary/pki-plan/consumed.json", b'{"state":"CONSUMED"}'
    filename = hashlib.sha256(name.encode()).hexdigest()
    files = {
        name: {
            "kind": "file",
            "bytes": len(data),
            "stored_as": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    }
    inventory = {
        "format": "aegis-lab-host-custody/1",
        "files": files,
        "inventory_sha256": digest(files),
        "links_followed": False,
        "historical_records_executed": False,
    }
    snapshot.vault.write_private(tmp_path / filename, data)
    snapshot.vault.write_json(tmp_path / "inventory.json", inventory)
    before = (tmp_path / "inventory.json").read_bytes()
    assert archive.verify_records(tmp_path, digest(inventory)) == inventory
    assert (tmp_path / "inventory.json").read_bytes() == before


@pytest.mark.parametrize("problem", ["escape", "symlink", "duplicate", "missing", "size"])
def test_packed_custody_rejects_inconsistent_members_even_with_a_known_hash(tmp_path, problem):
    data, name = b"inert-private-fixture", "primary/pki-plan/expired.key"
    member_name = hashlib.sha256(name.encode()).hexdigest()
    contents = io.BytesIO()
    with tarfile.open(fileobj=contents, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for _ in range(2 if problem == "duplicate" else 0 if problem == "missing" else 1):
            member = tarfile.TarInfo("../escape" if problem == "escape" else member_name)
            member.size = len(data)
            if problem == "symlink":
                member.type, member.linkname, member.size = tarfile.SYMTYPE, "/outside", 0
            out.addfile(member, io.BytesIO(data) if member.isfile() else None)
    packed = contents.getvalue()
    files = {
        name: {
            "kind": "file",
            "bytes": len(data) + (problem == "size"),
            "stored_as": member_name,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    }
    inventory = {
        "format": "aegis-lab-host-custody/2",
        "files": files,
        "inventory_sha256": digest(files),
        "links_followed": False,
        "historical_records_executed": False,
        "pack": {"bytes": len(packed), "sha256": hashlib.sha256(packed).hexdigest()},
    }
    snapshot.vault.write_private(tmp_path / "records.tar", packed)
    snapshot.vault.write_json(tmp_path / "inventory.json", inventory)
    with pytest.raises(snapshot.SnapshotError, match="pack_entry|integrity"):
        archive.verify_records(tmp_path, digest(inventory))
    assert not (tmp_path.parent / "escape").exists()


def test_incomplete_custody_pack_never_publishes_an_inventory(tmp_path, monkeypatch):
    root = tmp_path / ".local"
    root.mkdir(mode=0o700)
    snapshot.vault.write_private(tmp_path / ".env", b"PRIVATE_FIXTURE=opaque")
    roots = {"primary": root}
    expected = archive.record_paths(roots)
    monkeypatch.setattr(
        snapshot.vault, "write_json", lambda *_: (_ for _ in ()).throw(OSError("fixture"))
    )
    with pytest.raises(OSError):
        archive.capture_records(roots, expected, tmp_path / "custody")
    assert (tmp_path / "custody/records.tar").exists()
    assert not (tmp_path / "custody/inventory.json").exists()
