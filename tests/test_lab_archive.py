"""Private cold archives and custody records; temporary files only."""

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
    contents = [
        (tmp_path / "custody" / v["stored_as"]).read_bytes() for v in result["files"].values()
    ]
    assert b'{"state":"EXPIRED"}' in contents and b'{"state":"CONSUMED"}' in contents
    assert b"must-not-be-followed" not in contents
    assert before == {p: (p.lstat().st_mtime_ns, p.lstat().st_ctime_ns) for p in root.rglob("*")}
    item = next(iter(result["files"].values()))
    (tmp_path / "custody" / item["stored_as"]).write_bytes(b"corrupted")
    with pytest.raises(snapshot.SnapshotError, match="integrity"):
        archive.verify_records(tmp_path / "custody", digest(result))
