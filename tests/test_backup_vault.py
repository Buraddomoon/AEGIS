"""Real age streaming, private files and fail-closed decryption; no Docker/SQL."""

import hashlib
import io
import json
import os
import struct

import pytest
from aegis.operations import vault

ID = "20261026T160000Z-" + "a" * 32


@pytest.fixture
def sealed(tmp_path):
    root = tmp_path / "private"
    vault.private_directory(root)
    source = root / "source"
    vault.private_directory(source)
    dump = b"PGDMP synthetic test fixture\x00" * 10000
    manifest = {"id": ID, "dump_sha256": hashlib.sha256(dump).hexdigest()}
    vault.write_private(source / "database.dump", dump)
    vault.write_json(source / "manifest.json", manifest)
    key = vault.generate_key(root / "keys")
    identity = vault.load_key(root / "keys", key["key_id"])
    envelope = vault.seal(source, ID, root / "vault", key["recipient"])
    return root, source, key, identity, envelope


def test_real_streaming_roundtrip_preserves_original_bytes_and_does_not_print_key(sealed, capsys):
    root, source, key, identity, envelope = sealed
    assert "AGE-SECRET-KEY" not in json.dumps(key)
    assert "AGE-SECRET-KEY" not in capsys.readouterr().out
    assert envelope["status"] == "sealed_not_yet_verified"
    assert (
        (root / "vault" / envelope["id"] / "bundle.age")
        .read_bytes()
        .startswith(b"age-encryption.org/v1\n")
    )
    for _ in range(2):
        with vault.decrypted(
            root / "vault", envelope["id"], envelope["ciphertext_sha256"], identity, root / "work"
        ) as (folder, actual):
            assert actual == envelope
            for name in ("manifest.json", "database.dump"):
                assert (folder / name).read_bytes() == (source / name).read_bytes()
                assert (folder / name).stat().st_mode & 0o777 == 0o600
        assert not folder.exists()
        assert list((root / "work").iterdir()) == []
    assert (source / "database.dump").exists()


def test_wrong_key_and_expected_hash_refused(sealed):
    root, _, _, identity, envelope = sealed
    wrong = vault.crypto().x25519.Identity.generate()
    for key, expected in ((wrong, envelope["ciphertext_sha256"]), (identity, "0" * 64)):
        with pytest.raises(vault.VaultError):
            with vault.decrypted(root / "vault", envelope["id"], expected, key, root / "work"):
                pytest.fail("Unauthenticated content exposed")


@pytest.mark.parametrize(
    "change", ["flip-header", "flip-middle", "flip-last", "truncate", "append"]
)
def test_tampering_rejected_even_if_outer_envelope_hash_is_rewritten(sealed, change):
    root, _, _, identity, envelope = sealed
    folder = root / "vault" / envelope["id"]
    path = folder / "bundle.age"
    content = bytearray(path.read_bytes())
    if change == "truncate":
        content = content[:-1]
    elif change == "append":
        content += b"trailing-data"
    else:
        at = {"flip-header": 45, "flip-middle": len(content) // 2, "flip-last": len(content) - 1}[
            change
        ]
        content[at] ^= 1
    path.write_bytes(content)
    envelope.update(
        ciphertext_sha256=hashlib.sha256(content).hexdigest(), ciphertext_bytes=len(content)
    )
    (folder / "envelope.json").write_text(json.dumps(envelope))
    with pytest.raises((vault.VaultError, ValueError, OSError, vault.crypto().DecryptError)):
        with vault.decrypted(
            root / "vault", envelope["id"], envelope["ciphertext_sha256"], identity, root / "work"
        ):
            pytest.fail("Unauthenticated content exposed")
    assert list((root / "work").iterdir()) == []


@pytest.mark.parametrize("change", ["public", "symlink", "hardlink", "fifo"])
def test_unsafe_files_rejected_without_reading_or_blocking(sealed, change):
    root, source, *_ = sealed
    path = source / "database.dump"
    if change == "public":
        path.chmod(0o644)
    elif change == "symlink":
        path.unlink()
        path.symlink_to(source / "manifest.json")
    elif change == "hardlink":
        os.link(path, source / "other")
    else:
        path.unlink()
        os.mkfifo(path, 0o600)
    with pytest.raises((vault.VaultError, OSError)):
        with vault.private_file(path):
            pytest.fail("Unsafe input opened")


def test_source_hash_mismatch_does_not_publish_envelope(sealed):
    root, source, key, *_ = sealed
    (source / "database.dump").write_bytes(b"changed")
    with pytest.raises(vault.VaultError, match="hash"):
        vault.seal(source, ID, root / "other-vault", key["recipient"])
    assert not list((root / "other-vault").glob("*/envelope.json"))


def test_decrypted_size_limit_and_manifest_bounds_prevent_unbounded_output(sealed, monkeypatch):
    root, _, _, identity, envelope = sealed
    monkeypatch.setattr(vault, "MAX_CONTENT", 1024)
    with pytest.raises((vault.VaultError, OSError)):
        with vault.decrypted(
            root / "vault", envelope["id"], envelope["ciphertext_sha256"], identity, root / "work"
        ):
            pytest.fail("Oversize exposed")
    assert list((root / "work").iterdir()) == []
    for content in (
        b"bad",
        vault.MAGIC + b"\x00",
        vault.MAGIC + struct.pack(">I", vault.MAX_MANIFEST + 1),
    ):
        with pytest.raises(vault.VaultError):
            vault.unpack(io.BytesIO(content), root, ID)


def test_key_and_envelope_paths_are_fixed_and_invalid_recipient_never_creates_vault(tmp_path):
    for bad in ("../other", "x", "a" * 31, "a" * 32 + "/secret"):
        with pytest.raises(vault.VaultError):
            vault.load_key(tmp_path / "keys", bad)
    with pytest.raises((vault.VaultError, vault.crypto().RecipientError)):
        vault.seal(tmp_path, ID, tmp_path / "vault", "age-plugin-untrusted")
    assert not (tmp_path / "vault").exists()


def test_symlink_parent_refused_and_key_never_overwritten(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(vault.VaultError):
        vault.private_directory(link / "keys")
    monkeypatch.setattr(vault.uuid, "uuid4", lambda: type("Id", (), {"hex": "a" * 32})())
    key = vault.generate_key(tmp_path / "keys")
    original = (tmp_path / "keys" / (key["key_id"] + ".agekey")).read_bytes()
    with pytest.raises(FileExistsError):
        vault.generate_key(tmp_path / "keys")
    assert (tmp_path / "keys" / (key["key_id"] + ".agekey")).read_bytes() == original


def test_inventory_is_read_only_and_preserves_unverified_missing_keys_and_incomplete_copies(sealed):
    root, _, _, _, envelope = sealed
    partial = root / "vault" / "incomplete-preserved"
    partial.mkdir(mode=0o700)
    vault.write_private(partial / "bundle.age.partial", b"partial")
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in root.rglob("*") if p.is_file()}
    result = vault.retention_inventory(root / "vault", root / "keys")
    assert result["deletion_performed"] is result["transfer_performed"] is False
    row = next(r for r in result["copies"] if r["id"] == envelope["id"])
    assert row["key_present_locally"] and not row["verification_recorded"]
    assert row["reason"] == "unverified_copy_preserved" and row["action"] == "keep"
    assert before == {
        p: (p.stat().st_mtime_ns, p.read_bytes()) for p in root.rglob("*") if p.is_file()
    }
    missing = vault.retention_inventory(root / "absent", root / "absent-keys")
    assert missing["copies"] == [] and not (root / "absent").exists()


def record_verification(root, envelope):
    from aegis.operations.backup import INVENTORY_FORMAT

    receipt = {
        "format": vault.FORMAT,
        "id": envelope["id"],
        "status": "decrypted_and_restore_verified",
        "ciphertext_sha256": envelope["ciphertext_sha256"],
        "recipient": envelope["recipient"],
        "recovery": {
            "status": "verified",
            "backup_id": envelope["backup_id"],
            "inventory_format": INVENTORY_FORMAT,
            "clone_removed": True,
            "network": "none",
            "application_started": False,
        },
    }
    path = root / "vault" / envelope["id"] / ("verification-" + "b" * 32 + ".json")
    vault.write_json(path, receipt)
    return path, receipt


def test_inventory_receipt_is_hash_bound_and_key_availability_is_not_assumed(sealed):
    root, _, _, _, envelope = sealed
    path, receipt = record_verification(root, envelope)
    row = vault.retention_inventory(root / "vault", root / "keys")["copies"][0]
    assert row["verification_recorded"] and row["action"] == "keep"
    row = vault.retention_inventory(root / "vault", root / "missing-keys")["copies"][0]
    assert row["verification_recorded"] and not row["key_present_locally"]
    assert row["reason"] == "missing_local_key_preserved"
    receipt["ciphertext_sha256"] = "0" * 64
    path.write_text(json.dumps(receipt))
    row = vault.retention_inventory(root / "vault", root / "keys")["copies"][0]
    assert not row["verification_recorded"] and row["action"] == "keep"


def test_retention_counts_distinct_verified_snapshots_and_unverified_copies_do_not_replace_good_backups(
    sealed,
):
    from datetime import UTC, datetime

    root, source, key, _, original = sealed
    record_verification(root, original)
    original_path = root / "vault" / original["id"] / "envelope.json"
    original["created_at"] = "2026-01-01T00:00:00+00:00"
    original_path.write_text(json.dumps(original))
    for i in range(10):
        identifier = "20260201T160000Z-" + f"{i:032x}"
        manifest = json.loads((source / "manifest.json").read_text())
        manifest["id"] = identifier
        (source / "manifest.json").write_text(json.dumps(manifest))
        envelope = vault.seal(source, identifier, root / "vault", key["recipient"])
        envelope["created_at"] = "2026-02-01T00:00:00+00:00"
        (root / "vault" / envelope["id"] / "envelope.json").write_text(json.dumps(envelope))
    plan = vault.retention_inventory(
        root / "vault", root / "keys", at=datetime(2026, 10, 26, tzinfo=UTC)
    )
    assert plan["distinct_backups"] == 11
    assert all(r["action"] == "keep" for r in plan["copies"]), (
        "Unverified copies must not evict good snapshots"
    )
    # Ten ciphertexts of one good snapshot still count as only one retained snapshot.
    for _ in range(8):
        envelope = vault.seal(source, identifier, root / "vault", key["recipient"])
        record_verification(root, envelope)
    plan = vault.retention_inventory(
        root / "vault", root / "keys", at=datetime(2026, 10, 26, tzinfo=UTC)
    )
    assert all(r["action"] == "keep" for r in plan["copies"])
