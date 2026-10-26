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
