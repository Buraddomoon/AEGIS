"""Explicit private snapshot enrollment and authenticated, self-contained archives.

Source backups are read-only. A store is identified by an exclusive ownership
marker; only its enrolled plaintext copies can later become retention targets.
"""

import fcntl
import io
import json
import os
import re
import tarfile
import tempfile
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aegis.domain.validation import digest
from aegis.operations import backup, retention, vault

MAX_BYTES = 512 * 1024**2
MAX_FILES = 256
DATA_NAME = re.compile(
    r"(?:manifest\.json|database\.dump|(?:verification|application-verification|"
    r"demo-reconciliation-verification|demo-cycle-verification)-[a-f0-9]{32}\.json)"
)


def copy_exact(source, destination, expected_bytes):
    count = 0
    while chunk := source.read(vault.CHUNK):
        count += len(chunk)
        if count > expected_bytes:
            raise ValueError("Source grew during copy")
        destination.write(chunk)
    if count != expected_bytes:
        raise ValueError("Source truncated during copy")


def read_json(path):
    with vault.private_file(path, maximum=vault.MAX_MANIFEST) as stream:
        return json.load(stream)


def files(folder):
    vault.check_directory(folder)
    paths = sorted(folder.iterdir())
    if len(paths) > MAX_FILES:
        raise ValueError("Snapshot file limit exceeded")
    result = {}
    for path in paths:
        if not (DATA_NAME.fullmatch(path.name) or path.name == "enrollment.json"):
            raise ValueError("Unexpected snapshot member")
        with vault.private_file(path, maximum=MAX_BYTES) as stream:
            result[path.name] = {
                "sha256": vault.hash_stream(stream),
                "bytes": os.fstat(stream.fileno()).st_size,
            }
    if sum(x["bytes"] for x in result.values()) > MAX_BYTES - 2 * 1024**2:
        raise ValueError("Snapshot size limit exceeded")
    return result


def validate_snapshot(folder, identifier):
    observed = files(folder)
    manifest = read_json(folder / "manifest.json")
    summary = retention.manifest_summary(manifest, identifier)
    if (
        "database.dump" not in observed
        or observed["database.dump"]["bytes"] == 0
        or manifest["dump_sha256"] != observed["database.dump"]["sha256"]
        or manifest["source"]["postgres_major"] != 17
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", manifest["source"]["image_id"])
    ):
        raise ValueError("Snapshot dump or source mismatch")
    return observed, summary


def initialize(root, selected_policy):
    selected_policy = retention.policy(selected_policy)
    vault.no_symlink_parents(root)
    root.mkdir(mode=0o700)  # Exclusive; never adopt an existing directory.
    vault.check_directory(root)
    for name in ("snapshots", "archives", "receipts", "work"):
        (root / name).mkdir(mode=0o700)
    marker = {"format": retention.FORMAT, "store_id": uuid.uuid4().hex}
    vault.write_json(root / "owner.json", marker)
    vault.write_json(root / "policy.json", selected_policy)
    vault.write_private(root / "lock", b"")
    vault.sync_directory(root)
    vault.sync_directory(root.parent)
    return marker


@contextmanager
def locked(root):
    vault.check_directory(root)
    marker = read_json(root / "owner.json")
    if marker.get("format") != retention.FORMAT or not re.fullmatch(
        r"[a-f0-9]{32}", marker.get("store_id", "")
    ):
        raise ValueError("Owned retention store required")
    for name in ("snapshots", "archives", "receipts", "work"):
        vault.check_directory(root / name)
    with vault.private_file(root / "lock", maximum=0) as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Retention store busy") from None
        yield marker


def enroll(root, source):
    """Copy reviewed complete backup; never move/adopt/delete original files."""
    identifier = source.name
    if not re.fullmatch(vault.BACKUP_ID, identifier):
        raise ValueError("Source must be a backup ID directory")
    with locked(root) as marker:
        observed, _ = validate_snapshot(source, identifier)
        if "enrollment.json" in observed:
            raise ValueError("Cannot enroll another store's copy")
        target = root / "snapshots" / identifier
        target.mkdir(mode=0o700)
        vault.sync_directory(target.parent)
        for name in observed:
            with vault.private_file(source / name, maximum=MAX_BYTES) as src:
                fd = os.open(
                    target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(fd, "wb") as out:
                    copy_exact(src, out, observed[name]["bytes"])
                    out.flush()
                    os.fsync(out.fileno())
        if files(source) != observed or files(target) != observed:
            raise ValueError("Source drift; incomplete enrolled copy preserved")
        vault.write_json(
            target / "enrollment.json",
            {**marker, "id": identifier, "files": observed},
        )
        return {"id": identifier, "status": "enrolled_copy_original_preserved"}


def enrolled(root, identifier, marker):
    if not re.fullmatch(vault.BACKUP_ID, identifier):
        raise ValueError("Invalid snapshot ID")
    folder = root / "snapshots" / identifier
    observed, summary = validate_snapshot(folder, identifier)
    enrollment = read_json(folder / "enrollment.json")
    if (
        enrollment.get("format") != retention.FORMAT
        or enrollment.get("store_id") != marker["store_id"]
        or enrollment.get("id") != identifier
        or enrollment.get("files") != {k: v for k, v in observed.items() if k != "enrollment.json"}
    ):
        raise ValueError("Enrollment integrity mismatch")
    return folder, observed, summary


def archive(root, identifier, recipient):
    public = vault.crypto().x25519.Recipient.from_str(recipient)
    with locked(root) as marker:
        folder, observed, _ = enrolled(root, identifier, marker)
        archive_id = identifier + "-" + uuid.uuid4().hex
        target = root / "archives" / archive_id
        target.mkdir(mode=0o700)
        vault.sync_directory(target.parent)
        index = {**marker, "id": archive_id, "backup_id": identifier, "files": observed}
        # Unlinked plaintext scratch; all output stays private, even on failure.
        with tempfile.TemporaryFile(dir=root / "work") as plain:
            with tarfile.open(fileobj=plain, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
                data = json.dumps(index, sort_keys=True).encode()
                entry = tarfile.TarInfo("archive-index.json")
                entry.size, entry.mode = len(data), 0o600
                bundle.addfile(entry, io.BytesIO(data))
                for name, info in observed.items():
                    with vault.private_file(folder / name, maximum=MAX_BYTES) as stream:
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode = info["bytes"], 0o600
                        bundle.addfile(entry, stream)
            if plain.tell() > MAX_BYTES:
                raise ValueError("Archive size limit exceeded")
            plain.seek(0)
            path = target / "bundle.age.partial"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                vault.crypto().encrypt_io(plain, output, [public])
                output.flush()
                os.fsync(output.fileno())
        if files(folder) != observed:
            raise ValueError("Snapshot drift; partial archive preserved")
        path.rename(target / "bundle.age")
        vault.sync_directory(target)
        with vault.private_file(target / "bundle.age", maximum=MAX_BYTES + 1024**2) as stream:
            envelope = {
                **index,
                "recipient": str(public),
                "ciphertext_sha256": vault.hash_stream(stream),
                "ciphertext_bytes": os.fstat(stream.fileno()).st_size,
            }
        vault.write_json(target / "envelope.json", envelope)
        return envelope


def archive_files(folder):
    """Bind every archive/verification member, including partial failures."""
    vault.check_directory(folder)
    result = {}
    paths = sorted(folder.iterdir())
    if len(paths) > MAX_FILES:
        raise ValueError("Archive member limit exceeded")
    for path in paths:
        if not (
            path.name in {"bundle.age", "bundle.age.partial", "envelope.json"}
            or re.fullmatch(r"verification-[a-f0-9]{32}\.json", path.name)
        ):
            raise ValueError("Unexpected archive member")
        with vault.private_file(path, maximum=MAX_BYTES + 1024**2) as stream:
            result[path.name] = {
                "sha256": vault.hash_stream(stream),
                "bytes": os.fstat(stream.fileno()).st_size,
            }
    return result


def load_archive(root, archive_id, expected_sha256):
    if not re.fullmatch(vault.SEALED_ID, archive_id):
        raise ValueError("Invalid archive ID")
    folder = root / "archives" / archive_id
    vault.check_directory(folder)
    envelope = read_json(folder / "envelope.json")
    if (
        envelope.get("format") != retention.FORMAT
        or envelope.get("id") != archive_id
        or envelope.get("backup_id") != archive_id.rsplit("-", 1)[0]
        or envelope.get("ciphertext_sha256") != expected_sha256
    ):
        raise ValueError("Archive envelope mismatch")
    return folder, envelope


@contextmanager
def restored_files(root, archive_id, expected_sha256, identity):
    """Authenticated data only; no tar extraction helper or live DB import."""
    folder, envelope = load_archive(root, archive_id, expected_sha256)
    if envelope["recipient"] != str(identity.to_public()):
        raise ValueError("Archive key mismatch")
    with tempfile.TemporaryDirectory(prefix="restore-", dir=root / "work") as temporary:
        staging = Path(temporary)
        with (
            vault.private_file(folder / "bundle.age", maximum=MAX_BYTES + 1024**2) as encrypted,
            tempfile.TemporaryFile(dir=staging) as plain,
        ):
            if (
                vault.hash_stream(encrypted) != expected_sha256
                or os.fstat(encrypted.fileno()).st_size != envelope["ciphertext_bytes"]
            ):
                raise ValueError("Archive ciphertext drift")
            bounded = vault.BoundedWriter(plain)
            consumed = vault.CipherReader(encrypted)
            vault.crypto().decrypt_io(consumed, bounded, [identity])
            if consumed.digest.hexdigest() != expected_sha256 or plain.tell() > MAX_BYTES:
                raise ValueError("Archive changed or exceeds limit")
            plain.seek(0)
            expected = {k: envelope[k] for k in ("format", "store_id", "id", "backup_id", "files")}
            seen, total = set(), 0
            with tarfile.open(fileobj=plain, mode="r:") as bundle:
                for entry in bundle:
                    name = entry.name
                    if (
                        not entry.isfile()
                        or entry.pax_headers
                        or entry.issparse()
                        or name in seen
                        or name not in {"archive-index.json", *envelope["files"]}
                        or not (
                            name == "archive-index.json"
                            or DATA_NAME.fullmatch(name)
                            or name == "enrollment.json"
                        )
                        or len(seen) > MAX_FILES
                        or entry.size < 0
                    ):
                        raise ValueError("Unsafe archive member")
                    seen.add(name)
                    total += entry.size
                    if total > MAX_BYTES:
                        raise ValueError("Archive size limit exceeded")
                    content = bundle.extractfile(entry)
                    if content is None:
                        raise ValueError("Missing archive member")
                    with content:
                        if name == "archive-index.json":
                            if entry.size > vault.MAX_MANIFEST or json.load(content) != expected:
                                raise ValueError("Archive index mismatch")
                        else:
                            fd = os.open(
                                staging / name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600,
                            )
                            with os.fdopen(fd, "wb") as output:
                                copy_exact(content, output, entry.size)
                                output.flush()
                                os.fsync(output.fileno())
            if (
                seen != {"archive-index.json", *envelope["files"]}
                or files(staging) != envelope["files"]
            ):
                raise ValueError("Archive incomplete or content drift")
        validate_snapshot(staging, envelope["backup_id"])
        yield staging, envelope
    # Context exits only after private plaintext staging cleanup succeeds.


def verify(root, archive_id, expected_sha256, identity, restore):
    """Restore is the trusted host coordinator, never a callback from input JSON."""
    with locked(root):
        return verify_locked(root, archive_id, expected_sha256, identity, restore)


def verify_locked(root, archive_id, expected_sha256, identity, restore):
    with restored_files(root, archive_id, expected_sha256, identity) as (folder, envelope):
        receipt = restore(envelope["backup_id"], folder)
        if (
            receipt.get("status") != "verified"
            or receipt.get("backup_id") != envelope["backup_id"]
            or receipt.get("dump_sha256") != envelope["files"]["database.dump"]["sha256"]
            or receipt.get("inventory_format") != backup.INVENTORY_FORMAT
            or receipt.get("clone_removed") is not True
            or receipt.get("network") != "none"
            or receipt.get("application_started") is not False
        ):
            raise ValueError("Isolated restore and cleanup not confirmed")
    result = {
        "format": retention.FORMAT,
        "archive_id": archive_id,
        "ciphertext_sha256": expected_sha256,
        "status": "restore_verified",
        "verified_at": datetime.now(UTC).isoformat(),
        "recovery": receipt,
    }
    vault.write_json(
        root / "archives" / archive_id / ("verification-" + uuid.uuid4().hex + ".json"), result
    )
    return result


def inventory(root, marker):
    archives = {}
    paths = sorted((root / "archives").iterdir())
    if len(paths) > 1000:
        raise ValueError("Archive inventory limit exceeded")
    for path in paths:
        if not re.fullmatch(vault.SEALED_ID, path.name):
            raise ValueError("Unrecognized archive directory")
        observed = archive_files(path)
        entry = {"id": path.name, "files": observed, "restore_verified": False}
        if {"envelope.json", "bundle.age"} <= observed.keys():
            envelope = read_json(path / "envelope.json")
            load_archive(root, path.name, observed["bundle.age"]["sha256"])
            entry["ciphertext_sha256"] = observed["bundle.age"]["sha256"]
            entry["snapshot_files"] = envelope["files"]
            for name in observed:
                if not name.startswith("verification-"):
                    continue
                receipt = read_json(path / name)
                if (
                    receipt.get("format") == retention.FORMAT
                    and receipt.get("archive_id") == path.name
                    and receipt.get("ciphertext_sha256") == entry["ciphertext_sha256"]
                    and receipt.get("status") == "restore_verified"
                ):
                    entry["restore_verified"] = True
        archives.setdefault(path.name.rsplit("-", 1)[0], []).append(entry)
    rows = []
    paths = sorted((root / "snapshots").iterdir())
    if len(paths) > 1000:
        raise ValueError("Snapshot inventory limit exceeded")
    for folder in paths:
        identifier = folder.name
        if not re.fullmatch(vault.BACKUP_ID, identifier):
            raise ValueError("Unrecognized snapshot directory")
        observed = files(folder)
        row = {
            "id": identifier,
            "files": observed,
            "bytes": sum(x["bytes"] for x in observed.values()),
            "complete": False,
            "restore_verified": False,
            "archives": archives.pop(identifier, []),
        }
        try:
            _, _, summary = enrolled(root, identifier, marker)
        except (ValueError, KeyError, FileNotFoundError):
            pass  # Incomplete/unsupported copies are preserved, never deletion candidates.
        else:
            row.update(summary, complete=True)
            row["restore_verified"] = any(
                a["restore_verified"] and a.get("snapshot_files") == observed
                for a in row["archives"]
            )
        rows.append(row)
    # Archive-only members remain bound to the plan, even after plaintext removal.
    return rows, archives


def build_plan(root, *, at=None, expires_at=None):
    with locked(root) as marker:
        return plan_locked(root, marker, at=at, expires_at=expires_at)


def plan_locked(root, marker, *, at=None, expires_at=None):
    at = at or datetime.now(UTC).isoformat()
    expires_at = expires_at or (retention.instant(at) + timedelta(minutes=15)).isoformat()
    rows, archives = inventory(root, marker)
    value = retention.plan(
        rows,
        read_json(root / "policy.json"),
        store_id=marker["store_id"],
        at=at,
        expires_at=expires_at,
    )
    body = {k: v for k, v in value.items() if k != "sha256"}
    body["retained_archives"] = archives
    return {**body, "sha256": digest(body)}
