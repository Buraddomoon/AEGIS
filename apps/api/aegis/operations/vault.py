"""Host-only age/X25519 backup envelopes; never imported by the API or worker.

The framing below is data packaging, not a cryptographic construction. age owns
key wrapping, authenticated encryption, chunk order and final-stream validation.
"""

import hashlib
import io
import json
import os
import re
import stat
import struct
import tempfile
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

FORMAT = "aegis-backup-vault/1"
MAGIC = b"AEGIS-BACKUP-CONTENT/1\n"
MAX_MANIFEST = 4 * 1024 * 1024
MAX_CONTENT = 1024 * 1024 * 1024
MAX_CIPHERTEXT = MAX_CONTENT + 1024 * 1024
CHUNK = 64 * 1024
BACKUP_ID = r"\d{8}T\d{6}Z-[a-f0-9]{32}"
SEALED_ID = BACKUP_ID + r"-[a-f0-9]{32}"


class VaultError(RuntimeError):
    pass


def crypto():
    try:
        import pyrage
    except ImportError:
        raise VaultError("Install the locked host-only backup extra first") from None
    return pyrage


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def no_symlink_parents(path):
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise VaultError("Absolute paths without symlink components are required")


def private_directory(path):
    no_symlink_parents(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise VaultError("Private directories must be owned by this user and mode0700")
    sync_directory(path)
    sync_directory(path.parent)


@contextmanager
def private_file(path, *, maximum=MAX_CIPHERTEXT):
    no_symlink_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > maximum
        ):
            raise VaultError("Private regular unlinked-copy files and size bounds are required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


def write_private(path, content):
    no_symlink_parents(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def write_json(path, value):
    write_private(path, json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")


def hash_stream(stream):
    stream.seek(0)
    value = hashlib.file_digest(stream, "sha256").hexdigest()
    stream.seek(0)
    return value


def generate_key(keys):
    private_directory(keys)
    identity = crypto().x25519.Identity.generate()
    identifier = uuid.uuid4().hex
    path = keys / (identifier + ".agekey")
    write_private(path, (str(identity) + "\n").encode())
    return {"key_id": identifier, "recipient": str(identity.to_public()), "private_path": str(path)}


def load_key(keys, identifier):
    if not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise VaultError("Invalid key ID")
    private_directory(keys)
    with private_file(keys / (identifier + ".agekey"), maximum=1024) as stream:
        value = stream.read().decode().strip()
    try:
        return crypto().x25519.Identity.from_str(value)
    except (ValueError, crypto().IdentityError):
        raise VaultError("Invalid X25519 identity; secret omitted") from None


class ContentReader:
    """Bounded streaming concatenation, preserving source FDs throughout encryption."""

    def __init__(self, manifest, dump):
        if not 0 < len(manifest) <= MAX_MANIFEST:
            raise VaultError("Manifest size outside reviewed bounds")
        self.prefix = io.BytesIO(MAGIC + struct.pack(">I", len(manifest)) + manifest)
        self.dump = dump
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size):
        if size < 0 or size > CHUNK * 16:
            raise VaultError("Unbounded content read refused")
        value = self.prefix.read(size)
        if len(value) < size:
            part = self.dump.read(size - len(value))
            self.digest.update(part)
            value += part
        self.count += len(value)
        if self.count > MAX_CONTENT:
            raise VaultError("Content exceeds reviewed size bound")
        return value


class BoundedWriter:
    def __init__(self, stream):
        self.stream = stream
        self.count = 0

    def write(self, value):
        if self.count + len(value) > MAX_CONTENT:
            raise VaultError("Decrypted content exceeds reviewed size bound")
        written = self.stream.write(value)
        self.count += written
        return written

    def flush(self):
        self.stream.flush()


def seal(folder, identifier, destination, recipient):
    if not re.fullmatch(BACKUP_ID, identifier):
        raise VaultError("Invalid backup ID")
    try:
        public = crypto().x25519.Recipient.from_str(recipient)
    except (ValueError, crypto().RecipientError):
        raise VaultError("Only a valid X25519 age recipient is accepted") from None
    private_directory(folder)
    private_directory(destination)
    sealed_id = identifier + "-" + uuid.uuid4().hex
    target = destination / sealed_id
    target.mkdir(mode=0o700)
    sync_directory(destination)
    with (
        private_file(folder / "manifest.json", maximum=MAX_MANIFEST) as metadata,
        private_file(folder / "database.dump", maximum=MAX_CONTENT) as dump,
    ):
        manifest_bytes = metadata.read()
        manifest = json.loads(manifest_bytes)
        if manifest.get("id") != identifier:
            raise VaultError("Manifest identity mismatch")
        reader = ContentReader(manifest_bytes, dump)
        path = target / "bundle.age.partial"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            try:
                crypto().encrypt_io(reader, output, [public])
            except (crypto().EncryptError, OSError):
                raise VaultError("Encryption failed; private partial copy preserved") from None
            output.flush()
            os.fsync(output.fileno())
        if reader.digest.hexdigest() != manifest.get("dump_sha256"):
            raise VaultError("Source dump changed or its hash does not match")
    path.rename(target / "bundle.age")
    sync_directory(target)
    with private_file(target / "bundle.age") as stream:
        cipher_hash = hash_stream(stream)
        size = os.fstat(stream.fileno()).st_size
    envelope = {
        "format": FORMAT,
        "id": sealed_id,
        "backup_id": identifier,
        "created_at": datetime.now(UTC).isoformat(),
        "recipient": str(public),
        "ciphertext_sha256": cipher_hash,
        "ciphertext_bytes": size,
        "status": "sealed_not_yet_verified",
    }
    # This is the publication marker. Failed/partial copies have no envelope.
    write_json(target / "envelope.json", envelope)
    return envelope


def load_envelope(vault, identifier, expected_hash):
    if not re.fullmatch(SEALED_ID, identifier) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
        raise VaultError("A sealed ID and independently expected SHA256 are required")
    private_directory(vault)
    folder = vault / identifier
    private_directory(folder)
    with private_file(folder / "envelope.json", maximum=16384) as stream:
        envelope = json.load(stream)
    if (
        envelope.get("format") != FORMAT
        or envelope.get("id") != identifier
        or envelope.get("backup_id") != identifier.rsplit("-", 1)[0]
        or envelope.get("ciphertext_sha256") != expected_hash
        or envelope.get("status") != "sealed_not_yet_verified"
    ):
        raise VaultError("Sealed envelope mismatch")
    return folder, envelope


def unpack(stream, folder, identifier):
    if stream.read(len(MAGIC)) != MAGIC:
        raise VaultError("Unsupported decrypted content framing")
    length_bytes = stream.read(4)
    if len(length_bytes) != 4:
        raise VaultError("Truncated decrypted content")
    size = struct.unpack(">I", length_bytes)[0]
    if not 0 < size <= MAX_MANIFEST:
        raise VaultError("Manifest size outside reviewed bounds")
    manifest = stream.read(size)
    if len(manifest) != size or json.loads(manifest).get("id") != identifier:
        raise VaultError("Decrypted manifest mismatch")
    write_private(folder / "manifest.json", manifest)
    fd = os.open(
        folder / "database.dump", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    count = 0
    with os.fdopen(fd, "wb") as out:
        while value := stream.read(CHUNK):
            count += len(value)
            if count > MAX_CONTENT:
                raise VaultError("Dump exceeds reviewed size bound")
            out.write(value)
        out.flush()
        os.fsync(out.fileno())
    if not count:
        raise VaultError("Empty dump refused")
    sync_directory(folder)


@contextmanager
def decrypted(vault, identifier, expected_hash, identity, work):
    folder, envelope = load_envelope(vault, identifier, expected_hash)
    if envelope["recipient"] != str(identity.to_public()):
        raise VaultError("The selected key does not match the recipient")
    private_directory(work)
    with private_file(folder / "bundle.age") as encrypted:
        # Same FD for hash and decryption; never use plaintext source as fallback.
        if (
            hash_stream(encrypted) != expected_hash
            or os.fstat(encrypted.fileno()).st_size != envelope["ciphertext_bytes"]
        ):
            raise VaultError("Ciphertext size or hash mismatch")
        with tempfile.TemporaryDirectory(prefix="verify-", dir=work) as temporary:
            staging = Path(temporary)
            # Unlinked private scratch. No caller can consume partially authenticated data.
            with tempfile.TemporaryFile(dir=staging) as scratch:
                limited = BoundedWriter(scratch)
                try:
                    crypto().decrypt_io(encrypted, limited, [identity])
                except (crypto().DecryptError, OSError):
                    raise VaultError(
                        "Decryption/authentication failed; no content released"
                    ) from None
                limited.flush()
                scratch.seek(0)
                unpack(scratch, staging, envelope["backup_id"])
            yield staging, envelope
