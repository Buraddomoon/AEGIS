"""Fixed operation-local PostgreSQL authentication policy, no database or daemon IO."""

import hashlib
import os
from pathlib import Path

import runner_pki as pki
from runner_activation_metadata import ActivationError

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / ".local/pki-activation-runtime"
FILENAME = "database-review-pg_hba.conf"
CONTENT = (
    "# AEGIS isolated PostgreSQL review; no include, trust, peer or DNS rules.\n"
    "local all all reject\n"
    "local replication all reject\n"
    "host aegis aegis_app 127.0.0.1/32 scram-sha-256\n"
    "host all all 0.0.0.0/0 reject\n"
    "host all all ::/0 reject\n"
    "host replication all 0.0.0.0/0 reject\n"
    "host replication all ::/0 reject\n"
).encode("ascii")
CONTENT_SHA256 = hashlib.sha256(CONTENT).hexdigest()


def _folder(store, root, *, create=False):
    state = store.review()
    if state["closed"]:
        raise ActivationError("database_policy_open_operation_required")
    operation = store.summary()["id"]
    parent = pki.private_directory(root, create=create)
    return pki.private_directory(parent / operation, create=create)


def prepare(store, *, root=DEFAULT_ROOT):
    """Exclusive file outside the intent chain, no effects on the original HBA."""
    folder = _folder(store, root, create=True)
    path = folder / FILENAME
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(CONTENT)
            output.flush()
            # Nonsecret policy readable by UID70 inside a single-file RO bind.
            # The containing host directories remain0700; no secret directory mount.
            os.fchmod(output.fileno(), 0o444)
            os.fsync(output.fileno())
        pki.sync(folder)
        return verify(store, root=root)
    except (OSError, ValueError):
        # Ambiguous publication must not be overwritten or automatically removed.
        raise ActivationError("database_policy_preparation_unconfirmed") from None


def verify(store, *, root=DEFAULT_ROOT):
    """Before every effect, exact fixed bytes/mode/owner/single link, no free path."""
    original = store.review()
    folder = _folder(store, root)
    try:
        path = folder / FILENAME
        if pki.read(path, modes=(0o444,), maximum=4096) != CONTENT:
            raise ActivationError("database_policy_content_mismatch")
        if store.review() != original:
            raise ActivationError("database_policy_operation_changed")
    except (OSError, ValueError):
        raise ActivationError("database_policy_verification_failed") from None
    return {
        "format": "aegis-database-review-authentication-policy/1",
        "operation_id": store.summary()["id"],
        "path": str(path),
        "content_sha256": CONTENT_SHA256,
        "fixed_policy_verified": True,
        "original_hba_modified": False,
        "database_credentials_changed": False,
        "runtime_mount_verified": False,
        "authentication_verified": False,
        "effects_authorized": False,
        "normal_operation_permitted": False,
    }
