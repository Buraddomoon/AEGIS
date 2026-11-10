"""Private one-use identity-assay records; storage is not authorization or TLS proof."""

import errno
import json
import os
import stat
from datetime import datetime, timedelta
from pathlib import Path

import runner_pki as pki
from aegis.domain.validation import digest
from build_review_runner import _write
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_metadata import ActivationError, _unique

ROOT = Path(__file__).resolve().parents[1] / ".local/pki-identity-runtime"
FORMAT = "aegis-identity-assay-artifact/1"
MAX_BYTES = 256 * 1024
INVENTORY_FAILURE_CODES = frozenset(
    {
        "identity_artifact_store_closed",
        "identity_artifact_operation_or_directory_changed",
        "identity_artifact_unexpected_inventory",
        "identity_artifact_empty_inventory",
        "identity_artifact_inventory_changed",
        "identity_artifact_unsafe_file",
        "identity_artifact_size_exceeded",
        "identity_artifact_json_invalid",
        "identity_artifact_integrity_mismatch",
        "identity_artifact_encoding_mismatch",
        "private_directory_required",
        "unsafe_path",
        "intent_session_not_writable",
        "intent_lock_or_directory_changed",
        "intent_history_changed",
        "intent_partial_or_unexpected_history",
        "intent_history_invalid",
        "identity_artifact_permission_denied",
        "identity_artifact_missing",
        "identity_artifact_io_unconfirmed",
        "identity_artifact_inventory_unconfirmed",
    }
)
NAMES = frozenset(
    {
        "requested",
        "network-create-gate",
        "network-lifecycle",
        "server-create-gate",
        "server-start-gate",
        "server-running-gate",
        "server-lifecycle",
        "client-request",
        "client-create-gate",
        "client-start-gate",
        "client-exited-gate",
        "client-lifecycle",
        "cleanup",
        "receipt",
    }
)


def inventory_failure_code(error):
    """Closed diagnostics only; never serialize paths or arbitrary exception text."""
    if (
        isinstance(error, (ActivationError, pki.PKIError))
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in INVENTORY_FAILURE_CODES
    ):
        return error.args[0]
    if isinstance(error, OSError):
        if error.errno in {errno.EACCES, errno.EPERM}:
            return "identity_artifact_permission_denied"
        if error.errno == errno.ENOENT:
            return "identity_artifact_missing"
        return "identity_artifact_io_unconfirmed"
    return "identity_artifact_inventory_unconfirmed"


def _encode(value):
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    except (TypeError, ValueError, RecursionError):
        raise ActivationError("identity_artifact_json_invalid") from None
    if len(raw) > MAX_BYTES:
        raise ActivationError("identity_artifact_size_exceeded")
    return raw


def _name(name):
    if not isinstance(name, str) or name not in NAMES:
        raise ActivationError("identity_artifact_name_not_allowed")
    return name + ".json"


def decode_record(raw, name, anchor):
    """Closed historical integrity check; never admission or a current lease."""
    _name(name)
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ActivationError("identity_artifact_size_exceeded")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ActivationError("identity_artifact_json_invalid") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"format", *anchor, "name", "recorded_at", "body_sha256", "body"}
        or value["format"] != FORMAT
        or value["name"] != name
        or any(value[key] != expected for key, expected in anchor.items())
        or not isinstance(value["body"], dict)
        or digest(value["body"]) != value["body_sha256"]
        or datetime.fromisoformat(value["recorded_at"]).utcoffset() != timedelta(0)
    ):
        raise ActivationError("identity_artifact_integrity_mismatch")
    if _encode(value) != raw:
        raise ActivationError("identity_artifact_encoding_mismatch")
    return value


class IdentityArtifacts:
    """Trusted host coordinator only; fixed names, no overwrite or resume writer.

    Records accept only JSON objects produced by internal normalized reviewers.
    Callers must never supply keys, passwords, raw Docker output or exception text.
    O_EXCL retains even a partial failed write as a fence. A successful write has
    flushed the file and directory; a partial record cannot pass review. Hashes
    detect changes relative to retained receipts, not a malicious local owner.
    Cleanup evidence remains writable after lease expiry/operation closure; this
    class never creates a new operational lease or performs native effects.
    """

    def __init__(self, confirmation, *, root=ROOT):
        self.fd = None
        if not isinstance(confirmation, ConfirmedPlan):
            raise ActivationError("identity_artifact_confirmed_plan_required")
        if confirmation._guard()["resources"]:
            raise ActivationError("identity_artifact_new_operation_required")
        self.confirmation = confirmation
        self.anchor = {
            "operation_id": confirmation.operation,
            "begin_sha256": confirmation.begin_sha256,
            "plan_sha256": confirmation.plan_sha256,
            "scope_sha256": confirmation.scope,
        }
        # operation_id was validated by the durable intent's UUID parser.
        self.root = pki.private_directory(root, create=True)
        self.folder = self.root / confirmation.operation
        try:
            self.folder.mkdir(mode=0o700)  # Existing folder is never adopted.
            pki.sync(self.root)
            self.fd = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            requested = self.write(
                "requested",
                {
                    "tool_commit": confirmation.artifact["tool_commit"],
                    "pki_manifest_sha256": confirmation.artifact["pki"]["manifest_sha256"],
                    "runner_image": confirmation.artifact["metadata"]["images"]["runner"]["id"],
                    "confirmed_at": confirmation.confirmed_at.isoformat(),
                    "expires_at": confirmation.expires.isoformat(),
                    "normal_operation_permitted": False,
                },
            )
            # A fresh operation must not reuse this plan's consumed scope. Keep
            # the fence with the immutable plan, independently of runtime root.
            use = {
                "format": "aegis-identity-assay-plan-use/1",
                **self.anchor,
                "requested_artifact_sha256": requested,
            }
            _write(confirmation.path.parent / "identity-assay-requested.json", _encode(use))
            self.plan_use_sha256 = digest(use)
            if confirmation._guard()["resources"]:
                raise ActivationError("identity_artifact_new_operation_required")
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _check(self):
        if self.fd is None:
            raise ActivationError("identity_artifact_store_closed")
        pki.private_directory(self.root)
        info = pki.private_directory(self.folder).stat()
        opened = os.fstat(self.fd)
        c = self.confirmation
        state, summary = c.store.review(), c.store.summary()
        if (
            (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)
            or summary["id"] != self.anchor["operation_id"]
            or summary["begin_sha256"] != self.anchor["begin_sha256"]
            or state["header"]
            != {
                "plan_id": c.artifact["id"],
                "plan_sha256": self.anchor["plan_sha256"],
                "scope_sha256": self.anchor["scope_sha256"],
            }
        ):
            raise ActivationError("identity_artifact_operation_or_directory_changed")

    def write(self, name, body):
        filename = _name(name)
        self._check()
        if not isinstance(body, dict):
            raise ActivationError("identity_artifact_object_required")
        # No default=str: objects/NaN/bytes must not silently become evidence.
        body = json.loads(_encode(body))
        envelope = {
            "format": FORMAT,
            **self.anchor,
            "name": name,
            "recorded_at": pki.clock().isoformat(),
            "body_sha256": digest(body),
            "body": body,
        }
        raw = _encode(envelope)
        fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)
        self._check()
        # Verify bytes/permissions before the caller can proceed to an effect.
        if self.read(name) != envelope:
            raise ActivationError("identity_artifact_write_unconfirmed")
        return digest(envelope)

    def read(self, name):
        filename = _name(name)
        self._check()
        fd = os.open(
            filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > MAX_BYTES
            ):
                raise ActivationError("identity_artifact_unsafe_file")
            raw = stream.read(MAX_BYTES + 1)
        value = decode_record(raw, name, self.anchor)
        self._check()
        return value

    def inventory(self):
        self._check()
        names = self._names()
        if not names:
            raise ActivationError("identity_artifact_empty_inventory")
        if any(name not in {_name(key) for key in NAMES} for name in names):
            raise ActivationError("identity_artifact_unexpected_inventory")
        result = {name[:-5]: digest(self.read(name[:-5])) for name in names}
        if self._names() != names:
            raise ActivationError("identity_artifact_inventory_changed")
        return result

    def _names(self):
        self._check()
        # The pinned descriptor was opened while the directory was empty.
        # Btrfs can retain that older enumeration view on the same open file
        # description even after openat writes/fsync. Open a fresh reader rooted
        # at the pinned directory; never reopen/adopt a path supplied by a caller.
        fd = os.open(
            ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd
        )
        try:
            names = sorted(os.listdir(fd))
        finally:
            os.close(fd)
        self._check()
        return names
