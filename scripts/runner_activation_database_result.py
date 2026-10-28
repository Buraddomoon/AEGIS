"""Private PostgreSQL proof transport and exclusive local capture, never authorization."""

import hashlib
import json
import os
from pathlib import Path

import runner_pki as pki
from aegis.domain.validation import digest
from aegis.lab_runner.continuity import ContinuityError
from aegis.lab_runner.persisted_probe import FORMAT, MAX_INPUT, MAX_OUTPUT, _unique
from aegis.lab_runner.persisted_probe import decode as decode_request
from aegis.lab_runner.persisted_review import expected_proofs
from aegis.lab_runner.protocol import RunnerIdentity
from runner_activation_intents import DATABASE_REVIEW_ROLES, _hash
from runner_activation_metadata import ActivationError

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / ".local/pki-activation-runtime"


def context(identity, old_descriptor_sha256):
    if not isinstance(identity, RunnerIdentity):
        raise ActivationError("database_reader_identity_required")
    _hash(old_descriptor_sha256)
    return {
        "format": FORMAT,
        "identity": identity.model_dump(mode="json"),
        "old_descriptor_sha256": old_descriptor_sha256,
    }


def request(identity, old_descriptor_sha256, password):
    """Private bytes only. Never include these bytes or password hashes in receipts."""
    public = context(identity, old_descriptor_sha256)
    if type(password) is not str or not 1 <= len(password) <= 512 or "\0" in password:
        raise ActivationError("database_reader_private_request_invalid")
    try:
        payload = json.dumps(
            {**public, "database_password": password},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        if len(payload) > MAX_INPUT:
            raise ContinuityError("input_limit")
        decode_request(payload, digest(public))
        return payload, digest(public)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ActivationError("database_reader_private_request_invalid") from None


def decode(raw, identity, old_descriptor_sha256):
    expected = context(identity, old_descriptor_sha256)
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_OUTPUT:
            raise ContinuityError("output_limit")
        bundle = json.loads(raw, object_pairs_hook=_unique)
        proof_sha256 = digest(bundle)
        parsed_identity, _ = expected_proofs(bundle, proof_sha256)
        if (
            digest(parsed_identity.model_dump(mode="json")) != digest(expected["identity"])
            or bundle["old_descriptor_sha256"] != old_descriptor_sha256
        ):
            raise ContinuityError("context_mismatch")
        return bundle, proof_sha256
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        raise ActivationError("database_reader_private_reply_invalid") from None


def _operation(store, role, identity, old_descriptor_sha256):
    if role not in DATABASE_REVIEW_ROLES:
        raise ActivationError("database_reader_role_required")
    state = store.review()
    item = state["resources"].get(role)
    expected_context = digest(context(identity, old_descriptor_sha256))
    if (
        item is None
        or item["state"] not in {"START_REQUESTED", "REMOVAL_REQUESTED", "ABSENT"}
        or item.get("start", {}).get("request_context_sha256") != expected_context
    ):
        raise ActivationError("database_reader_started_context_required")
    return state, store.summary()["id"]


def capture(store, role, raw, identity, old_descriptor_sha256, *, root=DEFAULT_ROOT):
    """Write once outside the intent hashchain; preserve ambiguous output for review."""
    original, operation = _operation(store, role, identity, old_descriptor_sha256)
    bundle, proof_sha256 = decode(raw, identity, old_descriptor_sha256)
    encoded = (
        json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()
    if len(encoded) > MAX_OUTPUT:
        raise ActivationError("database_reader_private_reply_invalid")
    folder = pki.private_directory(root, create=True)
    folder = pki.private_directory(folder / operation, create=True)
    path = folder / (role + "-proofs.json")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        pki.sync(folder)
        if pki.read(path, modes=(0o600,), maximum=MAX_OUTPUT) != encoded:
            raise ActivationError("database_reader_capture_changed")
        if digest(store.review()) != digest(original):
            raise ActivationError("database_reader_capture_operation_changed")
    except (OSError, ValueError):
        # No unlink/retry/overwrite after a partial write or fsync failure.
        raise ActivationError("database_reader_capture_unconfirmed") from None
    return {
        "format": "aegis-database-reader-capture/1",
        "operation_id": operation,
        "role": role,
        "plan_sha256": original["header"]["plan_sha256"],
        "scope_sha256": original["header"]["scope_sha256"],
        "request_context_sha256": digest(context(identity, old_descriptor_sha256)),
        "proof_bundle_sha256": proof_sha256,
        "file_sha256": hashlib.sha256(encoded).hexdigest(),
        "proofs_reviewed": len(bundle["proofs"]),
        "environment_version": bundle["environment_version"],
        "capture_verified": True,
        "database_volume_binding_verified": False,
        "journal_verified": False,
        "authorization_verified": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }


def load(store, role, expected_sha256, identity, old_descriptor_sha256, *, root=DEFAULT_ROOT):
    """Reload with an independently retained canonical SHA, never infer it from disk."""
    _hash(expected_sha256)
    _, operation = _operation(store, role, identity, old_descriptor_sha256)
    folder = pki.private_directory(root)
    folder = pki.private_directory(folder / operation)
    raw = pki.read(folder / (role + "-proofs.json"), modes=(0o600,), maximum=MAX_OUTPUT)
    bundle, actual_sha256 = decode(raw, identity, old_descriptor_sha256)
    if actual_sha256 != expected_sha256:
        raise ActivationError("database_reader_capture_integrity_mismatch")
    return bundle
