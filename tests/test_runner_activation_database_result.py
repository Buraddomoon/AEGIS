"""Proof request/capture on temporary files and SQLite, no original lab or Docker."""

import copy
import json
import os
import stat
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner.persisted_probe import decode as decode_request
from aegis.lab_runner.protocol import RunnerIdentity
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_database_result as results  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def identity(bundle):
    return RunnerIdentity.model_validate(bundle["identity"])


@pytest.fixture
def store(tmp_path, identity, bundle):
    with ActivationIntents(tmp_path / "intents") as value:
        value.begin(uuid4().hex, "a" * 64, "b" * 64)
        value.request("db")
        value.append("observed", {"role": "db", "resource_id": "c" * 64})
        value.request("database-review-before")
        value.append("observed", {"role": "database-review-before", "resource_id": "d" * 64})
        value.append(
            "database_review_start_requested",
            {
                "role": "database-review-before",
                "recipe_sha256": "e" * 64,
                "gates_sha256": "f" * 64,
                "request_context_sha256": digest(
                    results.context(identity, bundle["old_descriptor_sha256"])
                ),
            },
        )
        yield value


def capture(store, bundle, identity, tmp_path):
    return results.capture(
        store,
        "database-review-before",
        json.dumps(bundle).encode(),
        identity,
        bundle["old_descriptor_sha256"],
        root=tmp_path / "capture",
    )


def test_private_request_roundtrips_and_public_fingerprint_never_depends_on_password(
    identity, bundle
):
    first, second = "private-password-one", "private-password-two"
    one, one_sha = results.request(identity, bundle["old_descriptor_sha256"], first)
    two, two_sha = results.request(identity, bundle["old_descriptor_sha256"], second)
    assert one != two and one_sha == two_sha
    actual_identity, actual_descriptor, password = decode_request(one, one_sha)
    assert actual_identity == identity and actual_descriptor == bundle["old_descriptor_sha256"]
    assert password == first
    assert "password" not in json.dumps(results.context(identity, actual_descriptor))


@pytest.mark.parametrize("password", [None, b"secret", "", "x" * 513, "bad\0value", {}, True])
def test_invalid_secret_rejected_without_diagnostics(identity, bundle, password):
    with pytest.raises(results.ActivationError, match="private_request_invalid") as caught:
        results.request(identity, bundle["old_descriptor_sha256"], password)
    assert "bad" not in str(caught.value)


def test_private_reply_decoder_supports_more_than_metadata_limit_and_exact_original_context(
    bundle, identity
):
    raw = b" " * 65536 + json.dumps(bundle).encode()
    actual, sha = results.decode(raw, identity, bundle["old_descriptor_sha256"])
    assert actual == bundle and sha == digest(bundle)


@pytest.mark.parametrize(
    "scene",
    [
        "empty",
        "text",
        "duplicate",
        "deep",
        "oversize",
        "str",
        "identity",
        "descriptor",
        "flag",
        "proof_hash",
        "extra",
        "bool_count",
    ],
)
def test_invalid_or_rebound_private_output_fails_closed(bundle, identity, scene):
    raw = json.dumps(bundle).encode()
    if scene == "empty":
        raw = b""
    elif scene == "text":
        raw = b"private-password-sentinel"
    elif scene == "duplicate":
        raw = b'{"format":"a","format":"b"}'
    elif scene == "deep":
        raw = b"[" * 2000 + b"]" * 2000
    elif scene == "oversize":
        raw = b" " * (results.MAX_OUTPUT + 1)
    elif scene == "str":
        raw = raw.decode()
    else:
        changed = copy.deepcopy(bundle)
        if scene == "identity":
            identity = identity.model_copy(update={"runner_id": uuid4()})
        elif scene == "descriptor":
            changed["old_descriptor_sha256"] = "f" * 64
        elif scene == "flag":
            changed["database_volume_binding_verified"] = True
        elif scene == "proof_hash":
            changed["proofs_sha256"] = "f" * 64
        elif scene == "extra":
            changed["private-password-sentinel"] = True
        elif scene == "bool_count":
            changed["review"]["dispatches_examined"] = True
        raw = json.dumps(changed).encode()
    with pytest.raises(results.ActivationError, match="private_reply_invalid") as caught:
        results.decode(raw, identity, bundle["old_descriptor_sha256"])
    assert "private-password-sentinel" not in str(caught.value)


def test_capture_is_exclusive_private_and_durable_with_no_proofs_in_public_receipt(
    store, bundle, identity, tmp_path
):
    receipt = capture(store, bundle, identity, tmp_path)
    root = tmp_path / "capture"
    folder = root / store.summary()["id"]
    file = folder / "database-review-before-proofs.json"
    assert stat.S_IMODE(root.stat().st_mode) == stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert receipt["capture_verified"] and receipt["proofs_reviewed"] == 1
    assert receipt["proof_bundle_sha256"] == digest(bundle)
    assert bundle["proofs"][0]["spec"]["marker"] not in json.dumps(receipt)
    assert all(
        receipt[key] is False
        for key in (
            "database_volume_binding_verified",
            "journal_verified",
            "authorization_verified",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    loaded = results.load(
        store,
        "database-review-before",
        digest(bundle),
        identity,
        bundle["old_descriptor_sha256"],
        root=root,
    )
    assert loaded == bundle
    before = file.read_bytes()
    with pytest.raises(results.ActivationError, match="capture_unconfirmed"):
        capture(store, bundle, identity, tmp_path)
    assert file.read_bytes() == before
    assert len(list(store.folder.iterdir())) == len(store.events)


@pytest.mark.parametrize(
    "scene",
    [
        "unknown_role",
        "not_started",
        "wrong_context",
        "wrong_hash",
        "edited",
        "mode",
        "symlink",
        "hardlink",
    ],
)
def test_capture_or_reload_never_accepts_unpinned_state_or_unsafe_artifact(
    store, bundle, identity, tmp_path, scene
):
    root = tmp_path / "capture"
    if scene == "unknown_role":
        with pytest.raises(results.ActivationError, match="role_required"):
            results.capture(
                store, "api", b"{}", identity, bundle["old_descriptor_sha256"], root=root
            )
        return
    if scene == "not_started":
        store.request("database-review-after")
        with pytest.raises(results.ActivationError, match="started_context_required"):
            results.capture(
                store,
                "database-review-after",
                b"{}",
                identity,
                bundle["old_descriptor_sha256"],
                root=root,
            )
        return
    if scene == "wrong_context":
        with pytest.raises(results.ActivationError, match="started_context_required"):
            results.capture(store, "database-review-before", b"{}", identity, "f" * 64, root=root)
        return
    capture(store, bundle, identity, tmp_path)
    file = root / store.summary()["id"] / "database-review-before-proofs.json"
    expected = digest(bundle)
    if scene == "wrong_hash":
        expected = "f" * 64
    elif scene == "edited":
        changed = copy.deepcopy(bundle)
        changed["environment_version"] += 1
        changed["review"]["environment_version"] += 1
        file.write_text(json.dumps(changed))
    elif scene == "mode":
        file.chmod(0o644)
    elif scene == "symlink":
        target = tmp_path / "external"
        file.rename(target)
        file.symlink_to(target)
    elif scene == "hardlink":
        os.link(file, tmp_path / "second-name")
    with pytest.raises((ValueError, OSError)):
        results.load(
            store,
            "database-review-before",
            expected,
            identity,
            bundle["old_descriptor_sha256"],
            root=root,
        )


def test_file_fsync_failure_preserves_artifact_and_never_produces_success(
    store, bundle, identity, tmp_path, monkeypatch
):
    original = os.fsync

    def fail(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("private-password-sentinel")
        return original(fd)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(results.ActivationError, match="capture_unconfirmed") as caught:
        capture(store, bundle, identity, tmp_path)
    assert "private-password-sentinel" not in str(caught.value)
    assert (
        tmp_path / "capture" / store.summary()["id"] / "database-review-before-proofs.json"
    ).exists()
