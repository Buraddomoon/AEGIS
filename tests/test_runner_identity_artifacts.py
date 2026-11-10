"""Private durable records with real temporary plans/PKI/intents; no native Docker."""

import errno
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from test_runner_activation_network_gates import code as code
from test_runner_activation_network_gates import context as context
from test_runner_activation_network_gates import material as material

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_artifacts as artifacts  # noqa: E402


@pytest.mark.parametrize(
    "error,expected",
    [
        (
            artifacts.ActivationError("identity_artifact_unsafe_file"),
            "identity_artifact_unsafe_file",
        ),
        (
            PermissionError(errno.EACCES, "private-sensitive-sentinel"),
            "identity_artifact_permission_denied",
        ),
        (
            FileNotFoundError(errno.ENOENT, "private-sensitive-sentinel"),
            "identity_artifact_missing",
        ),
        (OSError(errno.EIO, "private-sensitive-sentinel"), "identity_artifact_io_unconfirmed"),
        (ValueError("private-sensitive-sentinel"), "identity_artifact_inventory_unconfirmed"),
        (
            artifacts.ActivationError("private-sensitive-sentinel"),
            "identity_artifact_inventory_unconfirmed",
        ),
        (
            TypeError({"private-sensitive-sentinel": True}),
            "identity_artifact_inventory_unconfirmed",
        ),
    ],
)
def test_inventory_diagnostics_use_only_closed_codes_and_never_exception_text(error, expected):
    assert artifacts.inventory_failure_code(error) == expected
    assert "private-sensitive-sentinel" not in artifacts.inventory_failure_code(error)


@pytest.fixture
def records(context, tmp_path):
    confirmation, world = context
    with artifacts.IdentityArtifacts(confirmation, root=tmp_path / "records") as value:
        yield value, confirmation, world


def test_durable_record_binds_original_operation_and_has_private_permissions(records):
    value, c, world = records
    proof = {"gate": {"checked": True}, "synthetic": True}
    expected = value.write("client-create-gate", proof)
    proof["gate"]["checked"] = False
    observed = value.read("client-create-gate")
    assert observed["body"] == {"gate": {"checked": True}, "synthetic": True}
    assert observed["operation_id"] == c.operation
    assert observed["begin_sha256"] == c.begin_sha256
    assert observed["plan_sha256"] == c.plan_sha256
    assert observed["scope_sha256"] == c.scope
    assert artifacts.digest(observed) == expected
    assert value.inventory() == {
        "client-create-gate": expected,
        "requested": artifacts.digest(value.read("requested")),
    }
    assert stat.S_IMODE(value.folder.stat().st_mode) == 0o700
    assert stat.S_IMODE(value.root.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in value.folder.iterdir())
    assert world.effects == [] and c.store.review()["resources"] == {}


def test_existing_operation_folder_and_existing_record_cannot_be_adopted_or_overwritten(records):
    value, c, _ = records
    original = (value.folder / "requested.json").read_bytes()
    with pytest.raises(FileExistsError):
        value.write("requested", {})
    with pytest.raises(FileExistsError):
        artifacts.IdentityArtifacts(c, root=value.root)
    assert (value.folder / "requested.json").read_bytes() == original


def test_plan_scope_cannot_be_replayed_by_another_operation_or_runtime_root(records, tmp_path):
    from runner_activation_intents import ActivationIntents

    value, c, _ = records
    path = c.path.parent / "identity-assay-requested.json"
    before = path.read_bytes()
    fence = json.loads(before)
    assert artifacts.digest(fence) == value.plan_use_sha256
    assert fence["requested_artifact_sha256"] == artifacts.digest(value.read("requested"))
    with ActivationIntents(tmp_path / "other-intents") as store:
        store.begin(c.artifact["id"], c.plan_sha256, c.scope)
        other = artifacts.ConfirmedPlan(
            c.path, c.plan_sha256, store, c.scope, c.expires.isoformat()
        )
        with pytest.raises(FileExistsError):
            artifacts.IdentityArtifacts(other, root=tmp_path / "other-records")
        assert store.review()["resources"] == {}
    assert path.read_bytes() == before


@pytest.mark.parametrize("name", ["../receipt", "receipt.json", "/tmp/receipt", "", "worker", 1])
def test_only_closed_record_names_are_accepted(records, name):
    value, _, _ = records
    before = value.inventory()
    with pytest.raises(artifacts.ActivationError, match="name_not_allowed"):
        value.write(name, {})
    assert value.inventory() == before


@pytest.mark.parametrize("body", [[], b"secret", {"value": float("nan")}, {"value": object()}])
def test_non_objects_non_json_and_non_finite_numbers_do_not_become_evidence(records, body):
    value, _, _ = records
    with pytest.raises(artifacts.ActivationError):
        value.write("receipt", body)
    assert not (value.folder / "receipt.json").exists()


def test_size_limit_applies_to_complete_envelope_before_any_write(records):
    value, _, _ = records
    with pytest.raises(artifacts.ActivationError, match="size_exceeded"):
        value.write("receipt", {"oversized": "x" * artifacts.MAX_BYTES})
    assert not (value.folder / "receipt.json").exists()


def test_normalized_review_larger_than_docker_metadata_cap_round_trips(records):
    value, _, _ = records
    body = {"normalized_review": "x" * (96 * 1024)}
    expected = value.write("client-lifecycle", body)
    assert value.read("client-lifecycle")["body"] == body
    assert value.inventory()["client-lifecycle"] == expected


@pytest.mark.parametrize("scene", ["symlink", "hardlink", "fifo", "permissions", "truncated"])
def test_unsafe_and_partial_records_cannot_pass_review(records, tmp_path, scene):
    value, _, _ = records
    target = value.folder / "receipt.json"
    source = tmp_path / "external"
    source.write_bytes(b"confidential-sentinel")
    source.chmod(0o600)
    if scene == "symlink":
        target.symlink_to(source)
    elif scene == "hardlink":
        os.link(source, target)
    elif scene == "fifo":
        os.mkfifo(target, 0o600)
    elif scene == "permissions":
        value.write("receipt", {})
        target.chmod(0o644)
    else:
        target.write_bytes(b'{"format":')
        target.chmod(0o600)
    with pytest.raises((OSError, ValueError)):
        value.read("receipt")
    with pytest.raises(FileExistsError):
        value.write("receipt", {})
    assert source.read_bytes() == b"confidential-sentinel"


@pytest.mark.parametrize("field", ["body", "operation_id", "begin_sha256", "name", "extra"])
def test_tampering_and_cross_operation_records_are_rejected(records, field):
    value, _, _ = records
    value.write("receipt", {"normal_operation_permitted": False})
    target = value.folder / "receipt.json"
    item = json.loads(target.read_bytes())
    item[field] = {"normal_operation_permitted": True} if field == "body" else "wrong"
    target.write_bytes(artifacts._encode(item))
    with pytest.raises(artifacts.ActivationError, match="integrity_mismatch"):
        value.inventory()


def test_cleanup_records_can_be_saved_after_expiry_and_durable_operation_closure(
    records, monkeypatch
):
    value, c, _ = records
    monkeypatch.setattr(artifacts.pki, "clock", lambda: c.expires)
    with pytest.raises(artifacts.ActivationError, match="scope_or_budget_unconfirmed"):
        c._guard()
    c.store.append("closed", {"evidence_sha256": "e" * 64})
    value.write("cleanup", {"operation_closed": True})
    assert value.read("cleanup")["body"]["operation_closed"] is True
    assert value.read("requested")["body"]["expires_at"] == c.expires.isoformat()


def test_directory_substitution_cannot_redirect_existing_store(records):
    value, _, _ = records
    old = value.folder.with_name(value.folder.name + "-preserved")
    value.folder.rename(old)
    value.folder.mkdir(mode=0o700)
    with pytest.raises(artifacts.ActivationError, match="directory_changed"):
        value.write("cleanup", {})
    assert list(value.folder.iterdir()) == []
    assert (old / "requested.json").exists()


def test_directory_symlink_and_unknown_inventory_are_rejected(records, tmp_path):
    value, _, _ = records
    (value.folder / "unexpected.log").write_text("private")
    with pytest.raises(artifacts.ActivationError, match="unexpected_inventory"):
        value.inventory()
    value.folder.rename(tmp_path / "preserved")
    value.folder.symlink_to(tmp_path / "preserved", target_is_directory=True)
    with pytest.raises(artifacts.pki.PKIError, match="unsafe_path"):
        value.write("cleanup", {})


def test_failed_fsync_leaves_one_use_fence_and_cannot_silently_retry(records, monkeypatch):
    value, _, _ = records
    with monkeypatch.context() as patch:
        patch.setattr(artifacts.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("fixture")))
        with pytest.raises(OSError):
            value.write("client-create-gate", {"checked": True})
    with pytest.raises(FileExistsError):
        value.write("client-create-gate", {"checked": True})


def test_closed_store_has_no_write_or_review_capability(records):
    value, _, _ = records
    value.close()
    value.close()
    with pytest.raises(artifacts.ActivationError, match="store_closed"):
        value.write("cleanup", {})
    with pytest.raises(artifacts.ActivationError, match="store_closed"):
        value.read("requested")
