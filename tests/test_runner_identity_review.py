"""Historical integrity inspection after lease/PKI expiry; native boundary remains fixtures."""

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_identity_coordinator import code as code
from test_runner_identity_coordinator import material as material
from test_runner_identity_coordinator import world as world

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_metadata as metadata  # noqa: E402
import runner_identity_review as review  # noqa: E402


@pytest.fixture
def saved(world):
    world.scene = "network_ambiguous"
    result = world.execute()
    pins = [
        world.c.operation,
        world.c.begin_sha256,
        world.c.plan_sha256,
        world.c.scope,
        review.digest(result),
    ]
    return world, result, pins


def test_historical_inspection_uses_no_lease_pki_docker_intents_or_writes(saved, monkeypatch):
    world, result, pins = saved
    folder = world.root / world.c.operation
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in folder.iterdir()}
    effects = list(world.effects)
    monkeypatch.setattr(review.artifacts.pki, "clock", lambda: world.c.expires + timedelta(days=60))
    monkeypatch.setattr(review.artifacts.pki, "openssl", lambda *a, **kw: pytest.fail("no PKI"))
    monkeypatch.setattr(world.c.store, "review", lambda: pytest.fail("no intent/lease"))
    monkeypatch.setattr(review.client.plan, "load_plan", lambda *a, **kw: pytest.fail("no plan"))
    monkeypatch.setattr(metadata, "_execute", lambda *a, **kw: pytest.fail("no native"))
    observed = review.review(*pins, root=world.root)
    assert observed["recorded_assay_status"] == result["status"]
    assert observed["recorded_tls_controls_verified"] is False
    assert observed["native_runtime_rechecked"] is False
    assert observed["plan_use_file_rechecked"] is False
    assert observed["normal_operation_permitted"] is False
    assert effects == world.effects
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in folder.iterdir()}


def test_original_v1_receipts_remain_reviewable_without_invented_diagnostics(saved):
    world, _, pins = saved
    path = world.root / world.c.operation / "receipt.json"
    record = json.loads(path.read_bytes())
    record["body"]["format"] = "aegis-identity-assay-receipt/1"
    record["body"].pop("failure_code")
    record["body"].pop("artifact_inventory_failure_code")
    record["body_sha256"] = pins[-1] = review.digest(record["body"])
    path.write_bytes(review.artifacts._encode(record))
    result = review.review(*pins, root=world.root)
    assert result["recorded_assay_status"] == "identity_assay_failed_and_closed"
    assert result["recorded_tls_controls_verified"] is False


@pytest.mark.parametrize("field", ["failure_code", "artifact_inventory_failure_code"])
def test_unreviewed_diagnostics_cannot_be_published_by_rehashing_receipt(saved, field):
    world, _, pins = saved
    path = world.root / world.c.operation / "receipt.json"
    record = json.loads(path.read_bytes())
    record["body"][field] = "private-sensitive-sentinel"
    record["body_sha256"] = pins[-1] = review.digest(record["body"])
    path.write_bytes(review.artifacts._encode(record))
    with pytest.raises(review.ActivationError, match="saved_artifacts_unconfirmed"):
        review.review(*pins, root=world.root)


def test_cli_explains_a_pinned_unverified_inventory_without_rewriting_or_approving_it(
    saved, monkeypatch, capsys
):
    world, _, pins = saved
    path = world.root / world.c.operation / "receipt.json"
    record = json.loads(path.read_bytes())
    record["body"]["artifact_inventory_verified"] = False
    record["body"]["artifacts"] = None
    record["body"]["artifact_inventory_failure_code"] = "identity_artifact_io_unconfirmed"
    record["body_sha256"] = pins[-1] = review.digest(record["body"])
    path.write_bytes(review.artifacts._encode(record))
    before = path.read_bytes()
    original = review.review
    monkeypatch.setattr(review, "review", lambda *args: original(*args, root=world.root))
    names = ("operation-id", "begin-sha256", "plan-sha256", "scope-sha256", "receipt-body-sha256")
    args = [arg for name, value in zip(names, pins, strict=True) for arg in ("--" + name, value)]
    assert review.main(args) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["reason"] == "recorded_artifact_inventory_unverified"
    assert output["native_runtime_rechecked"] is False
    assert path.read_bytes() == before


@pytest.mark.parametrize("index", range(5))
def test_another_operation_scope_or_retained_hash_cannot_be_substituted(saved, index):
    world, _, pins = saved
    pins[index] = "f" * (32 if index == 0 else 64)
    with pytest.raises(review.ActivationError, match="saved_artifacts_unconfirmed"):
        review.review(*pins, root=world.root)


@pytest.mark.parametrize("scene", ["rehashed_gate", "missing", "extra", "symlink", "partial"])
def test_saved_inventory_tampering_cannot_be_hidden_by_rehashing_an_individual_record(
    saved, scene, tmp_path
):
    world, _, pins = saved
    folder = world.root / world.c.operation
    target = folder / "network-create-gate.json"
    if scene == "missing":
        target.unlink()
    elif scene == "extra":
        (folder / "confidential-sentinel.log").write_text("confidential-sentinel")
    elif scene == "symlink":
        outside = tmp_path / "secret"
        outside.write_text("confidential-sentinel")
        target.unlink()
        target.symlink_to(outside)
    elif scene == "partial":
        target.write_bytes(b'{"partial":')
    else:
        value = json.loads(target.read_bytes())
        value["body"]["gate"]["checks"]["worker_stopped"] = False
        value["body_sha256"] = review.digest(value["body"])
        target.write_bytes(review.artifacts._encode(value))
    with pytest.raises(review.ActivationError, match="saved_artifacts_unconfirmed") as caught:
        review.review(*pins, root=world.root)
    assert "confidential-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tls_controls_verified", True),
        ("normal_operation_permitted", True),
        ("tls_controls_verified", 0),
        ("artifact_inventory_verified", 1),
    ],
)
def test_rehashed_receipt_cannot_promote_failed_or_integer_claims(saved, field, value):
    world, _, pins = saved
    path = world.root / world.c.operation / "receipt.json"
    item = json.loads(path.read_bytes())
    item["body"][field] = value
    item["body_sha256"] = pins[-1] = review.digest(item["body"])
    path.write_bytes(review.artifacts._encode(item))
    with pytest.raises(review.ActivationError, match="saved_artifacts_unconfirmed"):
        review.review(*pins, root=world.root)


def test_second_sample_detects_changes_after_initial_inventory_pass(saved, monkeypatch):
    world, _, pins = saved
    original = review.artifacts.pki.read
    seen = []

    def changed(path, **kwargs):
        raw = original(path, **kwargs)
        if path.name == "network-create-gate.json":
            seen.append(path.name)
            if len(seen) == 2:
                return raw + b" "
        return raw

    monkeypatch.setattr(review.artifacts.pki, "read", changed)
    with pytest.raises(review.ActivationError, match="saved_artifacts_unconfirmed"):
        review.review(*pins, root=world.root)
    assert len(seen) == 2


def test_read_only_cli_reports_saved_integrity_without_turning_failed_assay_into_success(
    saved, monkeypatch, capsys
):
    world, result, pins = saved
    original = review.review
    monkeypatch.setattr(review, "review", lambda *args: original(*args, root=world.root))
    names = ("operation-id", "begin-sha256", "plan-sha256", "scope-sha256", "receipt-body-sha256")
    args = [arg for name, value in zip(names, pins, strict=True) for arg in ("--" + name, value)]
    assert review.main(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["recorded_assay_status"] == result["status"] == "identity_assay_failed_and_closed"
    assert output["native_runtime_rechecked"] is False


def test_read_only_cli_redacts_arbitrary_os_error_and_never_prints_paths(monkeypatch, capsys):
    monkeypatch.setattr(
        review, "review", lambda *args: (_ for _ in ()).throw(OSError("private-sensitive-sentinel"))
    )
    names = ("operation-id", "begin-sha256", "plan-sha256", "scope-sha256", "receipt-body-sha256")
    args = [arg for name in names for arg in ("--" + name, "a" * 64)]
    assert review.main(args) == 1
    output = capsys.readouterr().out
    assert "private-sensitive-sentinel" not in output
    assert json.loads(output)["error"] == "identity_saved_artifacts_unconfirmed"


@pytest.mark.parametrize("args", [[], ["--execute"]])
def test_read_only_cli_has_no_native_command_and_requires_all_independent_pins(monkeypatch, args):
    monkeypatch.setattr(review, "review", lambda *a: pytest.fail("no incomplete invocation"))
    with pytest.raises(SystemExit) as caught:
        review.main(args)
    assert caught.value.code == 2
