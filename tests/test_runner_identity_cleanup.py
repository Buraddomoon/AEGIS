"""Separate cleanup-only scope on real temporary plans/intents and fixture ownership."""

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_network_gates import code as code
from test_runner_activation_network_gates import context as context
from test_runner_activation_network_gates import material as material
from test_runner_activation_ownership import OBJECT
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_identity_coordinator import world as world

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_cleanup as cleanup  # noqa: E402


@pytest.fixture
def prepared(context, tmp_path):
    c, world = context
    runtime = tmp_path / "runtime"
    with cleanup.artifacts.IdentityArtifacts(c, root=runtime):
        pass
    c.store.request("network-isolated")
    result = cleanup.prepare(
        c.path, c.plan_sha256, c.store, root=tmp_path / "cleanup", runtime_root=runtime
    )
    folder = Path(result["plan_path"]).parent
    return c, world, runtime, folder, result


def execute(prepared, **kwargs):
    c, world, _, folder, result = prepared
    return cleanup.execute(
        folder,
        result["plan_sha256"],
        result["scope_sha256"],
        c.store,
        confirm_owned_cleanup=True,
        docker=world,
        ownership_docker=world,
        **kwargs,
    )


def present(prepared):
    c, world, *_ = prepared
    world.owner = Owner(c.operation, "network-isolated")
    world.owner.details["plan"] = c.plan_sha256


def test_preparation_pins_original_evidence_and_state_without_native_effects_or_new_authority(
    prepared,
):
    c, world, _, folder, report = prepared
    value = cleanup.load(folder, report["plan_sha256"])
    assert value["snapshot"]["begin_sha256"] == c.begin_sha256
    assert value["snapshot"]["state"] == c.store.review()
    assert value["profile"]["roles"] == sorted(cleanup.ROLES)
    assert value["profile"]["max_seconds"] == 120
    assert report["cleanup_executed"] is False
    assert report["normal_operation_permitted"] is False
    assert world.effects == [] and not (folder / "requested.json").exists()


def test_original_expiry_does_not_prevent_separately_approved_cleanup_and_never_restarts_assay(
    prepared, monkeypatch
):
    c, world, runtime, _, _ = prepared
    monkeypatch.setattr(cleanup.artifacts.pki, "clock", lambda: c.expires + timedelta(days=30))
    report = cleanup.prepare(
        c.path, c.plan_sha256, c.store, root=runtime.parent / "new-cleanup", runtime_root=runtime
    )
    fresh = (*prepared[:3], Path(report["plan_path"]).parent, report)
    observed = execute(fresh)
    assert observed["status"] == "identity_owned_cleanup_verified_and_closed"
    assert observed["assay_resumed"] is False and observed["normal_operation_permitted"] is False
    assert c.store.review()["closed"] is True and world.effects == []


def test_ambiguous_requested_network_is_removed_only_after_exact_owned_identity_reconciliation(
    prepared,
):
    c, world, _, folder, _ = prepared
    present(prepared)
    observed = execute(prepared)
    assert world.effects == ["remove"]
    assert c.store.review()["resources"]["network-isolated"] == {
        "state": "ABSENT",
        "resource_id": OBJECT,
    }
    assert observed["managed_resources_absence_verified"] is True
    assert json.loads((folder / "receipt.json").read_bytes()) == observed
    with pytest.raises((ValueError, OSError)):
        execute(prepared)
    assert world.effects == ["remove"]


@pytest.mark.parametrize("confirmation", [False, 1, None])
def test_cleanup_confirmation_is_literal_and_checked_before_io(monkeypatch, confirmation):
    monkeypatch.setattr(cleanup, "load", lambda *a: pytest.fail("no policy read"))
    with pytest.raises(cleanup.ActivationError, match="explicit_confirmation_required"):
        cleanup.execute(
            Path("ignored"), "a" * 64, "b" * 64, None, confirm_owned_cleanup=confirmation
        )


def test_another_scope_or_new_role_cannot_expand_cleanup(prepared):
    c, world, _, folder, report = prepared
    with pytest.raises(cleanup.ActivationError, match="authorized_scope_mismatch"):
        cleanup.execute(
            folder, report["plan_sha256"], "f" * 64, c.store, confirm_owned_cleanup=True
        )
    c.store.request("redis")
    with pytest.raises(cleanup.ActivationError, match="open_identity_operation_required"):
        execute(prepared)
    assert world.effects == [] and not (folder / "requested.json").exists()


@pytest.mark.parametrize("scene", ["cleanup_failed", "foreign"])
def test_cleanup_failure_or_foreign_identity_is_retained_and_never_adopted(prepared, scene):
    c, world, *_ = prepared
    present(prepared)
    if scene == "foreign":
        world.owner.details["plan"] = "f" * 64
    else:
        world.scene = scene
    observed = execute(prepared)
    assert observed["status"] == "identity_owned_cleanup_unconfirmed"
    assert observed["managed_resources_absence_verified"] is False
    assert c.store.review()["closed"] is False and world.owner is not None
    if scene == "foreign":
        assert world.effects == []


@pytest.mark.parametrize("clock", ["forward", "rollback", "monotonic"])
def test_clock_change_during_query_blocks_removal_and_prevents_claiming_absence(
    prepared, monkeypatch, clock
):
    c, world, _, folder, report = prepared
    present(prepared)
    value = cleanup.load(folder, report["plan_sha256"])
    created = cleanup.plan.datetime.fromisoformat(value["created_at"])
    query = world.query
    calls = []

    def changed(*args):
        output = query(*args)
        calls.append(args)
        if clock == "monotonic":
            later = cleanup.time.monotonic() + 121
            monkeypatch.setattr(cleanup.time, "monotonic", lambda: later)
        else:
            delta = timedelta(seconds=121 if clock == "forward" else -1)
            monkeypatch.setattr(cleanup.artifacts.pki, "clock", lambda: created + delta)
        return output

    monkeypatch.setattr(world, "query", changed)
    observed = execute(prepared)
    assert len(calls) == 1 and world.effects == []
    assert observed["managed_resources_absence_verified"] is False
    assert world.owner is not None and c.store.review()["closed"] is False


@pytest.mark.parametrize("scene", ["integer_profile", "original_request", "plan_use"])
def test_rehashing_policy_or_changing_original_evidence_does_not_authorize_cleanup(prepared, scene):
    c, world, runtime, folder, report = prepared
    if scene == "integer_profile":
        path = folder / "plan.json"
        value = json.loads(path.read_bytes())
        value["profile"]["start_permitted"] = 0
        value["scope_sha256"] = cleanup.digest(
            {key: item for key, item in value.items() if key != "scope_sha256"}
        )
        path.write_bytes(cleanup.artifacts._encode(value))
        report["scope_sha256"], report["plan_sha256"] = value["scope_sha256"], cleanup.digest(value)
    elif scene == "original_request":
        path = runtime / c.operation / "requested.json"
        path.write_bytes(b'{"partial":')
    else:
        path = c.path.parent / "identity-assay-requested.json"
        value = json.loads(path.read_bytes())
        value["operation_id"] = "f" * 32
        path.write_bytes(cleanup.artifacts._encode(value))
    with pytest.raises((ValueError, OSError)):
        execute(prepared)
    assert world.effects == [] and not (folder / "requested.json").exists()


def test_cleanup_policy_output_cannot_be_nested_in_preserved_runtime_or_pki(prepared):
    c, world, runtime, *_ = prepared
    for root in (runtime / "new", c.path.parent / "new", c.store.root / "new"):
        with pytest.raises(cleanup.ActivationError, match="output_must_be_separate"):
            cleanup.prepare(c.path, c.plan_sha256, c.store, root=root, runtime_root=runtime)
        assert not root.exists()
    assert world.effects == []


def test_native_command_boundary_requires_removal_fence_and_clips_timeout_without_free_commands(
    prepared, monkeypatch
):
    c, _, _, folder, report = prepared
    value = cleanup.load(folder, report["plan_sha256"])
    native = cleanup._Native(folder, report["plan_sha256"], value, c.store)
    calls = []
    monkeypatch.setattr(
        cleanup.metadata, "_execute", lambda args, **kw: calls.append((args, kw)) or b""
    )
    with pytest.raises(cleanup.ActivationError, match="removal_fence_required"):
        native.effect("remove", c.operation, c.plan_sha256, "network-isolated", OBJECT)
    assert calls == []
    native.query("name", c.operation, c.plan_sha256, "network-isolated")
    c.store.append("removal_requested", {"role": "network-isolated"})
    c.store.append("observed", {"role": "network-isolated", "resource_id": OBJECT})
    with pytest.raises(FileNotFoundError):
        native.effect("remove", c.operation, c.plan_sha256, "network-isolated", OBJECT)
    assert len(calls) == 1
    cleanup._write(
        folder / "requested.json",
        cleanup.artifacts._encode(
            {
                "plan_sha256": report["plan_sha256"],
                "scope_sha256": report["scope_sha256"],
                "operation_id": c.operation,
                "begin_sha256": c.begin_sha256,
                "expires_at": native.expires.isoformat(),
            }
        ),
    )
    monkeypatch.setattr(
        cleanup.artifacts.pki, "clock", lambda: native.expires - timedelta(seconds=2)
    )
    native.effect("remove", c.operation, c.plan_sha256, "network-isolated", OBJECT)
    assert calls[-1][0] == ("network", "rm", OBJECT) and 0 < calls[-1][1]["timeout"] <= 2
    before = len(calls)
    for kind, role in (("start", "network-isolated"), ("remove", "db")):
        with pytest.raises(cleanup.ActivationError):
            native.effect(kind, c.operation, c.plan_sha256, role, OBJECT)
    assert len(calls) == before


def test_cleanup_interruption_keeps_owned_resource_and_receipt_without_retry(prepared, monkeypatch):
    c, world, _, folder, _ = prepared
    present(prepared)
    calls = []

    def interrupted(*args):
        calls.append(args)
        raise KeyboardInterrupt

    monkeypatch.setattr(world, "effect", interrupted)
    with pytest.raises(KeyboardInterrupt):
        execute(prepared)
    receipt = json.loads((folder / "receipt.json").read_bytes())
    assert receipt["status"] == "identity_owned_cleanup_unconfirmed"
    assert receipt["error"] == "identity_cleanup_interrupted"
    assert c.store.review()["closed"] is False and world.owner is not None
    with pytest.raises((ValueError, OSError)):
        execute(prepared)
    assert len(calls) == 1


def test_recovery_of_full_three_role_assay_after_original_expiry_preserves_old_receipt(
    world, tmp_path, monkeypatch
):
    world.scene = "cleanup_failure"
    old = world.execute()
    assert old["status"] == "identity_assay_cleanup_unconfirmed"
    path = world.root / world.c.operation / "receipt.json"
    preserved = (path.read_bytes(), path.stat().st_mtime_ns)
    monkeypatch.setattr(
        cleanup.artifacts.pki, "clock", lambda: world.c.expires + timedelta(days=10)
    )
    report = cleanup.prepare(
        world.c.path,
        world.c.plan_sha256,
        world.c.store,
        root=tmp_path / "cleanup",
        runtime_root=world.root,
    )
    world.scene = None
    before = len(world.effects)
    receipt = cleanup.execute(
        Path(report["plan_path"]).parent,
        report["plan_sha256"],
        report["scope_sha256"],
        world.c.store,
        confirm_owned_cleanup=True,
        docker=world,
        ownership_docker=world,
    )
    assert receipt["status"] == "identity_owned_cleanup_verified_and_closed"
    assert world.effects[before:] == [
        "identity-client_remove",
        "runner_stop",
        "runner_remove",
        "network-isolated_remove",
    ]
    assert receipt["assay_resumed"] is False and receipt["normal_operation_permitted"] is False
    assert all(not owner.named for owner in world.owners.values())
    assert (path.read_bytes(), path.stat().st_mtime_ns) == preserved
