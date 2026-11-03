"""Original-window and closed-native-adapter tests; all RPC/route boundaries are fixtures."""

import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_network_gates import code as code
from test_runner_activation_network_gates import context as context
from test_runner_activation_network_gates import material as material

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_budget as budget  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402


@pytest.fixture
def prepared(context, monkeypatch):
    original, world = context
    c = ConfirmedPlan(
        original.path,
        original.plan_sha256,
        original.store,
        original.scope,
        (original.started_at + timedelta(seconds=240)).isoformat(),
    )
    value = budget.IdentityBudget(c)
    native = budget.IdentityNativeAdapters(value)
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return ("c" * 64 + "\n").encode()

    monkeypatch.setattr(budget.metadata, "_execute", execute)
    return value, native, calls, world


def test_long_effect_window_cannot_consume_reserved_cleanup_time(context):
    original, world = context
    with pytest.raises(budget.ActivationError, match="cleanup_reserve_required"):
        budget.IdentityBudget(original)
    assert world.effects == []


def test_effect_and_cleanup_windows_share_original_utc_and_monotonic_origin(prepared, monkeypatch):
    value, native, calls, _ = prepared
    c = value.confirmation
    assert value.expires == c.started_at + timedelta(seconds=300)
    assert value.deadline == c.deadline + 60
    monkeypatch.setattr(budget.pki, "clock", lambda: c.expires - timedelta(seconds=3))
    assert value.remaining(effect=True) <= 3
    assert value.remaining() == 20
    monkeypatch.setattr(budget.pki, "clock", lambda: c.expires)
    with pytest.raises(budget.ActivationError, match="scope_or_budget_unconfirmed"):
        native.bridge_create.create(c.store)
    native.cleanup.effect("remove", c.operation, c.plan_sha256, "identity-client", "c" * 64)
    assert calls[-1][1]["timeout"] == 20
    monkeypatch.setattr(budget.pki, "clock", lambda: value.expires - timedelta(seconds=2))
    native.ownership.query("name", c.operation, c.plan_sha256, "runner")
    assert calls[-1][1]["timeout"] <= 2
    before = len(calls)
    monkeypatch.setattr(budget.pki, "clock", lambda: value.expires)
    with pytest.raises(budget.ActivationError, match="budget_exhausted"):
        native.cleanup.effect("remove", c.operation, c.plan_sha256, "runner", "c" * 64)
    assert len(calls) == before


def test_clock_rollback_cannot_extend_monotonic_cleanup_deadline(prepared, monkeypatch):
    value, native, calls, _ = prepared
    c = value.confirmation
    monkeypatch.setattr(budget.pki, "clock", lambda: c.started_at - timedelta(seconds=60))
    monkeypatch.setattr(budget.time, "monotonic", lambda: value.deadline - 1)
    native.cleanup.effect("remove", c.operation, c.plan_sha256, "runner", "c" * 64)
    assert calls[-1][1]["timeout"] == 1
    monkeypatch.setattr(budget.time, "monotonic", lambda: value.deadline)
    with pytest.raises(budget.ActivationError, match="budget_exhausted"):
        value.remaining()


def test_reconstructed_confirmation_uses_remaining_original_hard_window(prepared, monkeypatch):
    value, _, _, _ = prepared
    c = value.confirmation
    later = c.started_at + timedelta(seconds=200)
    monkeypatch.setattr(budget.pki, "clock", lambda: later)
    before = budget.time.monotonic()
    resumed = ConfirmedPlan(c.path, c.plan_sha256, c.store, c.scope, c.expires.isoformat())
    limited = budget.IdentityBudget(resumed)
    assert limited.expires == value.expires
    assert before + 99 <= limited.deadline <= budget.time.monotonic() + 100
    assert limited.remaining() == 20


@pytest.mark.parametrize("cap", [True, 0, -1, 21, float("nan"), "20"])
def test_invalid_budget_cannot_reach_native_transport(prepared, cap):
    value, _, calls, _ = prepared
    with pytest.raises(budget.ActivationError, match="cap_invalid"):
        value.remaining(cap)
    assert calls == []


@pytest.mark.parametrize("scene", ["role", "operation", "plan"])
def test_cleanup_and_ownership_cannot_expand_identity_assay_scope(prepared, scene):
    value, native, calls, _ = prepared
    c = value.confirmation
    op = "f" * 32 if scene == "operation" else c.operation
    plan = "f" * 64 if scene == "plan" else c.plan_sha256
    role = "db" if scene == "role" else "runner"
    with pytest.raises(budget.ActivationError, match="scope_mismatch"):
        native.ownership.query("name", op, plan, role)
    with pytest.raises(budget.ActivationError, match="scope_mismatch"):
        native.cleanup.effect("remove", op, plan, role, "c" * 64)
    assert calls == []


def test_native_readers_compile_only_closed_queries_and_clip_each_call(prepared, monkeypatch):
    value, native, calls, _ = prepared
    c = value.confirmation
    monkeypatch.setattr(budget.pki, "clock", lambda: value.expires - timedelta(seconds=4))
    native.metadata.query("containers")
    native.physical.query("image", c.artifact["metadata"]["images"]["runner"]["id"])
    native.subnet.query(timeout=10)
    assert [args[:2] for args, _ in calls] == [
        ("ps", "--all"),
        ("image", "inspect"),
        ("network", "ls"),
    ]
    assert all(0 < kw["timeout"] <= 4 for _, kw in calls)
    with pytest.raises(budget.ActivationError):
        native.metadata.query("exec")
    with pytest.raises(budget.ActivationError, match="physical_role_mismatch"):
        native.physical.query("container", "sha256:" + "a" * 64, spec={"role": "api"})
    with pytest.raises(budget.ActivationError, match="store_mismatch"):
        native.network.query(object(), "c" * 64)
    assert len(calls) == 3


def test_route_reader_uses_fixed_route_tool_with_clipped_deadline(prepared, monkeypatch):
    value, native, calls, _ = prepared
    seen = []
    monkeypatch.setattr(budget.pki, "clock", lambda: value.expires - timedelta(seconds=1))
    monkeypatch.setattr(
        budget.subnet.RouteReader, "query", lambda self, *, timeout: seen.append(timeout) or b"[]"
    )
    assert native.routes.query(timeout=5) == b"[]" and seen == [1]
    assert calls == []


def test_bridge_create_is_single_fixed_command_and_cleanup_has_no_force_or_volume_flags(prepared):
    value, native, calls, _ = prepared
    c = value.confirmation
    c.store.request("network-isolated")
    assert native.bridge_create.create(c.store) == "c" * 64
    args, kw = calls[-1]
    assert args[:2] == ("network", "create") and 0 < kw["timeout"] <= 20
    assert "--internal" in args and "--subnet" in args
    for role in budget.ROLES:
        native.cleanup.effect("remove", c.operation, c.plan_sha256, role, "c" * 64)
        assert calls[-1][0] == (
            "network" if role.startswith("network-") else "container",
            "rm",
            "c" * 64,
        )
    assert all("--force" not in args and "--volumes" not in args for args, _ in calls)
