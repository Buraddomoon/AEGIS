"""Closed native driver admission with simulated RPC only; fixture replies are not TLS evidence."""

import json
import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_client_gates import prepared as prepared
from test_runner_activation_identity_client_runtime import ready as ready
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_client_driver as driver  # noqa: E402

CLIENT_ID = "e" * 64


def approved_start(prepared, *, gate_sha=None):
    value, world, spec, *_ = prepared
    approved = value.review("start", spec)
    value.confirmation.store.append(
        "identity_client_start_requested",
        {
            "role": driver.runtime.ROLE,
            "recipe_sha256": driver.digest(spec),
            "gates_sha256": gate_sha or driver.digest(approved),
            "request_context_sha256": value.context_sha256,
            "runner_resource_id": spec["runner_resource_id"],
            "network_resource_id": spec["network_resource_id"],
        },
    )
    return value, world, spec


def wire(value):
    # Wire fixture only. Actual TLS controls are tested in test_runner_identity_probe.
    return json.dumps(
        driver.gates.request.probe._result(value.context, "connection_closed_without_tls_reason")
    ).encode()


@pytest.mark.parametrize("prepared", ["create"], indirect=True)
def test_create_has_only_pinned_arguments_after_computed_gate(prepared, monkeypatch):
    value, _world, spec, *_ = prepared
    value.review("create", spec)
    calls = []

    def execute(args, *, timeout):
        calls.append(args)
        assert args == driver.runtime.create_arguments(
            value.confirmation.store,
            value.confirmation.path,
            value.confirmation.plan_sha256,
            value.context_sha256,
        )
        assert 0 < timeout <= 10
        return (CLIENT_ID + "\n").encode()

    monkeypatch.setattr(driver, "_execute", execute)
    assert driver.IdentityClientDocker().create(value) == CLIENT_ID
    assert len(calls) == 1


def test_attach_uses_original_pipe_payload_and_only_returns_closed_4k_result(prepared, monkeypatch):
    value, _world, _spec = approved_start(prepared)
    expected, calls = wire(value), []

    def execute(args, *, payload, timeout, output_limit):
        calls.append(args)
        assert args == ("container", "start", "--attach", "--interactive", CLIENT_ID)
        assert payload == value._payload and 0 < timeout <= 15
        assert output_limit == 4096
        return expected

    monkeypatch.setattr(driver, "_execute", execute)
    assert driver.IdentityClientDocker().start(value, CLIENT_ID) == expected
    assert len(calls) == 1
    assert value._last_gate is None
    with pytest.raises(driver.ActivationError, match="computed_recent_gate_required"):
        driver.IdentityClientDocker().start(value, CLIENT_ID)
    assert len(calls) == 1
    assert json.loads(expected)["missing_client_rejection_verified"] is False
    assert json.loads(expected)["status"] == "identity_tls_controls_inconclusive"


@pytest.mark.parametrize("prepared", ["create"], indirect=True)
def test_ambiguous_create_consumes_admission_and_rejects_second_rpc(prepared, monkeypatch):
    value, _world, spec, *_ = prepared
    value.review("create", spec)
    calls = []

    def execute(*args, **options):
        calls.append(args)
        raise OSError("private-sensitive-sentinel")

    monkeypatch.setattr(driver, "_execute", execute)
    with pytest.raises(driver.ActivationError, match="create_outcome_unconfirmed") as error:
        driver.IdentityClientDocker().create(value)
    assert value._last_gate is None and "private-sensitive-sentinel" not in str(error.value)
    with pytest.raises(driver.ActivationError, match="computed_recent_gate_required"):
        driver.IdentityClientDocker().create(value)
    assert len(calls) == 1


def test_no_gate_is_not_an_authorized_rpc(prepared, monkeypatch):
    value, *_ = prepared
    monkeypatch.setattr(driver, "_execute", lambda *a, **kw: pytest.fail("no RPC"))
    with pytest.raises(driver.ActivationError, match="computed_recent_gate_required"):
        driver.IdentityClientDocker().start(value, CLIENT_ID)


@pytest.mark.parametrize("kind", ["exec", "restart", "run", "remove", "attach"])
def test_free_docker_operations_cannot_be_selected(prepared, kind):
    with pytest.raises(driver.ActivationError, match="command_not_allowed"):
        driver.command(kind, prepared[0], CLIENT_ID)


def test_computed_gate_does_not_replace_a_durable_start_fence(prepared, monkeypatch):
    value, _world, spec, *_ = prepared
    value.review("start", spec)
    monkeypatch.setattr(driver, "_execute", lambda *a, **kw: pytest.fail("no RPC"))
    with pytest.raises(driver.ActivationError, match="started_recipe_required"):
        driver.IdentityClientDocker().start(value, CLIENT_ID)


@pytest.mark.parametrize("scene", ["gate_hash", "id", "request", "lease"])
def test_changed_fence_target_or_request_and_expired_lease_block_before_rpc(
    prepared, monkeypatch, scene
):
    value, _world, _spec = approved_start(
        prepared, gate_sha="f" * 64 if scene == "gate_hash" else None
    )
    known = "f" * 64 if scene == "id" else CLIENT_ID
    if scene == "request":
        value._payload = b"{}"
    elif scene == "lease":
        monkeypatch.setattr(driver.gates.plan.pki, "clock", lambda: value.confirmation.expires)
    monkeypatch.setattr(driver, "_execute", lambda *a, **kw: pytest.fail("no RPC"))
    with pytest.raises(ValueError):
        driver.IdentityClientDocker().start(value, known)


@pytest.mark.parametrize("scene", ["rejected", "integer_bool", "oversize", "wrong_context"])
def test_successful_cli_exit_cannot_make_invalid_wire_or_modified_claims_valid(
    prepared, monkeypatch, scene
):
    value, _world, _spec = approved_start(prepared)
    result = json.loads(wire(value))
    if scene == "rejected":
        result = {"status": "rejected", "message": "private-sensitive-sentinel"}
    elif scene == "integer_bool":
        result["candidate_client_certificate_verified"] = 1
    elif scene == "wrong_context":
        result["context_sha256"] = "f" * 64
    raw = json.dumps(result).encode()
    if scene == "oversize":
        raw += b" " * 4096
    monkeypatch.setattr(driver, "_execute", lambda *a, **kw: raw)
    with pytest.raises(driver.ActivationError, match="capture_outcome_unconfirmed") as error:
        driver.IdentityClientDocker().start(value, CLIENT_ID)
    assert "private-sensitive-sentinel" not in str(error.value)


def test_remaining_original_budget_caps_capture_timeout(prepared, monkeypatch):
    value, _world, _spec = approved_start(prepared)
    monkeypatch.setattr(driver.time, "monotonic", lambda: 300.0)
    value.confirmation.deadline = 303.0
    limits = []

    def execute(*args, **options):
        limits.append(options["timeout"])
        return wire(value)

    monkeypatch.setattr(driver, "_execute", execute)
    driver.IdentityClientDocker().start(value, CLIENT_ID)
    assert limits == [3.0]


def test_failed_recheck_revokes_private_cached_gate_without_erasing_prior_evidence(prepared):
    value, world, spec, *_ = prepared
    value.review("start", spec)
    world.meta.responses["containers", None] += ("f" * 64 + "\n").encode()
    with pytest.raises(ValueError):
        value.review("start", spec)
    assert value._last_gate is None and len(value.evidence) == 1


def test_saved_assertions_cannot_construct_driver_admission():
    with pytest.raises(driver.ActivationError, match="computed_gates_required"):
        driver.IdentityClientDocker().create({"checks": {"all": True}})
