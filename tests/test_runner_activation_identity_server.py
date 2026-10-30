"""Compile fenced commands and emulate RPC replies; never invoke the native daemon."""

import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_ownership import OBJECT

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_server as server  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402


@pytest.fixture
def confirmed(context):
    store, path, sha = context
    return ConfirmedPlan(
        path,
        sha,
        store,
        store.review()["header"]["scope_sha256"],
        (server.plan.pki.clock() + timedelta(seconds=280)).isoformat(),
    )


def started(c, **changes):
    c.store.request("runner")
    c.store.append("observed", {"role": "runner", "resource_id": OBJECT})
    spec = server.runtime.recipe(c.store, c.path, c.plan_sha256)
    c.store.append(
        "identity_start_requested",
        {
            "role": "runner",
            "mode": "identity-only",
            "recipe_sha256": server.digest(spec),
            "gates_sha256": "1" * 64,
            "network_resource_id": spec["network_resource_id"],
            "pki_manifest_sha256": c.artifact["pki"]["manifest_sha256"],
            **changes,
        },
    )


def test_compile_requires_requested_create_and_exact_durable_start_fence(confirmed):
    c = confirmed
    with pytest.raises(server.ActivationError, match="new_runner_intent_required"):
        server.command("create", c)
    c.store.request("runner")
    args = server.command("create", c)
    assert args[:2] == ("container", "create") and args[args.index("--pull") + 1] == "never"
    c.store.append("observed", {"role": "runner", "resource_id": OBJECT})
    with pytest.raises(server.ActivationError, match="started_recipe_required"):
        server.command("start", c, OBJECT)
    spec = server.runtime.recipe(c.store, c.path, c.plan_sha256)
    c.store.append(
        "identity_start_requested",
        {
            "role": "runner",
            "mode": "identity-only",
            "recipe_sha256": server.digest(spec),
            "gates_sha256": "1" * 64,
            "network_resource_id": spec["network_resource_id"],
            "pki_manifest_sha256": c.artifact["pki"]["manifest_sha256"],
        },
    )
    assert server.command("start", c, OBJECT) == ("container", "start", OBJECT)
    c.store.append(
        "identity_runtime_observed",
        {
            "role": "runner",
            "runtime_evidence_sha256": "2" * 64,
        },
    )
    with pytest.raises(server.ActivationError, match="started_recipe_required"):
        server.command("start", c, OBJECT)


@pytest.mark.parametrize("field", ["recipe_sha256", "pki_manifest_sha256"])
def test_changed_start_recipe_or_pki_is_rejected(confirmed, field):
    started(confirmed, **{field: "f" * 64})
    with pytest.raises(server.ActivationError, match="started_recipe_required"):
        server.command("start", confirmed, OBJECT)


@pytest.mark.parametrize("kind", ["exec", "attach", "restart", "remove", "run"])
def test_no_generic_docker_operation_is_exposed(confirmed, kind):
    with pytest.raises(server.ActivationError, match="command_not_allowed"):
        server.command(kind, confirmed, OBJECT)


def test_another_container_id_cannot_be_started(confirmed):
    started(confirmed)
    with pytest.raises(server.ActivationError, match="started_recipe_required"):
        server.command("start", confirmed, "f" * 64)


def test_new_incompatible_role_after_start_fence_blocks_driver_before_rpc(confirmed, monkeypatch):
    started(confirmed)
    confirmed.store.request("redis")
    monkeypatch.setattr(server, "_execute", lambda *a, **kw: pytest.fail("no RPC"))
    with pytest.raises(server.ActivationError, match="incompatible_resource"):
        server.IdentityServerDocker().start(confirmed, OBJECT)


@pytest.mark.parametrize("phase", ["create", "start"])
@pytest.mark.parametrize("reply", [b"bad", b"f" * 64 + b"\n", b"private-sensitive-sentinel"])
def test_rpc_reply_errors_never_authorize_retry_or_expose_contents(
    confirmed, monkeypatch, phase, reply
):
    if phase == "start":
        started(confirmed)
    else:
        confirmed.store.request("runner")
    calls = []

    def execute(args, *, timeout):
        assert 0 < timeout <= server.TIMEOUT
        calls.append(args)
        return reply

    monkeypatch.setattr(server, "_execute", execute)
    driver = server.IdentityServerDocker()
    if phase == "create" and reply == b"f" * 64 + b"\n":
        # Syntax only; lifecycle must independently reconcile the returned ID.
        assert driver.create(confirmed) == "f" * 64
    else:
        with pytest.raises(server.ActivationError, match=f"{phase}_outcome_unconfirmed") as error:
            driver.create(confirmed) if phase == "create" else driver.start(confirmed, OBJECT)
        assert "private-sensitive-sentinel" not in str(error.value)
    assert len(calls) == 1


def test_expiration_blocks_rpc_before_daemon_access(confirmed, monkeypatch):
    confirmed.store.request("runner")
    monkeypatch.setattr(server.plan.pki, "clock", lambda: confirmed.expires)
    monkeypatch.setattr(server, "_execute", lambda *a, **kw: pytest.fail("no RPC"))
    with pytest.raises(server.ActivationError, match="scope_or_budget_unconfirmed"):
        server.IdentityServerDocker().create(confirmed)


def test_rpc_timeout_cannot_outlive_remaining_original_monotonic_budget(confirmed, monkeypatch):
    confirmed.store.request("runner")
    confirmed.deadline = server.time.monotonic() + 3
    limits = []

    def execute(args, *, timeout):
        limits.append(timeout)
        return (OBJECT + "\n").encode()

    monkeypatch.setattr(server, "_execute", execute)
    assert server.IdentityServerDocker().create(confirmed) == OBJECT
    assert len(limits) == 1 and 0 < limits[0] <= 3
