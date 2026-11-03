"""Dedicated client active contexts over real temporary PKI and fixture daemon metadata."""

import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_client_network import World
from test_runner_activation_identity_client_runtime import CONTEXT
from test_runner_activation_identity_client_runtime import ready as ready
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_active_metadata as active  # noqa: E402
import runner_activation_active_plan as plan  # noqa: E402


def setup(ready, phase, attached=False):
    world = World(ready, phase, attached)
    world.meta = ready.meta
    world.meta.responses["containers", None] = ready.owners["runner"].named + world.owner.named
    world.meta.calls.clear()
    return world


def recheck(world, context=CONTEXT):
    return plan.recheck(
        world.ready.path,
        world.ready.sha,
        world.ready.store,
        active.IDENTITY_CLIENT_ROLE,
        "identity-" + world.phase,
        request_context_sha256=context,
        docker=world.meta,
        ownership_docker=world,
    )


@pytest.mark.parametrize(
    "phase,attached",
    [
        ("create", False),
        ("start", False),
        ("start", True),
        ("exited", False),
        ("exited", True),
    ],
)
def test_specific_client_context_rechecks_full_plan_without_enabling_normal_operation(
    ready, phase, attached
):
    world = setup(ready, phase, attached)
    before = ready.store.summary()
    result = recheck(world)
    assert result["status"] == "active_plan_revalidated_not_activated"
    assert result["request_context_sha256"] == CONTEXT
    assert result["owned_metadata"]["identity_only_ownership_context_verified"]
    assert result["owned_metadata"]["resources_reviewed"] == 3
    assert result["owned_metadata"]["journal_consumer_set_verified"]
    assert result["owned_metadata"]["project_membership_verified"]
    assert result["activation_performed"] is result["authorization_granted"] is False
    assert ready.store.summary() == before


@pytest.mark.parametrize(
    "scene",
    [
        "worker",
        "journal_consumer",
        "database_consumer",
        "other_network",
        "other_role",
        "extra_member",
        "server_stopped",
        "client_running",
        "wrong_image",
        "empty_bridge",
    ],
)
def test_client_active_context_refuses_global_or_parent_drift(ready, scene):
    world = setup(ready, "exited")
    if scene == "other_role":
        ready.store.request("redis")
    elif scene in {"extra_member", "empty_bridge"}:
        ready.owners["network-isolated"].details["member_count"] = (
            3 if scene == "extra_member" else 0
        )
    elif scene == "server_stopped":
        ready.owners["runner"].details["running"] = False
    elif scene == "client_running":
        world.owner.details["running"] = True
    elif scene == "wrong_image":
        world.owner.details["image"] = "sha256:" + "f" * 64
    else:
        key = {
            "worker": ("containers", None),
            "journal_consumer": ("consumers", "journal"),
            "database_consumer": ("consumers", "postgres-data"),
            "other_network": ("network_name", "backend"),
        }[scene]
        world.meta.responses[key] += ("f" * 64 + "\n").encode()
    with pytest.raises(active.ActivationError):
        recheck(world)


def test_changed_request_hash_cannot_rebind_existing_start_before_metadata_io(ready):
    world = setup(ready, "exited")
    with pytest.raises(active.ActivationError, match="client_start_binding_mismatch"):
        recheck(world, context="b" * 64)
    assert world.meta.calls == []


def test_exited_context_requires_the_durable_start_even_if_container_metadata_would_match(ready):
    world = setup(ready, "start")
    world.phase = "exited"
    with pytest.raises(active.ActivationError, match="client_start_binding_mismatch"):
        recheck(world)
    assert world.meta.calls == []


def test_client_context_requires_explicit_hash_while_other_roles_refuse_it(ready, monkeypatch):
    world = setup(ready, "start")
    monkeypatch.setattr(plan.activation, "load_plan", lambda *a: pytest.fail("no plan IO"))
    with pytest.raises(active.ActivationError, match="sha256_required"):
        plan.recheck(
            ready.path, ready.sha, ready.store, active.IDENTITY_CLIENT_ROLE, "identity-start"
        )
    with pytest.raises(active.ActivationError, match="client_context_not_allowed"):
        plan.recheck(
            ready.path,
            ready.sha,
            ready.store,
            "runner",
            "identity-running",
            request_context_sha256=CONTEXT,
        )
    assert world.meta.calls == []


@pytest.mark.parametrize("scene", ["intent", "metadata", "expiry"])
def test_change_during_active_review_is_not_published_as_current(ready, monkeypatch, scene):
    world = setup(ready, "start")
    query, changed = world.meta.query, []
    expires = plan.activation.datetime.fromisoformat(
        plan.activation.load_plan(ready.path, ready.sha)["expires_at"]
    )

    def mutate(*args):
        raw = query(*args)
        if args[0] == "daemon" and not changed:
            changed.append(True)
            if scene == "intent":
                ready.store.request("redis")
            elif scene == "metadata":
                world.meta.responses["containers", None] += ("f" * 64 + "\n").encode()
            else:
                monkeypatch.setattr(plan.activation.pki, "clock", lambda: expires)
        return raw

    monkeypatch.setattr(world.meta, "query", mutate)
    with pytest.raises(active.ActivationError):
        recheck(world)


@pytest.mark.parametrize(
    "role,phase",
    [
        ("identity-client", "create"),
        ("identity-client", "start"),
        ("identity-client", "running"),
        ("identity-client", "identity-running"),
        ("runner", "identity-exited"),
        ("db", "identity-exited"),
    ],
)
def test_generic_or_foreign_roles_do_not_gain_new_phases(role, phase):
    assert active.context_allowed(role, phase) is False
