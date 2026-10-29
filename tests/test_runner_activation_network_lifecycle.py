"""Single-create network lifecycle with fixture daemon; never create real networks."""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from test_runner_activation_isolated_network import OBJECT, Docker, Owner
from test_runner_activation_isolated_network import store as store
from test_runner_activation_metadata import images

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_network_lifecycle as life  # noqa: E402

SECRET = "private-sensitive-sentinel"


class World:
    def __init__(self, store, scene=None):
        self.store, self.scene = store, scene
        self.owner, self.effects, self.gates = None, [], []
        self.runtime = Docker(store)

    def query(self, kind, *args):
        if self.owner is None:
            assert kind != "inspect"
            return b""
        return self.owner.query(kind, *args)

    def gate(self, phase, spec):
        self.gates.append(phase)
        assert spec == life.network.recipe(self.store)
        now = datetime.now(UTC)
        value = {
            "format": "aegis-rotation-network-gate/1",
            "phase": phase,
            "operation_id": self.store.summary()["id"],
            "plan_sha256": "a" * 64,
            "scope_sha256": "b" * 64,
            "recipe_sha256": digest(spec),
            "network_name": spec["name"],
            "checked_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=20)).isoformat(),
            "checks": dict.fromkeys(life.CHECKS, True),
        }
        if self.scene == "deny":
            value["checks"]["specific_authorization_verified"] = False
        elif self.scene == "integer":
            value["checks"]["worker_stopped"] = 1
        elif self.scene == "scope":
            value["scope_sha256"] = "c" * 64
        elif self.scene == "stale":
            value["checked_at"] = (now - timedelta(seconds=11)).isoformat()
        elif self.scene == "mutate_store":
            self.store.request("journal-before")
        elif self.scene == "collision":
            self.owner = Owner(self.store.summary()["id"], life.network.ROLE)
        return value

    def create(self, store):
        assert life.network.create_arguments(store)[:2] == ("network", "create")
        assert (
            json.loads(sorted(store.folder.glob("*.json"))[-1].read_bytes())["kind"]
            == "create_requested"
        )
        self.effects.append("create")
        if self.scene == "failed_before":
            raise life.ActivationError(SECRET)
        self.owner = Owner(store.summary()["id"], life.network.ROLE)
        if self.scene == "failed_after":
            raise life.ActivationError(SECRET)
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        if self.scene in {"unsafe_runtime", "cleanup_failed"}:
            self.runtime.item["internal"] = False
        if self.scene == "member":
            self.owner.details["member_count"] = 1
        return "c" * 64 if self.scene == "wrong_id" else OBJECT

    def effect(self, kind, operation, plan, role, known_id):
        assert kind == "remove" and role == life.network.ROLE and known_id == OBJECT
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        self.effects.append(kind)
        if self.scene == "cleanup_failed":
            raise life.ActivationError(SECRET)
        self.owner = None


def invoke(world):
    return life.create_network(
        world.store,
        images(),
        before_effect=world.gate,
        lifecycle=world,
        runtime_docker=world.runtime,
        ownership_docker=world,
        cleanup_docker=world,
    )


def test_success_retains_only_inspected_empty_network_and_does_not_allow_create_replay(store):
    world = World(store)
    result = invoke(world)
    assert result["network_retained"] and result["runtime"]["members_absent_verified"]
    assert result["status"] == "empty_owned_network_created_and_retained"
    assert world.effects == ["create"] and world.gates == ["create"]
    assert all(
        result[key] is False
        for key in (
            "network_absence_verified",
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    with pytest.raises(life.ActivationError, match="no_replay"):
        invoke(world)


@pytest.mark.parametrize("scene", ["deny", "integer", "scope", "stale", "mutate_store"])
def test_fresh_exact_computed_gates_and_unchanged_context_precede_create(store, scene):
    world = World(store, scene)
    result = invoke(world)
    assert not result["network_retained"]
    assert result["network_absence_verified"] is (scene != "mutate_store")
    if scene == "mutate_store":
        # The unexpected pending dependent must be reconciled first. Do not
        # weaken shared cleanup dependencies to report a convenient success.
        assert result["status"] == "network_cleanup_unconfirmed"
        assert store.review()["resources"]["journal-before"]["state"] == "REQUESTED"
    assert result["failure_phase"] == "create_gate" and world.effects == []


@pytest.mark.parametrize("scene", ["failed_before", "failed_after", "wrong_id", "unsafe_runtime"])
def test_ambiguous_or_invalid_creation_is_closed_without_retry_or_error_echo(store, scene):
    world = World(store, scene)
    result = invoke(world)
    assert result["status"] == "network_failed_and_absence_verified"
    assert world.effects.count("create") == 1 and SECRET not in json.dumps(result)
    assert store.review()["resources"][life.network.ROLE]["state"] == "ABSENT"
    with pytest.raises(life.ActivationError, match="no_replay"):
        invoke(world)


@pytest.mark.parametrize("scene", ["collision", "member", "cleanup_failed"])
def test_foreign_member_or_uncertain_cleanup_is_retained_without_success(store, scene):
    world = World(store, scene)
    result = invoke(world)
    assert result["status"] == "network_cleanup_unconfirmed"
    assert not result["network_absence_verified"] and not result["network_retained"]
    if scene in {"collision", "member"}:
        assert "remove" not in world.effects
    if scene == "collision":
        assert store.review()["resources"][life.network.ROLE]["state"] == "CONFLICT"
    assert SECRET not in json.dumps(result)


def test_interrupt_propagates_after_owned_network_cleanup(store):
    world = World(store, "interrupt")
    with pytest.raises(KeyboardInterrupt):
        invoke(world)
    assert world.effects == ["create", "remove"]
    assert store.review()["resources"][life.network.ROLE]["state"] == "ABSENT"


def test_concrete_creation_uses_only_fixed_compiler_and_static_errors(store, monkeypatch):
    store.request(life.network.ROLE)
    calls = []
    monkeypatch.setattr(
        life, "_execute", lambda args: calls.append(args) or (OBJECT + "\n").encode()
    )
    assert life.NetworkLifecycleDocker().create(store) == OBJECT
    assert calls == [life.network.create_arguments(store)]

    def fail(_args):
        raise subprocess.CalledProcessError(1, "fixed", stderr=SECRET.encode())

    monkeypatch.setattr(life, "_execute", fail)
    with pytest.raises(life.ActivationError, match="outcome_unconfirmed") as caught:
        life.NetworkLifecycleDocker().create(store)
    assert SECRET not in str(caught.value)


def test_approval_dictionary_cannot_replace_trusted_gate_callback(store):
    with pytest.raises(life.ActivationError, match="images_and_gates_required"):
        life.create_network(
            store, images(), before_effect={"checks": dict.fromkeys(life.CHECKS, True)}
        )
    assert store.review()["resources"] == {}
