"""Actual computed gates over temporary PKI/intents and simulated daemon effects only."""

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_identity_inspection import projection
from test_runner_activation_identity_network import member
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_isolated_network import projection as bridge_projection
from test_runner_activation_metadata import FakeDocker
from test_runner_activation_ownership import OBJECT
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_lifecycle as life  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402

SECRET = "private-sensitive-sentinel"


class World:
    def __init__(self, context, monkeypatch):
        self.store, self.path, self.sha = context
        self.scene, self.effects = None, []
        self.monkeypatch = monkeypatch
        self.spec = life.runtime.recipe(*context)
        self.meta = FakeDocker()
        self.owners = {}
        for role, known in (
            ("network-isolated", self.spec["network_resource_id"]),
            ("runner", OBJECT),
        ):
            owner = Owner(self.store.summary()["id"], role, present=role != "runner")
            owner.details.update(id=known, plan=self.sha)
            owner.named = owner.labelled = owner.known = (
                (known + "\n").encode() if owner.named else b""
            )
            if role == "runner":
                owner.details.update(image=self.spec["image"], running=False)
            self.owners[role] = owner
        self.meta.responses["networks", None] = self.owners["network-isolated"].named
        self.meta.responses["network_name", "isolated"] = self.owners["network-isolated"].named
        self.bridge = bridge_projection(life.runtime.network.recipe(self.store))
        self.bridge["id"] = self.spec["network_resource_id"]
        self.config = projection(self.spec)
        self.image = {
            "id": self.spec["image"],
            "user": "10001:10001",
            "volumes": None,
            "environment": [{"key": k, "valid": True} for k in life.inspection.probe.ENV_FIXED],
            "ports": None,
            "onbuild": None,
        }
        monkeypatch.setattr(
            life.gates.image,
            "review",
            lambda *a, **kw: {
                "native_image_id": self.spec["image"],
                "tool_commit": life.gates.plan.tool_state(),
                "package_and_dependency_sources_current": True,
                "build_client_exit_verified": True,
            },
        )
        self.confirmation = ConfirmedPlan(
            self.path,
            self.sha,
            self.store,
            self.store.review()["header"]["scope_sha256"],
            (life.gates.plan.pki.clock() + timedelta(seconds=280)).isoformat(),
        )
        self.gates = life.gates.IdentityGates(
            self.confirmation,
            {"fixture": "sealed boundary"},
            docker=self.meta,
            ownership_docker=self,
            runtime_docker=self,
            network_docker=self,
        )

    def query(self, *args, **kwargs):
        if isinstance(args[0], str) and args[0] in {"image", "container"}:
            return json.dumps(self.image if args[0] == "image" else self.config).encode()
        if len(args) == 2:  # Fixed bridge inspection.
            return json.dumps(self.bridge).encode()
        return self.owners[args[3]].query(*args)

    def create(self, c):
        assert life.server.command("create", c)[:2] == ("container", "create")
        assert c.store.review()["resources"]["runner"]["state"] == "REQUESTED"
        self.effects.append("create")
        if self.scene == "create_before":
            raise life.ActivationError(SECRET)
        owner = self.owners["runner"]
        owner.named = owner.labelled = owner.known = (OBJECT + "\n").encode()
        self.meta.responses["containers", None] = owner.named
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        if self.scene == "create_after":
            raise life.ActivationError(SECRET)
        if self.scene == "created_mount":
            self.config["mounts"][0]["writable"] = True
        return "f" * 64 if self.scene == "wrong_id" else OBJECT

    def start(self, c, known):
        assert life.server.command("start", c, known) == ("container", "start", OBJECT)
        event = json.loads(sorted(c.store.folder.glob("*.json"))[-1].read_bytes())
        assert event["kind"] == "identity_start_requested"
        assert event["data"]["gates_sha256"] == self.gates.evidence[-1]["gate_sha256"]
        self.effects.append("start")
        if self.scene == "start_before":
            raise life.ActivationError(SECRET)
        self.owners["runner"].details["running"] = True
        self.owners["network-isolated"].details["member_count"] = 1
        self.bridge["containers"] = {OBJECT: member(self.spec)}
        self.config = projection(self.spec, "running")
        if self.scene in {"start_after", "cleanup_failure"}:
            raise life.ActivationError(SECRET)
        if self.scene == "running_mount":
            self.config["mounts"][0]["writable"] = True
        if self.scene == "foreign_endpoint":
            self.bridge["containers"] = {"f" * 64: member(self.spec)}
        if self.scene == "expiry_after":
            self.monkeypatch.setattr(life.gates.plan.pki, "clock", lambda: c.expires)

    def effect(self, kind, operation, plan, role, known_id):
        assert role == "runner" and known_id == OBJECT
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        self.effects.append(kind)
        if self.scene == "cleanup_failure":
            raise life.ActivationError(SECRET)
        owner = self.owners[role]
        if kind == "stop":
            owner.details["running"] = False
        else:
            assert kind == "remove"
            owner.named = owner.labelled = owner.known = b""
            self.meta.responses["containers", None] = b""
            self.bridge["containers"].pop(OBJECT, None)
            self.owners["network-isolated"].details["member_count"] = len(self.bridge["containers"])

    def run(self):
        return life.start_server(self.gates, lifecycle=self, cleanup_docker=self)


@pytest.fixture
def world(context, monkeypatch):
    return World(context, monkeypatch)


def test_success_retains_only_inspected_server_and_durable_fence_blocks_replay(world):
    result = world.run()
    assert result["status"] == "owned_identity_server_running_and_retained"
    assert world.effects == ["create", "start"]
    assert set(result["gate_sha256"]) == {"create", "start", "running"}
    assert result["server_retained"] is True and result["runtime"]["runtime_configuration_verified"]
    assert all(
        result[key] is False
        for key in (
            "mutual_tls_verified",
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
            "marker_executed",
        )
    )
    current = world.store.review()["resources"]["runner"]
    assert current["state"] == "OBSERVED" and "start" in current
    assert "runtime_evidence_sha256" in current
    with pytest.raises(life.ActivationError, match="new_role_required_no_replay"):
        world.run()
    assert world.effects == ["create", "start"]


@pytest.mark.parametrize(
    "scene,expected",
    [
        ("create_before", ["create"]),
        ("create_after", ["create", "remove"]),
        ("wrong_id", ["create", "remove"]),
        ("created_mount", ["create", "remove"]),
        ("start_before", ["create", "start", "remove"]),
        ("start_after", ["create", "start", "stop", "remove"]),
        ("running_mount", ["create", "start", "stop", "remove"]),
        ("foreign_endpoint", ["create", "start", "stop", "remove"]),
        ("expiry_after", ["create", "start", "stop", "remove"]),
    ],
)
def test_ambiguous_or_unsafe_outcome_cleans_only_own_server_and_never_replays(
    world, scene, expected
):
    world.scene = scene
    result = world.run()
    assert result["status"] == "identity_server_failed_and_absence_verified"
    assert result["server_absence_verified"] and not result["server_retained"]
    assert world.effects == expected
    assert world.store.review()["resources"]["runner"]["state"] == "ABSENT"
    assert world.store.review()["resources"]["network-isolated"]["state"] == "OBSERVED"
    assert world.store.review()["closed"] is False
    if scene == "foreign_endpoint":
        assert set(world.bridge["containers"]) == {"f" * 64}
    assert SECRET not in json.dumps(result)
    reason = (
        "scope_or_budget_unconfirmed" if scene == "expiry_after" else "new_role_required_no_replay"
    )
    with pytest.raises(life.ActivationError, match=reason):
        world.run()
    assert world.effects == expected


def test_failed_cleanup_keeps_exact_resource_and_original_network_for_reconciliation(world):
    world.scene = "cleanup_failure"
    result = world.run()
    assert result["status"] == "identity_server_cleanup_unconfirmed"
    assert result["server_absence_verified"] is False
    assert world.effects == ["create", "start", "stop"]
    state = world.store.review()
    assert state["resources"]["runner"]["state"] == "REMOVAL_REQUESTED"
    assert state["resources"]["network-isolated"]["state"] == "OBSERVED" and not state["closed"]
    assert SECRET not in json.dumps(result)


def test_interruption_cleans_ambiguous_create_then_propagates_without_retry(world):
    world.scene = "interrupt"
    with pytest.raises(KeyboardInterrupt):
        world.run()
    assert world.effects == ["create", "remove"]
    assert world.store.review()["resources"]["runner"]["state"] == "ABSENT"


def test_live_gate_failure_prevents_create_and_preserves_parent_network(world):
    world.meta.responses["consumers", "journal"] = ("f" * 64 + "\n").encode()
    result = world.run()
    assert world.effects == [] and result["failure_phase"] == "create_gate"
    assert result["server_absence_verified"] and not result["server_retained"]


def test_resource_appearing_before_our_create_is_neither_adopted_nor_deleted(world, monkeypatch):
    original = world.gates.review

    def appeared(*args):
        result = original(*args)
        owner = world.owners["runner"]
        owner.named = owner.labelled = owner.known = (OBJECT + "\n").encode()
        return result

    monkeypatch.setattr(world.gates, "review", appeared)
    result = world.run()
    assert world.effects == [] and not result["server_absence_verified"]
    assert world.store.review()["resources"]["runner"]["state"] == "CONFLICT"


def test_saved_positive_checks_do_not_replace_computed_gate_object():
    with pytest.raises(life.ActivationError, match="computed_gates_required"):
        life.start_server({"checks": {"all_passed": True}})


def test_actual_intent_resume_after_ambiguous_start_can_only_reconcile_not_restart(
    material, code, tmp_path, monkeypatch
):
    prepared, _ = prepare(material, tmp_path)
    path, sha = Path(prepared["plan_path"]), prepared["plan_sha256"]
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], sha, prepared["scope_sha256"])
        store.request("network-isolated")
        store.append("observed", {"role": "network-isolated", "resource_id": "c" * 64})
        world = World((store, path, sha), monkeypatch)
        world.scene = "start_after"
        assert world.run()["server_absence_verified"]
        origin, expires = store.summary(), world.confirmation.expires.isoformat()
        before = {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in store.folder.glob("*.json")
        }
    with ActivationIntents(tmp_path / "intents") as resumed:
        resumed.resume(origin["id"], origin["begin_sha256"])
        c = ConfirmedPlan(path, sha, resumed, prepared["scope_sha256"], expires)
        with pytest.raises(life.ActivationError, match="new_role_required_no_replay"):
            life.start_server(
                life.gates.IdentityGates(c, {}), lifecycle=world, cleanup_docker=world
            )
        assert before == {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in resumed.folder.glob("*.json")
        }
    assert world.effects == ["create", "start", "stop", "remove"]
