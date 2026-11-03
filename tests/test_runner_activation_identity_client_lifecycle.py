"""Full client orchestration with actual gates/driver and fixture RPC; no native TLS claim."""

import copy
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_identity_client_inspection import projected
from test_runner_activation_identity_client_runtime import ready as ready
from test_runner_activation_identity_inspection import projection
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_activation_plan import prepare
from test_runner_identity_active_plan import setup as parent_setup

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_client_lifecycle as life  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402

CLIENT_ID = "e" * 64
SECRET = "private-sensitive-sentinel"


class World:
    def __init__(self, ready, monkeypatch):
        self.ready, self.scene, self.effects = ready, None, []
        self.monkeypatch = monkeypatch
        self.c = ConfirmedPlan(
            ready.path,
            ready.sha,
            ready.store,
            ready.store.review()["header"]["scope_sha256"],
            (life.gates.plan.pki.clock() + timedelta(seconds=250)).isoformat(),
        )
        raw, expected = life.gates.request.request(self.c)
        self.spec = life.runtime.recipe(ready.store, ready.path, ready.sha, expected)
        self.parent = projection(
            life.runtime.server.recipe(ready.store, ready.path, ready.sha), "running"
        )
        self.client = projected(self.spec, "created")
        self.owner = Owner(ready.store.summary()["id"], life.runtime.ROLE, present=False)
        self.owner.details.update(
            id=CLIENT_ID, plan=ready.sha, image=self.spec["image"], running=False
        )
        self.item = copy.deepcopy(ready.item)
        self.image = {
            "id": self.spec["image"],
            "user": "10001:10001",
            "volumes": None,
            "ports": None,
            "onbuild": None,
            "environment": [{"key": k, "valid": True} for k in life.parent.probe.ENV_FIXED],
        }
        # Existing sealed image proof is an explicit fixture boundary; its real
        # source/receipt checks have their own integration tests.
        monkeypatch.setattr(
            life.gates.image,
            "review",
            lambda *a, **kw: {
                "native_image_id": self.spec["image"],
                "tool_commit": self.c.artifact["tool_commit"],
                "package_and_dependency_sources_current": True,
                "build_client_exit_verified": True,
            },
        )
        self.gates = life.gates.IdentityClientGates(
            self.c,
            {"fixture": "sealed boundary"},
            raw,
            expected,
            docker=ready.meta,
            ownership_docker=self,
            runtime_docker=self,
            network_docker=self,
        )
        monkeypatch.setattr(life.driver, "_execute", self.rpc)

    def query(self, *args, **kwargs):
        if isinstance(args[0], str) and args[0] in {"image", "container"}:
            role = kwargs.get("spec", {}).get("role")
            item = (
                self.image
                if args[0] == "image"
                else self.parent
                if role == "runner"
                else self.client
            )
            return json.dumps(item).encode()
        if len(args) == 2:
            return json.dumps(self.item).encode()
        if args[3] == life.runtime.ROLE:
            return self.owner.query(*args)
        return self.ready.query(*args)

    def present(self):
        self.owner.named = self.owner.labelled = self.owner.known = (CLIENT_ID + "\n").encode()
        self.ready.meta.responses["containers", None] = (
            self.ready.owners["runner"].named + self.owner.named
        )

    def rpc(self, args, *, timeout, payload=None, output_limit=None):
        store = self.ready.store
        if args[:2] == ("container", "create"):
            assert store.review()["resources"][life.runtime.ROLE]["state"] == "REQUESTED"
            assert self.gates._last_gate is None  # Admission consumed before RPC.
            self.effects.append("create")
            if self.scene == "create_before":
                raise OSError(SECRET)
            self.present()
            if self.scene == "interrupt":
                raise KeyboardInterrupt
            if self.scene == "create_after":
                raise OSError(SECRET)
            if self.scene == "created_mount":
                self.client["mounts"][0]["writable"] = True
            return (("f" * 64 if self.scene == "wrong_id" else CLIENT_ID) + "\n").encode()
        assert args == ("container", "start", "--attach", "--interactive", CLIENT_ID)
        event = json.loads(sorted(store.folder.glob("*.json"))[-1].read_bytes())
        assert event["kind"] == "identity_client_start_requested"
        assert event["data"]["gates_sha256"] == self.gates.evidence[-1]["gate_sha256"]
        assert payload == self.gates._payload and output_limit == 4096 and 0 < timeout <= 15
        self.effects.append("start")
        if self.scene == "start_before":
            raise OSError(SECRET)
        if self.scene == "start_running":
            self.owner.details["running"] = True
            raise OSError(SECRET)
        self.client = projected(self.spec, "exited")
        if self.scene == "exit_profile":
            self.client["mounts"][0]["writable"] = True
        if self.scene == "expiry":
            self.monkeypatch.setattr(life.gates.plan.pki, "clock", lambda: self.c.expires)
        if self.scene == "bad_wire":
            return json.dumps({"status": "rejected", "message": SECRET}).encode()
        # Protocol fixture only, not simulated capture presented as real TLS.
        return json.dumps(
            life.gates.request.probe._result(
                self.gates.context, "connection_closed_without_tls_reason"
            )
        ).encode()

    def effect(self, kind, operation, plan, role, known):
        assert role == life.runtime.ROLE and known == CLIENT_ID
        assert self.ready.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        self.effects.append(kind)
        if self.scene == "cleanup_failed":
            raise OSError(SECRET)
        if kind == "stop":
            self.owner.details["running"] = False
        else:
            assert kind == "remove"
            self.owner.named = self.owner.labelled = self.owner.known = b""
            self.ready.meta.responses["containers", None] = self.ready.owners["runner"].named

    def run(self):
        return life.run_client(self.gates, cleanup_docker=self)


@pytest.fixture
def world(ready, monkeypatch):
    return World(ready, monkeypatch)


def test_full_review_records_reply_and_cleanup_without_promoting_inconclusive_control(world):
    result = world.run()
    assert result["status"] == "probe_completed_and_removed" and result["probe_removed"]
    assert (
        result["probe_result_verified"]
        and result["tls_controls_status"] == "identity_tls_controls_inconclusive"
    )
    assert result["result"]["candidate_client_certificate_verified"]
    assert result["result"]["missing_client_rejection_verified"] is False
    assert (
        result["normal_operation_permitted"]
        is result["activation_verified"]
        is result["marker_executed"]
        is False
    )
    assert (
        set(result["gate_records"]) == set(result["gate_sha256"]) == {"create", "start", "exited"}
    )
    for phase, record in result["gate_records"].items():
        gate_sha = life.digest(record["gate"])
        evidence = next(item for item in result["gate_evidence"] if item["gate_sha256"] == gate_sha)
        assert gate_sha == result["gate_sha256"][phase]
        assert life.digest(record["review"]["plan_before"]) == evidence["before_sha256"]
        assert life.digest(record["review"]["plan_after"]) == evidence["after_sha256"]
        assert life.digest(record["review"]["network"]) == evidence["network_sha256"]
    assert result["gate_records"]["exited"]["review"]["client_runtime"][
        "runtime_configuration_verified"
    ]
    assert world.effects == ["create", "start", "remove"]
    state = world.ready.store.review()
    current = state["resources"][life.runtime.ROLE]
    assert current["state"] == "ABSENT" and "result_sha256" in current
    assert (
        state["resources"]["runner"]["state"]
        == state["resources"]["network-isolated"]["state"]
        == "OBSERVED"
    )
    assert not state["closed"]
    with pytest.raises(life.ActivationError, match="new_role_required_no_replay"):
        world.run()
    assert world.effects == ["create", "start", "remove"]


@pytest.mark.parametrize(
    "scene,expected",
    [
        ("create_before", ["create"]),
        ("create_after", ["create", "remove"]),
        ("wrong_id", ["create", "remove"]),
        ("created_mount", ["create", "remove"]),
        ("start_before", ["create", "start", "remove"]),
        ("start_running", ["create", "start", "stop", "remove"]),
        ("bad_wire", ["create", "start", "remove"]),
        ("exit_profile", ["create", "start", "remove"]),
        ("expiry", ["create", "start", "remove"]),
    ],
)
def test_ambiguous_or_unsafe_effect_never_replays_and_cleans_only_owned_client(
    world, scene, expected
):
    world.scene = scene
    result = world.run()
    assert result["status"] == "probe_execution_unconfirmed" and result["probe_removed"]
    assert result["result"] is None and not result["probe_result_verified"]
    assert world.effects == expected and SECRET not in json.dumps(result)
    state = world.ready.store.review()
    assert state["resources"][life.runtime.ROLE]["state"] == "ABSENT"
    assert (
        state["resources"]["runner"]["state"]
        == state["resources"]["network-isolated"]["state"]
        == "OBSERVED"
    )
    assert not state["closed"]
    reason = "scope_or_budget_unconfirmed" if scene == "expiry" else "new_role_required_no_replay"
    with pytest.raises(life.ActivationError, match=reason):
        world.run()
    assert world.effects == expected


def test_cleanup_failure_preserves_reply_facts_but_retains_resource_and_parents(world):
    world.scene = "cleanup_failed"
    result = world.run()
    assert result["status"] == "probe_cleanup_unconfirmed" and not result["probe_removed"]
    assert (
        result["probe_result_verified"] and result["result"]["normal_operation_permitted"] is False
    )
    assert world.effects == ["create", "start", "remove"]
    assert (
        world.ready.store.review()["resources"][life.runtime.ROLE]["state"] == "REMOVAL_REQUESTED"
    )
    assert SECRET not in json.dumps(result)


def test_interruption_after_create_runs_selected_cleanup_before_propagating(world):
    world.scene = "interrupt"
    with pytest.raises(KeyboardInterrupt):
        world.run()
    assert world.effects == ["create", "remove"]
    assert world.ready.store.review()["resources"][life.runtime.ROLE]["state"] == "ABSENT"


def test_lifecycle_does_not_accept_saved_positive_json():
    with pytest.raises(life.ActivationError, match="computed_gates_required"):
        life.run_client({"checks": {"all": True}})


def test_collision_after_gate_is_quarantined_without_adoption_or_delete(world, monkeypatch):
    review = world.gates.review

    def appeared(*args):
        result = review(*args)
        if args[0] == "create":
            world.present()
        return result

    monkeypatch.setattr(world.gates, "review", appeared)
    result = world.run()
    assert world.effects == [] and result["status"] == "probe_cleanup_unconfirmed"
    assert world.ready.store.review()["resources"][life.runtime.ROLE]["state"] == "CONFLICT"


def test_actual_resume_cannot_replay_with_a_new_readonly_request_in_the_same_window(
    material, code, tmp_path, monkeypatch
):
    prepared, _ = prepare(material, tmp_path)
    path, sha = Path(prepared["plan_path"]), prepared["plan_sha256"]
    root = tmp_path / "intents"
    with ActivationIntents(root) as store:
        store.begin(prepared["id"], sha, prepared["scope_sha256"])
        store.request("network-isolated")
        store.append("observed", {"role": "network-isolated", "resource_id": "c" * 64})
        ready = parent_setup((store, path, sha), "running")
        world = World(ready, monkeypatch)
        assert world.run()["probe_removed"]
        origin, expires = store.summary(), world.c.expires.isoformat()
        before = {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in store.folder.glob("*.json")
        }
    with ActivationIntents(root) as resumed:
        resumed.resume(origin["id"], origin["begin_sha256"])
        c = ConfirmedPlan(path, sha, resumed, prepared["scope_sha256"], expires)
        payload, expected = life.gates.request.request(c)  # Read-only, never a new execution grant.
        reviews = life.gates.IdentityClientGates(c, {}, payload, expected)
        with pytest.raises(life.ActivationError, match="new_role_required_no_replay"):
            life.run_client(reviews)
        assert before == {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in resumed.folder.glob("*.json")
        }
    assert world.effects == ["create", "start", "remove"]
