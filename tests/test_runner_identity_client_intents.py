"""Dedicated identity-client ownership/fences and dependency cleanup, fixture daemon only."""

import sys
from pathlib import Path
from uuid import uuid4

import pytest
from test_runner_activation_metadata import images
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_identity_intents import NETWORK, RUNNER, observed, start
from test_runner_identity_intents import store as store

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_active_metadata as active  # noqa: E402
import runner_activation_cleanup as cleanup  # noqa: E402
import runner_diagnostic_plan as diagnostic  # noqa: E402
from runner_activation_intents import IDENTITY_CLIENT_ROLE as CLIENT  # noqa: E402
from runner_activation_intents import ActivationError, ActivationIntents  # noqa: E402

CLIENT_ID = "e" * 64


@pytest.fixture
def server(store):
    store.append("identity_start_requested", start())
    store.append("identity_runtime_observed", observed())
    return store


def client_start():
    return {
        "role": CLIENT,
        "recipe_sha256": "1" * 64,
        "gates_sha256": "2" * 64,
        "request_context_sha256": "3" * 64,
        "runner_resource_id": RUNNER,
        "network_resource_id": NETWORK,
    }


def client_reply():
    return {"role": CLIENT, "result_sha256": "4" * 64, "runtime_evidence_sha256": "5" * 64}


def requested(server):
    server.request(CLIENT)
    server.append("observed", {"role": CLIENT, "resource_id": CLIENT_ID})


def test_client_requires_observed_identity_mode_and_physical_runtime_fence(store):
    before = store.summary()
    with pytest.raises(ActivationError, match="observed_identity_server_required"):
        store.request(CLIENT)
    assert store.summary() == before
    store.append("identity_start_requested", start())
    with pytest.raises(ActivationError, match="observed_identity_server_required"):
        store.request(CLIENT)
    store.append("identity_runtime_observed", observed())
    store.request(CLIENT)
    assert store.review()["resources"][CLIENT] == {"state": "REQUESTED", "resource_id": None}


def test_reply_and_start_are_distinct_and_neither_can_be_repeated(server):
    requested(server)
    with pytest.raises(ActivationError, match="reply_observation_invalid"):
        server.append("identity_client_reply_observed", client_reply())
    server.append("identity_client_start_requested", client_start())
    assert server.review()["resources"][CLIENT]["state"] == "START_REQUESTED"
    with pytest.raises(ActivationError, match="already_requested"):
        server.append("identity_client_start_requested", client_start())
    server.append("identity_client_reply_observed", client_reply())
    current = server.review()["resources"][CLIENT]
    assert current["state"] == "OBSERVED" and current["result_sha256"] == "4" * 64
    assert current["start"]["request_context_sha256"] == "3" * 64
    for kind, data in (
        ("identity_client_start_requested", client_start()),
        ("identity_client_reply_observed", client_reply()),
    ):
        with pytest.raises(ActivationError):
            server.append(kind, data)
    assert all(
        server.summary()[key] is False
        for key in (
            "authorization_verified",
            "activation_verified",
            "normal_operation_permitted",
        )
    )


@pytest.mark.parametrize("scene", ["runner", "network", "context", "extra", "role"])
def test_unpinned_parent_context_or_free_command_cannot_become_a_client_start(server, scene):
    requested(server)
    data = client_start()
    if scene in {"runner", "network"}:
        data[scene + "_resource_id"] = "f" * 64
    elif scene == "context":
        data["request_context_sha256"] = "not-a-hash"
    elif scene == "extra":
        data["command"] = "unreviewed"
    else:
        data["role"] = "runner"
    before = server.summary()
    with pytest.raises(ActivationError):
        server.append("identity_client_start_requested", data)
    assert server.summary() == before


@pytest.mark.parametrize("role", ["db", "redis", "api", "journal-before", "network-backend"])
def test_another_live_or_pending_role_blocks_client_creation(server, role):
    server.request(role)
    with pytest.raises(ActivationError, match="observed_identity_server_required"):
        server.request(CLIENT)


@pytest.mark.parametrize("parent", ["runner", "network-isolated"])
@pytest.mark.parametrize("state", ["REQUESTED", "START_REQUESTED", "OBSERVED"])
def test_uncertain_client_retains_server_and_network_until_its_absence_is_confirmed(
    server, parent, state
):
    server.request(CLIENT)
    if state != "REQUESTED":
        server.append("observed", {"role": CLIENT, "resource_id": CLIENT_ID})
        server.append("identity_client_start_requested", client_start())
        if state == "OBSERVED":
            server.append("identity_client_reply_observed", client_reply())
    with pytest.raises(ActivationError, match="dependencies_retained"):
        server.append("removal_requested", {"role": parent})


class World:
    def __init__(self, server, failure=False):
        self.store, self.failure, self.effects, self.objects = server, failure, [], {}
        for role, known in (("network-isolated", NETWORK), ("runner", RUNNER), (CLIENT, CLIENT_ID)):
            owner = Owner(server.summary()["id"], role)
            owner.details.update(id=known, plan=server.review()["header"]["plan_sha256"])
            owner.named = owner.labelled = owner.known = (known + "\n").encode()
            if role != "network-isolated":
                owner.details.update(image=images()["runner"], running=True)
            else:
                owner.details["member_count"] = 2
            self.objects[role] = owner

    def query(self, kind, operation, plan, role, known_id=None):
        return self.objects[role].query(kind, operation, plan, role, known_id)

    def effect(self, kind, operation, plan, role, known_id):
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        self.effects.append((role, kind))
        if self.failure and role == CLIENT:
            raise ActivationError("private-sensitive-sentinel")
        obj = self.objects[role]
        if kind == "stop":
            obj.details["running"] = False
        else:
            assert kind == "remove"
            obj.named = obj.labelled = obj.known = b""
            if role != "network-isolated":
                self.objects["network-isolated"].details["member_count"] -= 1


def test_owned_client_cleanup_precedes_server_and_network_without_removing_volumes(server):
    requested(server)
    server.append("identity_client_start_requested", client_start())
    world = World(server)
    result = cleanup.cleanup(server, images(), docker=world, ownership_docker=world)
    assert result["managed_resources_absence_verified"] and server.review()["closed"]
    assert result["volumes_removed"] is False
    assert world.effects == [
        (CLIENT, "stop"),
        (CLIENT, "remove"),
        ("runner", "stop"),
        ("runner", "remove"),
        ("network-isolated", "remove"),
    ]


def test_uncertain_client_cleanup_blocks_parent_effects_and_keeps_intents(server):
    requested(server)
    world = World(server, failure=True)
    result = cleanup.cleanup(server, images(), docker=world, ownership_docker=world)
    assert not result["managed_resources_absence_verified"] and not server.review()["closed"]
    assert set(result["blockers"]) == {CLIENT, "runner", "network-isolated"}
    assert world.effects == [(CLIENT, "stop")]


def test_new_role_does_not_enable_diagnostic_or_existing_active_contexts():
    assert CLIENT not in diagnostic.profile()["roles"]
    for phase in ("create", "start", "running", "identity-create", "identity-start"):
        assert not active.context_allowed(CLIENT, phase)


def test_client_presence_does_not_relax_existing_runner_only_active_review(server):
    requested(server)
    with pytest.raises(ActivationError, match="unresolved_or_incompatible"):
        active.review(server, images(), {}, "runner", "identity-running")


def test_actual_resume_keeps_client_start_fence_and_refuses_second_start(tmp_path):
    root = tmp_path / "intents"
    with ActivationIntents(root) as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        for role, known in (("network-isolated", NETWORK), ("runner", RUNNER)):
            store.request(role)
            store.append("observed", {"role": role, "resource_id": known})
        store.append("identity_start_requested", start())
        store.append("identity_runtime_observed", observed())
        requested(store)
        store.append("identity_client_start_requested", client_start())
        before = store.summary()
        files = {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in store.folder.glob("*.json")
        }
    with ActivationIntents(root) as resumed:
        resumed.resume(before["id"], before["begin_sha256"])
        with pytest.raises(ActivationError, match="already_requested"):
            resumed.append("identity_client_start_requested", client_start())
        assert files == {
            p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in resumed.folder.glob("*.json")
        }
