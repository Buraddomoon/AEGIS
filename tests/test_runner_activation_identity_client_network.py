"""Exact two-resource endpoint checks against fixture metadata, no bridge creation/traffic."""

import copy
import json
import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_client_runtime import CONTEXT
from test_runner_activation_identity_client_runtime import ready as ready
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_ownership import FakeDocker as Owner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_client_network as network  # noqa: E402

CLIENT_ID = "e" * 64


class World:
    def __init__(self, ready, phase, attached=False):
        self.ready, self.phase, self.calls = ready, phase, 0
        store = ready.store
        store.request(network.runtime.ROLE)
        if phase != "create":
            store.append("observed", {"role": network.runtime.ROLE, "resource_id": CLIENT_ID})
        self.spec = network.runtime.recipe(store, ready.path, ready.sha, CONTEXT)
        if phase == "exited":
            store.append(
                "identity_client_start_requested",
                {
                    "role": network.runtime.ROLE,
                    "recipe_sha256": network.digest(self.spec),
                    "gates_sha256": "1" * 64,
                    "request_context_sha256": CONTEXT,
                    "runner_resource_id": self.spec["runner_resource_id"],
                    "network_resource_id": self.spec["network_resource_id"],
                },
            )
        self.owner = Owner(store.summary()["id"], network.runtime.ROLE, present=phase != "create")
        self.owner.details.update(
            id=CLIENT_ID, image=self.spec["image"], plan=ready.sha, running=False
        )
        self.owner.named = self.owner.labelled = self.owner.known = (
            (CLIENT_ID + "\n").encode() if phase != "create" else b""
        )
        self.item = copy.deepcopy(ready.item)
        if attached:
            self.item["containers"][CLIENT_ID] = {
                "Name": self.spec["name"],
                "EndpointID": "f" * 64,
                "MacAddress": "02:42:ac:1e:58:03",
                "IPv4Address": "192.168.253.3/29",
                "IPv6Address": "",
            }
        ready.owners["network-isolated"].details["member_count"] = len(self.item["containers"])

    def query(self, *args):
        if len(args) == 2:
            self.calls += 1
            return json.dumps(self.item).encode()
        if args[3] == network.runtime.ROLE:
            return self.owner.query(*args)
        return self.ready.query(*args)

    def review(self, context=CONTEXT):
        return network.review(
            self.ready.store,
            self.ready.path,
            self.ready.sha,
            context,
            self.phase,
            docker=self,
            ownership_docker=self,
        )


@pytest.mark.parametrize(
    "phase,attached,count",
    [
        ("create", False, 1),
        ("start", False, 1),
        ("start", True, 2),
        ("exited", False, 1),
        ("exited", True, 2),
    ],
)
def test_only_running_server_and_optional_exact_stopped_client_are_admitted(
    ready, phase, attached, count
):
    world = World(ready, phase, attached)
    before = ready.store.summary()
    result = world.review()
    assert result["members_reviewed"] == count and world.calls == 2
    assert (
        result["expected_member_set_verified"]
        and result["configured_internal_isolated_bridge_verified"]
    )
    assert before == ready.store.summary()
    assert all(
        result[key] is False
        for key in (
            "mutual_tls_verified",
            "network_reachability_verified",
            "project_quiescence_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )


@pytest.mark.parametrize(
    "scene",
    [
        "foreign_same_count",
        "missing_runner",
        "third_member",
        "client_name",
        "client_ip",
        "ipv6",
        "duplicate_endpoint",
        "server_ip",
        "member_count",
        "client_running",
        "server_stopped",
        "driver",
        "extra_field",
    ],
)
def test_counts_never_substitute_for_exact_owned_members_and_endpoint_configuration(ready, scene):
    world = World(ready, "exited", attached=True)
    members = world.item["containers"]
    client = members[CLIENT_ID]
    runner = members[world.spec["runner_resource_id"]]
    if scene == "foreign_same_count":
        members["a" * 64] = members.pop(CLIENT_ID)
    elif scene == "missing_runner":
        members.pop(world.spec["runner_resource_id"])
    elif scene == "third_member":
        members["a" * 64] = client.copy()
    elif scene == "client_name":
        client["Name"] = "foreign"
    elif scene == "client_ip":
        client["IPv4Address"] = "192.168.253.4/29"
    elif scene == "ipv6":
        client["IPv6Address"] = "2001:db8::1/64"
    elif scene == "duplicate_endpoint":
        client["EndpointID"] = runner["EndpointID"]
    elif scene == "server_ip":
        runner["IPv4Address"] = "192.168.253.3/29"
    elif scene == "member_count":
        ready.owners["network-isolated"].details["member_count"] = 1
    elif scene == "client_running":
        world.owner.details["running"] = True
    elif scene == "server_stopped":
        ready.owners["runner"].details["running"] = False
    elif scene == "driver":
        world.item["internal"] = False
    else:
        client["unreviewed"] = True
    with pytest.raises(network.ActivationError):
        world.review()


@pytest.mark.parametrize("scene", ["metadata", "intent", "deadline", "context"])
def test_changed_snapshots_intents_budget_or_request_context_block_review(
    ready, monkeypatch, scene
):
    world = World(ready, "exited", attached=True)
    query = world.query

    def changed(*args):
        raw = query(*args)
        if len(args) == 2 and world.calls == 1:
            if scene == "metadata":
                world.item["containers"][CLIENT_ID]["EndpointID"] = "a" * 64
            elif scene == "intent":
                ready.store.request("redis")
            elif scene == "deadline":
                when = network.time.monotonic() + 21
                monkeypatch.setattr(network.time, "monotonic", lambda: when)
        return raw

    monkeypatch.setattr(world, "query", changed)
    with pytest.raises(network.ActivationError):
        world.review(context="b" * 64 if scene == "context" else CONTEXT)


def test_create_cannot_adopt_a_client_endpoint_or_resource_that_already_appeared(ready):
    world = World(ready, "create", attached=True)
    with pytest.raises(network.ActivationError, match="member_set_mismatch"):
        world.review()


def test_old_single_runner_network_contract_stays_closed_when_client_exists(ready):
    World(ready, "start", attached=True)
    with pytest.raises(network.ActivationError, match="owned_context_required"):
        network.server.review(ready.store, ready.path, ready.sha, "running")
