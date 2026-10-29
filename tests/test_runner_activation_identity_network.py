"""Exact network-member validation with daemon fixtures; no traffic or network mutation."""

import copy
import json
import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_inspection import spec as spec
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_isolated_network import projection
from test_runner_activation_ownership import OBJECT
from test_runner_activation_ownership import FakeDocker as Owner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_network as review  # noqa: E402


def member(spec):
    return {
        "Name": spec["name"],
        "EndpointID": "e" * 64,
        "MacAddress": "02:42:ac:1e:58:02",
        "IPv4Address": review.runtime.IP + "/29",
        "IPv6Address": "",
    }


@pytest.fixture
def bridge(spec):
    spec["network_recipe"] = {"name": spec["network_name"], "labels": spec["labels"]}
    item = projection(spec["network_recipe"])
    item["id"] = spec["network_resource_id"]
    return item


def test_empty_bridge_and_one_exact_runner_have_distinct_phase_requirements(spec, bridge):
    assert review._members(spec, bridge, None, "create") == 0
    assert review._members(spec, bridge, OBJECT, "start") == 0
    with pytest.raises(review.ActivationError, match="member_set"):
        review._members(spec, bridge, OBJECT, "running")
    bridge["containers"] = {OBJECT: member(spec)}
    assert review._members(spec, bridge, OBJECT, "start") == 1
    assert review._members(spec, bridge, OBJECT, "running") == 1
    with pytest.raises(review.ActivationError, match="member_set"):
        review._members(spec, bridge, None, "create")


@pytest.mark.parametrize(
    "scene",
    ["foreign_id", "two_members", "name", "address", "ipv6", "endpoint", "mac", "extra", "driver"],
)
def test_member_count_alone_cannot_adopt_foreign_or_changed_endpoints(spec, bridge, scene):
    entry = member(spec)
    bridge["containers"] = {OBJECT: entry}
    if scene == "foreign_id":
        bridge["containers"] = {"f" * 64: entry}
    elif scene == "two_members":
        bridge["containers"]["f" * 64] = entry.copy()
    elif scene == "name":
        entry["Name"] = "foreign-container"
    elif scene == "address":
        entry["IPv4Address"] = "172.30.88.3/29"
    elif scene == "ipv6":
        entry["IPv6Address"] = "2001:db8::1/64"
    elif scene == "endpoint":
        entry["EndpointID"] = "short"
    elif scene == "mac":
        entry["MacAddress"] = "not-a-mac"
    elif scene == "extra":
        entry["unreviewed"] = True
    else:
        bridge["internal"] = False
    with pytest.raises(review.ActivationError):
        review._members(spec, bridge, OBJECT, "running")


class World:
    def __init__(self, context, phase):
        self.store, self.path, self.sha = context
        self.phase, self.calls, self.owners = phase, 0, {}
        self.store.request("runner")
        if phase != "create":
            self.store.append("observed", {"role": "runner", "resource_id": OBJECT})
        spec = review.runtime.recipe(*context)
        if phase == "running":
            self.store.append(
                "identity_start_requested",
                {
                    "role": "runner",
                    "recipe_sha256": review.digest(spec),
                    "gates_sha256": "1" * 64,
                    "pki_manifest_sha256": review.runtime.plan.load_plan(self.path, self.sha)[
                        "pki"
                    ]["manifest_sha256"],
                    "network_resource_id": spec["network_resource_id"],
                    "mode": "identity-only",
                },
            )
        for key, known in ((review.network.ROLE, spec["network_resource_id"]), ("runner", OBJECT)):
            owner = Owner(
                self.store.summary()["id"], key, present=key != "runner" or phase != "create"
            )
            owner.details.update(id=known, plan=self.sha)
            owner.named = owner.labelled = owner.known = (
                (known + "\n").encode() if owner.named else b""
            )
            if key == "runner":
                owner.details.update(image=spec["image"], running=phase == "running")
            else:
                owner.details["member_count"] = int(phase == "running")
            self.owners[key] = owner
        self.item = projection(review.network.recipe(self.store))
        self.item["id"] = spec["network_resource_id"]
        if phase == "running":
            self.item["containers"] = {OBJECT: member(spec)}

    def query(self, *args):
        if len(args) == 2:
            self.calls += 1
            return json.dumps(self.item).encode()
        return self.owners[args[3]].query(*args)

    def review(self):
        return review.review(
            self.store, self.path, self.sha, self.phase, docker=self, ownership_docker=self
        )


@pytest.mark.parametrize("phase", ["create", "start", "running"])
def test_two_snapshots_bind_network_and_runner_ownership_without_granting_traffic_or_tls(
    context, phase
):
    world = World(context, phase)
    before = world.store.summary()
    result = world.review()
    assert result["expected_member_set_verified"] and result["members_reviewed"] == int(
        phase == "running"
    )
    assert all(
        result[k] is False
        for k in (
            "mutual_tls_verified",
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    assert world.calls == 2 and world.store.summary() == before


@pytest.mark.parametrize(
    "scene", ["owner", "member_count", "same_count_foreign", "drift", "timeout", "intent", "expiry"]
)
def test_changed_ownership_member_identity_clock_or_plan_cannot_publish_review(
    context, monkeypatch, scene
):
    world = World(context, "running")
    original = world.query
    if scene == "owner":
        world.owners["runner"].details["image"] = "sha256:" + "f" * 64
    elif scene == "member_count":
        world.owners[review.network.ROLE].details["member_count"] = 0
    elif scene == "same_count_foreign":
        world.item["containers"] = {"f" * 64: copy.deepcopy(world.item["containers"][OBJECT])}
    else:

        def change(*args):
            raw = original(*args)
            if len(args) == 2:
                if scene == "drift":
                    world.item["containers"][OBJECT]["EndpointID"] = "f" * 64
                elif scene == "timeout":
                    when = review.time.monotonic() + 21
                    monkeypatch.setattr(review.time, "monotonic", lambda: when)
                elif scene == "intent" and world.calls == 1:
                    world.store.request("redis")
                elif scene == "expiry":
                    artifact = review.runtime.plan.load_plan(world.path, world.sha)
                    expires = review.runtime.plan.datetime.fromisoformat(artifact["expires_at"])
                    monkeypatch.setattr(review.runtime.plan.pki, "clock", lambda: expires)
            return raw

        monkeypatch.setattr(world, "query", change)
    with pytest.raises(review.ActivationError):
        world.review()
