"""Read-only fixed bridge and exact identity-runner membership; no lifecycle or traffic."""

import re
import time

import runner_activation_identity_runtime as runtime
import runner_activation_isolated_network as network
from aegis.domain.validation import digest
from runner_activation_metadata import TIMEOUT, ActivationError, _execute, document
from runner_activation_ownership import command as ownership_command
from runner_activation_ownership import identifier, observe


def _members(spec, item, runner_id, phase):
    network._configuration(spec["network_recipe"], item, spec["network_resource_id"])
    members = item["containers"]
    if members is None:
        members = {}
    if not isinstance(members, dict) or len(members) > 1 or (phase == "running" and not members):
        raise ActivationError("identity_network_member_set_mismatch")
    if members:
        if runner_id is None or set(members) != {runner_id}:
            raise ActivationError("identity_network_member_set_mismatch")
        entry = members[runner_id]
        if (
            not isinstance(entry, dict)
            or set(entry) != {"Name", "EndpointID", "MacAddress", "IPv4Address", "IPv6Address"}
            or entry["Name"] != spec["name"]
            or entry["IPv4Address"] != runtime.IP + "/29"
            or entry["IPv6Address"] != ""
            or not isinstance(entry["MacAddress"], str)
            or not re.fullmatch("(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", entry["MacAddress"])
        ):
            raise ActivationError("identity_network_endpoint_mismatch")
        identifier(entry["EndpointID"])
    return len(members)


def review(store, path, plan_sha256, phase, *, docker=None, ownership_docker=None):
    deadline = time.monotonic() + 20
    if phase not in {"create", "start", "running"}:
        raise ActivationError("identity_network_phase_invalid")
    original = store.review()
    current = original["resources"].get("runner")
    if (
        current is None
        or (phase == "create" and current != {"state": "REQUESTED", "resource_id": None})
        or (
            phase != "create"
            and (
                current["state"] not in {"OBSERVED", "START_REQUESTED"}
                or current["resource_id"] is None
            )
        )
        or (phase == "running" and current.get("start", {}).get("mode") != "identity-only")
        or any(
            key not in {"runner", network.ROLE} and value["state"] != "ABSENT"
            for key, value in original["resources"].items()
        )
    ):
        raise ActivationError("identity_network_owned_context_required")
    spec = runtime.recipe(store, path, plan_sha256)
    spec["network_recipe"] = network.recipe(store)
    operation = store.summary()["id"]

    def budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ActivationError("identity_network_review_deadline")
        return min(TIMEOUT, remaining)

    class Owners:
        def query(self, *args):
            limit = budget()
            value = (
                ownership_docker.query(*args)
                if ownership_docker is not None
                else _execute(ownership_command(*args), timeout=limit)
            )
            budget()
            return value

    owners = Owners()

    def snapshot():
        parent = observe(
            operation, plan_sha256, network.ROLE, spec["network_resource_id"], docker=owners
        )
        runner = observe(operation, plan_sha256, "runner", current["resource_id"], docker=owners)
        if (
            parent["status"] != "present_owned_snapshot"
            or runner["status"]
            != ("absent_snapshot" if phase == "create" else "present_owned_snapshot")
            or (
                phase != "create"
                and (
                    runner["details"]["image"] != spec["image"]
                    or runner["details"]["running"] is not (phase == "running")
                )
            )
        ):
            raise ActivationError("identity_network_ownership_mismatch")
        limit = budget()
        raw = (
            docker.query(store, spec["network_resource_id"])
            if docker is not None
            else _execute(network.command(store, spec["network_resource_id"]), timeout=limit)
        )
        budget()
        item = document(raw)
        count = _members(spec, item, current["resource_id"], phase)
        if parent["details"]["member_count"] != count:
            raise ActivationError("identity_network_member_count_changed")
        return {"parent": parent, "runner": runner, "configuration": item, "count": count}

    before, after = snapshot(), snapshot()
    if digest(before) != digest(after) or store.review() != original:
        raise ActivationError("identity_network_changed_during_review")
    repeated = runtime.recipe(store, path, plan_sha256)
    repeated["network_recipe"] = network.recipe(store)
    if digest(repeated) != digest(spec):
        raise ActivationError("identity_network_plan_drift")
    budget()
    return {
        "format": "aegis-identity-network-review/1",
        "phase": phase,
        "network_resource_id": spec["network_resource_id"],
        "members_reviewed": after["count"],
        "snapshot_sha256": digest(after),
        "configured_internal_isolated_bridge_verified": True,
        "expected_member_set_verified": True,
        "mutual_tls_verified": False,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
