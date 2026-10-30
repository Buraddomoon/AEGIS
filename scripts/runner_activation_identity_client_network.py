"""Exact runner/client endpoints on the owned bridge; read-only, no traffic or lifecycle."""

import time

import runner_activation_identity_client_runtime as runtime
import runner_activation_identity_network as server
import runner_activation_isolated_network as network
from aegis.domain.validation import digest
from runner_activation_metadata import TIMEOUT, ActivationError, _execute, document
from runner_activation_ownership import command as ownership_command
from runner_activation_ownership import observe


def _members(spec, item, client_id, phase):
    network._configuration(spec["network_recipe"], item, spec["network_resource_id"])
    members = item["containers"]
    runner = spec["runner_resource_id"]
    expected = [{runner}]
    if phase != "create" and client_id is not None:
        expected.append({runner, client_id})
    if not isinstance(members, dict) or set(members) not in expected:
        raise ActivationError("identity_client_network_member_set_mismatch")
    server._member(members[runner], spec["runner_name"], runtime.server.IP)
    if client_id is not None and client_id in members:
        server._member(members[client_id], spec["name"], runtime.IP)
        if len({entry["EndpointID"] for entry in members.values()}) != len(members):
            raise ActivationError("identity_client_network_duplicate_endpoint")
    return len(members)


def review(
    store,
    path,
    plan_sha256,
    context_sha256,
    phase,
    *,
    docker=None,
    ownership_docker=None,
):
    deadline = time.monotonic() + 20
    if phase not in {"create", "start", "exited"}:
        raise ActivationError("identity_client_network_phase_invalid")
    original = store.review()
    current = original["resources"].get(runtime.ROLE, {})
    if (
        (phase == "create" and current != {"state": "REQUESTED", "resource_id": None})
        or (
            phase != "create"
            and (
                current.get("state") not in {"OBSERVED", "START_REQUESTED"}
                or current.get("resource_id") is None
            )
        )
        or (phase == "exited" and "start" not in current)
    ):
        raise ActivationError("identity_client_network_context_required")
    spec = runtime.recipe(store, path, plan_sha256, context_sha256)
    if "start" in current and any(
        current["start"].get(k) != v
        for k, v in {
            "recipe_sha256": digest(spec),
            "request_context_sha256": context_sha256,
            "runner_resource_id": spec["runner_resource_id"],
            "network_resource_id": spec["network_resource_id"],
        }.items()
    ):
        raise ActivationError("identity_client_network_start_binding_mismatch")
    spec["network_recipe"] = network.recipe(store)
    spec["runner_name"] = runtime.server.recipe(store, path, plan_sha256)["name"]
    operation = store.summary()["id"]

    def budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ActivationError("identity_client_network_deadline")
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

    def sample():
        reports = {}
        for role, known in (
            (network.ROLE, spec["network_resource_id"]),
            ("runner", spec["runner_resource_id"]),
            (runtime.ROLE, current["resource_id"]),
        ):
            report = observe(operation, plan_sha256, role, known, docker=owners)
            absent = role == runtime.ROLE and phase == "create"
            if report["status"] != ("absent_snapshot" if absent else "present_owned_snapshot"):
                raise ActivationError("identity_client_network_ownership_mismatch")
            if (
                role != network.ROLE
                and not absent
                and (
                    report["details"]["image"] != spec["image"]
                    or report["details"]["running"] is not (role == "runner")
                )
            ):
                raise ActivationError("identity_client_network_ownership_mismatch")
            reports[role] = report
        limit = budget()
        raw = (
            docker.query(store, spec["network_resource_id"])
            if docker is not None
            else _execute(network.command(store, spec["network_resource_id"]), timeout=limit)
        )
        budget()
        item = document(raw)
        count = _members(spec, item, current["resource_id"], phase)
        if reports[network.ROLE]["details"]["member_count"] != count:
            raise ActivationError("identity_client_network_count_changed")
        return {"owners": reports, "configuration": item, "count": count}

    before, after = sample(), sample()
    repeated = runtime.recipe(store, path, plan_sha256, context_sha256)
    repeated["network_recipe"] = network.recipe(store)
    repeated["runner_name"] = runtime.server.recipe(store, path, plan_sha256)["name"]
    if before != after or store.review() != original or digest(repeated) != digest(spec):
        raise ActivationError("identity_client_network_changed_during_review")
    budget()
    return {
        "format": "aegis-identity-client-network-review/1",
        "phase": phase,
        "network_resource_id": spec["network_resource_id"],
        "runner_resource_id": spec["runner_resource_id"],
        "client_resource_id": current["resource_id"],
        "request_context_sha256": context_sha256,
        "members_reviewed": after["count"],
        "snapshot_sha256": digest(after),
        "expected_member_set_verified": True,
        "configured_internal_isolated_bridge_verified": True,
        "mutual_tls_verified": False,
        "network_reachability_verified": False,
        "project_quiescence_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
