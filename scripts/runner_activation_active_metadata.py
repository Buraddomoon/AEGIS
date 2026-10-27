"""Read-only metadata gates while exact durably owned activation resources exist."""

import copy
import time

import runner_activation_metadata as metadata
import runner_activation_ownership as ownership
from aegis.domain.validation import digest
from runner_activation_cleanup import IMAGE_ROLE
from runner_activation_metadata import ActivationError


class _Budget:
    def __init__(self, backend, own, deadline):
        self.backend, self.own, self.deadline = backend, own, deadline

    def query(self, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ActivationError("active_metadata_time_limit")
        if self.backend is not None:
            raw = self.backend.query(*args)
        else:
            command = ownership.command(*args) if self.own else metadata.command(*args)
            raw = metadata._execute(command, timeout=min(metadata.TIMEOUT, remaining))
        if time.monotonic() >= self.deadline:
            raise ActivationError("active_metadata_time_limit")
        return raw


def _ids(raw, maximum):
    if type(raw) is not bytes or len(raw) > metadata.MAX_OUTPUT:
        raise ActivationError("active_metadata_id_projection_invalid")
    try:
        values = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise ActivationError("active_metadata_id_projection_invalid") from None
    if len(values) > maximum or len(set(values)) != len(values):
        raise ActivationError("active_metadata_ambiguous_resources")
    return {ownership.identifier(value) for value in values}


def review(store, images, expected_inventory, role, phase, *, docker=None, ownership_docker=None):
    """No SQL/PKI/auth/worker/runtime proof is inferred from these metadata gates."""
    deadline = time.monotonic() + 20
    if role not in {"journal-before", "journal-after"} or phase not in {"create", "start"}:
        raise ActivationError("active_metadata_probe_context_required")
    original = store.review()
    images = copy.deepcopy(images)
    expected_inventory_sha256 = digest(expected_inventory)
    owned = original["resources"]
    current = owned.get(role)
    if (
        original["closed"]
        or current is None
        or (
            phase == "create"
            and (current["state"] != "REQUESTED" or current["resource_id"] is not None)
        )
        or (
            phase == "start"
            and (
                current["state"] not in {"OBSERVED", "START_REQUESTED"}
                or current["resource_id"] is None
            )
        )
        or any(item["state"] in {"CONFLICT", "REMOVAL_REQUESTED"} for item in owned.values())
        or any(item["state"] == "REQUESTED" and key != role for key, item in owned.items())
        or ("runner" in owned and owned["runner"]["state"] != "ABSENT")
    ):
        raise ActivationError("active_metadata_unresolved_or_incompatible_ownership")
    operation = store.summary()["id"]
    plan = original["header"]["plan_sha256"]
    docker, owners = _Budget(docker, False, deadline), _Budget(ownership_docker, True, deadline)

    def sample():
        observed = metadata.inventory(images, docker=docker)
        if digest(observed) != expected_inventory_sha256:
            raise ActivationError("active_metadata_inventory_drift")
        reports = {}
        containers, networks = set(), set()
        network_names = {}
        for key, item in owned.items():
            found = ownership.observe(operation, plan, key, item["resource_id"], docker=owners)
            should_exist = item["state"] != "ABSENT" and not (key == role and phase == "create")
            if (found["status"] == "present_owned_snapshot") != should_exist:
                raise ActivationError("active_metadata_resource_presence_mismatch")
            if should_exist:
                if item["resource_id"] is None or found["resource_id"] != item["resource_id"]:
                    raise ActivationError("active_metadata_resource_id_unconfirmed")
                if key in IMAGE_ROLE:
                    if found["details"]["image"] != images[IMAGE_ROLE[key]]:
                        raise ActivationError("active_metadata_owned_image_mismatch")
                    if key == role and found["details"]["running"] is not False:
                        raise ActivationError("active_metadata_probe_already_running")
                    containers.add(item["resource_id"])
                else:
                    networks.add(item["resource_id"])
                    network_names[key.removeprefix("network-")] = {item["resource_id"]}
            reports[key] = found
        if (
            _ids(docker.query("containers"), 6) != containers
            or _ids(docker.query("networks"), 3) != networks
        ):
            raise ActivationError("active_metadata_project_membership_mismatch")
        for name in metadata.NETWORKS:
            if _ids(docker.query("network_name", name), 1) != network_names.get(name, set()):
                raise ActivationError("active_metadata_reserved_network_mismatch")
        journal_ids = {current["resource_id"]} if phase == "start" else set()
        db = owned.get("db")
        db_ids = {db["resource_id"]} if db and db["state"] != "ABSENT" else set()
        if (
            _ids(docker.query("consumers", "journal"), 1) != journal_ids
            or _ids(docker.query("consumers", "postgres-data"), 1) != db_ids
        ):
            raise ActivationError("active_metadata_volume_consumer_mismatch")
        return {"inventory": observed, "ownership": reports}

    before = sample()
    after = sample()
    if digest(before) != digest(after) or digest(store.review()) != digest(original):
        raise ActivationError("active_metadata_changed_during_review")
    result = {
        "format": "aegis-active-activation-metadata/1",
        "operation_id": operation,
        "plan_sha256": plan,
        "role": role,
        "phase": phase,
        "status": "owned_metadata_snapshot_consistent",
        "inventory": before["inventory"],
        "ownership_sha256": digest(before["ownership"]),
        "resources_reviewed": len(owned),
        "journal_consumer_set_verified": True,
        "project_membership_verified": True,
        "database_binding_verified": False,
        "journal_contents_verified": False,
        "image_provenance_verified": False,
        "network_isolation_verified": False,
        "authorization_verified": False,
        "normal_operation_permitted": False,
    }
    if time.monotonic() >= deadline:
        raise ActivationError("active_metadata_time_limit")
    return result
