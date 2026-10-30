"""Read-only client configuration and ownership, never TLS-result or lifecycle evidence."""

import time

import runner_activation_identity_client_runtime as runtime
import runner_activation_identity_inspection as server
from aegis.domain.validation import digest
from runner_activation_metadata import TIMEOUT, ActivationError, _execute, document
from runner_activation_ownership import command as ownership_command
from runner_activation_ownership import identifier, observe


def validate(spec, item, known_id, phase):
    if phase not in {"created", "exited"}:
        raise ActivationError("identity_client_runtime_phase_invalid")
    server._configuration(spec, item, known_id, phase, ip=runtime.IP, stdin_open=True)


def review(
    store,
    path,
    plan_sha256,
    context_sha256,
    known_id,
    phase,
    *,
    docker=None,
    ownership_docker=None,
):
    deadline = time.monotonic() + 20

    def budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ActivationError("identity_client_runtime_deadline")
        return min(TIMEOUT, remaining)

    if phase not in {"created", "exited"}:
        raise ActivationError("identity_client_runtime_phase_invalid")
    original = store.review()
    current = original["resources"].get(runtime.ROLE, {})
    if (
        current.get("resource_id") != identifier(known_id)
        or current.get("state") not in {"OBSERVED", "START_REQUESTED"}
        or (phase == "exited" and "start" not in current)
    ):
        raise ActivationError("identity_client_observed_context_required")
    spec = runtime.recipe(store, path, plan_sha256, context_sha256)
    if "start" in current and any(
        current["start"].get(key) != value
        for key, value in {
            "recipe_sha256": digest(spec),
            "request_context_sha256": context_sha256,
            "runner_resource_id": spec["runner_resource_id"],
            "network_resource_id": spec["network_resource_id"],
        }.items()
    ):
        raise ActivationError("identity_client_start_binding_mismatch")
    operation = store.summary()["id"]

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
    before = observe(operation, plan_sha256, runtime.ROLE, known_id, docker=owners)
    limit = budget()
    item = document(
        docker.query("container", spec["image"], spec=spec, known_id=known_id)
        if docker is not None
        else _execute(
            server.command("container", spec["image"], spec=spec, known_id=known_id), timeout=limit
        )
    )
    budget()
    validate(spec, item, known_id, phase)
    after = observe(operation, plan_sha256, runtime.ROLE, known_id, docker=owners)
    if (
        before != after
        or before["status"] != "present_owned_snapshot"
        or before["details"]["image"] != spec["image"]
        or before["details"]["running"] is not False
        or store.review() != original
        or digest(runtime.recipe(store, path, plan_sha256, context_sha256)) != digest(spec)
    ):
        raise ActivationError("identity_client_runtime_changed")
    budget()
    return {
        "format": "aegis-identity-client-runtime-review/1",
        "phase": phase,
        "resource_id": known_id,
        "runner_resource_id": spec["runner_resource_id"],
        "network_resource_id": spec["network_resource_id"],
        "request_context_sha256": context_sha256,
        "recipe_sha256": digest(spec),
        "configuration_sha256": digest(item),
        "runtime_configuration_verified": True,
        "original_volumes_not_mounted_verified": True,
        "published_ports_absent_verified": True,
        "candidate_client_mount_paths_verified": True,
        "tls_result_verified": False,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
