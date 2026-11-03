"""Recheck a pinned activation plan during exact durable ownership; no new effects."""

from datetime import datetime
from pathlib import Path

import runner_activation as activation
import runner_activation_active_metadata as active
from aegis.domain.validation import digest
from runner_activation_metadata import IMAGES, ActivationError


def recheck(
    path,
    expected_sha256,
    store,
    role,
    phase,
    *,
    docker=None,
    ownership_docker=None,
    request_context_sha256=None,
):
    if not active.context_allowed(role, phase):
        raise ActivationError("active_plan_probe_context_required")
    client_context = role == active.IDENTITY_CLIENT_ROLE
    if client_context:
        activation.sha256(request_context_sha256)
    elif request_context_sha256 is not None:
        raise ActivationError("active_plan_client_context_not_allowed")
    artifact = activation.load_plan(path, expected_sha256)
    state = store.review()
    if (
        state["header"]["plan_id"] != artifact["id"]
        or state["header"]["plan_sha256"] != expected_sha256
        or state["header"]["scope_sha256"] != artifact["scope_sha256"]
        or state["closed"]
    ):
        raise ActivationError("active_plan_intent_mismatch")
    if role == "runner":
        from runner_activation_identity_runtime import recipe

        spec = recipe(store, path, expected_sha256)
        started = state["resources"].get("runner", {}).get("start")
        if started is not None and (
            started.get("mode") != "identity-only"
            or started.get("recipe_sha256") != digest(spec)
            or started.get("pki_manifest_sha256") != artifact["pki"]["manifest_sha256"]
            or started.get("network_resource_id") != spec["network_resource_id"]
        ):
            raise ActivationError("active_plan_identity_start_binding_mismatch")
    if client_context:
        from runner_activation_identity_client_runtime import recipe

        spec = recipe(store, path, expected_sha256, request_context_sha256)
        started = state["resources"].get(active.IDENTITY_CLIENT_ROLE, {}).get("start")
        if (phase == "identity-exited" and started is None) or (
            started is not None
            and any(
                started.get(key) != value
                for key, value in {
                    "recipe_sha256": digest(spec),
                    "request_context_sha256": request_context_sha256,
                    "runner_resource_id": spec["runner_resource_id"],
                    "network_resource_id": spec["network_resource_id"],
                }.items()
            )
        ):
            raise ActivationError("active_plan_identity_client_start_binding_mismatch")
    images = {key: artifact["metadata"]["images"][key]["id"] for key in IMAGES}
    observed = None

    def collect(expected_images):
        nonlocal observed
        observed = active.review(
            store,
            expected_images,
            artifact["metadata"],
            role,
            phase,
            docker=docker,
            ownership_docker=ownership_docker,
        )
        return observed["inventory"]

    current = activation.snapshot(
        Path(artifact["source_path"]),
        Path(artifact["candidate_path"]),
        artifact["pki"]["manifest_sha256"],
        images,
        inventory_reader=collect,
    )
    if not activation.snapshot_matches(artifact, current):
        raise ActivationError("active_plan_input_drift")
    checked_at = activation.pki.clock()
    if (
        not datetime.fromisoformat(artifact["created_at"])
        <= checked_at
        < datetime.fromisoformat(artifact["expires_at"])
    ):
        raise ActivationError("active_plan_expired_during_review")
    if digest(store.review()) != digest(state):
        raise ActivationError("active_plan_ownership_changed")
    # Recheck time after durable ownership IO as well, never publish a stale gate.
    checked_at = activation.pki.clock()
    if (
        not datetime.fromisoformat(artifact["created_at"])
        <= checked_at
        < datetime.fromisoformat(artifact["expires_at"])
    ):
        raise ActivationError("active_plan_expired_during_review")
    return {
        "format": "aegis-active-activation-plan-review/1",
        "id": artifact["id"],
        "plan_sha256": expected_sha256,
        "operation_id": store.summary()["id"],
        "role": role,
        "phase": phase,
        "status": "active_plan_revalidated_not_activated",
        "checked_at": checked_at.isoformat(),
        "expires_at": artifact["expires_at"],
        "pki_manifest_sha256": artifact["pki"]["manifest_sha256"],
        "old_descriptor_sha256": artifact["pki"]["old_descriptor_sha256"],
        "new_descriptor_sha256": artifact["pki"]["new_descriptor_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        **({"request_context_sha256": request_context_sha256} if client_context else {}),
        "owned_metadata": observed,
        "pending_gates": list(activation.PENDING),
        **activation.FLAGS,
    }
