"""Internal read-only diagnostic checks under durable ownership; never an approval."""

import time

import runner_activation_active_metadata as active
import runner_diagnostic_plan as plan
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError


def _public(expected, repo):
    public, _validity = plan.pki.inventory(repo / ".local/linux-lab", current=False)
    if (
        digest(public) != expected["public_source_sha256"]
        or public["descriptor_sha256"] != expected["old_descriptor_sha256"]
        or {name: public["connection"][name] for name in plan.pki.IDS} != expected["identity"]
    ):
        raise ActivationError("diagnostic_public_identity_drift")


def inputs(expected, *, repo=plan.ROOT):
    """Revalidate executable code/image inputs without assuming a quiescent daemon."""
    if plan.source._state(repo) != expected["tool_commit"]:
        raise ActivationError("diagnostic_tool_commit_drift")
    images = {key: expected["metadata"]["images"][key]["id"] for key in plan.metadata.IMAGES}
    if digest(expected["postgres_origin"]) != expected["postgres_origin_sha256"]:
        raise ActivationError("diagnostic_postgres_origin_integrity_mismatch")
    plan.pg_origin.review(images["postgres"], expected["postgres_origin"])
    plan.pg_origin.inspection.review_image(images["postgres"])
    build = plan._runner(expected["runner_build"], images)
    if (
        plan._current_source(repo, build) != expected["tool_commit"]
        or build["source_sha256"] != expected["runner_source_sha256"]
    ):
        raise ActivationError("diagnostic_executable_input_drift")
    _public(expected, repo)
    return images


def recheck(
    folder,
    expected_sha256,
    store,
    role,
    phase,
    *,
    repo=plan.ROOT,
    docker=None,
    ownership_docker=None,
):
    """Compute facts only: authorization, SQL contents and physical runtime are separate."""
    deadline = time.monotonic() + 30
    artifact = plan.load(folder, expected_sha256)
    state = store.review()
    if (
        not active.context_allowed(role, phase)
        or role not in plan.profile()["roles"]
        or state["closed"]
        or state["header"]
        != {
            "plan_id": artifact["id"],
            "plan_sha256": expected_sha256,
            "scope_sha256": artifact["scope_sha256"],
        }
        or not set(state["resources"]) <= set(plan.profile()["roles"])
    ):
        raise ActivationError("diagnostic_owned_context_mismatch")
    expected = artifact["snapshot"]
    images = inputs(expected, repo=repo)
    database = state["resources"].get("db")
    if role != "db" and (
        database is None
        or database["state"] != "OBSERVED"
        or "start" not in database
        or "runtime_evidence_sha256" not in database
    ):
        raise ActivationError("diagnostic_started_database_required")
    observed = active.review(
        store,
        images,
        expected["metadata"],
        role,
        phase,
        docker=docker,
        ownership_docker=ownership_docker,
    )
    _public(expected, repo)
    if (
        plan.source._state(repo) != expected["tool_commit"]
        or digest(store.review()) != digest(state)
        or plan.load(folder, expected_sha256) != artifact
        or time.monotonic() >= deadline
    ):
        raise ActivationError("diagnostic_owned_inputs_changed_or_expired")
    return {
        "format": "aegis-owned-diagnostic-review/1",
        "plan_id": artifact["id"],
        "plan_sha256": expected_sha256,
        "scope_sha256": artifact["scope_sha256"],
        "operation_id": store.summary()["id"],
        "role": role,
        "phase": phase,
        "checked_at": plan.pki.clock().isoformat(),
        "status": "owned_diagnostic_inputs_consistent_not_authorized",
        "local_runner_build_inputs_verified": True,
        "owned_metadata": observed,
        **plan.FLAGS,
    }
