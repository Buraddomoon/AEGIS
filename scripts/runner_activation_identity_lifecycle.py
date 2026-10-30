"""Single identity-server create/start under computed gates; no CLI or automatic invocation."""

import copy
import subprocess

import runner_activation_identity_gates as gates
import runner_activation_identity_inspection as inspection
import runner_activation_identity_runtime as runtime
import runner_activation_identity_server as server
import runner_activation_owned_probe as owned
from aegis.domain.validation import digest
from runner_activation_metadata import IMAGES, ActivationError
from runner_activation_ownership import identifier, observe


def start_server(reviews, *, lifecycle=None, cleanup_docker=None):
    """Keep an inspected identity-only server for a future bounded client.

    Trusted internal coordinator only, following specific native authorization.
    An existing role, including ABSENT, can only be reconciled/cleaned, never
    restarted here. No DB/journal/marker access, socket, health exec or retries.
    """
    if not isinstance(reviews, gates.IdentityGates):
        raise ActivationError("identity_server_computed_gates_required")
    c = reviews.confirmation
    state = c._guard()
    if "runner" in state["resources"]:
        raise ActivationError("identity_server_new_role_required_no_replay")
    spec = runtime.recipe(c.store, c.path, c.plan_sha256)
    images = {key: c.artifact["metadata"]["images"][key]["id"] for key in IMAGES}

    def ownership(known_id=None):
        return observe(
            c.operation,
            c.plan_sha256,
            "runner",
            known_id,
            docker=reviews.ownership_docker,
        )

    if ownership()["status"] != "absent_snapshot":
        raise ActivationError("identity_server_prior_resource_present")
    lifecycle = lifecycle or server.IdentityServerDocker()
    attempted, success, cleanup = False, False, None
    object_id, physical, error = None, None, None
    phase, failure_phase = "create_gate", None
    approved_hashes = {}

    def gate(stage):
        before = c._guard()
        approved = reviews.review(stage, copy.deepcopy(spec))
        gates.validate(
            approved, stage, spec, before, c.operation, c.artifact["pki"]["manifest_sha256"]
        )
        if c._guard() != before or digest(runtime.recipe(c.store, c.path, c.plan_sha256)) != digest(
            spec
        ):
            raise ActivationError("identity_server_gate_context_changed")
        approved_hashes[stage] = digest(approved)
        return approved, before

    def inspect(stage):
        return inspection.review(
            c.store,
            c.path,
            c.plan_sha256,
            object_id,
            stage,
            docker=reviews.runtime_docker,
            ownership_docker=reviews.ownership_docker,
        )

    try:
        c.store.request("runner")
        approved, requested = gate("create")
        if c._guard() != requested or ownership()["status"] != "absent_snapshot":
            raise ActivationError("identity_server_create_context_changed")
        owned.fresh(approved)
        c._guard()
        phase, attempted = "create", True
        object_id = identifier(lifecycle.create(c))
        found = ownership()
        if found["status"] != "present_owned_snapshot" or found["resource_id"] != object_id:
            raise ActivationError("identity_server_created_id_unconfirmed")
        c.store.append("observed", {"role": "runner", "resource_id": object_id})
        phase = "start_gate"
        approved, _ = gate("start")  # Includes physical created configuration.
        c.store.append(
            "identity_start_requested",
            {
                "role": "runner",
                "mode": "identity-only",
                "recipe_sha256": digest(spec),
                "gates_sha256": digest(approved),
                "pki_manifest_sha256": c.artifact["pki"]["manifest_sha256"],
                "network_resource_id": spec["network_resource_id"],
            },
        )
        fenced = c._guard()
        phase = "inspect_before_start"
        inspect("created")
        if c._guard() != fenced:
            raise ActivationError("identity_server_start_context_changed")
        owned.fresh(approved)
        phase = "start"
        lifecycle.start(c, object_id)
        phase = "inspect_running"
        physical = inspect("running")
        c._guard()
        c.store.append(
            "identity_runtime_observed",
            {
                "role": "runner",
                "runtime_evidence_sha256": digest(physical),
            },
        )
        phase = "running_gate"
        gate("running")
        c._guard()
        success = True
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        error, failure_phase = "identity_server_startup_unconfirmed", phase
    finally:
        if not success:
            cleanup = owned.cleanup_owned_probe(
                c.store,
                images,
                "runner",
                attempted,
                ownership_docker=reviews.ownership_docker,
                cleanup_docker=cleanup_docker,
            )
    removed = cleanup is not None and cleanup["selected_resources_absence_verified"] is True
    return {
        "format": "aegis-identity-server-lifecycle-review/1",
        "operation_id": c.operation,
        "resource_id": object_id,
        "plan_sha256": c.plan_sha256,
        "scope_sha256": c.scope,
        "recipe_sha256": digest(spec),
        "gate_sha256": approved_hashes,
        "status": "owned_identity_server_running_and_retained"
        if success
        else "identity_server_failed_and_absence_verified"
        if removed
        else "identity_server_cleanup_unconfirmed",
        "error": error,
        "failure_phase": failure_phase,
        "runtime": physical if success else None,
        "cleanup": cleanup,
        "server_retained": success,
        "server_absence_verified": removed,
        "mutual_tls_verified": False,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
        "marker_executed": False,
    }
