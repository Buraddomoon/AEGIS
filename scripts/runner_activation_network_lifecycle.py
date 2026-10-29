"""Internal single-create rotation network; real invocation requires future authorized gates."""

import copy
import subprocess

import runner_activation_isolated_network as network
import runner_activation_owned_probe as owned
from aegis.domain.validation import digest
from runner_activation_metadata import IMAGES, ActivationError, _execute, image_id
from runner_activation_ownership import identifier, observe

CHECKS = frozenset(
    {
        "specific_authorization_verified",
        "plan_current",
        "pki_candidate_verified",
        "reviewed_network_profile",
        "project_quiescent_or_owned",
        "subnet_availability_verified",
        "worker_stopped",
    }
)


class NetworkLifecycleDocker:
    def create(self, store):
        try:
            raw = _execute(network.create_arguments(store))
            return identifier(raw.decode("ascii").removesuffix("\n"))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("isolated_network_create_outcome_unconfirmed") from None


def _gate(callback, spec, state, operation):
    value = callback("create", copy.deepcopy(spec))
    expected = {
        "format": "aegis-rotation-network-gate/1",
        "phase": "create",
        "operation_id": operation,
        "plan_sha256": state["header"]["plan_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        "recipe_sha256": digest(spec),
        "network_name": spec["name"],
    }
    if (
        not isinstance(value, dict)
        or set(value) != {*expected, "checked_at", "expires_at", "checks"}
        or any(value[key] != item for key, item in expected.items())
        or not isinstance(value["checks"], dict)
        or set(value["checks"]) != CHECKS
        or any(item is not True for item in value["checks"].values())
    ):
        raise ActivationError("isolated_network_gate_mismatch")
    owned.fresh(value)
    return value


def create_network(
    store,
    images,
    *,
    before_effect,
    lifecycle=None,
    runtime_docker=None,
    ownership_docker=None,
    cleanup_docker=None,
):
    """Retain only an inspected empty owned bridge; no public CLI or gate JSON input.

    The full coordinator must derive these gates before any native invocation.
    Success does not prove traffic isolation, mTLS, PKI activation or authorization.
    """
    if not isinstance(images, dict) or set(images) != set(IMAGES) or not callable(before_effect):
        raise ActivationError("isolated_network_original_images_and_gates_required")
    images = copy.deepcopy(images)
    for value in images.values():
        image_id(value)
    if len(set(images.values())) != len(IMAGES):
        raise ActivationError("isolated_network_distinct_images_required")
    state = store.review()
    if state["closed"] or network.ROLE in state["resources"]:
        raise ActivationError("isolated_network_new_role_required_no_replay")
    spec = network.recipe(store)
    operation, plan = store.summary()["id"], state["header"]["plan_sha256"]
    if (
        observe(operation, plan, network.ROLE, docker=ownership_docker)["status"]
        != "absent_snapshot"
    ):
        raise ActivationError("isolated_network_prior_resource_present")
    lifecycle = lifecycle or NetworkLifecycleDocker()
    attempted, success, cleanup = False, False, None
    known_id, runtime, approved_sha, error = None, None, None, None
    phase, failure_phase = "create_gate", None
    try:
        store.request(network.ROLE)
        requested = store.review()
        approved = _gate(before_effect, spec, state, operation)
        approved_sha = digest(approved)
        if (
            store.review() != requested
            or digest(network.recipe(store)) != digest(spec)
            or observe(operation, plan, network.ROLE, docker=ownership_docker)["status"]
            != "absent_snapshot"
        ):
            raise ActivationError("isolated_network_create_context_changed")
        owned.fresh(approved)
        phase, attempted = "create", True
        known_id = identifier(lifecycle.create(store))
        found = observe(operation, plan, network.ROLE, docker=ownership_docker)
        if found["status"] != "present_owned_snapshot" or found["resource_id"] != known_id:
            raise ActivationError("isolated_network_created_id_unconfirmed")
        store.append("observed", {"role": network.ROLE, "resource_id": known_id})
        phase = "inspect_created"
        runtime = network.review(
            store, known_id, docker=runtime_docker, ownership_docker=ownership_docker
        )
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
        error, failure_phase = "isolated_network_creation_unconfirmed", phase
    finally:
        if not success:
            cleanup = owned.cleanup_owned_probe(
                store,
                images,
                network.ROLE,
                attempted,
                ownership_docker=ownership_docker,
                cleanup_docker=cleanup_docker,
            )
    removed = cleanup is not None and cleanup["selected_resources_absence_verified"] is True
    return {
        "format": "aegis-isolated-network-lifecycle-review/1",
        "operation_id": operation,
        "resource_id": known_id,
        "recipe_sha256": digest(spec),
        "gate_sha256": approved_sha,
        "status": "empty_owned_network_created_and_retained"
        if success
        else "network_failed_and_absence_verified"
        if removed
        else "network_cleanup_unconfirmed",
        "error": error,
        "failure_phase": failure_phase,
        "runtime": runtime if success else None,
        "cleanup": cleanup,
        "network_retained": success,
        "network_absence_verified": removed,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
