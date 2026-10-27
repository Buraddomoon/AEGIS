"""Internal fixed probe lifecycle; the authorized coordinator must supply fresh gates."""

import copy
import json
import subprocess
from datetime import datetime, timedelta

import runner_activation_cleanup as closure
import runner_activation_probe_runtime as runtime
import runner_pki as pki
from aegis.domain.validation import digest
from aegis.lab_runner.journal_probe import MAX_INPUT
from aegis.lab_runner.persisted_review import expected_proofs
from runner_activation_intents import _hash
from runner_activation_metadata import IMAGES, ActivationError, _execute, image_id
from runner_activation_ownership import identifier, observe
from runner_activation_probe_result import decode

CHECKS = frozenset(
    {
        "specific_authorization_verified",
        "plan_current",
        "image_provenance_verified",
        "original_database_binding_verified",
        "persisted_history_verified",
        "existing_journal_volume_verified",
        "exclusive_journal_consumer_verified",
        "worker_stopped",
    }
)


def command(kind, operation_id, plan_sha256, role, image, proof_sha256, known_id=None):
    runtime.recipe(operation_id, plan_sha256, role, image, proof_sha256)
    if kind == "create" and known_id is None:
        return runtime.create_arguments(operation_id, plan_sha256, role, image, proof_sha256)
    if kind == "start" and known_id is not None:
        return ("container", "start", "--attach", "--interactive", identifier(known_id))
    raise ActivationError("journal_probe_lifecycle_command_not_allowed")


class ProbeDocker:
    def create(self, operation_id, plan_sha256, role, image, proof_sha256):
        try:
            raw = _execute(command("create", operation_id, plan_sha256, role, image, proof_sha256))
            return identifier(raw.decode("ascii").removesuffix("\n"))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("journal_probe_create_outcome_unconfirmed") from None

    def start(self, operation_id, plan_sha256, role, image, proof_sha256, known_id, payload):
        try:
            return _execute(
                command("start", operation_id, plan_sha256, role, image, proof_sha256, known_id),
                payload=payload,
                timeout=20,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ActivationError("journal_probe_start_outcome_unconfirmed") from None


def _fresh(gate):
    checked, expires = (
        datetime.fromisoformat(gate["checked_at"]),
        datetime.fromisoformat(gate["expires_at"]),
    )
    now = pki.clock()
    if (
        checked.utcoffset() != timedelta(0)
        or expires.utcoffset() != timedelta(0)
        or not timedelta(0) < expires - checked <= timedelta(seconds=30)
        or not checked <= now < expires
        or now - checked > timedelta(seconds=10)
    ):
        raise ActivationError("journal_probe_gate_stale")


def _gate(callback, phase, spec, state, operation_id, identity, bundle, proof_sha256):
    # This is a trusted internal callback, never an approval JSON accepted by an
    # API/CLI. The complete coordinator must compute the checks from real gates.
    gate = callback(phase, copy.deepcopy(spec))
    expected = {
        "format": "aegis-journal-probe-gate/1",
        "phase": phase,
        "operation_id": operation_id,
        "plan_sha256": state["header"]["plan_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        "recipe_sha256": digest(spec),
        "proof_bundle_sha256": proof_sha256,
        "old_descriptor_sha256": bundle["old_descriptor_sha256"],
        "identity_sha256": digest(identity.model_dump(mode="json")),
    }
    if (
        not isinstance(gate, dict)
        or set(gate) != {*expected, "checked_at", "expires_at", "checks"}
        or any(gate[key] != value for key, value in expected.items())
        or not isinstance(gate["checks"], dict)
        or set(gate["checks"]) != CHECKS
        or any(value is not True for value in gate["checks"].values())
    ):
        raise ActivationError("journal_probe_gate_mismatch")
    _fresh(gate)
    return gate


def execute_probe(
    store,
    images,
    role,
    bundle,
    proof_sha256,
    *,
    before_effect,
    lifecycle=None,
    runtime_docker=None,
    ownership_docker=None,
    cleanup_docker=None,
):
    """Execute at most once and remove only this probe, keeping its parent intent open.

    No public entry point. before_effect is required and must independently verify
    scope/authorization/plan/images/original DB/volume/consumers before each effect.
    Passing fixtures to that callback does not authorize a real Docker invocation.
    """
    _hash(proof_sha256)
    identity, _ = expected_proofs(bundle, proof_sha256)
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_INPUT:
        raise ActivationError("journal_probe_input_limit")
    if not isinstance(images, dict) or set(images) != set(IMAGES) or not callable(before_effect):
        raise ActivationError("journal_probe_images_and_trusted_gates_required")
    images = copy.deepcopy(images)
    for value in images.values():
        image_id(value)
    if len(set(images.values())) != len(IMAGES):
        raise ActivationError("journal_probe_distinct_images_required")
    state = store.review()
    operation_id, plan_sha256 = store.summary()["id"], state["header"]["plan_sha256"]
    spec = runtime.recipe(operation_id, plan_sha256, role, images["runner"], proof_sha256)
    if state["closed"] or role in state["resources"]:
        raise ActivationError("journal_probe_new_role_required_no_replay")
    lifecycle = lifecycle or ProbeDocker()
    result = None
    error = None
    cleanup = None
    gates = {}
    create_attempted = False

    def review(phase, known_id):
        return runtime.review(
            operation_id,
            plan_sha256,
            role,
            images["runner"],
            proof_sha256,
            known_id,
            phase,
            docker=runtime_docker,
            ownership_docker=ownership_docker,
        )

    runtime.review_image(
        operation_id, plan_sha256, role, images["runner"], proof_sha256, docker=runtime_docker
    )
    if (
        observe(operation_id, plan_sha256, role, docker=ownership_docker)["status"]
        != "absent_snapshot"
    ):
        raise ActivationError("journal_probe_prior_resource_present")
    try:
        store.request(role)
        gate = _gate(
            before_effect, "create", spec, state, operation_id, identity, bundle, proof_sha256
        )
        gates["create"] = digest(gate)
        if store.review()["resources"][role]["state"] != "REQUESTED":
            raise ActivationError("journal_probe_create_intent_changed")
        if (
            observe(operation_id, plan_sha256, role, docker=ownership_docker)["status"]
            != "absent_snapshot"
        ):
            raise ActivationError("journal_probe_resource_appeared_before_create")
        _fresh(gate)
        create_attempted = True
        created_id = lifecycle.create(
            operation_id, plan_sha256, role, images["runner"], proof_sha256
        )
        identifier(created_id)
        present = observe(operation_id, plan_sha256, role, docker=ownership_docker)
        if present["status"] != "present_owned_snapshot" or present["resource_id"] != created_id:
            raise ActivationError("journal_probe_created_id_unconfirmed")
        store.append("observed", {"role": role, "resource_id": created_id})
        review("created", created_id)
        gate = _gate(
            before_effect, "start", spec, state, operation_id, identity, bundle, proof_sha256
        )
        gates["start"] = digest(gate)
        store.append(
            "probe_start_requested",
            {
                "role": role,
                "recipe_sha256": digest(spec),
                "gates_sha256": digest(gate),
                "proof_bundle_sha256": proof_sha256,
            },
        )
        # Intention must be durable BEFORE the final runtime/ownership recheck.
        if store.review()["resources"][role]["state"] != "START_REQUESTED":
            raise ActivationError("journal_probe_start_intent_changed")
        review("created", created_id)
        _fresh(gate)
        raw = lifecycle.start(
            operation_id, plan_sha256, role, images["runner"], proof_sha256, created_id, payload
        )
        review("exited", created_id)
        result = decode(raw, bundle, proof_sha256)
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        error = "journal_probe_execution_unconfirmed"
    finally:
        try:
            current = store.review()
            # A collision detected before attempting create is not permission to
            # delete a pre-existing resource. Keep the intent for investigation.
            found = (
                None
                if create_attempted
                else observe(operation_id, plan_sha256, role, docker=ownership_docker)
            )
            if (
                not create_attempted
                and found["status"] != "absent_snapshot"
                and role in current["resources"]
                and current["resources"][role]["state"] == "REQUESTED"
            ):
                store.append("ownership_conflict", {"role": role, "evidence_sha256": digest(found)})
            may_clean = create_attempted or found["status"] == "absent_snapshot"
            if role in current["resources"] and may_clean:
                cleanup = closure.cleanup(
                    store,
                    images,
                    roles={role},
                    close_operation=False,
                    docker=cleanup_docker,
                    ownership_docker=ownership_docker,
                )
        except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError):
            cleanup = None
    clean = cleanup is not None and cleanup["selected_resources_absence_verified"]
    return {
        "format": "aegis-journal-probe-lifecycle-review/1",
        "operation_id": operation_id,
        "role": role,
        "recipe_sha256": digest(spec),
        "gate_sha256": gates,
        "status": "probe_completed_and_removed"
        if result is not None and clean
        else "probe_execution_unconfirmed"
        if clean
        else "probe_cleanup_unconfirmed",
        "error": error,
        "result": result,
        "cleanup": cleanup,
        "probe_removed": clean,
        "probe_result_verified": result is not None,
        "authorization_verified": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
