"""Internal fixed probe lifecycle; the authorized coordinator must supply fresh gates."""

import copy
import json
import subprocess

import runner_activation_owned_probe as owned_probe
import runner_activation_probe_runtime as runtime
from aegis.domain.validation import digest
from aegis.lab_runner.journal_probe import MAX_INPUT
from aegis.lab_runner.persisted_review import expected_proofs
from runner_activation_intents import _hash
from runner_activation_metadata import IMAGES, ActivationError, _execute, image_id
from runner_activation_ownership import identifier
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
    owned_probe.fresh(gate)
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

    return owned_probe.run(
        store,
        images,
        role,
        spec,
        proof_sha256,
        review_image=lambda: runtime.review_image(
            operation_id, plan_sha256, role, images["runner"], proof_sha256, docker=runtime_docker
        ),
        gate=lambda phase: _gate(
            before_effect, phase, spec, state, operation_id, identity, bundle, proof_sha256
        ),
        review_runtime=review,
        create=lambda: lifecycle.create(
            operation_id, plan_sha256, role, images["runner"], proof_sha256
        ),
        start=lambda known_id: lifecycle.start(
            operation_id, plan_sha256, role, images["runner"], proof_sha256, known_id, payload
        ),
        validate_reply=lambda raw: decode(raw, bundle, proof_sha256),
        ownership_docker=ownership_docker,
        cleanup_docker=cleanup_docker,
    )
