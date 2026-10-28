"""Internal fixed SQL proof reader lifecycle, awaiting a fully authorized coordinator."""

import copy
import subprocess

import runner_activation_database_result as results
import runner_activation_database_runtime as runtime
import runner_activation_owned_probe as owned_probe
from aegis.domain.validation import digest
from aegis.lab_runner.persisted_probe import MAX_OUTPUT, decode
from runner_activation_metadata import IMAGES, ActivationError, _execute, image_id
from runner_activation_ownership import identifier

CHECKS = frozenset(
    {
        "specific_authorization_verified",
        "plan_current",
        "image_provenance_verified",
        "original_database_volume_verified",
        "database_runtime_isolated",
        "database_authentication_policy_verified",
        "exclusive_database_consumer_verified",
        "worker_stopped",
    }
)


def command(kind, store, role, image, context_sha256, known_id=None):
    spec = runtime.recipe(store, role, image, context_sha256)
    current = store.review()["resources"].get(role)
    if current is None:
        raise ActivationError("database_reader_create_intent_required")
    if (
        kind == "create"
        and known_id is None
        and current["state"] == "REQUESTED"
        and current["resource_id"] is None
    ):
        return runtime.create_arguments(store, role, image, context_sha256)
    if (
        kind == "start"
        and known_id is not None
        and current["state"] == "START_REQUESTED"
        and current["resource_id"] == identifier(known_id)
        and current["start"]["recipe_sha256"] == digest(spec)
        and current["start"]["request_context_sha256"] == context_sha256
    ):
        return ("container", "start", "--attach", "--interactive", known_id)
    raise ActivationError("database_reader_lifecycle_command_not_allowed")


class DatabaseProbeDocker:
    def create(self, store, role, image, context_sha256):
        try:
            raw = _execute(command("create", store, role, image, context_sha256))
            return identifier(raw.decode("ascii").removesuffix("\n"))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("database_reader_create_outcome_unconfirmed") from None

    def start(self, store, role, image, context_sha256, known_id, payload):
        try:
            decode(payload, context_sha256)
            return _execute(
                command("start", store, role, image, context_sha256, known_id),
                payload=payload,
                timeout=20,
                output_limit=MAX_OUTPUT,
            )
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            raise ActivationError("database_reader_start_outcome_unconfirmed") from None


def _gate(callback, phase, spec, state, operation, identity, descriptor, context_sha256):
    # Internal trusted callback only; no approval JSON can be supplied over API/CLI.
    approved = callback(phase, copy.deepcopy(spec))
    expected = {
        "format": "aegis-database-reader-gate/1",
        "phase": phase,
        "operation_id": operation,
        "plan_sha256": state["header"]["plan_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        "recipe_sha256": digest(spec),
        "request_context_sha256": context_sha256,
        "old_descriptor_sha256": descriptor,
        "identity_sha256": digest(identity.model_dump(mode="json")),
        "database_resource_id": spec["database_resource_id"],
    }
    if (
        not isinstance(approved, dict)
        or set(approved) != {*expected, "checked_at", "expires_at", "checks"}
        or any(approved[key] != value for key, value in expected.items())
        or not isinstance(approved["checks"], dict)
        or set(approved["checks"]) != CHECKS
        or any(value is not True for value in approved["checks"].values())
    ):
        raise ActivationError("database_reader_gate_mismatch")
    owned_probe.fresh(approved)
    return approved


def execute_reader(
    store,
    images,
    role,
    identity,
    old_descriptor_sha256,
    password,
    *,
    before_effect,
    lifecycle=None,
    runtime_docker=None,
    ownership_docker=None,
    cleanup_docker=None,
    capture_root=results.DEFAULT_ROOT,
):
    """Once per role, private capture, cleanup even on interrupt; never close parent.

    Gates prove physical DB/runtime/auth/provenance before reading it, not the
    history this probe has yet to collect. This breaks no prerequisite by asserting
    persisted_history_verified before the query. No real invocation in tests/CI.
    """
    payload, context_sha256 = results.request(identity, old_descriptor_sha256, password)
    if not isinstance(images, dict) or set(images) != set(IMAGES) or not callable(before_effect):
        raise ActivationError("database_reader_images_and_trusted_gates_required")
    images = copy.deepcopy(images)
    for value in images.values():
        image_id(value)
    if len(set(images.values())) != len(IMAGES):
        raise ActivationError("database_reader_distinct_images_required")
    state = store.review()
    operation = store.summary()["id"]
    spec = runtime.recipe(store, role, images["runner"], context_sha256)
    lifecycle = lifecycle or DatabaseProbeDocker()

    def review(phase, known_id):
        # Recompile from durable parent state, rather than accepting a foreign ID.
        if digest(runtime.recipe(store, role, images["runner"], context_sha256)) != digest(spec):
            raise ActivationError("database_reader_recipe_changed")
        return runtime.review(
            store,
            role,
            images["runner"],
            context_sha256,
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
        context_sha256,
        review_image=lambda: runtime.review_image(
            store, role, images["runner"], context_sha256, docker=runtime_docker
        ),
        gate=lambda phase: _gate(
            before_effect,
            phase,
            spec,
            state,
            operation,
            identity,
            old_descriptor_sha256,
            context_sha256,
        ),
        review_runtime=review,
        create=lambda: lifecycle.create(store, role, images["runner"], context_sha256),
        start=lambda known_id: lifecycle.start(
            store, role, images["runner"], context_sha256, known_id, payload
        ),
        validate_reply=lambda raw: results.capture(
            store, role, raw, identity, old_descriptor_sha256, root=capture_root
        ),
        ownership_docker=ownership_docker,
        cleanup_docker=cleanup_docker,
    )
