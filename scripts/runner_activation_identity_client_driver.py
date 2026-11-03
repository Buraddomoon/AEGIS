"""Closed create/attach driver requiring computed recent gates; no CLI or invocation on import."""

import subprocess
import time

import runner_activation_identity_client_gates as gates
import runner_activation_identity_client_runtime as runtime
from aegis.domain.validation import digest
from runner_activation_metadata import SMALL_PROBE_OUTPUT, TIMEOUT, ActivationError, _execute
from runner_activation_ownership import identifier


def _gate(reviews, phase, spec, state):
    value = reviews._last_gate
    if (
        value is None
        or not reviews.evidence
        or digest(value) != reviews.evidence[-1]["gate_sha256"]
    ):
        raise ActivationError("identity_client_computed_recent_gate_required")
    c = reviews.confirmation
    gates.validate(value, phase, spec, state, c.operation, c.artifact["pki"]["manifest_sha256"])
    return value


def command(kind, reviews, known_id=None):
    """Internal guard/compiler only; JSON positives cannot stand in for a gate object."""
    if not isinstance(reviews, gates.IdentityClientGates):
        raise ActivationError("identity_client_computed_gates_required")
    if kind not in {"create", "start"}:
        raise ActivationError("identity_client_command_not_allowed")
    c = reviews.confirmation
    original = c._guard()
    spec = runtime.recipe(c.store, c.path, c.plan_sha256, reviews.context_sha256)
    current = original["resources"].get(runtime.ROLE, {})
    approved = _gate(reviews, kind, spec, original)
    if kind == "create" and known_id is None:
        args = runtime.create_arguments(c.store, c.path, c.plan_sha256, reviews.context_sha256)
    elif kind == "start" and known_id is not None:
        expected = {
            "recipe_sha256": digest(spec),
            "gates_sha256": digest(approved),
            "request_context_sha256": reviews.context_sha256,
            "runner_resource_id": spec["runner_resource_id"],
            "network_resource_id": spec["network_resource_id"],
        }
        if (
            current.get("state") != "START_REQUESTED"
            or current.get("resource_id") != identifier(known_id)
            or current.get("start") != expected
        ):
            raise ActivationError("identity_client_started_recipe_required")
        args = ("container", "start", "--attach", "--interactive", known_id)
    else:
        raise ActivationError("identity_client_command_not_allowed")
    if (
        gates.request.review(c, reviews._payload, reviews.context_sha256) != reviews.context
        or c._guard() != original
        or digest(runtime.recipe(c.store, c.path, c.plan_sha256, reviews.context_sha256))
        != digest(spec)
    ):
        raise ActivationError("identity_client_driver_context_changed")
    _gate(reviews, kind, spec, original)
    return args


def _prepare(kind, reviews, known_id=None):
    if not isinstance(reviews, gates.IdentityClientGates):
        raise ActivationError("identity_client_computed_gates_required")
    try:
        c = reviews.confirmation
        original = c._guard()
        args = command(kind, reviews, known_id)
        c._guard()
        remaining = min(
            TIMEOUT if kind == "create" else 15,
            c.deadline - time.monotonic(),
            (c.expires - gates.plan.pki.clock()).total_seconds(),
        )
        if remaining <= 0 or c._guard() != original:
            raise ActivationError("identity_client_driver_budget_or_context_changed")
        spec = runtime.recipe(c.store, c.path, c.plan_sha256, reviews.context_sha256)
        _gate(reviews, kind, spec, original)  # Freshness immediately before the single RPC.
        return args, remaining
    finally:
        # Even an ambiguous outcome consumes this in-memory admission. Durable
        # lifecycle fences must ALSO prevent reissuing a create/start on resume.
        reviews._last_gate = None


class IdentityClientDocker:
    """Lifecycle must prohibit replay and cleanup ambiguous outcomes by ownership."""

    def create(self, reviews):
        args, remaining = _prepare("create", reviews)
        try:
            return identifier(_execute(args, timeout=remaining).decode("ascii").removesuffix("\n"))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("identity_client_create_outcome_unconfirmed") from None

    def start(self, reviews, known_id):
        if gates.request.probe.MAX_OUTPUT != SMALL_PROBE_OUTPUT:
            raise ActivationError("identity_client_output_profile_mismatch")
        args, remaining = _prepare("start", reviews, known_id)
        try:
            raw = _execute(
                args, payload=reviews._payload, timeout=remaining, output_limit=SMALL_PROBE_OUTPUT
            )
            gates.request.probe.decode_result(raw, reviews.context, reviews.context_sha256)
            return raw
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            raise ActivationError("identity_client_capture_outcome_unconfirmed") from None
