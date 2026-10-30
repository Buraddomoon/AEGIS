"""Closed internal identity-server driver; no CLI, coordinator or native authorization."""

import subprocess
import time

import runner_activation as plan
import runner_activation_identity_runtime as runtime
from aegis.domain.validation import digest
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_metadata import TIMEOUT, ActivationError, _execute
from runner_activation_ownership import identifier


def command(kind, confirmation, known_id=None):
    """Compile only; the lifecycle must derive live gates before invoking a driver."""
    if not isinstance(confirmation, ConfirmedPlan):
        raise ActivationError("identity_server_confirmed_plan_required")
    c = confirmation
    original = c._guard()
    if any(
        role not in {"runner", "network-isolated"} and item["state"] != "ABSENT"
        for role, item in original["resources"].items()
    ):
        raise ActivationError("identity_server_incompatible_resource")
    if plan.tool_state() != c.artifact["tool_commit"]:
        raise ActivationError("identity_server_executor_drift")
    spec = runtime.recipe(c.store, c.path, c.plan_sha256)
    current = original["resources"].get("runner", {})
    if kind == "create" and known_id is None:
        result = runtime.create_arguments(c.store, c.path, c.plan_sha256)
    elif kind == "start" and known_id is not None:
        if (
            current.get("state") != "START_REQUESTED"
            or current.get("resource_id") != identifier(known_id)
            or current.get("start", {}).get("mode") != "identity-only"
            or current["start"].get("recipe_sha256") != digest(spec)
            or current["start"].get("pki_manifest_sha256") != c.artifact["pki"]["manifest_sha256"]
            or current["start"].get("network_resource_id") != spec["network_resource_id"]
        ):
            raise ActivationError("identity_server_started_recipe_required")
        result = ("container", "start", known_id)
    else:
        raise ActivationError("identity_server_command_not_allowed")
    if c._guard() != original or plan.tool_state() != c.artifact["tool_commit"]:
        raise ActivationError("identity_server_inputs_changed")
    return result


class IdentityServerDocker:
    """One RPC per lifecycle phase; never call on resume or retry an ambiguous outcome."""

    def create(self, confirmation):
        args = command("create", confirmation)
        remaining = _budget(confirmation)
        try:
            raw = _execute(args, timeout=remaining)
            return identifier(raw.decode("ascii").removesuffix("\n"))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("identity_server_create_outcome_unconfirmed") from None

    def start(self, confirmation, known_id):
        args = command("start", confirmation, known_id)
        remaining = _budget(confirmation)
        try:
            raw = _execute(args, timeout=remaining)
            if identifier(raw.decode("ascii").removesuffix("\n")) != known_id:
                raise ActivationError("identity_server_start_outcome_unconfirmed")
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("identity_server_start_outcome_unconfirmed") from None


def _budget(c):
    c._guard()
    remaining = min(c.deadline - time.monotonic(), (c.expires - plan.pki.clock()).total_seconds())
    if remaining <= 0:
        raise ActivationError("identity_server_rpc_budget_exhausted")
    return min(TIMEOUT, remaining)
