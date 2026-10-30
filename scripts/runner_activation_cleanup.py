"""Internal owned-resource cleanup; no CLI, creation, start, volume or global deletion."""

import subprocess

from aegis.domain.validation import digest
from runner_activation_intents import ROLES, resource
from runner_activation_metadata import IMAGES, ActivationError, _execute, image_id
from runner_activation_ownership import identifier, observe

ORDER = (
    "identity-client",
    "api",
    "database-review-after",
    "database-review-before",
    "journal-after",
    "journal-before",
    "runner",
    "redis",
    "db",
    "network-ingress",
    "network-backend",
    "network-isolated",
)
IMAGE_ROLE = {
    "identity-client": "runner",
    "api": "application",
    "runner": "runner",
    "journal-before": "runner",
    "journal-after": "runner",
    "database-review-before": "runner",
    "database-review-after": "runner",
    "redis": "redis",
    "db": "postgres",
}


def command(kind, operation_id, plan_sha256, role, known_id):
    item = resource(operation_id, plan_sha256, role)
    identifier(known_id)
    if kind == "stop" and item["kind"] == "container":
        return ("container", "stop", "--signal", "SIGTERM", "--timeout", "5", known_id)
    if kind == "remove":
        return (item["kind"], "rm", known_id)
    raise ActivationError("activation_cleanup_command_not_allowed")


class CleanupDocker:
    def effect(self, kind, operation_id, plan_sha256, role, known_id):
        try:
            _execute(command(kind, operation_id, plan_sha256, role, known_id))
        except ActivationError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise ActivationError("activation_cleanup_command_failed") from None


def cleanup(store, images, *, roles=None, close_operation=True, docker=None, ownership_docker=None):
    """Reconcile only an independently resumed, locked intent's exact resources.

    A caller must pin the original plan/images and the intent's begin hash.
    Expired plan/PKI must not prevent cleanup; this function never resumes work.
    The concrete driver is not invoked by tests, Make, API or a lifecycle CLI.
    """
    if not isinstance(images, dict) or set(images) != set(IMAGES):
        raise ActivationError("cleanup_original_images_required")
    for value in images.values():
        image_id(value)
    if len(set(images.values())) != len(IMAGES):
        raise ActivationError("cleanup_distinct_images_required")
    state = store.review()
    if not set(state["resources"]) <= ROLES:
        raise ActivationError("cleanup_resource_catalog_mismatch")
    if roles is not None and (not isinstance(roles, (set, frozenset)) or not roles):
        raise ActivationError("cleanup_selection_or_closure_invalid")
    selected = set(state["resources"]) if roles is None else set(roles)
    if (
        not selected <= set(state["resources"])
        or type(close_operation) is not bool
        or (close_operation and selected != set(state["resources"]))
    ):
        raise ActivationError("cleanup_selection_or_closure_invalid")
    operation = store.summary()["id"]
    plan = state["header"]["plan_sha256"]
    docker = docker or CleanupDocker()
    samples, blockers, reconciled = {}, {}, []

    def sample(role):
        current = store.review()["resources"][role]
        found = observe(operation, plan, role, current["resource_id"], docker=ownership_docker)
        if (
            found["status"] == "present_owned_snapshot"
            and role in IMAGE_ROLE
            and found["details"]["image"] != images[IMAGE_ROLE[role]]
        ):
            raise ActivationError("cleanup_owned_image_mismatch")
        return found

    def effect(kind, role, found):
        # Re-read the journal AND daemon immediately before each effect.
        state = store.review()["resources"][role]
        if state["state"] != "REMOVAL_REQUESTED" or sample(role) != found:
            raise ActivationError("cleanup_changed_before_effect")
        failed = False
        try:
            docker.effect(kind, operation, plan, role, found["resource_id"])
        except (ActivationError, OSError, subprocess.SubprocessError):
            failed = True
        after = sample(role)
        if failed:
            resolved = after["status"] == "absent_snapshot" or (
                kind == "stop" and after["stopped_or_empty_snapshot"]
            )
            if not resolved:
                raise ActivationError("cleanup_command_outcome_unconfirmed")
            reconciled.append({"role": role, "effect": kind})
        return after

    for role in ORDER:
        if role not in selected:
            continue
        try:
            current = store.review()["resources"][role]
            found = sample(role)
            if current["state"] == "ABSENT":
                if found["status"] != "absent_snapshot":
                    raise ActivationError("cleanup_previously_absent_resource_present")
            else:
                if current["state"] != "REMOVAL_REQUESTED":
                    store.append("removal_requested", {"role": role})
                if found["status"] == "present_owned_snapshot":
                    if current["resource_id"] is None:
                        store.append(
                            "observed", {"role": role, "resource_id": found["resource_id"]}
                        )
                        found = sample(role)
                    if role in IMAGE_ROLE and found["details"]["running"]:
                        found = effect("stop", role, found)
                    if found["status"] == "present_owned_snapshot":
                        if not found["stopped_or_empty_snapshot"]:
                            raise ActivationError("cleanup_resource_not_stopped_or_empty")
                        found = effect("remove", role, found)
                if found["status"] != "absent_snapshot":
                    raise ActivationError("cleanup_absence_unconfirmed")
                store.append("absence_recorded", {"role": role, "evidence_sha256": digest(found)})
            samples[role] = found
        except (ActivationError, OSError, subprocess.SubprocessError):
            # Fixed role/code only; no daemon/OS diagnostics or resource contents.
            blockers[role] = "owned_resource_cleanup_unconfirmed"

    # A second aggregate pass prevents an earlier absence observation from being
    # silently reused after closing the other resources. No effect on ABSENT items.
    for role in samples:
        try:
            found = sample(role)
            if found["status"] != "absent_snapshot":
                raise ActivationError("cleanup_final_absence_changed")
            samples[role] = found
        except (ActivationError, OSError, subprocess.SubprocessError):
            blockers[role] = "owned_resource_cleanup_unconfirmed"
    complete = not blockers and set(samples) == selected
    all_reviewed = selected == set(state["resources"])
    evidence = {
        "operation_id": operation,
        "plan_sha256": plan,
        "samples": samples,
        "blockers": blockers,
        "command_errors_reconciled": reconciled,
    }
    if complete and close_operation and not store.review()["closed"]:
        store.append("closed", {"evidence_sha256": digest(evidence)})
    return {
        "format": "aegis-activation-cleanup-review/1",
        "operation_id": operation,
        "status": (
            "owned_resources_absence_verified"
            if all_reviewed
            else "selected_owned_resources_absence_verified"
        )
        if complete
        else "cleanup_incomplete",
        "evidence_sha256": digest(evidence),
        "resources_reviewed": len(samples),
        "blockers": blockers,
        "command_errors_reconciled": reconciled,
        "selected_resources_absence_verified": complete,
        "managed_resources_absence_verified": complete and all_reviewed,
        "operation_closed": store.review()["closed"] if not store.poisoned else False,
        "volumes_removed": False,
        "authorization_verified": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
