"""Internal lifecycle shared by closed probe adapters; no CLI or free commands."""

import subprocess
from datetime import datetime, timedelta

import runner_activation_cleanup as closure
import runner_pki as pki
from aegis.domain.validation import digest
from runner_activation_intents import DATABASE_REVIEW_ROLES
from runner_activation_metadata import ActivationError
from runner_activation_ownership import identifier, observe


def fresh(gate):
    checked, expires = (datetime.fromisoformat(gate[key]) for key in ("checked_at", "expires_at"))
    now = pki.clock()
    if (
        checked.utcoffset() != timedelta(0)
        or expires.utcoffset() != timedelta(0)
        or not timedelta(0) < expires - checked <= timedelta(seconds=30)
        or not checked <= now < expires
        or now - checked > timedelta(seconds=10)
    ):
        raise ActivationError("journal_probe_gate_stale")


def run(
    store,
    images,
    role,
    spec,
    context_sha256,
    *,
    review_image,
    gate,
    review_runtime,
    create,
    start,
    validate_reply,
    ownership_docker=None,
    cleanup_docker=None,
):
    """Trusted adapter callbacks only; never accept callbacks/gates from API input.

    Callers validate the pinned recipe, input and each gate's complete context.
    This shared mechanism owns intent ordering, ambiguity quarantine and cleanup.
    The concrete authorized coordinator is still required before real invocation.
    """
    if role in {"journal-before", "journal-after"}:
        context_field, start_event, prefix = (
            "proof_bundle_sha256",
            "probe_start_requested",
            "journal_probe",
        )
    elif role in DATABASE_REVIEW_ROLES:
        context_field, start_event, prefix = (
            "request_context_sha256",
            "database_review_start_requested",
            "database_reader",
        )
    else:
        raise ActivationError("owned_probe_role_required")
    state = store.review()
    operation, plan = store.summary()["id"], state["header"]["plan_sha256"]
    if state["closed"] or role in state["resources"]:
        raise ActivationError(prefix + "_new_role_required_no_replay")
    result, error, cleanup = None, None, None
    gates, create_attempted = {}, False
    review_image()
    if observe(operation, plan, role, docker=ownership_docker)["status"] != "absent_snapshot":
        raise ActivationError(prefix + "_prior_resource_present")
    try:
        store.request(role)
        approved = gate("create")
        gates["create"] = digest(approved)
        if store.review()["resources"][role]["state"] != "REQUESTED":
            raise ActivationError(prefix + "_create_intent_changed")
        if observe(operation, plan, role, docker=ownership_docker)["status"] != "absent_snapshot":
            raise ActivationError(prefix + "_resource_appeared_before_create")
        fresh(approved)
        create_attempted = True
        created_id = identifier(create())
        present = observe(operation, plan, role, docker=ownership_docker)
        if present["status"] != "present_owned_snapshot" or present["resource_id"] != created_id:
            raise ActivationError(prefix + "_created_id_unconfirmed")
        store.append("observed", {"role": role, "resource_id": created_id})
        review_runtime("created", created_id)
        approved = gate("start")
        gates["start"] = digest(approved)
        store.append(
            start_event,
            {
                "role": role,
                "recipe_sha256": digest(spec),
                "gates_sha256": digest(approved),
                context_field: context_sha256,
            },
        )
        if store.review()["resources"][role]["state"] != "START_REQUESTED":
            raise ActivationError(prefix + "_start_intent_changed")
        review_runtime("created", created_id)
        fresh(approved)
        raw = start(created_id)
        review_runtime("exited", created_id)
        result = validate_reply(raw)
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        error = prefix + "_execution_unconfirmed"
    finally:
        cleanup = cleanup_owned_probe(
            store,
            images,
            role,
            create_attempted,
            ownership_docker=ownership_docker,
            cleanup_docker=cleanup_docker,
        )
    clean = cleanup is not None and cleanup["selected_resources_absence_verified"]
    return {
        "format": "aegis-journal-probe-lifecycle-review/1"
        if prefix == "journal_probe"
        else "aegis-database-reader-lifecycle-review/1",
        "operation_id": operation,
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


def cleanup_owned_probe(
    store, images, role, create_attempted, *, ownership_docker=None, cleanup_docker=None
):
    """Reconcile only the selected role; pre-create conflicts cannot be adopted."""
    try:
        current = store.review()
        operation, plan = store.summary()["id"], current["header"]["plan_sha256"]
        found = (
            None if create_attempted else observe(operation, plan, role, docker=ownership_docker)
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
            return closure.cleanup(
                store,
                images,
                roles={role},
                close_operation=False,
                docker=cleanup_docker,
                ownership_docker=ownership_docker,
            )
    except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    return None
