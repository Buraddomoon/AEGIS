"""Internal isolated PostgreSQL lifecycle; no CLI/API or real invocation in tests."""

import copy
import subprocess
import time

import runner_activation_database_inspection as inspection
import runner_activation_owned_probe as owned
from aegis.domain.validation import digest
from runner_activation_metadata import IMAGES, ActivationError, _execute, image_id
from runner_activation_ownership import identifier, observe

server = inspection.server
CHECKS = frozenset(
    {
        "specific_authorization_verified",
        "plan_current",
        "image_provenance_verified",
        "original_database_volume_verified",
        "database_policy_file_verified",
        "exclusive_database_consumer_verified",
        "original_journal_quiescent",
        "worker_stopped",
    }
)


def command(kind, store, image, *, policy_root=server.policy.DEFAULT_ROOT, known_id=None):
    spec = server.recipe(store, image, policy_root=policy_root)
    item = store.review()["resources"].get("db")
    if item is None:
        raise ActivationError("database_server_create_intent_required")
    if kind == "create" and known_id is None:
        return server.create_arguments(store, image, policy_root=policy_root)
    if (
        known_id is None
        or item["resource_id"] != identifier(known_id)
        or item.get("start", {}).get("recipe_sha256") != digest(spec)
        or item["start"].get("policy_sha256") != spec["policy_sha256"]
    ):
        raise ActivationError("database_server_started_recipe_required")
    if kind == "start" and item["state"] == "START_REQUESTED":
        return ("container", "start", known_id)
    if kind == "ready" and item["state"] == "OBSERVED" and "runtime_evidence_sha256" in item:
        return (
            "container",
            "exec",
            "--user",
            "70:70",
            known_id,
            "/usr/local/bin/pg_isready",
            "--quiet",
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
            "--username",
            "aegis_app",
            "--dbname",
            "aegis",
            "--timeout",
            "1",
        )
    raise ActivationError("database_server_lifecycle_command_not_allowed")


class DatabaseServerDocker:
    def create(self, store, image, *, policy_root):
        try:
            raw = _execute(command("create", store, image, policy_root=policy_root))
            return identifier(raw.decode("ascii").removesuffix("\n"))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("database_server_create_outcome_unconfirmed") from None

    def start(self, store, image, known_id, *, policy_root):
        try:
            raw = _execute(
                command("start", store, image, known_id=known_id, policy_root=policy_root)
            )
            if identifier(raw.decode("ascii").removesuffix("\n")) != known_id:
                raise ActivationError("database_server_started_id_mismatch")
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise ActivationError("database_server_start_outcome_unconfirmed") from None

    def ready(self, store, image, known_id, *, policy_root, timeout):
        try:
            raw = _execute(
                command("ready", store, image, known_id=known_id, policy_root=policy_root),
                timeout=timeout,
            )
            return raw == b""
        except (OSError, ValueError, subprocess.SubprocessError):
            # Nonzero/timeout only means no readiness evidence, never auth failure proof.
            return False


def _gate(callback, phase, spec, state, operation, resource_id):
    approved = callback(phase, copy.deepcopy(spec))
    expected = {
        "format": "aegis-database-server-gate/1",
        "phase": phase,
        "operation_id": operation,
        "resource_id": resource_id,
        "plan_sha256": state["header"]["plan_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        "recipe_sha256": digest(spec),
        "policy_sha256": spec["policy_sha256"],
        "volume": server.VOLUME,
    }
    if (
        not isinstance(approved, dict)
        or set(approved) != {*expected, "checked_at", "expires_at", "checks"}
        or any(approved[key] != value for key, value in expected.items())
        or not isinstance(approved["checks"], dict)
        or set(approved["checks"]) != CHECKS
        or any(value is not True for value in approved["checks"].values())
    ):
        raise ActivationError("database_server_gate_mismatch")
    owned.fresh(approved)
    return approved


def start_server(
    store,
    images,
    *,
    before_effect,
    policy_root=server.policy.DEFAULT_ROOT,
    lifecycle=None,
    runtime_docker=None,
    ownership_docker=None,
    cleanup_docker=None,
):
    """Start once, leave the confirmed parent available to readers, cleanup on failure.

    Only the complete trusted coordinator may call this against real resources
    after specific authorization. Callback fixtures are not execution grants.
    """
    if not isinstance(images, dict) or set(images) != set(IMAGES) or not callable(before_effect):
        raise ActivationError("database_server_images_and_trusted_gates_required")
    images = copy.deepcopy(images)
    for value in images.values():
        image_id(value)
    if len(set(images.values())) != len(IMAGES):
        raise ActivationError("database_server_distinct_images_required")
    state = store.review()
    if state["closed"] or "db" in state["resources"]:
        raise ActivationError("database_server_new_role_required_no_replay")
    operation, plan = store.summary()["id"], state["header"]["plan_sha256"]
    spec = server.recipe(store, images["postgres"], policy_root=policy_root)
    inspection.review_image(images["postgres"], docker=runtime_docker)
    if observe(operation, plan, "db", docker=ownership_docker)["status"] != "absent_snapshot":
        raise ActivationError("database_server_prior_resource_present")
    lifecycle = lifecycle or DatabaseServerDocker()
    create_attempted, success, cleanup = False, False, None
    error, object_id, runtime = None, None, None
    gates, attempts = {}, 0

    def review(phase):
        return inspection.review(
            store,
            images["postgres"],
            object_id,
            phase,
            policy_root=policy_root,
            docker=runtime_docker,
            ownership_docker=ownership_docker,
        )

    def gate(phase):
        approved = _gate(before_effect, phase, spec, state, operation, object_id)
        if digest(server.recipe(store, images["postgres"], policy_root=policy_root)) != digest(
            spec
        ):
            raise ActivationError("database_server_recipe_changed")
        return approved

    try:
        store.request("db")
        approved = gate("create")
        gates["create"] = digest(approved)
        if (
            store.review()["resources"]["db"]["state"] != "REQUESTED"
            or observe(operation, plan, "db", docker=ownership_docker)["status"]
            != "absent_snapshot"
        ):
            raise ActivationError("database_server_create_context_changed")
        owned.fresh(approved)
        create_attempted = True
        object_id = identifier(lifecycle.create(store, images["postgres"], policy_root=policy_root))
        found = observe(operation, plan, "db", docker=ownership_docker)
        if found["status"] != "present_owned_snapshot" or found["resource_id"] != object_id:
            raise ActivationError("database_server_created_id_unconfirmed")
        store.append("observed", {"role": "db", "resource_id": object_id})
        review("created")
        approved = gate("start")
        gates["start"] = digest(approved)
        store.append(
            "database_start_requested",
            {
                "role": "db",
                "recipe_sha256": digest(spec),
                "gates_sha256": digest(approved),
                "policy_sha256": spec["policy_sha256"],
            },
        )
        review("created")
        owned.fresh(approved)
        lifecycle.start(store, images["postgres"], object_id, policy_root=policy_root)
        runtime = review("running")
        store.append(
            "database_runtime_observed", {"role": "db", "runtime_evidence_sha256": digest(runtime)}
        )
        # Only these fixed health probes may repeat, never create/start. Includes
        # gate/runtime IO and final recheck; timeout is not extended by retries.
        deadline = time.monotonic() + 15
        for _ in range(8):
            approved = gate("ready")
            review("running")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ActivationError("database_server_readiness_deadline")
            owned.fresh(approved)
            attempts += 1
            ready = lifecycle.ready(
                store,
                images["postgres"],
                object_id,
                policy_root=policy_root,
                timeout=min(2, remaining),
            )
            if ready is True:
                runtime = review("running")
                if time.monotonic() >= deadline:
                    raise ActivationError("database_server_readiness_deadline")
                gates["ready"] = digest(approved)
                success = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.25, remaining))
        if not success:
            raise ActivationError("database_server_readiness_unconfirmed")
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        error = "database_server_startup_unconfirmed"
    except BaseException:
        success = False
        raise
    finally:
        if not success:
            cleanup = owned.cleanup_owned_probe(
                store,
                images,
                "db",
                create_attempted,
                ownership_docker=ownership_docker,
                cleanup_docker=cleanup_docker,
            )
    removed = cleanup is not None and cleanup["selected_resources_absence_verified"]
    return {
        "format": "aegis-original-database-server-lifecycle-review/1",
        "operation_id": operation,
        "resource_id": object_id,
        "recipe_sha256": digest(spec),
        "gate_sha256": gates,
        "status": "database_running_and_ready_not_activated"
        if success
        else "database_failed_and_absence_verified"
        if removed
        else "database_cleanup_unconfirmed",
        "error": error,
        "runtime": runtime if success else None,
        "cleanup": cleanup,
        "readiness_attempts": attempts,
        "connection_readiness_verified": success,
        "database_retained_running": success,
        "database_absence_verified": removed,
        "volumes_removed": False,
        "database_volume_readonly": False,
        "authentication_verified": False,
        "database_identity_verified": False,
        "image_provenance_verified": False,
        "authorization_verified": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
