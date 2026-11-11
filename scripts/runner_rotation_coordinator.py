"""Internal rotation orchestration over explicitly prepared, trusted runtime adapters.

No native runtime factory or CLI is exposed. The original-volume executor must
still supply reviewed physical mount/PKI/ownership gates and bounded lifecycle.
This core can be rehearsed with disposable PostgreSQL/SQLite and a fixture client.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import runner_activation as plan
from aegis import linux_labs, schemas
from aegis.domain.validation import digest
from aegis.lab_runner import activation_review as review
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.models import Laboratory, User
from build_review_runner import _write
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_metadata import ActivationError
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class PreparedRuntime:
    engine: object
    state_directory: Path
    actor_id: str
    registration: schemas.LinuxRegistration
    verify: Callable


@dataclass(frozen=True)
class Adapters:
    """Host code only, never commands, saved gates or values deserialized from an API."""

    prepare: Callable
    cleanup: Callable


def _current(c, runtime=None):
    c._guard()
    if plan.tool_state() != c.artifact["tool_commit"]:
        raise ActivationError("rotation_executor_source_changed")
    verified = plan.pki.verify(
        Path(c.artifact["source_path"]),
        Path(c.artifact["candidate_path"]),
        c.artifact["pki"]["manifest_sha256"],
    )
    if verified["descriptor_sha256"] != c.artifact["pki"]["new_descriptor_sha256"]:
        raise ActivationError("rotation_candidate_changed")
    if runtime is not None:
        runtime.verify(c)  # Trusted live provider must raise on any physical drift.
        if linux_labs.configured_hash() != c.artifact["pki"]["new_descriptor_sha256"]:
            raise ActivationError("rotation_deployment_descriptor_mismatch")
    c._guard()


def _after_binding(runtime, identity, old, new_descriptor):
    current = review.collect(runtime.engine, runtime.state_directory, identity, new_descriptor)
    if (
        current.environment_version != old.environment_version + 1
        or current.inventory_sha256 != old.inventory_sha256
        or current.proofs_examined != old.proofs_examined
    ):
        raise ActivationError("rotation_post_binding_continuity_changed")
    bundle = review.persisted_review.collect(runtime.engine, identity, new_descriptor)
    # These are the only intended changes. Compare the complete proof bodies and
    # every remaining field, rather than accepting a matching row count alone.
    bundle["old_descriptor_sha256"] = old.old_descriptor_sha256
    bundle["environment_version"] = old.environment_version
    bundle["review"]["environment_version"] = old.environment_version
    if review.stable_sha256(bundle) != old.stable_bundle_sha256:
        raise ActivationError("rotation_post_binding_history_changed")
    return current


def execute(c, *, adapters):
    """One attempt, durable request before runtime setup/commit, unconditional cleanup.

    The concrete runtime/lifecycle is deliberately a trusted host boundary. No
    default can mount originals or turn fixture output into physical validation.
    A resumed operation may only use the existing ownership cleanup, not execute.
    """
    if not isinstance(c, ConfirmedPlan) or not isinstance(adapters, Adapters):
        raise ActivationError("rotation_trusted_confirmation_and_adapters_required")
    if c._guard()["resources"]:
        raise ActivationError("rotation_new_operation_required_no_replay")
    _current(c)
    folder = plan.pki.private_directory(c.path.parent)
    anchor = {
        "operation_id": c.operation,
        "begin_sha256": c.begin_sha256,
        "plan_sha256": c.plan_sha256,
        "scope_sha256": c.scope,
        "authorization_expires_at": c.expires.isoformat(),
    }

    def record(name, value):
        _write(folder / ("rotation-" + name + ".json"), json.dumps(value, sort_keys=True).encode())

    # Exclusive publication consumes this plan across operations and processes.
    # A partial write is a fence too; it must never be deleted to permit replay.
    record("requested", anchor)
    failed, interrupted, cleanup, before = None, None, None, None
    binding_state, preflight_success = "not_requested", False
    try:
        _current(c)
        runtime = adapters.prepare(c)
        if (
            not isinstance(runtime, PreparedRuntime)
            or not isinstance(runtime.registration, schemas.LinuxRegistration)
            or not callable(runtime.verify)
        ):
            raise ActivationError("rotation_prepared_runtime_required")
        _current(c, runtime)
        with runtime.engine.connect() as connection:
            # The runtime role cannot read Alembic. Require the b7 capability;
            # source/image/schema provenance is independently a host review gate.
            if "scheduled_reports" not in inspect(connection).get_table_names():
                raise ActivationError("rotation_b7_schema_required")
        identity = RunnerIdentity.model_validate(c.artifact["pki"]["identities"])
        before = review.collect(
            runtime.engine,
            runtime.state_directory,
            identity,
            c.artifact["pki"]["old_descriptor_sha256"],
        )
        _current(c, runtime)
        remote = linux_labs.client()
        try:
            observed = remote.preflight()
            if observed != identity:
                raise ActivationError("rotation_candidate_identity_mismatch")
        finally:
            remote.close()
        # TLS IO must not make an older journal/SQL snapshot eligible for commit.
        fresh = review.collect(
            runtime.engine, runtime.state_directory, identity, before.old_descriptor_sha256
        )
        if (
            fresh.stable_bundle_sha256 != before.stable_bundle_sha256
            or fresh.inventory_sha256 != before.inventory_sha256
        ):
            raise ActivationError("rotation_continuity_changed_before_binding")
        _current(c, runtime)
        record(
            "binding-requested",
            {
                **anchor,
                "review_sha256": digest(
                    before.__dict__ | {"identity": identity.model_dump(mode="json")}
                ),
            },
        )
        binding_state = "unconfirmed"
        with Session(runtime.engine, expire_on_commit=False) as db:
            actor = db.get(User, runtime.actor_id)
            if not actor or not actor.active or actor.role != "administrator":
                raise ActivationError("rotation_active_administrator_required")
            lab = linux_labs.register(db, runtime.registration, actor, continuity_review=fresh)
            binding_state = "committed_revoked"
            _current(c, runtime)
            verification = linux_labs.preflight(db, lab, actor)
            preflight_success = verification.success
            if not preflight_success:
                raise ActivationError("rotation_new_preflight_unconfirmed")
        _after_binding(runtime, identity, before, c.artifact["pki"]["new_descriptor_sha256"])
        _current(c, runtime)
        with Session(runtime.engine) as db:
            lab = db.scalar(
                select(Laboratory)
                .where(Laboratory.id == str(identity.laboratory_id))
                .with_for_update()
            )
            if lab is None or lab.authorized or not linux_labs.verified(db, lab):
                raise ActivationError("rotation_revoked_binding_or_preflight_changed")
    except Exception:
        failed = "rotation_execution_unconfirmed"
    except BaseException as error:
        interrupted, failed = error, "rotation_interrupted"
    finally:
        # Admission expiry never creates a renewed lease, nor skips cleanup.
        # The provider must use the bounded ownership cleanup, retaining parents
        # and reservations when absence cannot be proven.
        try:
            cleanup = adapters.cleanup(c)
        except BaseException as error:
            failed = failed or "rotation_cleanup_unconfirmed"
            if not isinstance(error, Exception):
                interrupted = interrupted or error
    try:
        state = c.store.review()
        closed = bool(
            isinstance(cleanup, dict)
            and cleanup.get("managed_resources_absence_verified") is True
            and cleanup.get("operation_closed") is True
            and state["closed"]
            and all(item["state"] == "ABSENT" for item in state["resources"].values())
        )
    except Exception:
        closed = False
    if not closed:
        failed = failed or "rotation_cleanup_unconfirmed"
    verified = (
        failed is None and closed and preflight_success and binding_state == "committed_revoked"
    )
    receipt = {
        "format": "aegis-internal-rotation-receipt/1",
        **anchor,
        "status": "internal_rotation_reviewed_and_closed"
        if verified
        else "rotation_failed_and_closed"
        if closed
        else "rotation_cleanup_unconfirmed",
        "error": failed,
        "binding_commit_state": binding_state,
        "new_preflight_success": preflight_success,
        "journal_inventory_sha256": before.inventory_sha256 if before else None,
        "managed_resources_absence_verified": closed,
        "cleanup_sha256": digest(cleanup) if isinstance(cleanup, dict) else None,
        "native_runtime_verified": False,
        "activation_verified": False,
        "marker_executed": False,
        "worker_started": False,
        "normal_operation_permitted": False,
    }
    record("receipt", receipt)
    if interrupted is not None:
        raise interrupted
    return receipt
