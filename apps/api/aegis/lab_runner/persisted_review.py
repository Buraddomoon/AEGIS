"""Host probe building journal expectations from an independent read-only DB snapshot."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from uuid import UUID

from aegis.domain.validation import digest
from aegis.lab_runner.continuity import ContinuityError
from aegis.lab_runner.protocol import JobView, RunnerIdentity

if TYPE_CHECKING:
    from sqlalchemy import Engine

# Wire profile /1 bound; broadening the DB reviewer doesn't silently broaden stdin.
MAX_PROOFS = 1000


def collect(engine: Engine, identity: RunnerIdentity, old_descriptor_sha256: str) -> dict:
    """No settings, credentials, runner client, audit writes, or lifecycle effects.

    The caller must prove this engine reaches the original Linux DB volume.
    This function deliberately cannot infer that physical binding from SQL rows.
    """
    # The fixed journal probe only decodes bundles; don't load app settings/SQL
    # models or initialize a database stack merely to validate stdin.
    from sqlalchemy import select, text
    from sqlalchemy.orm import Session

    from aegis import binding_review
    from aegis.models import (
        Asset,
        CampaignRun,
        Laboratory,
        LinuxLabBinding,
        RunnerCleanup,
        RunnerDispatch,
    )
    from aegis.models import TestExecution as Execution

    if (
        not isinstance(identity, RunnerIdentity)
        or not isinstance(old_descriptor_sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", old_descriptor_sha256)
    ):
        raise ContinuityError("persisted_review_inputs_invalid")
    with Session(engine, autoflush=False, expire_on_commit=False) as db:
        db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        db.execute(text("SET TRANSACTION READ ONLY"))
        db.execute(text("SET LOCAL statement_timeout='15s'"))
        lab = db.get(Laboratory, str(identity.laboratory_id))
        binding = db.get(LinuxLabBinding, str(identity.laboratory_id))
        asset = db.get(Asset, str(identity.asset_id))
        if (
            lab is None
            or binding is None
            or asset is None
            or lab.kind != "linux"
            or lab.environment_version < 1
            or asset.laboratory_id != lab.id
            or asset.platform != "Linux"
            or asset.synthetic
            or asset.external_id != str(identity.asset_id)
            or binding.runner_id != str(identity.runner_id)
            or binding.configuration_hash != old_descriptor_sha256
        ):
            raise ContinuityError("persisted_original_binding_mismatch")
        status = binding_review.review(db, lab)
        if status["blockers"] or not status["dispatch_history_complete"]:
            raise ContinuityError("persisted_binding_review_blocked")
        # Review above checked both parent scope and this lab's assets. Only accept
        # the exact original integrated runner and complete, immutable CLEANED proofs.
        rows = db.execute(
            select(CampaignRun, Execution, RunnerDispatch, RunnerCleanup)
            .select_from(CampaignRun)
            .join(Execution, Execution.run_id == CampaignRun.id)
            .join(RunnerDispatch, RunnerDispatch.execution_id == Execution.id)
            .outerjoin(RunnerCleanup, RunnerCleanup.execution_id == Execution.id)
            .where(CampaignRun.laboratory_id == lab.id)
            .order_by(Execution.id)
            .limit(binding_review.HISTORY_LIMIT + 1)
        ).all()
        if (
            not rows
            or len(rows) > binding_review.HISTORY_LIMIT
            or len(rows) != status["dispatches_examined"]
        ):
            raise ContinuityError("persisted_complete_known_history_required")
        proofs = []
        for run, item, dispatch, cleanup in rows:
            if not binding_review.cleanup_confirmed(lab, run, item, dispatch, cleanup):
                raise ContinuityError("persisted_cleanup_unconfirmed")
            view = JobView.model_validate(cleanup.content)
            if any(
                getattr(view.spec, key) != getattr(identity, key)
                for key in ("runner_id", "laboratory_id", "asset_id")
            ):
                raise ContinuityError("persisted_job_identity_mismatch")
            proofs.append(view.model_dump(mode="json"))
        return {
            "format": "aegis-persisted-journal-proofs/1",
            "identity": identity.model_dump(mode="json"),
            "old_descriptor_sha256": old_descriptor_sha256,
            "laboratory_id": lab.id,
            "environment_version": lab.environment_version,
            "status": "persisted_proofs_require_original_journal_review",
            "review": status,
            "proofs": proofs,
            "proofs_sha256": digest(proofs),
            "database_volume_binding_verified": False,
            "journal_verified": False,
            "activation_permitted": False,
            "normal_operation_permitted": False,
        }


def expected_proofs(
    bundle: dict, expected_sha256: str
) -> tuple[RunnerIdentity, dict[UUID, JobView]]:
    """Decode an independently pinned bundle; no SQL/files/runtime access."""
    try:
        if (
            not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            or not isinstance(bundle, dict)
            or digest(bundle) != expected_sha256
        ):
            raise ContinuityError("persisted_proofs_integrity_mismatch")
        flags = (
            "database_volume_binding_verified",
            "journal_verified",
            "activation_permitted",
            "normal_operation_permitted",
        )
        if (
            set(bundle)
            != {
                "format",
                "identity",
                "old_descriptor_sha256",
                "laboratory_id",
                "environment_version",
                "status",
                "review",
                "proofs",
                "proofs_sha256",
                *flags,
            }
            or bundle["format"] != "aegis-persisted-journal-proofs/1"
            or bundle["status"] != "persisted_proofs_require_original_journal_review"
            or any(bundle[key] is not False for key in flags)
        ):
            raise ContinuityError("persisted_proofs_policy_mismatch")
        identity = RunnerIdentity.model_validate(bundle["identity"])
        summary = bundle["review"]
        if (
            bundle["laboratory_id"] != str(identity.laboratory_id)
            or digest(bundle["identity"]) != digest(identity.model_dump(mode="json"))
            or type(bundle["environment_version"]) is not int
            or bundle["environment_version"] < 1
            or summary["format"] != "aegis-linux-binding-review/1"
            or summary["laboratory_id"] != bundle["laboratory_id"]
            or summary["environment_version"] != bundle["environment_version"]
            or type(summary["environment_version"]) is not int
            or summary["status"] != "persisted_prerequisites_satisfied"
            or summary["blockers"] != []
            or summary["dispatch_history_complete"] is not True
            or any(
                type(summary[key]) is not int or summary[key] != 0
                for key in ("nonterminal_runs", "nonterminal_tests", "unconfirmed_cleanup_count")
            )
            or any(
                summary[key] is not False
                for key in (
                    "runner_contacted",
                    "journal_verified",
                    "activation_permitted",
                    "normal_operation_permitted",
                )
            )
            or not isinstance(bundle["proofs"], list)
            or not 1 <= len(bundle["proofs"]) <= MAX_PROOFS
            or len(bundle["proofs"]) != summary["dispatches_examined"]
            or type(summary["dispatches_examined"]) is not int
            or digest(bundle["proofs"]) != bundle["proofs_sha256"]
            or not re.fullmatch(r"[a-f0-9]{64}", bundle["old_descriptor_sha256"])
        ):
            raise ContinuityError("persisted_proofs_context_mismatch")
        proofs = {}
        for raw in bundle["proofs"]:
            view = JobView.model_validate(raw)
            if (
                view.spec.job_id in proofs
                or digest(raw) != digest(view.model_dump(mode="json"))
                or view.cleanup_state != "CLEANED"
                or view.state in {"PREPARED", "RUNNING"}
                or any(
                    getattr(view.spec, key) != getattr(identity, key)
                    for key in ("runner_id", "laboratory_id", "asset_id")
                )
            ):
                raise ContinuityError("persisted_proofs_job_invalid")
            proofs[view.spec.job_id] = view
        return identity, proofs
    except ContinuityError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ContinuityError("persisted_proofs_invalid") from None
