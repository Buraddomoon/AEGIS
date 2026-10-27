"""Persisted Linux binding prerequisites; never contact a runner or repair history."""

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aegis.domain.states import TERMINAL
from aegis.domain.validation import digest
from aegis.lab_runner.protocol import JobSpec, JobView
from aegis.models import (
    Asset,
    CampaignRun,
    Laboratory,
    RunnerCleanup,
    RunnerDispatch,
    TestExecution,
    now,
)

HISTORY_LIMIT = 1000
SAMPLE_LIMIT = 25


def cleanup_confirmed(
    lab: Laboratory,
    run: CampaignRun,
    item: TestExecution,
    dispatch: RunnerDispatch,
    cleanup: RunnerCleanup | None,
) -> bool:
    """Check the original immutable proof, not just presence of a cleanup row."""
    if cleanup is None:
        return False
    try:
        spec = JobSpec.model_validate(dispatch.spec)
        view = JobView.model_validate(cleanup.content)
        runner = run.scope.get("runner", {})
        if (
            run.synthetic
            or item.synthetic
            or digest(run.scope) != run.scope_hash
            or digest(dispatch.spec) != dispatch.spec_hash
            or digest(cleanup.content) != cleanup.sha256
            or view.spec.model_dump(mode="json") != dispatch.spec
            or view.spec_hash != dispatch.spec_hash
            or dispatch.generation != str(view.generation)
            or view.cleanup_state != "CLEANED"
            or view.state in {"PREPARED", "RUNNING"}
            or spec.job_id != UUID(item.id)
            or item.test_id != "linux-file-marker-v1"
            or str(spec.laboratory_id) != lab.id
            or run.laboratory_id != lab.id
            or str(spec.asset_id) != item.asset_id
            or spec.marker != item.marker
            or spec.scope_hash != run.scope_hash
            or str(spec.runner_id) != runner.get("runner_id")
            or str(spec.asset_id) != runner.get("asset_id")
            or str(spec.laboratory_id) != runner.get("laboratory_id")
        ):
            return False
        if view.receipt is None:
            return view.state != "SUCCEEDED" and view.receipt_sha256 is None
        receipt = view.receipt
        return bool(
            digest(receipt.model_dump(mode="json")) == view.receipt_sha256
            and receipt.job_id == spec.job_id
            and receipt.runner_id == spec.runner_id
            and receipt.laboratory_id == spec.laboratory_id
            and receipt.asset_id == spec.asset_id
            and receipt.marker == spec.marker
            and receipt.scope_hash == spec.scope_hash
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def review(db: Session, lab: Laboratory) -> dict:
    """Diagnostic snapshot; mutations must repeat this under the laboratory lock."""
    asset_ids = select(Asset.id).where(Asset.laboratory_id == lab.id)
    belongs = or_(CampaignRun.laboratory_id == lab.id, TestExecution.asset_id.in_(asset_ids))
    with db.no_autoflush:
        pending_runs = db.scalar(
            select(func.count())
            .select_from(CampaignRun)
            .where(CampaignRun.laboratory_id == lab.id, CampaignRun.state.not_in(TERMINAL))
        )
        pending_tests = db.scalar(
            select(func.count())
            .select_from(TestExecution)
            .join(CampaignRun, TestExecution.run_id == CampaignRun.id)
            .where(belongs, TestExecution.state.not_in(TERMINAL))
        )
        rows = db.execute(
            select(CampaignRun, TestExecution, RunnerDispatch, RunnerCleanup)
            .select_from(CampaignRun)
            .join(TestExecution, TestExecution.run_id == CampaignRun.id)
            .join(RunnerDispatch, RunnerDispatch.execution_id == TestExecution.id)
            .outerjoin(RunnerCleanup, RunnerCleanup.execution_id == TestExecution.id)
            .where(belongs)
            .order_by(RunnerDispatch.id)
            .limit(HISTORY_LIMIT + 1)
        ).all()
    blockers = []
    if lab.kind != "linux":
        blockers.append("not_linux")
    if lab.authorized:
        blockers.append("laboratory_authorized")
    if lab.active_run_id:
        blockers.append("laboratory_reserved")
    if pending_runs:
        blockers.append("nonterminal_runs")
    if pending_tests:
        blockers.append("nonterminal_tests")
    complete = len(rows) <= HISTORY_LIMIT
    if not complete:
        blockers.append("dispatch_history_limit")
    unresolved = [
        dispatch.execution_id
        for run, item, dispatch, cleanup in rows[:HISTORY_LIMIT]
        if not cleanup_confirmed(lab, run, item, dispatch, cleanup)
    ]
    if unresolved:
        blockers.append("unconfirmed_cleanup")
    return {
        "format": "aegis-linux-binding-review/1",
        "laboratory_id": lab.id,
        "environment_version": lab.environment_version,
        "reviewed_at": now().isoformat(),
        "status": "blocked" if blockers else "persisted_prerequisites_satisfied",
        "blockers": blockers,
        "nonterminal_runs": pending_runs,
        "nonterminal_tests": pending_tests,
        "dispatches_examined": min(len(rows), HISTORY_LIMIT),
        "dispatch_history_complete": complete,
        "unconfirmed_cleanup_count": len(unresolved),
        "unconfirmed_execution_ids": unresolved[:SAMPLE_LIMIT],
        "unconfirmed_sample_truncated": len(unresolved) > SAMPLE_LIMIT,
        "runner_contacted": False,
        "journal_verified": False,
        "activation_permitted": False,
        "normal_operation_permitted": False,
    }


def require_review(db: Session, lab: Laboratory) -> None:
    if review(db, lab)["blockers"]:
        raise HTTPException(
            409,
            "Revisão do binding bloqueada; revogue o laboratório e consulte "
            "binding-review. Preserve jobs e diário originais até cleanup confirmado.",
        )
