"""Automatic Demo document snapshots. No execution, SIEM or external I/O adapters."""

import json
import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import analytics, queries
from aegis.config import require_normal_operation
from aegis.db import session_factory
from aegis.domain.states import TERMINAL
from aegis.domain.validation import digest
from aegis.models import (
    CampaignRun,
    ScheduleAuthorization,
    ScheduledReport,
    ScheduleOccurrence,
    now,
)
from aegis.reporting import build_comparison_report, build_report, seal_analysis
from aegis.security import audit

POLICY_VERSION = "scheduled-demo-report/1"
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_ATTEMPTS = 3
RETRY_SECONDS = (10, 30)
log = logging.getLogger("aegis.scheduled_reports")


class GenerationError(ValueError):
    """Closed error code; do not retain arbitrary driver or document messages."""


def previous_run(db: Session, occurrence: ScheduleOccurrence) -> str | None:
    return db.scalar(
        select(ScheduleOccurrence.run_id)
        .where(
            ScheduleOccurrence.schedule_id == occurrence.schedule_id,
            ScheduleOccurrence.authorization_id == occurrence.authorization_id,
            ScheduleOccurrence.scheduled_for < occurrence.scheduled_for,
            ScheduleOccurrence.run_id.is_not(None),
        )
        .order_by(ScheduleOccurrence.scheduled_for.desc(), ScheduleOccurrence.id.desc())
        .limit(1)
    )


def request_report(db: Session, occurrence: ScheduleOccurrence) -> ScheduledReport:
    """Caller holds schedule lock; transaction also includes occurrence and enqueue."""
    run = db.get(CampaignRun, occurrence.run_id)
    if not run or run.synthetic is not True or run.scope.get("mode") != "demo":
        raise GenerationError("CONTEXT_MISMATCH")
    previous = previous_run(db, occurrence)
    report = ScheduledReport(
        schedule_id=occurrence.schedule_id,
        authorization_id=occurrence.authorization_id,
        occurrence_id=occurrence.id,
        run_id=occurrence.run_id,
        previous_run_id=previous,
        kind="COMPARISON" if previous else "BASELINE",
    )
    db.add(report)
    return report


def source_detail(db: Session, item: ScheduledReport, run_id: str) -> dict:
    detail = queries.execution_detail(db, run_id)
    approval = detail.get("approval") or {}
    occurrence = detail.get("schedule_occurrence") or {}
    if (
        detail["synthetic"] is not True
        or detail["scope"].get("mode") != "demo"
        or detail["scope"].get("synthetic") is not True
        or detail["schedule_id"] != item.schedule_id
        or approval.get("schedule_authorization_id") != item.authorization_id
        or not approval.get("used_at")
        or approval.get("scope_hash") != detail["scope_hash"]
        or digest(detail["scope"]) != detail["scope_hash"]
        or occurrence.get("schedule_id") != item.schedule_id
        or occurrence.get("authorization_id") != item.authorization_id
        or occurrence.get("run_id") != run_id
        or occurrence.get("status") != "QUEUED"
        or any(execution["synthetic"] is not True for execution in detail["executions"])
    ):
        raise GenerationError("CONTEXT_MISMATCH")
    return detail


def build_document(db: Session, item: ScheduledReport) -> tuple[dict, datetime]:
    captured_at = now()
    occurrence = db.get(ScheduleOccurrence, item.occurrence_id)
    grant = db.get(ScheduleAuthorization, item.authorization_id)
    if (
        not occurrence
        or not grant
        or grant.schedule_id != item.schedule_id
        or occurrence.run_id != item.run_id
        or occurrence.schedule_id != item.schedule_id
        or occurrence.authorization_id != item.authorization_id
        or previous_run(db, occurrence) != item.previous_run_id
        or (item.kind == "BASELINE") != (item.previous_run_id is None)
    ):
        raise GenerationError("CONTEXT_MISMATCH")
    current = source_detail(db, item, item.run_id)
    if current["state"] not in TERMINAL:
        raise GenerationError("CONTEXT_MISMATCH")
    if item.previous_run_id:
        before = source_detail(db, item, item.previous_run_id)
        report = build_comparison_report(
            queries.compare(db, item.previous_run_id, item.run_id),
            build_report(before),
            build_report(current),
        )
    else:
        report = build_report(current)
    report["automation"] = {
        "policy_version": POLICY_VERSION,
        "report_id": item.id,
        "kind": item.kind,
        "schedule_id": item.schedule_id,
        "authorization_id": item.authorization_id,
        "occurrence_id": item.occurrence_id,
        "run_id": item.run_id,
        "previous_run_id": item.previous_run_id,
        "snapshot_at": captured_at.isoformat(),
        "baseline_reason": "FIRST_ISSUED_RUN_IN_AUTHORIZATION"
        if not item.previous_run_id
        else None,
    }
    if item.previous_run_id:
        report = seal_analysis(
            {key: value for key, value in report.items() if key != "integrity_sha256"}
        )
    if (
        len(json.dumps(report, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        > MAX_DOCUMENT_BYTES
    ):
        raise GenerationError("SOURCE_LIMIT")
    return report, captured_at


def process_one(at: datetime | None = None) -> bool:
    """Row lock covers snapshot and atomic publication; never locks execution rows."""
    require_normal_operation()
    instant = at or now()
    with session_factory()() as db:
        item = db.scalar(
            select(ScheduledReport)
            .join(CampaignRun, ScheduledReport.run_id == CampaignRun.id)
            .where(
                ScheduledReport.state == "PENDING",
                ScheduledReport.next_attempt_at <= instant,
                CampaignRun.state.in_(TERMINAL),
            )
            .order_by(ScheduledReport.created_at, ScheduledReport.id)
            .with_for_update(of=ScheduledReport, skip_locked=True)
            .limit(1)
        )
        if not item:
            return False
        item.attempts += 1
        try:
            with analytics.read_snapshot(db) as snapshot:
                document, captured_at = build_document(snapshot, item)
        except GenerationError as error:
            item.state, item.error_code = "FAILED", str(error)
        except Exception:
            # Snapshot connection has rolled back; writer only holds our request row.
            item.error_code = "GENERATION_FAILED"
            if item.attempts >= MAX_ATTEMPTS:
                item.state = "FAILED"
            else:
                item.next_attempt_at = instant + timedelta(seconds=RETRY_SECONDS[item.attempts - 1])
            log.warning(
                "Automatic report attempt failed: request=%s attempt=%s", item.id, item.attempts
            )
        else:
            item.document = document
            item.document_sha256 = digest(document)
            item.generated_at = captured_at
            item.state, item.error_code = "READY", None
            audit(
                db,
                None,
                "report.scheduled.generated",
                item.id,
                kind=item.kind,
                document_sha256=item.document_sha256,
                synthetic=True,
            )
        if item.state == "FAILED":
            audit(
                db,
                None,
                "report.scheduled.failed",
                item.id,
                error_code=item.error_code,
                attempts=item.attempts,
                synthetic=True,
            )
        db.commit()
        return True


def report_loop(stop: threading.Event) -> None:
    require_normal_operation()
    while not stop.is_set():
        try:
            for _ in range(5):
                if stop.is_set() or not process_one():
                    break
        except Exception:
            log.warning("Automatic report transaction rolled back; no artifact published")
        stop.wait(0.5)
