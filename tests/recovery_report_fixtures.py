"""Explicit synthetic recovery data, created only in disposable test/restore DBs.

No worker, scheduler, start, login, adapter or historical-row updates. Cancelled
runs and fixture approvals are test data, never an operational authorization.
"""

from datetime import timedelta

from aegis import scheduled_reports, scheduling
from aegis.domain.validation import digest
from aegis.models import (
    Approval,
    Asset,
    Campaign,
    CampaignTest,
    Laboratory,
    LoginSession,
    Schedule,
    ScheduleAuthorization,
    ScheduledReport,
    ScheduleOccurrence,
    TestExecution,
    User,
    now,
    uid,
)
from aegis.services import move, request_run
from sqlalchemy import select
from sqlalchemy.orm import Session


def create_report_fixture(db: Session) -> dict:
    stamp = now()
    actor = User(
        username="recovery-fixture-" + uid(),
        password_hash="invalid-fixture-hash-no-login",
        role="administrator",
    )
    lab = Laboratory(
        name="Recovery fixture " + uid(),
        description="Synthetic recovery fixture; no execution or external evidence.",
        kind="demo",
        authorized=True,
        owner="Disposable fixture",
        isolation="Offline restoration clone or disposable test database only.",
    )
    db.add_all([actor, lab])
    db.flush()
    db.add(
        Asset(
            laboratory_id=lab.id,
            name="recovery-fixture",
            platform="Synthetic",
            external_id="recovery-fixture-" + uid(),
            synthetic=True,
        )
    )
    campaign = Campaign(
        name="Recovery fixture without dispatch",
        objective="Test frozen documents and recovery fences; no detection claim.",
        laboratory_id=lab.id,
        created_by=actor.id,
    )
    db.add(campaign)
    db.flush()
    db.add(CampaignTest(campaign_id=campaign.id, test_id="demo-shell"))
    db.flush()
    runs = [request_run(db, campaign.id, actor, uid(), commit=False) for _ in range(4)]
    schedule = Schedule(
        campaign_id=campaign.id,
        laboratory_id=lab.id,
        created_by=actor.id,
        state="ACTIVE",
        scope=runs[0].scope,
        scope_hash=runs[0].scope_hash,
        plan_hash="0" * 64,
        interval_seconds=60,
        max_occurrences=10,
        max_duration_seconds=60,
        starts_at=stamp - timedelta(minutes=3),
        ends_at=stamp + timedelta(hours=1),
        next_due_at=stamp + timedelta(seconds=60),
        occurrences_count=4,
    )
    db.add(schedule)
    db.flush()
    schedule.plan_hash = digest(scheduling.plan(schedule))
    grant = ScheduleAuthorization(
        schedule_id=schedule.id,
        approved_by=actor.id,
        plan_hash=schedule.plan_hash,
        expires_at=schedule.ends_at,
    )
    db.add(grant)
    db.flush()
    reports = []
    for index, run in enumerate(runs):
        run.schedule_id = schedule.id
        run.ended_at = stamp if index < 3 else None
        target = "CANCELLED" if index < 3 else "QUEUED"
        move(db, run, target, "Synthetic fixture, never dispatched.")
        for execution in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
            move(db, run, target, "Synthetic fixture, never executed.", execution)
            execution.ended_at = run.ended_at
        db.add(
            Approval(
                run_id=run.id,
                approved_by=actor.id,
                schedule_authorization_id=grant.id,
                scope_hash=run.scope_hash,
                expires_at=stamp + timedelta(hours=1),
                max_duration_seconds=60,
                used_at=stamp,
            )
        )
        occurrence = ScheduleOccurrence(
            schedule_id=schedule.id,
            authorization_id=grant.id,
            scheduled_for=schedule.starts_at + timedelta(seconds=index * 60),
            run_id=run.id,
            status="QUEUED",
            reason="Synthetic fixture occurrence; no scheduler or dispatch.",
        )
        db.add(occurrence)
        db.flush()
        item = scheduled_reports.request_report(db, occurrence)
        db.flush()
        if index < 2:
            item.document, item.generated_at = scheduled_reports.build_document(db, item)
            item.document_sha256 = digest(item.document)
            item.state, item.attempts = "READY", 1
        else:
            for attempt in range(1, 4 if index == 2 else 3):
                item.attempts = attempt
                db.flush()
            item.state = "FAILED" if index == 2 else "PENDING"
            item.error_code = "GENERATION_FAILED"
            item.next_attempt_at = stamp + timedelta(seconds=30)
        db.flush()
        reports.append(item.id)
    lab.active_run_id = runs[-1].id
    db.add(
        LoginSession(
            token_hash=digest("invalid-fixture-session-" + uid()),
            csrf_hash=digest("invalid-fixture-csrf-" + uid()),
            user_id=actor.id,
            expires_at=stamp + timedelta(hours=1),
        )
    )
    db.commit()
    return {"reports": reports, "runs": [run.id for run in runs], "schedule": schedule.id}


def report_rows(db: Session) -> dict:
    return {
        item.id: {column.key: getattr(item, column.key) for column in item.__table__.columns}
        for item in db.scalars(select(ScheduledReport).order_by(ScheduledReport.id))
    }
