"""Bounded Demo schedules. PostgreSQL owns slots, grants and the durable queue."""

import logging
import secrets
import threading
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from aegis import services
from aegis.config import require_normal_operation
from aegis.db import session_factory
from aegis.domain.states import TERMINAL
from aegis.domain.validation import digest
from aegis.models import (
    Approval,
    Campaign,
    CampaignRun,
    Schedule,
    ScheduleAuthorization,
    ScheduleOccurrence,
    User,
    now,
    uid,
)
from aegis.schemas import ScheduleCreate
from aegis.security import audit

log = logging.getLogger("aegis.scheduler")
LATE_GRACE_SECONDS = 30
OPEN_STATES = ("PENDING_APPROVAL", "ACTIVE", "PAUSED")


def plan(schedule: Schedule) -> dict:
    return {
        "version": "aegis-demo-schedule/1.0",
        "campaign_id": schedule.campaign_id,
        "laboratory_id": schedule.laboratory_id,
        "created_by": schedule.created_by,
        "scope_hash": schedule.scope_hash,
        "interval_seconds": schedule.interval_seconds,
        "max_occurrences": schedule.max_occurrences,
        "max_duration_seconds": schedule.max_duration_seconds,
        "starts_at": schedule.starts_at.astimezone(UTC).isoformat(),
        "ends_at": schedule.ends_at.astimezone(UTC).isoformat(),
        "late_grace_seconds": LATE_GRACE_SECONDS,
    }


def create(db: Session, data: ScheduleCreate, actor: User) -> Schedule:
    instant = now()
    if not instant <= data.starts_at <= instant + timedelta(days=30):
        raise HTTPException(422, "Início deve estar no futuro, dentro de 30 dias.")
    if data.ends_at > instant + timedelta(days=90):
        raise HTTPException(422, "Validade máxima: 90 dias a partir da criação.")
    # Serialize global capacity checks, never acquired by worker or pause paths.
    db.execute(text("SELECT pg_advisory_xact_lock(16490871)"))
    count = db.scalar(
        select(func.count()).select_from(Schedule).where(Schedule.state.in_(OPEN_STATES))
    )
    if count >= 64:
        raise HTTPException(409, "Limite global de 64 agendamentos abertos atingido.")
    campaign = services.get_or_404(db, Campaign, data.campaign_id)
    scope = services.snapshot_scope(db, campaign)
    if scope.get("mode") != "demo":
        raise HTTPException(409, "Agendamento habilitado somente para Demo.")
    item = Schedule(
        **data.model_dump(),
        laboratory_id=campaign.laboratory_id,
        created_by=actor.id,
        scope=scope,
        scope_hash=digest(scope),
        next_due_at=data.starts_at,
        state="PENDING_APPROVAL",
        occurrences_count=0,
    )
    item.plan_hash = digest(plan(item))
    db.add(item)
    db.flush()
    audit(db, actor.id, "schedule.create", item.id, plan_hash=item.plan_hash, synthetic=True)
    db.commit()
    return item


def locked(db: Session, identifier: str) -> Schedule:
    item = db.scalar(select(Schedule).where(Schedule.id == identifier).with_for_update())
    if not item:
        raise HTTPException(404, "Agendamento não encontrado.")
    return item


def fresh_scope(db: Session, item: Schedule) -> bool:
    if item.scope.get("mode") != "demo":
        return False
    if digest(plan(item)) != item.plan_hash or digest(item.scope) != item.scope_hash:
        return False
    try:
        campaign = services.get_or_404(db, Campaign, item.campaign_id)
        return digest(services.snapshot_scope(db, campaign)) == item.scope_hash
    except HTTPException:
        return False


def identities_valid(db: Session, item: Schedule, grant: ScheduleAuthorization) -> bool:
    creator = db.get(User, item.created_by)
    approver = db.get(User, grant.approved_by)
    return bool(
        creator
        and creator.active
        and creator.role in ("administrator", "operator")
        and approver
        and approver.active
        and approver.role == "administrator"
    )


def approve(db: Session, identifier: str, actor: User, confirmed_hash: str) -> Schedule:
    db.execute(text("SELECT pg_advisory_xact_lock(16490871)"))
    item = locked(db, identifier)
    if item.state not in ("PENDING_APPROVAL", "PAUSED") or item.ends_at <= now():
        raise HTTPException(409, "Agendamento não permite aprovação ou sua validade acabou.")
    if not secrets.compare_digest(item.plan_hash, confirmed_hash) or not fresh_scope(db, item):
        raise HTTPException(409, "Plano ou escopo mudou; crie novo agendamento.")
    count = db.scalar(select(func.count()).select_from(Schedule).where(Schedule.state == "ACTIVE"))
    if count >= 16:
        raise HTTPException(409, "Limite global de 16 agendamentos ativos atingido.")
    grant = ScheduleAuthorization(
        schedule_id=item.id, approved_by=actor.id, plan_hash=item.plan_hash, expires_at=item.ends_at
    )
    if not identities_valid(db, item, grant):
        raise HTTPException(409, "Criador ou aprovador sem permissão ativa.")
    db.add(grant)
    item.state, item.reason = "ACTIVE", None
    audit(
        db,
        actor.id,
        "schedule.approve",
        item.id,
        plan_hash=item.plan_hash,
        max_occurrences=item.max_occurrences,
        consumed=item.occurrences_count,
        expires_at=item.ends_at.isoformat(),
        max_duration_seconds=item.max_duration_seconds,
    )
    db.commit()
    return item


def stop_schedule(db: Session, identifier: str, actor: User, *, revoke: bool) -> Schedule:
    # Lock order: schedule -> run -> laboratory. Worker reads grants WITHOUT row locks.
    item = locked(db, identifier)
    if item.state == "REVOKED":
        return item
    if not revoke and item.state not in ("ACTIVE", "PENDING_APPROVAL"):
        raise HTTPException(409, "Somente agendamentos ativos ou pendentes podem ser pausados.")
    item.state = "REVOKED" if revoke else "PAUSED"
    item.reason = "Revogado pelo usuário." if revoke else "Pausado; retomada exige nova aprovação."
    for grant in db.scalars(
        select(ScheduleAuthorization).where(
            ScheduleAuthorization.schedule_id == item.id, ScheduleAuthorization.revoked_at.is_(None)
        )
    ):
        grant.revoked_at = now()
    db.flush()
    for run_id in db.scalars(
        select(CampaignRun.id)
        .where(CampaignRun.schedule_id == item.id, CampaignRun.state.not_in(list(TERMINAL)))
        .order_by(CampaignRun.id)
    ).all():
        run = services.locked_run(db, run_id)
        if run.state not in TERMINAL:
            services.cancel_run(db, run_id, actor, commit=False)
    audit(db, actor.id, "schedule.revoke" if revoke else "schedule.pause", item.id)
    db.commit()
    return item


def authorization_valid(db: Session, run: CampaignRun, approval: Approval | None) -> bool:
    """Check the EXACT originating grant, never a replacement grant. No row locks."""
    if not run.schedule_id:
        return approval is not None and approval.schedule_authorization_id is None
    if not approval or not approval.schedule_authorization_id:
        return False
    item = db.get(Schedule, run.schedule_id)
    grant = db.get(ScheduleAuthorization, approval.schedule_authorization_id)
    occurrence = db.scalar(select(ScheduleOccurrence).where(ScheduleOccurrence.run_id == run.id))
    return bool(
        item
        and grant
        and occurrence
        and occurrence.schedule_id == item.id
        and occurrence.authorization_id == grant.id
        and grant.schedule_id == item.id
        and grant.revoked_at is None
        and grant.expires_at > now()
        and item.ends_at > now()
        and item.state in ("ACTIVE", "EXHAUSTED")
        and grant.plan_hash == item.plan_hash
        and run.scope_hash == item.scope_hash
        and identities_valid(db, item, grant)
        and fresh_scope(db, item)
    )


def dispatch_one(at: datetime | None = None) -> bool:
    """One slot per transaction; competing dispatchers cannot emit the same slot."""
    require_normal_operation()
    instant = at or now()
    with session_factory()() as db:
        item = db.scalar(
            select(Schedule)
            .where(
                ((Schedule.state == "ACTIVE") & (Schedule.next_due_at <= instant))
                | (
                    Schedule.state.in_(("PENDING_APPROVAL", "PAUSED"))
                    & (Schedule.ends_at <= instant)
                )
            )
            .order_by(Schedule.next_due_at, Schedule.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not item:
            return False
        grant = db.scalar(
            select(ScheduleAuthorization).where(
                ScheduleAuthorization.schedule_id == item.id,
                ScheduleAuthorization.revoked_at.is_(None),
            )
        )
        if item.ends_at <= instant or (grant and grant.expires_at <= instant):
            item.state, item.reason = "EXPIRED", "Janela de autorização encerrada."
        elif (
            not grant
            or grant.plan_hash != item.plan_hash
            or not identities_valid(db, item, grant)
            or not fresh_scope(db, item)
        ):
            item.state, item.reason = (
                "INVALIDATED",
                "Autorização, identidade ou escopo deixou de ser válido.",
            )
        else:
            slot, run_id = item.next_due_at, None
            status, reason = (
                "SKIPPED_LATE",
                "Slot ultrapassou a tolerância de 30 segundos; sem repetição retroativa.",
            )
            if instant - slot <= timedelta(seconds=LATE_GRACE_SECONDS):
                # SAVEPOINT removes run, tests, approval, audit and reservation if lab is busy.
                try:
                    with db.begin_nested():
                        actor = db.get(User, item.created_by)
                        run = services.request_run(
                            db, item.campaign_id, actor, "schedule-" + uid(), commit=False
                        )
                        run.schedule_id = item.id
                        db.add(
                            Approval(
                                run_id=run.id,
                                approved_by=grant.approved_by,
                                scope_hash=run.scope_hash,
                                expires_at=min(item.ends_at, grant.expires_at),
                                max_duration_seconds=item.max_duration_seconds,
                                schedule_authorization_id=grant.id,
                            )
                        )
                        db.flush()
                        services.start_run(db, run.id, actor, commit=False, at=instant)
                        run_id, status, reason = (
                            run.id,
                            "QUEUED",
                            "Autorização recorrente delimitada consumiu um slot.",
                        )
                except HTTPException as exc:
                    if exc.status_code != 409 or "já possui execução" not in str(exc.detail):
                        raise
                    status, reason = (
                        "SKIPPED_BUSY",
                        "Laboratório reservado; slot descartado sem execução.",
                    )
            db.add(
                ScheduleOccurrence(
                    schedule_id=item.id,
                    authorization_id=grant.id,
                    scheduled_for=slot,
                    run_id=run_id,
                    status=status,
                    reason=reason,
                )
            )
            item.occurrences_count += 1
            item.next_due_at = item.starts_at + timedelta(
                seconds=item.interval_seconds * item.occurrences_count
            )
            if item.occurrences_count >= item.max_occurrences:
                item.state = "EXHAUSTED"
            elif item.next_due_at >= item.ends_at:
                # No future slots, but any previously issued run keeps its exact grant.
                item.state = "EXHAUSTED"
            audit(
                db,
                None,
                "schedule.slot",
                item.id,
                status=status,
                run_id=run_id,
                scheduled_for=slot.isoformat(),
                authorization_id=grant.id,
                synthetic=True,
            )
        if item.reason:
            audit(db, None, "schedule.stop", item.id, state=item.state, reason=item.reason)
        db.commit()
        return True


def scheduler_loop(stop: threading.Event) -> None:
    """Independent lightweight thread; sessions never cross thread boundaries."""
    require_normal_operation()
    while not stop.is_set():
        try:
            for _ in range(20):
                if stop.is_set() or not dispatch_one():
                    break
        except Exception:
            log.exception("Demo scheduler tick failed; transaction rolled back")
        stop.wait(0.5)
