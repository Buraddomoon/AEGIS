"""Real PostgreSQL constraints for the durable request and its immutable artifact."""

import pytest
from aegis import scheduling
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import ScheduledReport, ScheduleOccurrence, now, uid
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from test_scheduling import ready


def pending(admin):
    schedule, instant = ready(admin)
    assert scheduling.dispatch_one(instant)
    with session_factory()() as db:
        occurrence = db.scalar(select(ScheduleOccurrence))
        item = ScheduledReport(
            schedule_id=schedule["id"],
            authorization_id=occurrence.authorization_id,
            occurrence_id=occurrence.id,
            run_id=occurrence.run_id,
            kind="BASELINE",
        )
        db.add(item)
        db.commit()
        return item.id


def test_pending_request_is_durable_and_document_is_sql_null(admin):
    identifier = pending(admin)
    with session_factory()() as db:
        item = db.get(ScheduledReport, identifier)
        assert item.state == "PENDING" and item.attempts == 0
        assert item.document is None
        assert (
            db.scalar(
                select(func.count())
                .select_from(ScheduledReport)
                .where(ScheduledReport.document.is_(None))
            )
            == 1
        )


def test_completed_artifact_and_pending_identity_are_immutable_even_for_owner(admin):
    identifier = pending(admin)
    with session_factory()() as db:
        item = db.get(ScheduledReport, identifier)
        item.id = uid()
        with pytest.raises(DBAPIError, match="history is immutable"):
            db.commit()
        db.rollback()
        item = db.get(ScheduledReport, identifier)
        item.state, item.attempts, item.generated_at = "READY", 1, now()
        item.document = {"synthetic": True, "fixture": "not an operational report"}
        item.document_sha256 = digest(item.document)
        db.commit()
        item.document = {"tampered": True}
        with pytest.raises(DBAPIError, match="history is immutable"):
            db.commit()
        db.rollback()
        assert db.get(ScheduledReport, identifier).document["synthetic"] is True


def test_occurrence_cannot_request_duplicate_or_publish_partial_document(admin):
    identifier = pending(admin)
    with session_factory()() as db:
        item = db.get(ScheduledReport, identifier)
        db.add(
            ScheduledReport(
                schedule_id=item.schedule_id,
                authorization_id=item.authorization_id,
                occurrence_id=item.occurrence_id,
                run_id=item.run_id,
                kind="BASELINE",
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        item = db.get(ScheduledReport, identifier)
        item.state, item.attempts = "READY", 1
        with pytest.raises(IntegrityError, match="scheduled_report_artifact"):
            db.commit()
        db.rollback()
        assert db.get(ScheduledReport, identifier).state == "PENDING"
