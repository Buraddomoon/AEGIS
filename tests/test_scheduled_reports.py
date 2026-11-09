"""Durable requests processed against real PostgreSQL and actual Demo worker results."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from aegis import scheduled_reports as reports
from aegis import scheduling
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import AuditEvent, ScheduledReport, ScheduleOccurrence, now
from aegis.worker import claim_next, process_run
from sqlalchemy import func, select
from test_scheduling import approve, ready


def issue(schedule, instant):
    assert scheduling.dispatch_one(instant)
    with session_factory()() as db:
        occurrence = db.scalar(
            select(ScheduleOccurrence).order_by(ScheduleOccurrence.scheduled_for.desc())
        )
        request = db.scalar(
            select(ScheduledReport).where(ScheduledReport.occurrence_id == occurrence.id)
        )
        return request.id, request.run_id


def saved(identifier):
    with session_factory()() as db:
        return db.get(ScheduledReport, identifier)


def test_initial_report_then_comparison_preserve_snapshot_and_full_document_hash(admin):
    schedule, instant = ready(admin)
    first, first_run = issue(schedule, instant)
    assert reports.process_one() is False  # Wait for terminal run, no fabricated result.
    assert claim_next() == first_run
    process_run(first_run)
    assert reports.process_one()
    initial = saved(first)
    assert initial.kind == "BASELINE" and initial.state == "READY"
    assert initial.document["automation"]["previous_run_id"] is None
    assert initial.document["run"]["id"] == first_run
    assert initial.document["summary"]["detected_percentage"] == 100.0
    assert initial.document_sha256 == digest(initial.document)
    second, second_run = issue(schedule, instant + timedelta(seconds=60))
    assert saved(second).previous_run_id == first_run
    assert claim_next() == second_run
    process_run(second_run)
    assert reports.process_one()
    comparison = saved(second)
    assert comparison.kind == "COMPARISON" and comparison.state == "READY"
    assert comparison.document["comparison"]["comparable"] is True
    assert comparison.document["summary"]["detected_rate_delta_percentage_points"] == 0.0
    assert comparison.document_sha256 == digest(comparison.document)
    assert comparison.document["integrity_sha256"] == digest(
        {key: value for key, value in comparison.document.items() if key != "integrity_sha256"}
    )
    assert reports.process_one() is False
    assert saved(first).document == initial.document


def test_competing_processors_publish_once_and_record_one_audit(admin):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: reports.process_one(), range(2)))
    assert outcomes.count(True) == 1
    assert saved(identifier).attempts == 1 and saved(identifier).state == "READY"
    with session_factory()() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "report.scheduled.generated")
            )
            == 1
        )


def test_cancelled_previous_run_is_not_skipped_to_manufacture_positive_comparison(admin):
    schedule, instant = ready(admin)
    first, first_run = issue(schedule, instant)
    assert admin.post(f"/api/v1/executions/{first_run}/cancel").status_code == 200
    assert reports.process_one()
    assert saved(first).document["summary"]["detected_percentage"] is None
    second, second_run = issue(schedule, instant + timedelta(seconds=60))
    assert claim_next() == second_run
    process_run(second_run)
    assert reports.process_one()
    document = saved(second).document
    assert document["comparison"]["before_id"] == first_run
    assert document["comparison"]["comparable"] is False
    assert "incomplete_runs" in document["comparison"]["comparability_reasons"]
    assert document["summary"]["detected_rate_delta_percentage_points"] is None


def test_generation_failures_retry_with_backoff_then_stop_without_partial_document(
    admin, monkeypatch
):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)

    def failing(*args):
        raise RuntimeError("Sensitive driver sentinel must never be persisted")

    monkeypatch.setattr(reports, "build_document", failing)
    at = now()
    assert reports.process_one(at)
    first = saved(identifier)
    assert first.state == "PENDING" and first.error_code == "GENERATION_FAILED"
    assert first.next_attempt_at == at + timedelta(seconds=10)
    assert reports.process_one(at) is False
    assert reports.process_one(first.next_attempt_at)
    second = saved(identifier)
    assert second.state == "PENDING" and second.attempts == 2
    assert reports.process_one(second.next_attempt_at)
    final = saved(identifier)
    assert final.state == "FAILED" and final.attempts == 3
    assert final.document is final.document_sha256 is final.generated_at is None
    assert reports.process_one(now() + timedelta(days=1)) is False


def test_source_limit_fails_closed_without_retry_or_truncation(admin, monkeypatch):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    monkeypatch.setattr(reports, "MAX_DOCUMENT_BYTES", 1)
    assert reports.process_one()
    item = saved(identifier)
    assert item.state == "FAILED" and item.error_code == "SOURCE_LIMIT" and item.attempts == 1
    assert item.document is None


def test_reapproval_starts_new_baseline_and_never_rewrites_revoked_grant_report(admin):
    schedule, instant = ready(admin)
    first, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    assert reports.process_one()
    original = saved(first).document
    assert (
        admin.post(f"/api/v1/schedules/{schedule['id']}/pause", json={"confirm": True}).status_code
        == 200
    )
    approve(admin, schedule)
    second, run_id = issue(schedule, instant + timedelta(seconds=60))
    assert saved(second).authorization_id != saved(first).authorization_id
    assert saved(second).kind == "BASELINE" and saved(second).previous_run_id is None
    assert claim_next() == run_id
    process_run(run_id)
    assert reports.process_one()
    assert saved(first).document == original


def test_report_request_failure_rolls_back_occurrence_run_and_reservation(admin, monkeypatch):
    schedule, instant = ready(admin)

    def fail(*args):
        raise RuntimeError("Injected transaction failure")

    monkeypatch.setattr(reports, "request_report", fail)
    with pytest.raises(RuntimeError, match="Injected"):
        scheduling.dispatch_one(instant)
    from aegis.models import CampaignRun, Laboratory

    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(ScheduledReport)) == 0
        assert db.scalar(select(func.count()).select_from(ScheduleOccurrence)) == 0
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 0
        assert db.scalar(select(Laboratory.active_run_id)) is None


def test_crash_before_publication_rolls_back_attempt_and_audit_then_retry_publishes_once(
    admin, monkeypatch
):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)

    def fail(*args, **kwargs):
        raise RuntimeError("Injected publication failure")

    with monkeypatch.context() as patch:
        patch.setattr(reports, "audit", fail)
        with pytest.raises(RuntimeError, match="publication"):
            reports.process_one()
    item = saved(identifier)
    assert item.state == "PENDING" and item.attempts == 0 and item.document is None
    assert reports.process_one()
    assert saved(identifier).state == "READY" and saved(identifier).attempts == 1


@pytest.mark.parametrize("reason", ["late", "busy"])
def test_discarded_slots_do_not_request_or_generate_reports(admin, reason):
    from conftest import create_queued

    schedule, instant = ready(admin, max_occurrences=1)
    if reason == "busy":
        create_queued(admin, ["demo-shell"])
    assert scheduling.dispatch_one(instant + timedelta(minutes=2) if reason == "late" else instant)
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(ScheduledReport)) == 0
    assert reports.process_one() is False


def test_source_context_drift_cannot_be_published_as_demo_evidence(admin):
    from aegis.models import CampaignRun

    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    with session_factory()() as db:
        run = db.get(CampaignRun, run_id)
        run.scope = run.scope | {"mode": "linux"}
        db.commit()
    assert reports.process_one()
    item = saved(identifier)
    assert (
        item.state == "FAILED" and item.error_code == "CONTEXT_MISMATCH" and item.document is None
    )


def test_report_processing_refuses_recovery_mode_before_database_work(db_ready, monkeypatch):
    from aegis.config import settings

    monkeypatch.setattr(settings(), "operating_mode", "recovery")
    with pytest.raises(RuntimeError):
        reports.process_one()


def test_slow_snapshot_generation_does_not_lock_schedule_lab_or_next_dispatch(admin, monkeypatch):
    schedule, instant = ready(admin)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    entered, release = threading.Event(), threading.Event()
    original = reports.build_document

    def delayed(*args):
        document = original(*args)
        entered.set()
        assert release.wait(5)
        return document

    monkeypatch.setattr(reports, "build_document", delayed)
    with ThreadPoolExecutor(max_workers=2) as pool:
        report_task = pool.submit(reports.process_one)
        try:
            assert entered.wait(5)
            dispatch = pool.submit(scheduling.dispatch_one, instant + timedelta(seconds=60))
            assert dispatch.result(timeout=3) is True
        finally:
            release.set()
        assert report_task.result(timeout=5) is True
    assert saved(identifier).state == "READY"


def test_new_occurrence_can_reference_legacy_run_without_requesting_retroactive_report(
    admin, monkeypatch
):
    schedule, instant = ready(admin)
    with monkeypatch.context() as patch:
        # Model a slot emitted before this feature existed; no report request was stored.
        patch.setattr(reports, "request_report", lambda *args: None)
        assert scheduling.dispatch_one(instant)
    with session_factory()() as db:
        old_run = db.scalar(select(ScheduleOccurrence.run_id))
    assert claim_next() == old_run
    process_run(old_run)
    assert reports.process_one() is False
    identifier, run_id = issue(schedule, instant + timedelta(seconds=60))
    assert claim_next() == run_id
    process_run(run_id)
    assert reports.process_one()
    report = saved(identifier)
    assert report.kind == "COMPARISON" and report.previous_run_id == old_run
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(ScheduledReport)) == 1
