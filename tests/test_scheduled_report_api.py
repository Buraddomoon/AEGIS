"""Authenticated exports read the stored document, never current mutable source metadata."""

from datetime import timedelta
from io import BytesIO
from types import SimpleNamespace

import pytest
from aegis import pdf_reporting, scheduled_reports
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import AuditEvent, ScheduledReport
from aegis.scheduled_report_api import checked_document
from aegis.worker import claim_next, process_run
from fastapi import HTTPException
from pypdf import PdfReader
from sqlalchemy import func, select
from test_scheduled_reports import issue
from test_scheduling import ready


def completed(admin):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    assert scheduled_reports.process_one()
    return schedule, identifier


def exports():
    with session_factory()() as db:
        return db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "report.scheduled.export")
        )


def test_automatic_document_exports_preserve_hash_provenance_evidence_and_audit_only_metadata(
    admin,
):
    schedule, identifier = completed(admin)
    path = f"/api/v1/schedules/{schedule['id']}/reports"
    listing = admin.get(path).json()
    assert listing["schedule_id"] == schedule["id"] and listing["total"] == 1
    metadata = listing["items"][0]
    assert "document" not in metadata and metadata["state"] == "READY"
    document = admin.get(path + "/" + identifier).json()
    assert document["automation"]["report_id"] == identifier
    assert document["automation"]["kind"] == "BASELINE"
    assert document["synthetic"] is True
    assert metadata["document_sha256"] == digest(document)
    for format in ("html", "pdf"):
        response = admin.get(
            path + "/" + identifier,
            params={"format": format, "expected_sha256": metadata["document_sha256"]},
        )
        assert response.status_code == 200
        assert response.headers["x-aegis-report-sha256"] == digest(document)
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        if format == "pdf":
            assert response.headers["content-type"] == "application/pdf"
            reader = PdfReader(BytesIO(response.content), strict=True)
            assert all("DADOS SINTÉTICOS" in page.extract_text() for page in reader.pages)
            assert identifier in "\n".join(page.extract_text() for page in reader.pages)
        else:
            assert "EVIDÊNCIAS SINTÉTICAS" in response.text and identifier in response.text
    assert (
        admin.post(f"/api/v1/schedules/{schedule['id']}/revoke", json={"confirm": True}).status_code
        == 200
    )
    assert admin.get(path + "/" + identifier).json() == document
    with session_factory()() as db:
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "report.scheduled.export")
        ).all()
        assert all(set(event.details) == {"format", "kind", "document_sha256"} for event in events)
    assert admin.get(path, params={"offset": 1}).json()["items"] == []


@pytest.mark.parametrize(
    "path",
    ["/api/v1/schedules/missing/reports", "/api/v1/schedules/missing/reports/missing?format=pdf"],
)
def test_automatic_reports_require_authentication(client, path):
    assert client.get(path).status_code == 401


def test_pending_stale_wrong_context_and_invalid_inputs_fail_without_generating_a_document(admin):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, _ = issue(schedule, instant)
    path = f"/api/v1/schedules/{schedule['id']}/reports/{identifier}"
    assert admin.get(path).status_code == 409
    assert admin.get(path, params={"format": "xml"}).status_code == 422
    assert admin.get(path, params={"expected_sha256": "invalid"}).status_code == 422
    assert admin.get(f"/api/v1/schedules/wrong/reports/{identifier}").status_code == 404
    assert admin.get("/api/v1/schedules/wrong/reports").status_code == 404
    with session_factory()() as db:
        assert db.get(ScheduledReport, identifier).state == "PENDING"
    assert exports() == 0


def test_pdf_failure_does_not_audit_success_or_block_other_formats(admin, monkeypatch):
    schedule, identifier = completed(admin)
    path = f"/api/v1/schedules/{schedule['id']}/reports/{identifier}"
    assert admin.get(path, params={"expected_sha256": "f" * 64}).status_code == 409
    with pdf_reporting._RENDER_LOCK:
        assert admin.get(path, params={"format": "pdf"}).status_code == 503
    with monkeypatch.context() as patch:
        patch.setattr(pdf_reporting, "MAX_SOURCE_BYTES", 1)
        assert admin.get(path, params={"format": "pdf"}).status_code == 413
    assert exports() == 0
    assert (
        admin.get(path).status_code == admin.get(path, params={"format": "html"}).status_code == 200
    )


def test_viewer_can_export_existing_document_and_cannot_request_execution(admin):
    schedule, identifier = completed(admin)
    admin.post("/api/v1/auth/logout")
    response = admin.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    )
    assert response.status_code == 200
    admin.headers["x-csrf-token"] = response.json()["csrf_token"]
    assert admin.get(f"/api/v1/schedules/{schedule['id']}/reports/{identifier}").status_code == 200
    assert (
        admin.post(
            f"/api/v1/schedules/{schedule['id']}/approve",
            json={"confirm_plan_hash": schedule["plan_hash"], "confirm_automatic_execution": True},
        ).status_code
        == 403
    )


def test_document_hash_and_context_guard_refuse_corrupted_detached_snapshot_without_changing_database(
    admin,
):
    schedule, identifier = completed(admin)
    with session_factory()() as db:
        row = db.get(ScheduledReport, identifier)
        fields = {column.key: getattr(row, column.key) for column in row.__table__.columns}
    source = fields["document"]
    for replacement in (
        {**source, "synthetic": False},
        {**source, "automation": {}},
        {**source, "integrity_sha256": "f" * 64},
    ):
        fake = SimpleNamespace(
            **(fields | {"document": replacement, "document_sha256": digest(replacement)})
        )
        with pytest.raises(HTTPException) as caught:
            checked_document(fake)
        assert caught.value.status_code == 409
    assert admin.get(f"/api/v1/schedules/{schedule['id']}/reports/{identifier}").json() == source


def test_automatic_comparison_uses_sealed_snapshot_in_all_export_formats(admin):
    schedule, instant = ready(admin)
    first, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    assert scheduled_reports.process_one()
    second, run_id = issue(schedule, instant + timedelta(seconds=60))
    assert claim_next() == run_id
    process_run(run_id)
    assert scheduled_reports.process_one()
    path = f"/api/v1/schedules/{schedule['id']}/reports/{second}"
    document = admin.get(path).json()
    assert document["automation"]["kind"] == "COMPARISON"
    assert document["comparison"]["comparable"] is True
    assert document["summary"]["detected_rate_delta_percentage_points"] == 0.0
    assert document["automation"]["previous_run_id"] == document["comparison"]["before_id"]
    for format in ("html", "pdf"):
        response = admin.get(path, params={"format": format})
        assert response.status_code == 200 and response.headers["x-aegis-report-sha256"] == digest(
            document
        )
        text = (
            response.text
            if format == "html"
            else "\n".join(
                page.extract_text() for page in PdfReader(BytesIO(response.content)).pages
            )
        )
        assert document["comparison"]["before_id"] in text
        assert document["comparison"]["after_id"] in text and second in text


def test_automatic_pdf_shares_existing_pdf_limit_and_json_remains_available(admin):
    schedule, identifier = completed(admin)
    path = f"/api/v1/schedules/{schedule['id']}/reports/{identifier}"
    for index in range(10):
        target = path if index % 2 else "/api/v1/coverage/report"
        assert admin.get(target, params={"format": "pdf"}).status_code == 200
    assert admin.get(path, params={"format": "pdf"}).status_code == 429
    assert admin.get(path).status_code == 200


def test_failed_generation_is_visible_in_metadata_and_has_no_download(admin, monkeypatch):
    schedule, instant = ready(admin, max_occurrences=1)
    identifier, run_id = issue(schedule, instant)
    assert claim_next() == run_id
    process_run(run_id)
    monkeypatch.setattr(scheduled_reports, "MAX_DOCUMENT_BYTES", 1)
    assert scheduled_reports.process_one()
    path = f"/api/v1/schedules/{schedule['id']}/reports"
    item = admin.get(path).json()["items"][0]
    assert item["state"] == "FAILED" and item["error_code"] == "SOURCE_LIMIT"
    assert item["document_sha256"] is None and admin.get(path + "/" + identifier).status_code == 409
