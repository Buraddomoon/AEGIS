"""Real PostgreSQL/worker reports delivered as parseable PDFs, with no lab startup."""

from io import BytesIO

import pytest
from aegis import pdf_reporting as pdf
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import AuditEvent
from aegis.worker import claim_next, process_run
from conftest import create_queued
from pypdf import PdfReader
from sqlalchemy import func, select
from test_analytics_api import repeated


def export_count():
    with session_factory()() as db:
        return db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action.in_(["report.export", "report.analysis.export"]))
        )


def test_all_pdf_exports_preserve_evidence_scope_integrity_and_audit_only_metadata(admin, tmp_path):
    first, second = repeated(admin)
    paths = [
        f"/api/v1/reports/{first['id']}",
        "/api/v1/coverage/report?mode=demo",
        f"/api/v1/coverage/compare/report?before={first['id']}&after={second['id']}",
    ]
    for path in paths:
        original = admin.get(path).json()
        response = admin.get(path + ("&" if "?" in path else "?") + "format=pdf")
        assert response.status_code == 200, response.text[:200]
        assert response.headers["content-type"] == "application/pdf"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert '.pdf"' in response.headers["content-disposition"]
        text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(response.content)).pages)
        assert "DADOS SINTÉTICOS" in text and first["id"] in text
        assert len(response.headers["x-aegis-report-sha256"]) == 64
        if "/reports/" in path or "/compare/" in path:
            assert response.headers["x-aegis-report-sha256"] == digest(original)
            assert admin.get(path).json() == original
        if "/compare/" in path:
            assert "Comparabilidade não confirmada" in text and "não calculado" in text
        if "/reports/" in path:
            event = original["run"]["executions"][0]["events"][0]
            assert event["sha256"] in text
    with session_factory()() as db:
        rows = db.scalars(
            select(AuditEvent).where(AuditEvent.details["format"].astext == "pdf")
        ).all()
        assert len(rows) == 3
        assert all(set(row.details) <= {"format", "kind"} for row in rows)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/reports/missing?format=pdf",
        "/api/v1/coverage/report?format=pdf",
        "/api/v1/coverage/compare/report?before=a&after=b&format=pdf",
    ],
)
def test_pdf_requires_authentication(client, path):
    assert client.get(path).status_code == 401


def test_viewer_can_download_pdf_but_export_does_not_grant_write_permissions(client):
    result = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    )
    assert result.status_code == 200
    response = client.get("/api/v1/coverage/report?format=pdf")
    assert response.status_code == 200 and PdfReader(BytesIO(response.content)).pages
    assert client.post("/api/v1/campaigns", json={}).status_code in {403, 422}


def test_pdf_keeps_obsolete_scope_rejection_and_cannot_bypass_input_validation(admin):
    response = admin.get(
        "/api/v1/coverage/report",
        params={
            "format": "pdf",
            "expected_scope_sha256": "f" * 64,
        },
    )
    assert response.status_code == 409
    assert admin.get("/api/v1/coverage/report?format=pdf&mode=arbitrary").status_code == 422
    assert admin.get("/api/v1/reports/missing?format=pdf").status_code == 404


def test_pdf_refusals_do_not_record_success_or_disable_json_html_exports(admin, monkeypatch):
    run = create_queued(admin)
    assert claim_next() == run["id"]
    process_run(run["id"])
    path = f"/api/v1/reports/{run['id']}"
    count = export_count()
    with pdf._RENDER_LOCK:
        response = admin.get(path + "?format=pdf")
        assert response.status_code == 503 and response.headers["retry-after"] == "2"
    assert export_count() == count
    with monkeypatch.context() as patch:
        patch.setattr(pdf, "MAX_SOURCE_BYTES", 1)
        response = admin.get(path + "?format=pdf")
        assert response.status_code == 413 and "JSON/HTML" in response.json()["error"]["message"]
    assert export_count() == count
    assert admin.get(path).status_code == admin.get(path + "?format=html").status_code == 200


def test_pdf_rate_limit_is_shared_across_report_endpoints_and_does_not_limit_json(admin):
    run = create_queued(admin, ["demo-shell"])
    path = f"/api/v1/reports/{run['id']}?format=pdf"
    for index in range(10):
        target = path if index % 2 else "/api/v1/coverage/report?format=pdf"
        assert admin.get(target).status_code == 200
    limited = admin.get(path)
    assert limited.status_code == 429 and limited.headers["retry-after"] == "60"
    assert admin.get("/api/v1/coverage/report").status_code == 200


def test_execution_summary_follows_worker_results_and_matches_coverage_without_rewriting_history(
    admin,
):
    run = create_queued(admin)
    path = f"/api/v1/reports/{run['id']}"
    queued = admin.get(path).json()
    assert queued["summary"]["planned_tests"] == 4
    assert queued["summary"]["completed_tests"] == queued["summary"]["valid_tests"] == 0
    assert queued["summary"]["detected_percentage"] is None
    assert "Foram avaliadas" not in admin.get(path + "?format=html").text
    response = admin.get(path + "?format=pdf")
    assert response.status_code == 200
    text = " ".join(
        " ".join(page.extract_text().split()) for page in PdfReader(BytesIO(response.content)).pages
    )
    assert "Taxa não calculada" in text and "0 em 0 testes válidos" in text
    assert claim_next() == run["id"]
    process_run(run["id"])
    report = admin.get(path).json()
    summary = report["summary"]
    coverage = admin.get("/api/v1/coverage").json()
    assert summary["completed_tests"] == 4
    assert summary["valid_tests"] == coverage["valid_tests"] == 3
    assert summary["detected_tests"] == 1 and summary["excluded_tests"] == 1
    assert summary["detected_percentage"] == coverage["detected_percentage"] == 33.3
    detail = admin.get(f"/api/v1/executions/{run['id']}").json()
    # Detail HTTP uses Z while the existing report contract encodes UTC as +00:00.
    # Hash the exact report bytes' JSON values; independently ensure exports do not mutate history.
    assert report["run"]["id"] == detail["id"]
    assert report["integrity_sha256"] == digest(report["run"])
    html = admin.get(path + "?format=html").text
    response = admin.get(path + "?format=pdf")
    assert response.status_code == 200
    text = " ".join(
        " ".join(page.extract_text().split()) for page in PdfReader(BytesIO(response.content)).pages
    )
    assert "1 em 3 testes válidos" in text and "33,3%" in text and "33,3%" in html
    assert admin.get(path).json() == report
    assert admin.get(f"/api/v1/executions/{run['id']}").json() == detail


@pytest.mark.parametrize("terminal", ["CANCELLED", "CLEANUP_FAILED"])
def test_unsuccessful_run_has_no_detection_rate_in_any_report_format(admin, terminal):
    from aegis.integrations.demo import DemoExecutionAdapter

    class BrokenCleanup(DemoExecutionAdapter):
        def cleanup(self, ctx):
            raise RuntimeError("Injected cleanup failure")

    run = create_queued(admin, ["demo-shell"])
    if terminal == "CANCELLED":
        assert admin.post(f"/api/v1/executions/{run['id']}/cancel").status_code == 200
    else:
        assert claim_next() == run["id"]
        process_run(run["id"], BrokenCleanup())
    path = f"/api/v1/reports/{run['id']}"
    report = admin.get(path).json()
    assert report["run"]["state"] == terminal
    assert report["summary"]["valid_tests"] == report["summary"]["detected_tests"] == 0
    assert report["summary"]["detected_percentage"] is None
    assert admin.get("/api/v1/coverage").json()["valid_tests"] == 0
    assert "Taxa não calculada" in admin.get(path + "?format=html").text
    response = admin.get(path + "?format=pdf")
    assert response.status_code == 200
    text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(response.content)).pages)
    assert "Taxa não calculada" in text and terminal in text
