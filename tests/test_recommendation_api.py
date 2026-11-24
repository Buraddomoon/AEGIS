"""PostgreSQL/Redis15 integration tests. Synthetic Demo only; run sequentially."""

import pytest
from aegis import analytics, queries
from aegis.db import session_factory
from aegis.models import CampaignRun, DetectionEvidence, TelemetryEvent, User, ValidationResult
from aegis.models import TestExecution as Execution
from aegis.worker import claim_next, process_run
from conftest import create_queued
from sqlalchemy import func, select, text


@pytest.mark.parametrize("role", ["administrator", "operator", "viewer"])
def test_recommendations_real_storage_read_only_and_historical_exports_unchanged(
    admin, monkeypatch, role
):
    run = create_queued(admin)
    assert claim_next() == run["id"]
    process_run(run["id"])
    historical = {
        format: admin.get(f"/api/v1/reports/{run['id']}", params={"format": format}).content
        for format in ("json", "html", "pdf")
    }
    tables = (CampaignRun, Execution, ValidationResult, TelemetryEvent, DetectionEvidence)

    def counts():
        with session_factory()() as db:
            return [db.scalar(select(func.count()).select_from(t)) for t in tables]

    before = counts()
    with session_factory()() as db:
        db.scalar(select(User).where(User.username == "administrator")).role = role
        db.commit()
    original = queries.execution_detail
    observed = []

    def check_snapshot(db, identifier):
        observed.append(
            (
                db.scalar(text("SHOW transaction_isolation")),
                db.scalar(text("SHOW transaction_read_only")),
            )
        )
        return original(db, identifier)

    monkeypatch.setattr(queries, "execution_detail", check_snapshot)
    detail = admin.get(f"/api/v1/executions/{run['id']}")
    assert detail.status_code == 200
    analysis = detail.json()["recommendation_analysis"]
    codes = {item["code"] for item in analysis["items"]}
    assert {"detected", "observed_not_alerted", "no_telemetry", "inconclusive"} <= codes
    for format in ("json", "html", "pdf"):
        response = admin.get(
            f"/api/v1/reports/{run['id']}/recommendations",
            params={"format": format, "expected_analysis_sha256": analysis["integrity_sha256"]},
        )
        assert response.status_code == 200, response.text[:200] if format != "pdf" else "PDF failed"
        if format == "json":
            assert response.json()["analysis"] == analysis
    assert observed and set(observed) == {("repeatable read", "on")}
    assert counts() == before
    for format, content in historical.items():
        assert (
            admin.get(f"/api/v1/reports/{run['id']}", params={"format": format}).content == content
        )


def test_recommendation_snapshot_export_rejects_new_facts_and_missing_run(admin):
    run = create_queued(admin, ["demo-shell"])
    preview = admin.get(f"/api/v1/executions/{run['id']}").json()["recommendation_analysis"]
    assert claim_next() == run["id"]
    process_run(run["id"])
    params = {"expected_analysis_sha256": preview["integrity_sha256"]}
    assert (
        admin.get(f"/api/v1/reports/{run['id']}/recommendations", params=params).status_code == 409
    )
    assert (
        admin.get(
            "/api/v1/reports/00000000-0000-0000-0000-000000000000/recommendations", params=params
        ).status_code
        == 404
    )
    with session_factory()() as db, analytics.read_snapshot(db) as snapshot:
        assert snapshot.scalar(text("SHOW transaction_read_only")) == "on"
