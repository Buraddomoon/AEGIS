"""Real PostgreSQL snapshots/exports; only disposable synthetic laboratory facts."""

import html
import json
import uuid
from io import BytesIO

import pytest
from aegis import analytics
from aegis import environment_analytics as env
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import Asset, CampaignRun, Laboratory, TelemetryEvent, ValidationResult
from aegis.models import TestExecution as Execution
from aegis.worker import claim_next, process_run
from conftest import create_queued
from pypdf import PdfReader
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from test_attack_api import catalog_client as _catalog_client
from test_attack_api import catalog_db as _catalog_db

BASE = "/api/v1/coverage/environments"


def pair(admin):
    first = create_queued(admin, ["demo-shell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    with session_factory()() as db:
        lab = Laboratory(
            name="AAA Second Demo",
            kind="demo",
            authorized=True,
            owner="Fixture",
            description="Synthetic only",
            isolation="In-memory",
        )
        db.add(lab)
        db.flush()
        db.add(
            Asset(
                laboratory_id=lab.id,
                name="fixture",
                platform="Synthetic",
                external_id=uuid.uuid4().hex,
                synthetic=True,
            )
        )
        second_lab = lab.id
        db.commit()
    second = create_queued(admin, ["demo-shell"])
    assert second["laboratory_id"] == second_lab
    assert claim_next() == second["id"]
    process_run(second["id"])
    return (
        {
            "before_laboratory_id": first["laboratory_id"],
            "after_laboratory_id": second_lab,
            "before_mode": "demo",
            "after_mode": "demo",
        },
        first,
        second,
    )


def test_snapshot_exports_members_origin_and_historical_reports_unchanged(admin):
    params, first, second = pair(admin)

    def counts():
        with session_factory()() as db:
            return [
                db.scalar(select(func.count()).select_from(model))
                for model in (CampaignRun, Execution, ValidationResult, TelemetryEvent)
            ]

    original_counts = counts()
    history = {
        f: admin.get(f"/api/v1/reports/{first['id']}?format={f}").content for f in ("json", "html")
    }
    response = admin.get(BASE, params=params)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["comparison"]["classification"] == "equivalent"
    assert report["comparison"]["detected_rate_delta_percentage_points"] == 0
    assert report["before"]["valid_tests"] == report["after"]["valid_tests"] == 1
    child = report["before"]["members"][0]["executions"][0]
    assert child["result"]["synthetic"] and child["events"] and child["evidence"]
    assert len(child["result_sha256"]) == len(child["events"][0]["record_sha256"]) == 64
    assert (
        digest({k: v for k, v in report.items() if k != "integrity_sha256"})
        == report["integrity_sha256"]
    )
    params.update(
        expected_snapshot_sha256=report["integrity_sha256"], snapshot_at=report["snapshot_at"]
    )
    assert admin.get(BASE + "/report", params=params).json() == report
    exported_html = admin.get(BASE + "/report", params={**params, "format": "html"})
    assert exported_html.status_code == 200 and "<script" not in exported_html.text
    embedded = html.unescape(exported_html.text.split("<pre>")[1].split("</pre>")[0])
    assert json.loads(embedded) == report
    pdf = admin.get(BASE + "/report", params={**params, "format": "pdf"})
    assert pdf.status_code == 200, pdf.text[:100]
    assert pdf.headers["x-aegis-report-sha256"] == digest(report)
    pages = PdfReader(BytesIO(pdf.content)).pages
    extracted = "\n".join(p.extract_text() for p in pages)
    assert "Comparação entre laboratórios" in extracted
    assert all("DADOS SINTÉTICOS" in p.extract_text() for p in pages)
    assert first["id"] in extracted and second["id"] in extracted
    assert report["integrity_sha256"] in extracted
    for f, original in history.items():
        assert admin.get(f"/api/v1/reports/{first['id']}?format={f}").content == original
    assert counts() == original_counts


def test_viewer_exports_the_same_snapshot(admin):
    params, _, _ = pair(admin)
    preview = admin.get(BASE, params=params).json()
    login = admin.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    )
    assert login.status_code == 200
    exported = admin.get(
        BASE + "/report",
        params={
            **params,
            "snapshot_at": preview["snapshot_at"],
            "expected_snapshot_sha256": preview["integrity_sha256"],
        },
    )
    assert exported.status_code == 200 and exported.json() == preview


def test_repeatable_read_readonly_covers_both_sides_and_concurrent_changes(admin):
    params, _, second = pair(admin)
    query = env.PairQuery(**params)
    with session_factory()() as db, analytics.read_snapshot(db) as snapshot:
        assert snapshot.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        assert snapshot.scalar(text("SHOW transaction_read_only")) == "on"
        before = env.build(snapshot, query)
        with session_factory()() as writer:
            run = writer.get(CampaignRun, second["id"])
            run.state = "RUNNING"  # Corruption/concurrent-state fixture, not real history.
            writer.commit()
        assert env.build(snapshot, query) == before
    with session_factory()() as db, analytics.read_snapshot(db) as snapshot:
        after = env.build(snapshot, query)
        assert after["after"]["valid_tests"] == 0
        assert after["comparison"]["classification"] == "incomparable"
    with (
        session_factory()() as db,
        analytics.read_snapshot(db) as snapshot,
        pytest.raises(DBAPIError),
    ):
        snapshot.execute(text("UPDATE laboratories SET name=name"))
    response = admin.get(
        BASE + "/report",
        params={
            **params,
            "snapshot_at": before["snapshot_at"],
            "expected_snapshot_sha256": before["integrity_sha256"],
        },
    )
    assert response.status_code == 409


@pytest.mark.parametrize("limit", ["MAX_RUNS", "MAX_EXECUTIONS", "MAX_EVENTS", "MAX_BYTES"])
def test_limits_refuse_entire_projection(admin, monkeypatch, limit):
    params, _, _ = pair(admin)
    monkeypatch.setattr(env, limit, 0)
    response = admin.get(BASE, params=params)
    assert response.status_code == 422 and "reduza" in response.json()["error"]["message"]


def test_explicit_modes_empty_period_revoked_labs_and_invalid_inputs(admin):
    params, first, _ = pair(admin)
    with session_factory()() as db:
        db.get(Laboratory, first["laboratory_id"]).authorized = False
        db.commit()
    assert admin.get(BASE, params=params).json()["before"]["valid_tests"] == 1
    empty = admin.get(
        BASE, params={**params, "after_requested_before": "2000-01-01T00:00:00Z"}
    ).json()
    assert empty["after"]["total_runs"] == 0
    assert empty["comparison"]["detected_rate_delta_percentage_points"] is None
    mixed = admin.get(BASE, params={**params, "after_mode": "linux"}).json()
    assert mixed["comparison"]["classification"] == "incomparable"
    assert "different_modes" in mixed["comparison"]["reasons"]
    for extra, status in [
        ({"after_laboratory_id": first["laboratory_id"]}, 409),
        ({"after_laboratory_id": str(uuid.uuid4())}, 404),
        ({"before_requested_from": "2026-01-01T10:00:00"}, 422),
        (
            {
                "before_requested_from": "2026-01-01T10:00:00Z",
                "before_requested_before": "2000-01-01T00:00:00Z",
            },
            422,
        ),
        ({"after_catalog_release": "f" * 64}, 404),
        ({"after_laboratory_id": "invalid"}, 422),
    ]:
        assert admin.get(BASE, params={**params, **extra}).status_code == status
    assert admin.get(BASE + "/report", params=params).status_code == 422


def test_result_drift_and_origin_mismatch_refuse_cached_export_and_rate(admin):
    params, _, second = pair(admin)
    before = admin.get(BASE, params=params).json()
    with session_factory()() as db:
        from aegis.models import TestExecution as Execution

        result = db.scalar(
            select(ValidationResult).join(Execution).where(Execution.run_id == second["id"])
        )
        result.synthetic = False
        db.commit()
    updated = admin.get(BASE, params=params).json()
    assert updated["after"]["detected_percentage"] is None
    assert "after:origin_mismatch" in updated["comparison"]["reasons"]
    assert (
        admin.get(
            BASE + "/report",
            params={
                **params,
                "snapshot_at": before["snapshot_at"],
                "expected_snapshot_sha256": before["integrity_sha256"],
            },
        ).status_code
        == 409
    )


def test_query_requires_authentication_and_viewer_can_export(client):
    params = {
        "before_laboratory_id": str(uuid.uuid4()),
        "after_laboratory_id": str(uuid.uuid4()),
        "before_mode": "demo",
        "after_mode": "demo",
    }
    assert client.get(BASE, params=params).status_code == 401
    assert client.get(BASE + "/report", params=params).status_code == 401
    login = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    )
    assert login.status_code == 200
    assert client.get(BASE, params=params).status_code == 404


def test_catalog_current_drift_invalidates_export(catalog_client):
    from test_attack_publication import publish

    client, engine, actor = catalog_client
    params, _, _ = pair(client)
    params.update(before_catalog_release="current", after_catalog_release="current")
    before = client.get(BASE, params=params).json()
    publish(engine, actor)
    assert (
        client.get(
            BASE + "/report",
            params={
                **params,
                "snapshot_at": before["snapshot_at"],
                "expected_snapshot_sha256": before["integrity_sha256"],
            },
        ).status_code
        == 409
    )


catalog_client = _catalog_client
catalog_db = _catalog_db
