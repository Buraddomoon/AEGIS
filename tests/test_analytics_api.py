"""Scoped reads and exports over real PostgreSQL; all executions are Demo."""

import uuid
from datetime import timedelta

import pytest
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import CampaignRun, ValidationResult, now
from aegis.models import TestExecution as Execution
from aegis.worker import claim_next, process_run
from conftest import create_queued
from test_attack_api import catalog_client as _catalog_client
from test_attack_api import catalog_db as _catalog_db
from test_attack_api import finish
from test_attack_publication import publish

catalog_client = _catalog_client
catalog_db = _catalog_db


def test_historical_release_uses_its_snapshot_and_scoped_runs(catalog_client):
    client, engine, actor = catalog_client
    first = create_queued(client, ["demo-powershell"])
    finish(first["id"])
    old = first["scope"]["attack_catalog"]["release_id"]
    before_report = client.get("/api/v1/reports/" + first["id"]).json()
    publish(engine, actor)
    assert client.get("/api/v1/coverage?catalog_release=current").json()["total_runs"] == 0
    data = client.get("/api/v1/coverage?catalog_release=" + old).json()
    assert data["total_runs"] == data["evaluated_techniques"] == data["valid_tests"] == 1
    assert data["selection"]["evaluation_catalog"]["version"] == "19.2"
    assert data["attack_catalog"]["version"] == "20.0"
    assert data["catalogued_techniques"] == 706
    assert client.get("/api/v1/coverage?catalog_release=" + "f" * 64).status_code == 404
    assert client.get("/api/v1/reports/" + first["id"]).json() == before_report


@pytest.mark.parametrize(
    "params",
    [
        {"requested_from": "2026-10-26T12:00:00"},
        {"requested_from": "1720000000"},
        {"requested_from": "2026-10-26T13:00:00Z", "requested_before": "2026-10-26T12:00:00Z"},
        {"catalog_release": "20.0"},
        {"requested_from": "9999-12-31T23:59:59-14:00"},
    ],
)
def test_invalid_scope_is_consistently_422(admin, params):
    for path in ("/coverage", "/coverage/runs", "/coverage/report"):
        response = admin.get("/api/v1" + path, params=params)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == 422


def test_period_offsets_preview_export_hash_and_legacy_unknown(admin):
    first = create_queued(admin, ["demo-shell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    with session_factory()() as db:
        source = db.get(CampaignRun, first["id"])
        stamp = source.created_at
        scope = {
            k: v
            for k, v in source.scope.items()
            if k not in ("attack_catalog", "attack_techniques")
        }
        legacy = CampaignRun(
            campaign_id=source.campaign_id,
            laboratory_id=source.laboratory_id,
            requested_by=source.requested_by,
            idempotency_key=uuid.uuid4().hex,
            state="COMPLETED",
            scope=scope,
            scope_hash=digest(scope),
            synthetic=True,
            created_at=stamp + timedelta(seconds=2),
            ended_at=now(),
        )
        db.add(legacy)
        db.flush()
        execution = Execution(
            run_id=legacy.id,
            test_id="demo-shell",
            asset_id=scope["asset_id"],
            marker="legacy-fixture-" + uuid.uuid4().hex,
            state="COMPLETED",
            executed=True,
            synthetic=True,
        )
        db.add(execution)
        db.flush()
        db.add(
            ValidationResult(
                execution_id=execution.id,
                outcome="INCONCLUSIVE",
                reason="Synthetic historical fixture with unknown catalog context.",
                logic_version=scope["logic_version"],
                synthetic=True,
                collection_complete=False,
                telemetry_available=False,
                alerts_available=False,
            )
        )
        db.commit()
    params = {
        "requested_from": stamp.isoformat(),
        "requested_before": (stamp + timedelta(seconds=1)).isoformat(),
    }
    preview = admin.get("/api/v1/coverage", params=params).json()
    assert preview["total_runs"] == 1 and preview["outcomes"] == {"DETECTED": 1}
    options = admin.get("/api/v1/coverage/runs", params={**params, "limit": 1}).json()
    assert options["total"] == 1 and options["items"][0]["id"] == first["id"]
    assert options["scope_sha256"] == preview["scope_sha256"]
    listing = admin.get("/api/v1/reports", params=params).json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == first["id"]
    assert listing["selection"] == preview["selection"]
    params["expected_scope_sha256"] = preview["scope_sha256"]
    report = admin.get("/api/v1/coverage/report", params=params).json()
    assert report["integrity_sha256"] == digest(
        {k: v for k, v in report.items() if k != "integrity_sha256"}
    )
    assert report["metrics"]["selection"] == preview["selection"]
    assert report["metrics"]["members"][0]["run_id"] == first["id"]
    assert report["synthetic"] is True
    assert (
        admin.get(
            "/api/v1/coverage/report", params={**params, "expected_scope_sha256": "f" * 64}
        ).status_code
        == 409
    )
    legacy = admin.get("/api/v1/coverage?catalog_release=legacy").json()
    assert legacy["total_runs"] == legacy["unversioned_runs"] == 1
    assert legacy["evaluated_techniques"] is legacy["catalogued_techniques"] is None
    assert legacy["detected_percentage"] is None
    assert legacy["historical_evaluated_techniques"] == 1
    linux = admin.get("/api/v1/coverage?mode=linux").json()
    assert linux["total_runs"] == 0 and linux["synthetic"] is False


def repeated(admin):
    first = create_queued(admin, ["demo-shell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    second = admin.post(
        f"/api/v1/campaigns/{first['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    return first, second


def test_comparison_report_has_denominators_evidence_hashes_and_escaped_html(admin):
    first, second = repeated(admin)
    params = {"before": first["id"], "after": second["id"]}
    partial = admin.get("/api/v1/coverage/compare/report", params=params).json()
    assert not partial["comparison"]["comparable"]
    assert partial["summary"]["after"]["valid_tests"] == 0
    assert partial["summary"]["detected_rate_delta_percentage_points"] is None
    admin.post(
        f"/api/v1/executions/{second['id']}/approve",
        json={"confirm_scope_hash": second["scope_hash"]},
    )
    admin.post(f"/api/v1/executions/{second['id']}/start", json={"confirm": True})
    assert claim_next() == second["id"]
    process_run(second["id"])
    report = admin.get("/api/v1/coverage/compare/report", params=params).json()
    assert report["comparison"]["comparable"]
    assert report["summary"]["detected_rate_delta_percentage_points"] == 0
    assert report["summary"]["before"]["valid_tests"] == 1
    assert report["before"]["run"]["executions"][0]["evidence"]
    assert report["integrity_sha256"] == digest(
        {k: v for k, v in report.items() if k != "integrity_sha256"}
    )
    html = admin.get("/api/v1/coverage/compare/report", params={**params, "format": "html"})
    assert html.status_code == 200 and "attachment;" in html.headers["content-disposition"]
    assert (
        "SINTÉTICOS" in html.text and "Resumo executivo" in html.text and "<script" not in html.text
    )
    assert (
        admin.get(
            "/api/v1/coverage/compare", params={"before": first["id"], "after": first["id"]}
        ).status_code
        == 409
    )
    # Same historical pair remains stable; only export audit rows are appended.
    assert admin.get("/api/v1/coverage/compare/report", params=params).json() == report


def test_catalog_reference_changed_between_preview_and_export_is_conflict(catalog_client):
    client, engine, actor = catalog_client
    preview = client.get("/api/v1/coverage?catalog_release=current").json()
    publish(engine, actor)
    response = client.get(
        "/api/v1/coverage/report",
        params={"catalog_release": "current", "expected_scope_sha256": preview["scope_sha256"]},
    )
    assert response.status_code == 409


def test_exports_require_authentication_and_viewer_is_read_only(client):
    assert client.get("/api/v1/coverage/report").status_code == 401
    assert client.get("/api/v1/coverage/compare/report?before=a&after=b").status_code == 401
    result = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    )
    assert result.status_code == 200
    assert client.get("/api/v1/coverage/report").status_code == 200
    assert client.post("/api/v1/campaigns", json={}).status_code in (403, 422)


def test_completed_parent_with_failed_child_cannot_claim_valid_comparison(admin):
    first, second = repeated(admin)
    admin.post(
        f"/api/v1/executions/{second['id']}/approve",
        json={"confirm_scope_hash": second["scope_hash"]},
    )
    admin.post(f"/api/v1/executions/{second['id']}/start", json={"confirm": True})
    assert claim_next() == second["id"]
    process_run(second["id"])
    # Explicit corruption fixture; never rewrite real historical evidence.
    from sqlalchemy import select

    with session_factory()() as db:
        child = db.scalar(select(Execution).where(Execution.run_id == first["id"]))
        child.state = "FAILED"
        db.commit()
    params = {"before": first["id"], "after": second["id"]}
    result = admin.get("/api/v1/coverage/compare/report", params=params).json()
    assert not result["comparison"]["comparable"]
    assert "incomplete_test_executions" in result["comparison"]["comparability_reasons"]
    assert result["summary"]["before"]["outcomes"] == {"DETECTED": 1}
    assert result["summary"]["before"]["valid_tests"] == 0
    assert result["summary"]["before"]["detected_tests"] == 0
    assert result["summary"]["detected_rate_delta_percentage_points"] is None


def test_completed_child_without_validation_result_is_not_comparable(admin):
    first = create_queued(admin, ["demo-shell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    with session_factory()() as db:
        source = db.get(CampaignRun, first["id"])
        fixture = CampaignRun(
            campaign_id=source.campaign_id,
            laboratory_id=source.laboratory_id,
            requested_by=source.requested_by,
            idempotency_key=uuid.uuid4().hex,
            state="COMPLETED",
            scope=source.scope,
            scope_hash=source.scope_hash,
            synthetic=True,
            ended_at=now(),
        )
        db.add(fixture)
        db.flush()
        db.add(
            Execution(
                run_id=fixture.id,
                test_id="demo-shell",
                asset_id=source.scope["asset_id"],
                marker="missing-result-fixture-" + uuid.uuid4().hex,
                state="COMPLETED",
                executed=True,
                synthetic=True,
            )
        )
        fixture_id = fixture.id
        db.commit()
    report = admin.get(
        "/api/v1/coverage/compare/report", params={"before": first["id"], "after": fixture_id}
    ).json()
    assert not report["comparison"]["comparable"]
    assert "missing_validation_results" in report["comparison"]["comparability_reasons"]
    assert report["summary"]["after"]["valid_tests"] == 0
    assert report["summary"]["detected_rate_delta_percentage_points"] is None


def test_missing_planned_child_is_not_a_complete_comparative_scope(admin):
    first = create_queued(admin, ["demo-shell", "demo-powershell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    with session_factory()() as db:
        source = db.get(CampaignRun, first["id"])
        fixture = CampaignRun(
            campaign_id=source.campaign_id,
            laboratory_id=source.laboratory_id,
            requested_by=source.requested_by,
            idempotency_key=uuid.uuid4().hex,
            state="COMPLETED",
            scope=source.scope,
            scope_hash=source.scope_hash,
            synthetic=True,
            ended_at=now(),
        )
        db.add(fixture)
        db.flush()
        child = Execution(
            run_id=fixture.id,
            test_id="demo-shell",
            asset_id=source.scope["asset_id"],
            marker="missing-child-fixture-" + uuid.uuid4().hex,
            state="COMPLETED",
            executed=True,
            synthetic=True,
        )
        db.add(child)
        db.flush()
        db.add(
            ValidationResult(
                execution_id=child.id,
                outcome="INCONCLUSIVE",
                reason="Synthetic incomplete-manifest fixture.",
                logic_version=source.scope["logic_version"],
                synthetic=True,
                collection_complete=False,
                telemetry_available=False,
                alerts_available=False,
            )
        )
        fixture_id = fixture.id
        db.commit()
    result = admin.get(
        "/api/v1/coverage/compare/report", params={"before": first["id"], "after": fixture_id}
    ).json()
    assert not result["comparison"]["comparable"]
    assert "execution_manifest_mismatch" in result["comparison"]["comparability_reasons"]
