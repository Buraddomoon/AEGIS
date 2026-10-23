"""API/worker catalog transitions use isolated synthetic 19.2 -> reduced20.0 data."""

import secrets
import threading
import uuid

import pytest
from aegis import services, worker
from aegis.domain.validation import digest
from aegis.main import create_app
from aegis.models import (
    Approval,
    Asset,
    Campaign,
    CampaignRun,
    CampaignTest,
    Laboratory,
    User,
    ValidationResult,
    now,
)
from aegis.models import (
    TestExecution as Execution,
)
from aegis.security import hasher, redis_client, token_hash
from conftest import create_queued
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from test_attack_publication import catalog_db as _catalog_db
from test_attack_publication import publish

catalog_db = _catalog_db


@pytest.fixture
def catalog_client(catalog_db, monkeypatch):
    engine, actor = catalog_db
    username = "catalog-api-" + uuid.uuid4().hex
    password = secrets.token_urlsafe(32)
    peer = "catalog-peer-" + uuid.uuid4().hex
    with Session(engine) as db:
        user = db.get(User, actor)
        user.username = username
        user.password_hash = hasher.hash(password)
        db.commit()
    monkeypatch.setattr(worker, "stop", threading.Event())
    with TestClient(create_app(), client=(peer, 1234)) as client:
        auth = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
            headers={"x-aegis-request": "browser"},
        )
        assert auth.status_code == 200, auth.text
        client.headers["x-csrf-token"] = auth.json()["csrf_token"]
        yield client, engine, actor
    redis_client().delete(
        "aegis:limit:" + token_hash("login-ip:" + peer),
        "aegis:limit:" + token_hash("login-account:" + username),
    )


def finish(run_id):
    assert worker.claim_next() == run_id
    worker.process_run(run_id)


def test_new_release_preserves_reports_and_separates_current_coverage(catalog_client):
    client, engine, actor = catalog_client
    first = create_queued(client, ["demo-powershell"])
    finish(first["id"])
    before = client.get("/api/v1/reports/" + first["id"]).json()
    assert before["run"]["scope"]["attack_catalog"]["version"] == "19.2"
    assert before["run"]["scope"]["attack_techniques"][0]["id"] == "T1059.001"
    assert client.get("/api/v1/coverage").json()["evaluated_techniques"] == 1
    publish(engine, actor)
    assert client.get("/api/v1/reports/" + first["id"]).json() == before
    html = client.get("/api/v1/reports/" + first["id"] + "?format=html").text
    assert "Enterprise v19.2" in html
    coverage = client.get("/api/v1/coverage").json()
    assert (
        coverage["evaluated_techniques"] == 0 and coverage["historical_evaluated_techniques"] == 1
    )
    assert coverage["valid_tests"] == 1 and coverage["catalogued_techniques"] == 3
    listed = client.get("/api/v1/techniques?q=T1059.001").json()["items"][0]
    assert listed["coverage"] == "NOT_TESTED"
    second = client.post(
        f"/api/v1/campaigns/{first['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    assert second["scope"]["attack_catalog"]["version"] == "20.0"
    assert (
        client.post(
            "/api/v1/executions/" + second["id"] + "/start", json={"confirm": True}
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/v1/executions/" + second["id"] + "/approve",
            json={"confirm_scope_hash": second["scope_hash"]},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/executions/" + second["id"] + "/start", json={"confirm": True}
        ).status_code
        == 200
    )
    finish(second["id"])
    assert client.get("/api/v1/coverage").json()["evaluated_techniques"] == 1
    history = client.get("/api/v1/techniques/T1059.001").json()["coverage_history"]
    assert {h["catalog_version"] for h in history} == {"19.2", "20.0"}
    assert all(
        h["catalog_scope_recorded"] and h["technique_snapshot"]["id"] == "T1059.001"
        for h in history
    )
    comparison = client.get(
        f"/api/v1/coverage/compare?before={first['id']}&after={second['id']}"
    ).json()
    assert not comparison["comparable"] and comparison["scope_changes"]["catalog_context_recorded"]
    assert "attack_catalog" in {row["key"] for row in comparison["scope_changes"]["environment"]}


def test_retired_or_absent_technique_cannot_enter_new_scope(catalog_client):
    client, engine, actor = catalog_client
    publish(engine, actor)
    detail = client.get("/api/v1/techniques/T1059.004").json()
    assert detail["catalog_status"] == "absent" and detail["dataset_version"] == "19.2"
    assert not detail["revoked"] and not detail["deprecated"]
    tests = client.get("/api/v1/tests").json()["items"]
    shell = next(t for t in tests if t["id"] == "demo-shell")
    assert shell["approved"] is True and shell["available_for_new_scope"] is False
    lab = client.get("/api/v1/labs").json()["items"][0]
    campaign = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Retired mapping fixture",
            "objective": "Must refuse new scope.",
            "laboratory_id": lab["id"],
            "test_ids": ["demo-shell"],
        },
    )
    # Creation itself validates the scope, not just the eventual worker.
    assert campaign.status_code == 409 and "retirada ou ausente" in campaign.text


def test_lifecycle_release_history_and_pagination_binding(catalog_client):
    client, engine, actor = catalog_client
    initial = client.get("/api/v1/techniques?limit=1").json()
    old_id = initial["catalog_release_id"]
    publish(engine, actor)
    assert client.get("/api/v1/techniques?offset=1&catalog_release_id=" + old_id).status_code == 409
    assert (
        client.get("/api/v1/techniques/T1059.001?catalog_release_id=" + old_id).status_code == 409
    )
    status = client.get("/api/v1/catalog/attack").json()
    assert status["counts"] == {"active": 3, "revoked": 1, "deprecated": 1, "absent": 703}
    assert status["current"]["source_commit"] == "a" * 40
    for lifecycle, technique in [("revoked", "T1066"), ("deprecated", "T1153")]:
        page = client.get("/api/v1/techniques?lifecycle=" + lifecycle).json()
        assert len(page["items"]) == 1 and page["items"][0]["id"] == technique
        assert page["items"][0]["coverage_applicable"] is False
        assert (
            client.get("/api/v1/techniques?lifecycle=" + lifecycle + "&coverage=NOT_TESTED").json()[
                "total"
            ]
            == 0
        )
    snapshots = client.get("/api/v1/catalog/attack/releases").json()
    assert snapshots["total"] == 2 and all("document" not in r for r in snapshots["items"])
    previous = client.get(
        "/api/v1/catalog/attack/releases/" + old_id + "/techniques?q=T1059.004"
    ).json()
    assert previous["items"][0]["dataset_version"] == "19.2"
    assert previous["release"]["provenance"] == "bundled"


def test_legacy_scope_is_visible_without_fabricated_version(catalog_client):
    client, engine, actor = catalog_client
    # Construct a labelled historical fixture. Never rewrite a persisted scope.
    with Session(engine) as db:
        lab = db.scalar(select(Laboratory))
        asset = db.scalar(select(Asset))
        campaign = Campaign(
            name="Synthetic legacy history",
            objective="Unknown catalog context fixture",
            laboratory_id=lab.id,
            created_by=actor,
        )
        db.add(campaign)
        db.flush()
        db.add(CampaignTest(campaign_id=campaign.id, test_id="demo-process-discovery"))
        db.flush()
        scope = services.snapshot_scope(db, campaign)
        scope.pop("attack_catalog")
        scope.pop("attack_techniques")
        run = CampaignRun(
            campaign_id=campaign.id,
            laboratory_id=lab.id,
            requested_by=actor,
            idempotency_key="legacy-fixture-unknown",
            state="COMPLETED",
            scope=scope,
            scope_hash=digest(scope),
            synthetic=True,
            started_at=now(),
            ended_at=now(),
        )
        db.add(run)
        db.flush()
        execution = Execution(
            run_id=run.id,
            test_id="demo-process-discovery",
            asset_id=asset.id,
            state="COMPLETED",
            marker="synthetic-legacy-" + uuid.uuid4().hex,
            synthetic=True,
            executed=True,
            started_at=now(),
            ended_at=now(),
        )
        db.add(execution)
        db.flush()
        db.add(
            ValidationResult(
                execution_id=execution.id,
                outcome="INCONCLUSIVE",
                reason="Synthetic legacy fixture; unavailable collection.",
                logic_version="aegis-correlation/1.1",
                synthetic=True,
                collection_complete=False,
                telemetry_available=False,
                alerts_available=False,
            )
        )
        db.commit()
        identifier = run.id
    history = client.get("/api/v1/techniques/T1057").json()["coverage_history"]
    assert history[0]["catalog_scope_recorded"] is False and history[0]["catalog_version"] is None
    coverage = client.get("/api/v1/coverage").json()
    assert (
        coverage["evaluated_techniques"] == 0 and coverage["historical_evaluated_techniques"] == 1
    )
    assert "não registrada" in client.get("/api/v1/reports/" + identifier + "?format=html").text


def test_unknown_catalog_scope_cannot_be_claimed_after_upgrade(catalog_client):
    client, engine, _ = catalog_client
    run = create_queued(client, ["demo-powershell"])
    # Migration/old-worker input fixture, before any adapter effect.
    with Session(engine) as db:
        item = db.get(CampaignRun, run["id"])
        scope = {
            k: v for k, v in item.scope.items() if k not in ("attack_catalog", "attack_techniques")
        }
        item.scope = scope
        item.scope_hash = digest(scope)
        db.scalar(select(Approval).where(Approval.run_id == item.id)).scope_hash = item.scope_hash
        db.commit()
    assert worker.claim_next() is None
    with Session(engine) as db:
        assert db.get(CampaignRun, run["id"]).state == "REJECTED"
        assert db.scalar(select(func.count()).select_from(ValidationResult)) == 0


def test_catalog_endpoints_are_authenticated_and_read_only(catalog_client):
    client, engine, actor = catalog_client
    with Session(engine) as db:
        db.get(User, actor).role = "viewer"
        db.commit()
    assert client.get("/api/v1/catalog/attack").status_code == 200
    assert client.get("/api/v1/catalog/attack/releases").status_code == 200
    assert client.post("/api/v1/catalog/attack", json={}).status_code == 405
    with TestClient(create_app()) as unauthenticated:
        assert unauthenticated.get("/api/v1/catalog/attack").status_code == 401
