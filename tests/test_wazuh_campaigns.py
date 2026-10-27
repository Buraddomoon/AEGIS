"""Worker/API integration against a local HTTP contract fixture, never an external SIEM."""

import json

import httpx
import pytest
from aegis import telemetry
from aegis.config import settings
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.integrations.wazuh import WazuhIndexerProvider
from aegis.integrations.wazuh_config import WazuhCollectionConfig
from aegis.models import Approval, Asset, CampaignRun, Laboratory, TelemetryCollection, uid
from aegis.models import TestExecution as Execution
from aegis.worker import claim_next, context_for, process_run
from sqlalchemy import func, select
from test_linux_campaigns import linux as linux
from test_linux_campaigns import login, queued, requested
from test_wazuh_collection import hit, response


@pytest.fixture
def wazuh(linux, tmp_path, monkeypatch):
    client, lab, runner = linux
    login(client, "administrator")
    client.patch(
        f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": False}
    ).raise_for_status()
    cfg = WazuhCollectionConfig(
        laboratory_id=lab["id"],
        asset_id=runner.identity.asset_id,
        agent_id="007",
        expected_rule="100200",
        archives_index="wazuh-archives-4.x-*",
        ingestion_window_seconds=1,
        ingestion_wait_seconds=1,
        poll_interval_seconds=0.1,
    )
    path = tmp_path / "wazuh-policy.json"
    path.write_text(cfg.model_dump_json())
    for name, value in {
        "wazuh_collection_config": path,
        "wazuh_url": "https://indexer.fixture:9200",
        "wazuh_username": "fixture-readonly",
        "wazuh_password": "fixture-only-not-a-real-secret",
        "wazuh_allowed_ip": "192.0.2.10",
        "wazuh_ca_bundle": None,
    }.items():
        monkeypatch.setattr(settings(), name, value)
    reviewed = client.put(
        f"/api/v1/labs/{lab['id']}/wazuh-binding",
        json={
            "review": "Mapeamento e regra de fixture revisados, sem acesso externo ou instalação Wazuh.",
            "confirm_read_only_scope": True,
        },
    )
    assert reviewed.status_code == 200, reviewed.text
    client.post(f"/api/v1/labs/{lab['id']}/preflight", json={"confirm": True}).raise_for_status()
    client.patch(
        f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": True}
    ).raise_for_status()
    scenario = {"outcome": "DETECTED", "calls": 0}

    def handle(request):
        scenario["calls"] += 1
        with session_factory()() as db:
            execution = db.scalar(select(Execution).order_by(Execution.created_at.desc()).limit(1))
            run = db.get(CampaignRun, execution.run_id)
            ctx = context_for(run, execution, run.scope["test_definitions"][0])
        archive = "archives" in request.url.path
        mode = scenario["outcome"]
        if mode == "INCONCLUSIVE":
            return httpx.Response(503, json={"error": "fixture-unavailable"})
        documents = []
        if mode == "DETECTED" or (mode == "OBSERVED_NOT_ALERTED" and archive):
            documents = [hit(ctx, "telemetry" if archive else "alert")]
        if mode == "WRONG_AGENT":
            documents = [hit(ctx)]
            documents[0]["_source"]["agent"]["id"] = ctx.asset_id
        return httpx.Response(200, json=response(documents))

    monkeypatch.setattr(
        telemetry,
        "configured_provider",
        lambda policy: WazuhIndexerProvider(
            "https://indexer.fixture:9200",
            "fixture",
            "fixture-password",
            "192.0.2.10",
            policy=policy,
            transport=httpx.MockTransport(handle),
        ),
    )
    return linux, path, scenario


@pytest.mark.parametrize(
    "outcome", ["DETECTED", "OBSERVED_NOT_ALERTED", "NO_TELEMETRY", "INCONCLUSIVE", "WRONG_AGENT"]
)
def test_worker_collects_validates_persists_and_reports_contract_evidence(wazuh, outcome):
    linux, path, scenario = wazuh
    scenario["outcome"] = outcome
    client = linux[0]
    run = queued(linux)
    assert run["scope"]["telemetry"]["provider"] == "wazuh-indexer"
    assert run["scope"]["test_definitions"][0]["expected_rule"] == "100200"
    assert "fixture-only-not-a-real-secret" not in json.dumps(run)
    assert claim_next() == run["id"]
    process_run(run["id"])
    detail = client.get("/api/v1/executions/" + run["id"]).json()
    assert detail["state"] == "COMPLETED", detail
    execution = detail["executions"][0]
    expected = "INCONCLUSIVE" if outcome == "WRONG_AGENT" else outcome
    assert execution["result"]["outcome"] == expected
    assert execution["collection"]["provider"] == "wazuh-indexer"
    assert execution["collection"]["attempts"] >= 1
    assert execution["runner_receipt"] and execution["runner_cleanup"]
    assert not execution["synthetic"]
    if outcome == "DETECTED":
        assert (
            execution["evidence"]
            and execution["events"][0]["raw"]["_source"]["agent"]["id"] == "007"
        )
    else:
        assert all(event["kind"] != "alert" for event in execution["events"])
    report = client.get(f"/api/v1/reports/{run['id']}").json()
    assert "SIEM não consultado" not in " ".join(report["limitations"])
    assert "pipeline" in " ".join(report["limitations"])
    assert "fixture-only-not-a-real-secret" not in json.dumps(report)
    assert client.get("/api/v1/coverage?mode=demo").json()["completed_tests"] == 0
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(TelemetryCollection)) == 1
        assert db.get(Laboratory, linux[1]["id"]).active_run_id is None


def test_changed_policy_after_queue_never_queries_or_executes(wazuh):
    linux, path, scenario = wazuh
    run = queued(linux)
    value = json.loads(path.read_text())
    value["agent_id"] = "008"
    path.write_text(json.dumps(value))
    assert claim_next() is None
    assert linux[0].get("/api/v1/executions/" + run["id"]).json()["state"] == "REJECTED"
    assert scenario["calls"] == 0


def test_binding_requires_administrator_revoked_lab_and_explicit_confirmation(wazuh):
    linux, _, scenario = wazuh
    client, lab, _ = linux
    payload = {"review": "Valid review with sufficient detail.", "confirm_read_only_scope": True}
    assert client.put(f"/api/v1/labs/{lab['id']}/wazuh-binding", json=payload).status_code == 409
    login(client, "operator")
    assert client.put(f"/api/v1/labs/{lab['id']}/wazuh-binding", json=payload).status_code == 403
    login(client, "administrator")
    client.patch(f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": False})
    assert (
        client.put(
            f"/api/v1/labs/{lab['id']}/wazuh-binding",
            json={"review": payload["review"], "confirm_read_only_scope": False},
        ).status_code
        == 422
    )
    assert (
        client.put(
            f"/api/v1/labs/{lab['id']}/wazuh-binding", json={**payload, "url": "https://untrusted"}
        ).status_code
        == 422
    )
    assert scenario["calls"] == 0


def test_old_approved_correlation_version_is_rejected_after_upgrade(linux):
    run = queued(linux)
    with session_factory()() as db:
        stored = db.get(CampaignRun, run["id"])
        stored.scope = {**stored.scope, "logic_version": "aegis-correlation/1.0"}
        stored.scope_hash = digest(stored.scope)
        db.scalar(
            select(Approval).where(Approval.run_id == stored.id)
        ).scope_hash = stored.scope_hash
        db.commit()
    assert claim_next() is None
    assert linux[0].get("/api/v1/executions/" + run["id"]).json()["state"] == "REJECTED"


def test_binding_removal_requires_no_reservation_and_preserves_historical_scope(wazuh):
    linux, _, _ = wazuh
    client, lab, _ = linux
    run = requested(linux)
    login(client, "administrator")
    client.patch(f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": False})
    result = client.post(f"/api/v1/labs/{lab['id']}/wazuh-binding/remove", json={"confirm": True})
    assert result.status_code == 409  # An unreserved pending request still blocks review.
    cancelled = client.post(f"/api/v1/executions/{run['id']}/cancel", json={"confirm": True})
    assert cancelled.status_code == 200, cancelled.text
    result = client.post(f"/api/v1/labs/{lab['id']}/wazuh-binding/remove", json={"confirm": True})
    assert result.status_code == 200
    assert result.json()["status"] == "unbound"
    historical = client.get("/api/v1/executions/" + run["id"]).json()
    assert historical["scope"]["telemetry"] == run["scope"]["telemetry"]


def test_duplicate_agent_binding_conflicts_without_changing_environment(wazuh):
    linux, path, scenario = wazuh
    client = linux[0]
    with session_factory()() as db:
        other = Laboratory(
            name="Other authorized-scope fixture",
            description="Fixture only",
            kind="linux",
            owner="Fixture",
            isolation="Isolated fixture",
            authorized=False,
        )
        db.add(other)
        db.flush()
        asset = Asset(
            laboratory_id=other.id,
            name="Other endpoint fixture",
            platform="Linux",
            external_id=uid(),
            synthetic=False,
        )
        db.add(asset)
        db.commit()
        lab_id, asset_id, version = other.id, asset.id, other.environment_version
    value = json.loads(path.read_text())
    value.update({"laboratory_id": lab_id, "asset_id": asset_id})
    path.write_text(json.dumps(value))
    result = client.put(
        f"/api/v1/labs/{lab_id}/wazuh-binding",
        json={
            "review": "Duplicate external agent must not silently move to another scope.",
            "confirm_read_only_scope": True,
        },
    )
    assert result.status_code == 409
    with session_factory()() as db:
        assert db.get(Laboratory, lab_id).environment_version == version
    assert scenario["calls"] == 0
