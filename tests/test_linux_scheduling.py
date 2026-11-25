"""Real PostgreSQL with a local runner fixture; never operates a native Lab."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from aegis import linux_labs, scheduled_reports, scheduling
from aegis.config import settings
from aegis.db import session_factory
from aegis.models import (
    Approval,
    CampaignRun,
    Laboratory,
    LabVerification,
    RunnerCleanup,
    RunnerDispatch,
    RunnerReceipt,
    Schedule,
    ScheduleAuthorization,
    ScheduledReport,
    ScheduleOccurrence,
    User,
    now,
)
from aegis.worker import claim_next, process_run, recover_abandoned
from sqlalchemy import func, select
from test_linux_campaigns import linux as linux
from test_linux_campaigns import login
from test_scheduling import due, occurrences


@pytest.fixture
def enabled(linux, monkeypatch):
    monkeypatch.setattr(settings(), "linux_scheduling_enabled", True)
    return linux


def proposal(linux, *, requester="operator", confirm=True, expected=201):
    client, lab, _ = linux
    login(client, requester)
    campaign = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Recorrência Linux delimitada",
            "objective": "Fixture isolada; sem Lab nativo.",
            "laboratory_id": lab["id"],
            "test_ids": ["linux-file-marker-v1"],
        },
    )
    assert campaign.status_code == 201, campaign.text
    start = now() + timedelta(minutes=1)
    result = client.post(
        "/api/v1/schedules",
        json={
            "campaign_id": campaign.json()["id"],
            "starts_at": start.isoformat(),
            "ends_at": (start + timedelta(hours=1)).isoformat(),
            "interval_seconds": 60,
            "max_occurrences": 2,
            "max_duration_seconds": 30,
            "confirm_real_execution": confirm,
        },
    )
    assert result.status_code == expected, result.text
    return result.json()


def approve(linux, item, *, confirm=True, expected=200):
    client = linux[0]
    login(client, "administrator")
    result = client.post(
        f"/api/v1/schedules/{item['id']}/approve",
        json={
            "confirm_plan_hash": item["plan_hash"],
            "confirm_automatic_execution": True,
            "confirm_real_execution": confirm,
        },
    )
    assert result.status_code == expected, result.text


def ready(linux):
    item = proposal(linux)
    instant = due(item)
    item = linux[0].get("/api/v1/schedules/" + item["id"]).json()
    approve(linux, item)
    return item, instant


def emitted(linux):
    item, instant = ready(linux)
    assert scheduling.dispatch_one(instant)
    occurrence = occurrences(linux[0], item)[0]
    return item, instant, occurrence["run_id"]


def test_creation_requires_deployment_opt_in(linux):
    proposal(linux, expected=409)


def test_creation_requires_real_confirmation(enabled):
    proposal(enabled, confirm=False, expected=409)


def test_approval_requires_real_confirmation_and_different_administrator(enabled):
    item = proposal(enabled, requester="administrator")
    approve(enabled, item, expected=409)
    item = proposal(enabled)
    approve(enabled, item, confirm=False, expected=409)
    assert not occurrences(enabled[0], item)


def test_two_real_occurrences_use_exact_grant_receipts_cleanup_and_frozen_exports(enabled):
    client, lab, runner = enabled
    item, instant = ready(enabled)
    documents = []
    for offset in (0, 60):
        assert scheduling.dispatch_one(instant + timedelta(seconds=offset))
        occurrence = occurrences(client, item)[0]
        run_id = occurrence["run_id"]
        assert claim_next() == run_id
        process_run(run_id)
        detail = client.get("/api/v1/executions/" + run_id).json()
        assert detail["state"] == "COMPLETED", detail
        assert detail["synthetic"] is False
        assert detail["executions"][0]["result"]["outcome"] == "INCONCLUSIVE"
        assert scheduled_reports.process_one()
        listing = client.get(f"/api/v1/schedules/{item['id']}/reports").json()["items"]
        report = next(r for r in listing if r["run_id"] == run_id)
        assert report["synthetic"] is False and report["state"] == "READY"
        path = f"/api/v1/schedules/{item['id']}/reports/{report['id']}"
        document = client.get(path).json()
        assert document["synthetic"] is False
        assert document["automation"]["policy_version"] == "scheduled-linux-report/1"
        assert document["summary"].get("detected_percentage") is None
        for format in ("html", "pdf"):
            response = client.get(
                path + f"?format={format}&expected_sha256={report['document_sha256']}"
            )
            assert response.status_code == 200 and response.content
        documents.append((path, document))
        with session_factory()() as db:
            for model in (RunnerDispatch, RunnerReceipt, RunnerCleanup):
                assert db.scalar(select(func.count()).select_from(model)) == offset // 60 + 1
            assert db.get(Laboratory, lab["id"]).active_run_id is None
        assert not list(runner.workspace.root.iterdir())
    assert not scheduling.dispatch_one(instant + timedelta(seconds=120))
    for path, document in documents:
        assert client.get(path).json() == document


@pytest.mark.parametrize(
    "change",
    ["preflight", "lab", "environment", "creator", "approver", "role", "grant", "config", "opt_in"],
)
def test_each_occurrence_revalidates_trust_and_users_before_any_dispatch(
    enabled, monkeypatch, change
):
    item, instant = ready(enabled)
    if change == "opt_in":
        monkeypatch.setattr(settings(), "linux_scheduling_enabled", False)
    elif change == "config":
        path = settings().linux_runner_config
        original = json.loads(path.read_text())
        original["url"] = "https://192.168.253.6:8443"
        path.write_text(json.dumps(original))
    else:
        with session_factory()() as db:
            grant = db.scalar(
                select(ScheduleAuthorization).where(ScheduleAuthorization.schedule_id == item["id"])
            )
            if change == "preflight":
                db.scalar(select(LabVerification)).expires_at = now() - timedelta(seconds=1)
            elif change == "lab":
                db.get(Laboratory, item["laboratory_id"]).authorized = False
            elif change == "environment":
                db.get(Laboratory, item["laboratory_id"]).environment_version += 1
            elif change == "creator":
                db.get(User, item["created_by"]).active = False
            elif change == "approver":
                db.get(User, grant.approved_by).active = False
            elif change == "role":
                db.get(User, grant.approved_by).role = "operator"
            else:
                grant.revoked_at = now()
            db.commit()
    assert scheduling.dispatch_one(instant)
    with session_factory()() as db:
        assert db.get(Schedule, item["id"]).state == "INVALIDATED"
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 0
        assert db.scalar(select(func.count()).select_from(RunnerDispatch)) == 0


def test_competing_real_dispatchers_emit_once(enabled):
    item, instant = ready(enabled)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: scheduling.dispatch_one(instant), range(2)))
    assert len(occurrences(enabled[0], item)) == 1


def test_concurrent_identity_revocation_is_rechecked_after_writer_commits(enabled):
    item, instant = ready(enabled)
    entered = threading.Event()
    with session_factory()() as writer:
        creator = writer.scalar(select(User).where(User.id == item["created_by"]).with_for_update())
        creator.active = False
        writer.flush()

        def tick():
            entered.set()
            return scheduling.dispatch_one(instant)

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(tick)
            assert entered.wait(timeout=5)
            assert not pending.done()
            writer.commit()
            assert pending.result(timeout=10)
    with session_factory()() as db:
        assert db.get(Schedule, item["id"]).state == "INVALIDATED"
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 0


def test_revocation_after_real_start_still_confirms_cleanup(enabled, monkeypatch):
    item, _, run_id = emitted(enabled)
    factory = linux_labs.client

    def revoking_client():
        remote = factory()
        action = remote.action

        def revoke(view, operation):
            result = action(view, operation)
            if operation == "start":
                response = enabled[0].post(
                    f"/api/v1/schedules/{item['id']}/revoke", json={"confirm": True}
                )
                assert response.status_code == 200, response.text
            return result

        remote.action = revoke
        return remote

    monkeypatch.setattr(linux_labs, "client", revoking_client)
    assert claim_next() == run_id
    process_run(run_id)
    with session_factory()() as db:
        assert db.get(CampaignRun, run_id).state == "CANCELLED"
        assert db.scalar(select(RunnerCleanup)) is not None
        assert db.get(Laboratory, item["laboratory_id"]).active_run_id is None


def test_pause_reapproval_preserves_budget_and_does_not_revive_old_run(enabled):
    item, instant, run_id = emitted(enabled)
    client = enabled[0]
    assert (
        client.post(f"/api/v1/schedules/{item['id']}/pause", json={"confirm": True}).status_code
        == 200
    )
    approve(enabled, item)
    assert claim_next() is None
    with session_factory()() as db:
        run = db.get(CampaignRun, run_id)
        approval = db.scalar(select(Approval).where(Approval.run_id == run_id))
        assert not scheduling.authorization_valid(db, run, approval)
    assert scheduling.dispatch_one(instant + timedelta(seconds=60))
    rows = occurrences(client, item)
    assert len(rows) == 2 and rows[0]["authorization_id"] != rows[1]["authorization_id"]


def test_lost_start_response_retains_reservation_and_next_slot_cannot_replay(enabled, monkeypatch):
    item, instant, run_id = emitted(enabled)
    factory = linux_labs.client

    def broken_client():
        remote = factory()
        action = remote.action

        def lost(view, operation):
            if operation == "start":
                action(view, operation)
                raise TimeoutError("fixture: response lost after effect")
            if operation == "cleanup":
                raise TimeoutError("fixture: cleanup unavailable")
            return action(view, operation)

        remote.action = lost
        return remote

    monkeypatch.setattr(linux_labs, "client", broken_client)
    assert claim_next() == run_id
    process_run(run_id)
    with session_factory()() as db:
        assert db.get(CampaignRun, run_id).state == "CLEANUP_FAILED"
        assert db.get(Laboratory, item["laboratory_id"]).active_run_id == run_id
    assert scheduling.dispatch_one(instant + timedelta(seconds=60))
    assert occurrences(enabled[0], item)[0]["status"] == "SKIPPED_BUSY"
    assert claim_next() is None
    assert recover_abandoned() == 0
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(RunnerDispatch)) == 1


def test_failure_before_enqueue_commit_rolls_back_occurrence_and_report(enabled, monkeypatch):
    item, instant = ready(enabled)

    def broken(*args):
        raise RuntimeError("fixture before transaction commit")

    monkeypatch.setattr(scheduled_reports, "request_report", broken)
    with pytest.raises(RuntimeError):
        scheduling.dispatch_one(instant)
    with session_factory()() as db:
        for model in (CampaignRun, Approval, ScheduleOccurrence, ScheduledReport, RunnerDispatch):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.get(Laboratory, item["laboratory_id"]).active_run_id is None
