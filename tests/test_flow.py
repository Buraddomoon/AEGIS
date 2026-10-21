import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from aegis.db import session_factory
from aegis.models import Approval, CampaignRun, Laboratory, ValidationResult, now
from aegis.worker import claim_next, process_run, recover_abandoned
from conftest import create_queued
from sqlalchemy import func, select


def test_complete_demo_and_repeat_compare_report(admin):
    run = create_queued(admin)
    assert claim_next() == run["id"]
    assert claim_next() is None
    process_run(run["id"])
    process_run(run["id"])
    detail = admin.get("/api/v1/executions/" + run["id"]).json()
    assert detail["state"] == "COMPLETED", detail
    outcomes = {e["result"]["outcome"] for e in detail["executions"]}
    assert outcomes == {"DETECTED", "OBSERVED_NOT_ALERTED", "NO_TELEMETRY", "INCONCLUSIVE"}
    assert all(e["synthetic"] for e in detail["executions"])
    detected = next(e for e in detail["executions"] if e["result"]["outcome"] == "DETECTED")
    assert len(detected["evidence"]) == 1
    assert detected["events"][0]["sha256"]
    coverage = admin.get("/api/v1/coverage").json()
    assert coverage["valid_tests"] == 3
    assert coverage["detected_percentage"] == 33.3
    assert coverage["evaluated_techniques"] == 3
    linux_technique = admin.get("/api/v1/techniques/T1059.004?mode=linux").json()
    assert linux_technique["mode"] == "linux"
    assert linux_technique["coverage_history"] == linux_technique["tests"] == []
    assert admin.get("/api/v1/techniques/T1059.004?mode=demo").json()["coverage_history"]
    report = admin.get(f"/api/v1/reports/{run['id']}").json()
    assert report["synthetic"] and report["integrity_sha256"]
    from aegis.domain.validation import digest

    assert digest(report["run"]) == report["integrity_sha256"]
    html = admin.get(f"/api/v1/reports/{run['id']}?format=html")
    assert "EVIDÊNCIAS SINTÉTICAS" in html.text
    repeated = admin.post(
        f"/api/v1/campaigns/{run['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    assert (
        admin.post(
            f"/api/v1/executions/{repeated['id']}/approve",
            json={"confirm_scope_hash": repeated["scope_hash"]},
        ).status_code
        == 200
    )
    assert (
        admin.post(f"/api/v1/executions/{repeated['id']}/start", json={"confirm": True}).status_code
        == 200
    )
    assert claim_next() == repeated["id"]
    process_run(repeated["id"])
    comparison = admin.get(
        f"/api/v1/coverage/compare?before={run['id']}&after={repeated['id']}"
    ).json()
    assert comparison["comparable"]
    assert all(not t["changed"] for t in comparison["tests"])


def test_idempotent_start_and_request(admin):
    run = create_queued(admin, ["demo-shell"])
    assert (
        admin.post(f"/api/v1/executions/{run['id']}/start", json={"confirm": True}).status_code
        == 200
    )
    with session_factory()() as db:
        item = db.get(CampaignRun, run["id"])
        key = item.idempotency_key
    repeated = admin.post(
        f"/api/v1/campaigns/{run['campaign_id']}/runs", json={"idempotency_key": key}
    )
    assert repeated.json()["id"] == run["id"]
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 1


def test_concurrent_workers_only_one_claims(admin):
    run = create_queued(admin, ["demo-shell"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = list(pool.map(lambda _: claim_next(), range(2)))
    assert claimed.count(run["id"]) == 1
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: process_run(run["id"]), range(2)))
    with session_factory()() as db:
        assert db.get(CampaignRun, run["id"]).state == "COMPLETED"
        assert db.scalar(select(func.count()).select_from(ValidationResult)) == 1


def test_cancel_queued_releases_lab(admin):
    run = create_queued(admin)
    result = admin.post(f"/api/v1/executions/{run['id']}/cancel")
    assert result.json()["state"] == "CANCELLED"
    assert claim_next() is None
    with session_factory()() as db:
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id is None


def test_worker_revalidates_expiry(admin):
    run = create_queued(admin)
    with session_factory()() as db:
        approval = db.scalar(select(Approval).where(Approval.run_id == run["id"]))
        approval.expires_at = now() - timedelta(minutes=1)
        db.commit()
    assert claim_next() is None
    assert admin.get("/api/v1/executions/" + run["id"]).json()["state"] == "REJECTED"


def test_timeout_and_abandoned_recovery(admin):
    run = create_queued(admin)
    assert claim_next() == run["id"]
    with session_factory()() as db:
        entity = db.get(CampaignRun, run["id"])
        entity.deadline_at = now() - timedelta(seconds=60)
        entity.heartbeat_at = now() - timedelta(seconds=60)
        db.commit()
    assert recover_abandoned() == 1
    assert recover_abandoned() == 0
    assert admin.get("/api/v1/executions/" + run["id"]).json()["state"] == "TIMED_OUT"


def test_cancel_running_cleanup_and_failure(admin):
    from aegis.integrations.demo import DemoExecutionAdapter

    class CancellingAdapter(DemoExecutionAdapter):
        cleaned = False

        def execute(self, ctx):
            with session_factory()() as db:
                db.get(CampaignRun, run["id"]).cancel_requested = True
                db.commit()
            return True

        def cleanup(self, ctx):
            self.cleaned = True

    run = create_queued(admin, ["demo-shell"])
    assert claim_next() == run["id"]
    adapter = CancellingAdapter()
    process_run(run["id"], adapter)
    assert adapter.cleaned
    assert admin.get("/api/v1/executions/" + run["id"]).json()["state"] == "CANCELLED"


def test_cleanup_failure_visible_and_lab_reserved(admin):
    from aegis.integrations.demo import DemoExecutionAdapter

    class BrokenCleanup(DemoExecutionAdapter):
        def cleanup(self, ctx):
            raise RuntimeError("Injected cleanup failure")

    run = create_queued(admin, ["demo-shell"])
    assert claim_next() == run["id"]
    process_run(run["id"], BrokenCleanup())
    detail = admin.get("/api/v1/executions/" + run["id"]).json()
    assert detail["state"] == "CLEANUP_FAILED" and detail["error"]
    with session_factory()() as db:
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id == run["id"]
    assert (
        admin.post(
            f"/api/v1/labs/{run['laboratory_id']}/recover", json={"confirm": True}
        ).status_code
        == 200
    )
