import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from aegis import scheduling
from aegis.db import session_factory
from aegis.models import (
    Approval,
    CampaignRun,
    Laboratory,
    Schedule,
    ScheduleAuthorization,
    ScheduleOccurrence,
    User,
    now,
)
from aegis.worker import Interrupted, claim_next, guard, process_run
from conftest import create_queued
from sqlalchemy import func, select


def proposal(admin, expected_status=201, **overrides):
    lab = admin.get("/api/v1/labs").json()["items"][0]
    campaign = admin.post(
        "/api/v1/campaigns",
        json={
            "name": "Campanha recorrente",
            "objective": "Validar evidências sintéticas recorrentes.",
            "laboratory_id": lab["id"],
            "test_ids": ["demo-shell"],
        },
    ).json()
    starts = now() + timedelta(minutes=1)
    data = dict(
        campaign_id=campaign["id"],
        starts_at=starts.isoformat(),
        ends_at=(starts + timedelta(hours=1)).isoformat(),
        interval_seconds=60,
        max_occurrences=2,
        max_duration_seconds=30,
    )
    data.update(overrides)
    response = admin.post("/api/v1/schedules", json=data)
    assert response.status_code == expected_status, response.text
    return response.json(), starts


def approve(admin, item):
    response = admin.post(
        f"/api/v1/schedules/{item['id']}/approve",
        json={
            "confirm_plan_hash": item["plan_hash"],
            "confirm_automatic_execution": True,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def due(item):
    # Bring an immutable future plan into the actual present without sleeping in tests.
    with session_factory()() as db:
        schedule = db.get(Schedule, item["id"])
        schedule.starts_at = schedule.next_due_at = now() - timedelta(milliseconds=10)
        schedule.plan_hash = scheduling.digest(scheduling.plan(schedule))
        db.commit()
        return schedule.starts_at


def ready(admin, **overrides):
    item, _ = proposal(admin, **overrides)
    instant = due(item)
    item = admin.get("/api/v1/schedules/" + item["id"]).json()
    approve(admin, item)
    return item, instant


def occurrences(admin, item):
    return admin.get(f"/api/v1/schedules/{item['id']}/occurrences").json()["items"]


def test_pending_never_emits_and_hash_confirmation_required(admin):
    item, _ = proposal(admin)
    instant = due(item)
    assert scheduling.dispatch_one(instant) is False
    wrong = admin.post(
        f"/api/v1/schedules/{item['id']}/approve",
        json={
            "confirm_plan_hash": "0" * 64,
            "confirm_automatic_execution": True,
        },
    )
    assert wrong.status_code == 409
    assert not occurrences(admin, item)


def test_schedule_full_flow_exact_grant_report_and_budget(admin):
    item, instant = ready(admin, max_occurrences=1)
    assert scheduling.dispatch_one(instant)
    assert not scheduling.dispatch_one(instant)
    occurrence = occurrences(admin, item)[0]
    assert occurrence["status"] == "QUEUED"
    run_id = occurrence["run_id"]
    detail = admin.get("/api/v1/executions/" + run_id).json()
    assert detail["schedule_id"] == item["id"]
    assert detail["approval"]["schedule_authorization_id"] == occurrence["authorization_id"]
    assert detail["schedule_occurrence"]["id"] == occurrence["id"]
    assert claim_next() == run_id
    process_run(run_id)
    report = admin.get("/api/v1/reports/" + run_id).json()
    assert report["run"]["state"] == "COMPLETED"
    assert report["run"]["executions"][0]["result"]["outcome"] == "DETECTED"
    assert report["run"]["synthetic"]
    assert admin.get("/api/v1/schedules/" + item["id"]).json()["state"] == "EXHAUSTED"


def test_concurrent_dispatchers_emit_once(admin):
    item, instant = ready(admin)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: scheduling.dispatch_one(instant), range(2)))
    assert len(occurrences(admin, item)) == 1
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 1
        assert db.get(Schedule, item["id"]).occurrences_count == 1


def test_busy_slot_rolls_back_run_and_consumes_budget(admin):
    manual = create_queued(admin, ["demo-shell"])
    item, instant = ready(admin)
    assert scheduling.dispatch_one(instant)
    assert occurrences(admin, item)[0]["status"] == "SKIPPED_BUSY"
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 1
        assert db.scalar(select(func.count()).select_from(Approval)) == 1
        assert db.get(Laboratory, manual["laboratory_id"]).active_run_id == manual["id"]


def test_late_slots_do_not_backfill_and_exhaust_at_budget(admin):
    item, instant = ready(admin)
    assert scheduling.dispatch_one(instant + timedelta(minutes=5))
    assert scheduling.dispatch_one(instant + timedelta(minutes=5))
    assert not scheduling.dispatch_one(instant + timedelta(minutes=5))
    assert all(
        o["status"] == "SKIPPED_LATE" and o["run_id"] is None for o in occurrences(admin, item)
    )
    detail = admin.get("/api/v1/schedules/" + item["id"]).json()
    assert detail["occurrences_count"] == 2 and detail["state"] == "EXHAUSTED"


def test_pause_cancels_queue_and_resume_never_resurrects_old_grant(admin):
    item, instant = ready(admin)
    scheduling.dispatch_one(instant)
    first = occurrences(admin, item)[0]
    paused = admin.post(f"/api/v1/schedules/{item['id']}/pause", json={"confirm": True})
    assert paused.status_code == 200, paused.text
    assert claim_next() is None
    assert admin.get("/api/v1/executions/" + first["run_id"]).json()["state"] == "CANCELLED"
    approve(admin, item)
    assert scheduling.dispatch_one(instant + timedelta(seconds=60))
    second = occurrences(admin, item)[0]
    assert second["authorization_id"] != first["authorization_id"]
    with session_factory()() as db:
        old_run = db.get(CampaignRun, first["run_id"])
        old_approval = db.scalar(select(Approval).where(Approval.run_id == old_run.id))
        assert not scheduling.authorization_valid(db, old_run, old_approval)
        assert db.get(Schedule, item["id"]).occurrences_count == 2


@pytest.mark.parametrize(
    "change", ["approver_inactive", "approver_role", "creator_inactive", "environment", "scope"]
)
def test_changed_authorization_or_scope_invalidates_schedule(admin, change):
    item, instant = ready(admin)
    with session_factory()() as db:
        schedule = db.get(Schedule, item["id"])
        grant = db.scalar(
            select(ScheduleAuthorization).where(ScheduleAuthorization.schedule_id == item["id"])
        )
        if change == "approver_inactive":
            db.get(User, grant.approved_by).active = False
        elif change == "creator_inactive":
            db.get(User, schedule.created_by).active = False
        elif change == "approver_role":
            db.get(User, grant.approved_by).role = "operator"
        elif change == "environment":
            db.get(Laboratory, schedule.laboratory_id).environment_version += 1
        else:
            schedule.scope_hash = "0" * 64
        db.commit()
    scheduling.dispatch_one(instant)
    with session_factory()() as db:
        assert db.get(Schedule, item["id"]).state == "INVALIDATED"
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 0


def test_dispatch_failure_rolls_back_all_partial_effects(admin, monkeypatch):
    item, instant = ready(admin)
    original = scheduling.services.start_run

    def broken(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("after reservation before commit")

    monkeypatch.setattr(scheduling.services, "start_run", broken)
    with pytest.raises(RuntimeError):
        scheduling.dispatch_one(instant)
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(CampaignRun)) == 0
        assert db.scalar(select(func.count()).select_from(Approval)) == 0
        assert db.scalar(select(func.count()).select_from(ScheduleOccurrence)) == 0
        assert db.get(Schedule, item["id"]).occurrences_count == 0
        assert db.get(Laboratory, item["laboratory_id"]).active_run_id is None
    monkeypatch.setattr(scheduling.services, "start_run", original)
    assert scheduling.dispatch_one(instant)


def test_revocation_during_active_run_still_cleans_context(admin):
    from aegis.integrations.demo import DemoExecutionAdapter

    item, instant = ready(admin)
    scheduling.dispatch_one(instant)
    run_id = occurrences(admin, item)[0]["run_id"]
    assert claim_next() == run_id

    class Revoking(DemoExecutionAdapter):
        cleaned = False

        def execute(self, ctx):
            assert (
                admin.post(
                    f"/api/v1/schedules/{item['id']}/revoke", json={"confirm": True}
                ).status_code
                == 200
            )
            return True

        def cleanup(self, ctx):
            self.cleaned = True

    adapter = Revoking()
    process_run(run_id, adapter)
    assert adapter.cleaned
    assert admin.get("/api/v1/executions/" + run_id).json()["state"] == "CANCELLED"
    with session_factory()() as db:
        assert db.get(Laboratory, item["laboratory_id"]).active_run_id is None


def test_worker_rejects_revoked_original_grant_even_without_pause_api(admin):
    item, instant = ready(admin)
    scheduling.dispatch_one(instant)
    run_id = occurrences(admin, item)[0]["run_id"]
    with session_factory()() as db:
        grant = db.scalar(
            select(ScheduleAuthorization).where(ScheduleAuthorization.schedule_id == item["id"])
        )
        grant.revoked_at = now()
        db.commit()
    assert claim_next() is None
    assert admin.get("/api/v1/executions/" + run_id).json()["state"] == "REJECTED"


def test_guard_revalidates_grant_and_deadline_clipped_to_end(admin):
    item, instant = ready(admin)
    with session_factory()() as db:
        schedule = db.get(Schedule, item["id"])
        schedule.ends_at = now() + timedelta(seconds=15)
        schedule.plan_hash = scheduling.digest(scheduling.plan(schedule))
        grant = db.scalar(
            select(ScheduleAuthorization).where(ScheduleAuthorization.schedule_id == item["id"])
        )
        grant.plan_hash, grant.expires_at = schedule.plan_hash, schedule.ends_at
        db.commit()
    scheduling.dispatch_one(instant)
    run_id = occurrences(admin, item)[0]["run_id"]
    with session_factory()() as db:
        assert db.get(CampaignRun, run_id).deadline_at == db.get(Schedule, item["id"]).ends_at
    assert claim_next() == run_id
    with session_factory()() as db:
        db.get(User, item["created_by"]).active = False
        db.commit()
    with pytest.raises(Interrupted, match="recorrente"):
        guard(run_id)
    process_run(run_id)
    with session_factory()() as db:
        assert db.get(CampaignRun, run_id).state == "CANCELLED"


def test_expired_plan_does_not_emit(admin):
    item, instant = ready(admin)
    assert scheduling.dispatch_one(instant + timedelta(hours=2))
    assert admin.get("/api/v1/schedules/" + item["id"]).json()["state"] == "EXPIRED"
    assert not occurrences(admin, item)


def test_last_busy_slot_does_not_invalidate_previously_issued_run(admin):
    item, instant = ready(admin, max_duration_seconds=60)
    with session_factory()() as db:
        schedule = db.get(Schedule, item["id"])
        schedule.ends_at = instant + timedelta(seconds=90)
        schedule.plan_hash = scheduling.digest(scheduling.plan(schedule))
        grant = db.scalar(
            select(ScheduleAuthorization).where(ScheduleAuthorization.schedule_id == item["id"])
        )
        grant.plan_hash, grant.expires_at = schedule.plan_hash, schedule.ends_at
        db.commit()
    assert scheduling.dispatch_one(instant + timedelta(seconds=20))
    first = occurrences(admin, item)[0]
    assert scheduling.dispatch_one(instant + timedelta(seconds=60))
    assert occurrences(admin, item)[0]["status"] == "SKIPPED_BUSY"
    with session_factory()() as db:
        assert db.get(Schedule, item["id"]).state == "EXHAUSTED"
        run = db.get(CampaignRun, first["run_id"])
        grant = db.scalar(select(Approval).where(Approval.run_id == run.id))
        assert scheduling.authorization_valid(db, run, grant)


@pytest.mark.parametrize(
    "overrides",
    [
        {"interval_seconds": 1},
        {"max_occurrences": 101},
        {"max_duration_seconds": 301},
        {"starts_at": "2026-01-01T00:00:00"},
        {"starts_at": "2020-01-01T00:00:00Z"},
        {"ends_at": (now() + timedelta(days=91)).isoformat()},
    ],
)
def test_schedule_bounds(admin, overrides):
    proposal(admin, expected_status=422, **overrides)


def test_schedule_rbac(client):
    # Use real sessions and CSRF for every role.
    for role in ["viewer", "operator"]:
        login = client.post(
            "/api/v1/auth/login",
            headers={"x-aegis-request": "browser"},
            json={
                "username": role,
                "password": "Test-only-randomized-scope-23!",
            },
        )
        client.headers["x-csrf-token"] = login.json()["csrf_token"]
        assert client.get("/api/v1/schedules").status_code == 200
        assert (
            client.post(
                "/api/v1/schedules/" + str(uuid.uuid4()) + "/approve",
                json={
                    "confirm_plan_hash": "0" * 64,
                    "confirm_automatic_execution": True,
                },
            ).status_code
            == 403
        )
        if role == "viewer":
            assert client.post("/api/v1/schedules", json={}).status_code == 403
            assert (
                client.post(
                    "/api/v1/schedules/" + str(uuid.uuid4()) + "/pause", json={"confirm": True}
                ).status_code
                == 403
            )


def test_expired_pending_plan_releases_open_capacity_without_approval(admin):
    item, starts = proposal(admin)
    assert scheduling.dispatch_one(starts + timedelta(hours=2))
    detail = admin.get("/api/v1/schedules/" + item["id"]).json()
    assert detail["state"] == "EXPIRED"
    assert detail["occurrences_count"] == 0
    assert not detail["authorizations"]
