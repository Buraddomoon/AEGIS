"""Real PostgreSQL and API; disposable accounts only, no laboratory transport."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from aegis import identities, worker
from aegis.db import session_factory
from aegis.main import app
from aegis.models import Approval, AuditEvent, CampaignRun, Laboratory, LoginSession, User, now
from aegis.security import token_hash, verify_password
from conftest import create_queued
from fastapi.testclient import TestClient
from sqlalchemy import func, select

PASSWORD = "Test-only-randomized-scope-23!"
NEW_PASSWORD = "  New-test-password-with-spaces  "


def login(client, username="administrator", password=PASSWORD):
    result = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers={"x-aegis-request": "browser"},
    )
    if result.status_code == 200:
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
    return result


def users(admin):
    return {u["username"]: u for u in admin.get("/api/v1/users").json()["items"]}


def second_admin(admin):
    result = admin.post(
        "/api/v1/users",
        json={"username": "second-admin", "password": PASSWORD, "role": "administrator"},
    )
    assert result.status_code == 201
    client = TestClient(app)
    assert login(client, "second-admin").status_code == 200
    return client


def edit(client, user, *, role=None, active=True):
    return client.patch(
        f"/api/v1/users/{user['id']}",
        json={"role": role or user["role"], "active": active, "confirm": True},
    )


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_no_privilege_escalation_or_session_disclosure(admin, role):
    ids = users(admin)
    client = TestClient(app)
    login(client, role)
    assert edit(client, ids[role], role="administrator").status_code == 403
    assert (
        client.post(
            f"/api/v1/users/{ids['administrator']['id']}/password",
            json={"new_password": NEW_PASSWORD, "confirm": True},
        ).status_code
        == 403
    )
    for suffix, method in [("sessions", "GET"), ("sessions/revoke", "POST")]:
        assert (
            client.request(
                method,
                f"/api/v1/users/{ids['administrator']['id']}/{suffix}",
                **({"json": {"confirm": True}} if method == "POST" else {}),
            ).status_code
            == 403
        )
    assert client.get(f"/api/v1/users/{ids[role]['id']}/sessions").status_code == 200


@pytest.mark.parametrize("role,active", [("viewer", True), ("administrator", False)])
def test_last_admin_preserved(admin, role, active):
    item = users(admin)["administrator"]
    assert edit(admin, item, role=role, active=active).status_code == 409
    assert admin.get("/api/v1/auth/me").status_code == 200
    with session_factory()() as db:
        assert db.get(User, item["id"]).active
        assert db.get(User, item["id"]).role == "administrator"


@pytest.mark.parametrize("role,active", [("viewer", True), ("operator", False)])
def test_edit_revokes_all_sessions_and_reactivation_does_not_restore(admin, role, active):
    item = users(admin)["operator"]
    clients = [TestClient(app), TestClient(app)]
    for c in clients:
        login(c, "operator")
    assert admin.get(f"/api/v1/users/{item['id']}/sessions").json()["total"] == 2
    assert edit(admin, item, role=role, active=active).status_code == 200
    for c in clients:
        assert c.get("/api/v1/auth/me").status_code == 401
    assert edit(admin, item, role="operator").status_code == 200
    assert clients[0].get("/api/v1/auth/me").status_code == 401
    assert login(clients[0], "operator").status_code == 200


def test_password_change_reset_and_redaction(admin):
    item = users(admin)["viewer"]
    client = TestClient(app)
    login(client, "viewer")
    path = "/api/v1/auth/password"
    assert (
        client.post(
            path, json={"current_password": "wrong", "new_password": NEW_PASSWORD, "confirm": True}
        ).status_code
        == 403
    )
    assert client.get("/api/v1/auth/me").status_code == 200
    assert (
        client.post(
            path, json={"current_password": PASSWORD, "new_password": NEW_PASSWORD, "confirm": True}
        ).status_code
        == 204
    )
    assert client.get("/api/v1/auth/me").status_code == 401
    assert login(client, "viewer").status_code == 401
    assert login(client, "viewer", NEW_PASSWORD).status_code == 200
    assert (
        admin.post(
            f"/api/v1/users/{item['id']}/password", json={"new_password": PASSWORD, "confirm": True}
        ).status_code
        == 204
    )
    assert client.get("/api/v1/auth/me").status_code == 401
    own = users(admin)["administrator"]
    assert (
        admin.post(
            f"/api/v1/users/{own['id']}/password",
            json={"new_password": NEW_PASSWORD, "confirm": True},
        ).status_code
        == 409
    )
    with session_factory()() as db:
        stored = db.get(User, item["id"]).password_hash
        assert stored.startswith("$argon2id$") and verify_password(stored, PASSWORD)
        details = json.dumps([a.details for a in db.scalars(select(AuditEvent))])
        assert NEW_PASSWORD not in details and PASSWORD not in details and stored not in details
    assert "password" not in json.dumps(users(admin))


def test_sessions_self_revoke_expiry_csrf_validation_and_limit(admin):
    item = users(admin)["administrator"]
    path = f"/api/v1/users/{item['id']}/sessions"
    data = admin.get(path).json()
    assert data["total"] == 1 and data["items"][0]["current"] is True
    assert set(data["items"][0]) == {"current", "expires_at"}
    assert (
        admin.post(
            path + "/revoke", json={"confirm": True}, headers={"x-csrf-token": "wrong"}
        ).status_code
        == 403
    )
    assert admin.post(path + "/revoke", json={"confirm": False}).status_code == 422
    assert edit(admin, item, role="invalid").status_code == 422
    assert (
        admin.post(
            "/api/v1/auth/password",
            json={"new_password": "short", "confirm": True, "current_password": PASSWORD},
        ).status_code
        == 422
    )
    assert admin.post(path + "/revoke", json={"confirm": True}).status_code == 204
    assert admin.get("/api/v1/auth/me").status_code == 401
    login(admin)
    with session_factory()() as db:
        session = db.get(LoginSession, token_hash(admin.cookies["aegis_session"]))
        session.expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert admin.get("/api/v1/auth/me").status_code == 401
    login(admin)
    for _ in range(29):
        assert edit(admin, item).status_code == 200
    assert edit(admin, item).status_code == 429


def test_last_admin_race_on_two_connections(admin):
    other = second_admin(admin)
    items = users(admin)
    barrier = threading.Barrier(2)

    def demote(client, item):
        barrier.wait(timeout=5)
        return edit(client, item, role="viewer").status_code

    with ThreadPoolExecutor(2) as pool:
        a = pool.submit(demote, admin, items["administrator"])
        b = pool.submit(demote, other, items["second-admin"])
        assert sorted([a.result(timeout=10), b.result(timeout=10)]) == [200, 409]
    with session_factory()() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.active, User.role == "administrator")
            )
            == 1
        )


def test_login_serializes_with_password_reset(admin):
    item = users(admin)["viewer"]
    started = threading.Event()

    def attempt():
        started.set()
        return login(TestClient(app), "viewer").status_code

    with ThreadPoolExecutor(1) as pool, session_factory()() as db:
        identities.lock(db)
        pending = pool.submit(attempt)
        assert started.wait(5)
        identities.password(db, db.get(User, item["id"]), db.get(User, item["id"]), NEW_PASSWORD)
        db.commit()
        assert pending.result(timeout=10) == 401


@pytest.mark.parametrize("active,role", [(False, "administrator"), (True, "viewer")])
def test_worker_rejects_queued_revoked_approver_without_rewriting_approval(admin, active, role):
    other = second_admin(admin)
    item = users(admin)["administrator"]
    run = create_queued(admin, ["demo-shell"])
    with session_factory()() as db:
        before = db.scalar(select(Approval).where(Approval.run_id == run["id"]))
        original = (before.id, before.scope_hash, before.approved_by, before.used_at)
    assert edit(other, item, active=active, role=role).status_code == 200
    assert worker.claim_next() is None
    with session_factory()() as db:
        after = db.scalar(select(Approval).where(Approval.run_id == run["id"]))
        assert (after.id, after.scope_hash, after.approved_by, after.used_at) == original
        assert db.get(CampaignRun, run["id"]).state == "REJECTED"
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id is None


def test_revocation_during_execution_still_cleans_up(admin, monkeypatch):
    from aegis.integrations.demo import DemoExecutionAdapter

    other = second_admin(admin)
    item = users(admin)["administrator"]
    run = create_queued(admin, ["demo-shell"])
    cleaned = []
    original = DemoExecutionAdapter.execute

    def execute(self, context):
        result = original(self, context)
        assert edit(other, item, role="viewer").status_code == 200
        return result

    monkeypatch.setattr(DemoExecutionAdapter, "execute", execute)
    monkeypatch.setattr(
        DemoExecutionAdapter, "cleanup", lambda self, context: cleaned.append(context)
    )
    assert worker.claim_next() == run["id"]
    worker.process_run(run["id"])
    assert len(cleaned) == 1
    with session_factory()() as db:
        assert db.get(CampaignRun, run["id"]).state == "CANCELLED"
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id is None


def test_waiting_actor_cannot_use_revoked_admin_dependency(admin, monkeypatch):
    other = second_admin(admin)
    item = users(admin)["administrator"]
    waiting, resume = threading.Event(), threading.Event()
    original = identities.lock

    def lock(db):
        if any(
            isinstance(value, User) and value.id == item["id"] for value in db.identity_map.values()
        ):
            waiting.set()
            assert resume.wait(10)
        original(db)

    monkeypatch.setattr(identities, "lock", lock)
    with ThreadPoolExecutor(1, thread_name_prefix="stale-actor") as pool:
        pending = pool.submit(
            admin.post,
            "/api/v1/users",
            json={"username": "must-not-exist", "password": PASSWORD, "role": "administrator"},
        )
        assert waiting.wait(5)
        assert edit(other, item, role="viewer").status_code == 200
        resume.set()
        assert pending.result(timeout=10).status_code == 401
    with session_factory()() as db:
        assert db.scalar(select(User).where(User.username == "must-not-exist")) is None
