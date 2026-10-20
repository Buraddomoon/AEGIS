"""Verify the running Compose stack over HTTP; no fixed administrator account."""

import secrets
import time
import uuid
from datetime import timedelta

import httpx
from aegis.db import session_factory
from aegis.models import User, now
from aegis.security import audit, hasher
from sqlalchemy import text

username = "smoke-" + uuid.uuid4().hex[:12]
password = secrets.token_urlsafe(24)
with session_factory()() as db:
    permissions = db.execute(
        text("""
        SELECT
          NOT (SELECT rolsuper FROM pg_roles WHERE rolname='aegis_app'),
          NOT has_column_privilege('aegis_app','schedules','scope','UPDATE'),
          has_column_privilege('aegis_app','schedules','state','UPDATE'),
          NOT has_table_privilege('aegis_app','schedule_authorizations','DELETE'),
          NOT has_table_privilege('aegis_app','schedule_occurrences','UPDATE'),
          NOT has_table_privilege('aegis_app','schedule_occurrences','DELETE')
    """)
    ).one()
    assert all(permissions), "Runtime SQL permissions differ from immutable schedule policy"
    user = User(username=username, role="administrator", password_hash=hasher.hash(password))
    db.add(user)
    db.flush()
    audit(db, user.id, "test.compose_bootstrap", user.id, synthetic=True)
    db.commit()
    user_id = user.id
try:
    with httpx.Client(base_url="http://localhost:18780/api/v1", timeout=10) as client:
        assert client.get("/health/ready").json()["status"] == "ready"
        result = client.post(
            "/auth/login",
            json={"username": username, "password": password},
            headers={"x-aegis-request": "browser"},
        )
        result.raise_for_status()
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        lab = client.get("/labs").json()["items"][0]
        campaign = client.post(
            "/campaigns",
            json={
                "name": "Smoke Compose · demonstração sintética",
                "objective": "Validar a imagem Docker completa, papel SQL runtime e worker real; somente dados sintéticos.",
                "laboratory_id": lab["id"],
                "test_ids": [
                    "demo-shell",
                    "demo-powershell",
                    "demo-process-discovery",
                    "demo-file-marker",
                ],
            },
        )
        campaign.raise_for_status()
        run = client.post(
            f"/campaigns/{campaign.json()['id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
        )
        run.raise_for_status()
        run = run.json()
        client.post(
            f"/executions/{run['id']}/approve", json={"confirm_scope_hash": run["scope_hash"]}
        ).raise_for_status()
        client.post(f"/executions/{run['id']}/start", json={"confirm": True}).raise_for_status()
        for _ in range(100):
            detail = client.get(f"/executions/{run['id']}").json()
            if detail["state"] == "COMPLETED":
                break
            if detail["state"] in {"FAILED", "TIMED_OUT", "CLEANUP_FAILED"}:
                raise RuntimeError(detail["state"] + ": " + str(detail.get("error")))
            time.sleep(0.2)
        else:
            raise RuntimeError("Worker did not complete the Compose smoke test")
        outcomes = {e["result"]["outcome"] for e in detail["executions"]}
        assert outcomes == {"DETECTED", "OBSERVED_NOT_ALERTED", "NO_TELEMETRY", "INCONCLUSIVE"}
        report = client.get(f"/reports/{run['id']}").json()
        assert report["synthetic"] and report["integrity_sha256"]
        starts = now() + timedelta(seconds=3)
        schedule = client.post(
            "/schedules",
            json={
                "campaign_id": campaign.json()["id"],
                "interval_seconds": 60,
                "max_occurrences": 1,
                "max_duration_seconds": 30,
                "starts_at": starts.isoformat(),
                "ends_at": (starts + timedelta(minutes=2)).isoformat(),
            },
        )
        schedule.raise_for_status()
        schedule = schedule.json()
        client.post(
            f"/schedules/{schedule['id']}/approve",
            json={
                "confirm_plan_hash": schedule["plan_hash"],
                "confirm_automatic_execution": True,
            },
        ).raise_for_status()
        for _ in range(150):
            history = client.get(f"/schedules/{schedule['id']}/occurrences").json()["items"]
            if history and history[0]["run_id"]:
                scheduled = client.get("/executions/" + history[0]["run_id"]).json()
                if scheduled["state"] == "COMPLETED":
                    break
                if scheduled["state"] in {
                    "FAILED",
                    "REJECTED",
                    "TIMED_OUT",
                    "CANCELLED",
                    "CLEANUP_FAILED",
                }:
                    raise RuntimeError("Scheduled smoke failed: " + str(scheduled.get("error")))
            time.sleep(0.2)
        else:
            raise RuntimeError("Worker did not complete approved schedule under runtime role")
        assert scheduled["approval"]["schedule_authorization_id"] == history[0]["authorization_id"]
        assert scheduled["schedule_id"] == schedule["id"]
        assert all(e["synthetic"] and e["result"] for e in scheduled["executions"])
        scheduled_report = client.get("/reports/" + scheduled["id"]).json()
        assert scheduled_report["synthetic"] and scheduled_report["integrity_sha256"]
        assert (
            scheduled_report["run"]["schedule_plan"]["plan_hash"]
            == scheduled_report["run"]["schedule_authorization"]["plan_hash"]
        )
        client.post(
            f"/schedules/{schedule['id']}/revoke", json={"confirm": True}
        ).raise_for_status()
        assert client.get(f"/schedules/{schedule['id']}").json()["state"] == "REVOKED"
        client.post("/auth/logout").raise_for_status()
        print(
            "PASS: Compose API + restricted SQL role + worker + manual and scheduled runs + exact grant + revoke + 8 synthetic outcomes + JSON reports."
        )
finally:
    with session_factory()() as db:
        db.get(User, user_id).active = False
        audit(db, user_id, "test.compose_account_disabled", user_id)
        db.commit()
