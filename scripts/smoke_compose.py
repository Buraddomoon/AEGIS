"""Verify the running Compose stack over HTTP; no fixed administrator account."""

import secrets
import time
import uuid

import httpx
from aegis.db import session_factory
from aegis.models import User
from aegis.security import audit, hasher

username = "smoke-" + uuid.uuid4().hex[:12]
password = secrets.token_urlsafe(24)
with session_factory()() as db:
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
        client.post("/auth/logout").raise_for_status()
        print(
            "PASS: Compose API + runtime DB role + worker + 4 persisted synthetic outcomes + JSON report."
        )
finally:
    with session_factory()() as db:
        db.get(User, user_id).active = False
        audit(db, user_id, "test.compose_account_disabled", user_id)
        db.commit()
