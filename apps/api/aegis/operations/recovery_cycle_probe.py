"""Fixed loopback client used only inside an offline recovered API container."""

import json
import os
import re
import sys
import time
from collections import Counter

import httpx

from aegis.domain.validation import LOGIC_VERSION, digest
from aegis.operations.recovered_demo import FORMAT, TEST_IDS, context

BASE = "http://127.0.0.1:8080/api/v1"


def require_environment():
    if (
        os.environ.get("OPERATING_MODE") != "normal"
        or not re.fullmatch(
            r"postgresql\+psycopg://aegis_app:[a-f0-9]{64}@127\.0\.0\.1:5432/aegis_restore",
            os.environ.get("DATABASE_URL", ""),
        )
        or not re.fullmatch(
            r"redis://:[a-f0-9]{64}@127\.0\.0\.1:6379/0", os.environ.get("REDIS_URL", "")
        )
        or any(
            value
            for key, value in os.environ.items()
            if key.startswith(("WAZUH_", "LINUX_RUNNER_"))
        )
    ):
        raise ValueError("Probe restricted to the isolated recovered Demo environment")


def cycle(client, payload, *, pause=time.sleep):
    if set(payload) != {"recovery_id", "password"} or not re.fullmatch(
        r"[a-f0-9]{64}", payload.get("password", "")
    ):
        raise ValueError("Invalid fresh cycle input")
    fresh = context(payload["recovery_id"])

    def request(method, path, expected=200, **kwargs):
        response = client.request(method, path, **kwargs)
        if response.status_code != expected:
            raise ValueError("Recovered Demo API assertion failed")
        return response

    for _ in range(80):
        try:
            response = client.get("/health/ready")
            if response.status_code == 200 and response.json().get("status") == "ready":
                break
        except httpx.HTTPError:
            pass
        pause(0.25)
    else:
        raise ValueError("Recovered API unavailable")
    request("GET", "/auth/me", 401)
    login = request(
        "POST",
        "/auth/login",
        json={"username": fresh["username"], "password": payload["password"]},
        headers={"x-aegis-request": "browser"},
    ).json()
    if login["user"]["id"] != fresh["account_id"] or login["user"]["role"] != "administrator":
        raise ValueError("Fresh identity mismatch")
    client.headers["x-csrf-token"] = login["csrf_token"]
    labs = request("GET", "/labs").json()["items"]
    lab = next(item for item in labs if item["id"] == fresh["laboratory_id"])
    if (
        lab["kind"] != "demo"
        or lab["synthetic"] is not True
        or any(item["authorized"] or item["active_run_id"] for item in labs)
    ):
        raise ValueError("Restored authority remains")
    before = request("GET", "/coverage").json()
    authorized = request(
        "PATCH", f"/labs/{lab['id']}/authorization", json={"authorized": True}
    ).json()
    if authorized["environment_version"] != lab["environment_version"] + 1:
        raise ValueError("Fresh laboratory authorization missing")
    campaign = request(
        "POST",
        "/campaigns",
        201,
        json={
            "name": "Demo após recuperação isolada",
            "objective": "Validar novo ciclo sintético, sem reutilizar autorização restaurada.",
            "laboratory_id": lab["id"],
            "test_ids": list(TEST_IDS),
        },
    ).json()
    run = request(
        "POST",
        f"/campaigns/{campaign['id']}/runs",
        201,
        json={"idempotency_key": "recovery-" + payload["recovery_id"]},
    ).json()
    if run["state"] != "PENDING_APPROVAL" or run["synthetic"] is not True:
        raise ValueError("Fresh request missing")
    request("POST", f"/executions/{run['id']}/start", 409, json={"confirm": True})
    approval = request(
        "POST",
        f"/executions/{run['id']}/approve",
        json={"confirm_scope_hash": run["scope_hash"], "max_duration_seconds": 60},
    ).json()
    request("POST", f"/executions/{run['id']}/start", json={"confirm": True})
    for _ in range(160):
        detail = request("GET", f"/executions/{run['id']}").json()
        if detail["state"] == "COMPLETED":
            break
        if detail["state"] in {"FAILED", "TIMED_OUT", "CLEANUP_FAILED", "REJECTED", "CANCELLED"}:
            raise ValueError("Fresh worker cycle failed")
        pause(0.25)
    else:
        raise ValueError("Fresh worker cycle timed out")
    expected = {"DETECTED": 1, "OBSERVED_NOT_ALERTED": 1, "NO_TELEMETRY": 1, "INCONCLUSIVE": 1}
    results = detail["executions"]
    if (
        len(results) != 4
        or {e["test_id"] for e in results} != set(TEST_IDS)
        or detail["synthetic"] is not True
        or detail["requested_by"] != fresh["account_id"]
        or detail["approval"]["id"] != approval["id"]
        or not detail["approval"]["used_at"]
        or detail["approval"]["scope_hash"] != run["scope_hash"]
    ):
        raise ValueError("Fresh scope/approval mismatch")
    for item in results:
        result = item["result"]
        if (
            item["synthetic"] is not True
            or item["state"] != "COMPLETED"
            or not item["executed"]
            or result["synthetic"] is not True
            or result["logic_version"] != LOGIC_VERSION
            or any(
                e["synthetic"] is not True or digest(e["raw"]) != e["sha256"]
                for e in item["events"]
            )
            or item["runner_dispatch"] is not None
        ):
            raise ValueError("Synthetic evidence mismatch")
        if result["outcome"] == "DETECTED" and (not item["evidence"] or not item["events"]):
            raise ValueError("Synthetic detection lacks evidence")
    if Counter(e["result"]["outcome"] for e in results) != expected:
        raise ValueError("Synthetic classification mismatch")
    report = request("GET", f"/reports/{run['id']}").json()
    if report["synthetic"] is not True or report["integrity_sha256"] != digest(report["run"]):
        raise ValueError("Report integrity mismatch")
    html = request("GET", f"/reports/{run['id']}?format=html").text
    if "EVIDÊNCIAS SINTÉTICAS" not in html or report["integrity_sha256"] not in html:
        raise ValueError("HTML report mismatch")
    after = request("GET", "/coverage").json()
    if (
        after["total_runs"] != before["total_runs"] + 1
        or after["completed_tests"] != before["completed_tests"] + 4
        or after["valid_tests"] != before["valid_tests"] + 3
        or after["synthetic"] is not True
        or any(after["outcomes"].get(k, 0) != before["outcomes"].get(k, 0) + 1 for k in expected)
    ):
        raise ValueError("Coverage delta mismatch")
    request("PATCH", f"/labs/{lab['id']}/authorization", json={"authorized": False})
    labs = request("GET", "/labs").json()["items"]
    if any(item["authorized"] or item["active_run_id"] for item in labs):
        raise ValueError("Fresh laboratory did not close")
    request("POST", "/auth/logout", 204)
    request("GET", "/auth/me", 401)
    return {
        "format": FORMAT,
        "synthetic": True,
        "run_id": run["id"],
        "laboratory_id": lab["id"],
        "fresh_account_id": fresh["account_id"],
        "new_approval_id": approval["id"],
        "state": "COMPLETED",
        "outcomes": expected,
        "report_sha256": report["integrity_sha256"],
        "completed_tests_delta": 4,
        "valid_tests_delta": 3,
        "total_runs_delta": 1,
        "new_lab_revoked": True,
        "session_closed": True,
    }


def main():
    try:
        require_environment()
        payload = json.loads(sys.stdin.read(16384))
        with httpx.Client(base_url=BASE, timeout=3, trust_env=False) as client:
            result = cycle(client, payload)
        print(json.dumps(result))
    except Exception:
        raise SystemExit("Recovered Demo probe failed; no sensitive output displayed") from None


if __name__ == "__main__":
    main()
