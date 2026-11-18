"""Exactly one API campaign from the isolated controller; no free target or command."""

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from aegis.domain.validation import digest
from aegis.lab_runner.assay_profile import selected
from aegis.lab_runner.protocol import JobView

SECRETS = Path("/run/secrets")
EVIDENCE = Path("/evidence")
TERMINAL = {"COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED", "CLEANUP_FAILED", "REJECTED"}


def save_intent(value):
    path = EVIDENCE / "run.json"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def assay(plan, accounts, client, *, emit=print, persist=save_intent):
    profile = selected(plan)
    if plan["review"] != profile["review"] or len(accounts) != 2:
        raise ValueError("Pinned review required")
    admin = next(row for row in accounts if row["role"] == "administrator")
    operator = next(row for row in accounts if row["role"] == "operator")
    assert admin["username"] != operator["username"]
    lab_id = plan["identity"]["laboratory_id"]
    run = None
    registered = False
    cleaning = False

    def request(method, path, body=None):
        if method != "GET" and not cleaning:
            if datetime.now(UTC) >= datetime.fromisoformat(plan["expires_at"]):
                raise ValueError("Package expired; cleanup only")
        result = (
            client.request(method, path, json=body)
            if body is not None
            else client.request(method, path)
        )
        result.raise_for_status()
        return result.json()

    def login(account):
        result = client.post(
            "/auth/login",
            headers={"x-aegis-request": "browser"},
            json={key: account[key] for key in ("username", "password")},
        )
        result.raise_for_status()
        client.headers["x-csrf-token"] = result.json()["csrf_token"]

    def poll(identifier):
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            detail = request("GET", f"/executions/{identifier}")
            if detail["state"] in TERMINAL:
                return detail
            time.sleep(0.3)
        raise TimeoutError("Assay execution not terminal")

    try:
        login(admin)
        assert request("GET", "/executions?mode=linux")["total"] == 0
        lab = request(
            "POST",
            "/labs/linux/register",
            {
                "name": f"{profile['name']} isolated one-attempt lab",
                "owner": f"Explicitly authorized #{profile['issue']} assay",
                "isolation_review": "Fresh dedicated volumes, internal networks, pinned images, UID10001, read-only rootfs, no host ports/socket; exactly one code-reviewed fixed test.",
                "confirm_isolation_review": True,
            },
        )
        assert lab["id"] == lab_id and not lab["authorized"]
        registered = True
        assert request("POST", f"/labs/{lab_id}/preflight", {"confirm": True})["success"]
        request("PATCH", f"/labs/{lab_id}/authorization", {"authorized": True})
        login(operator)
        campaign = request(
            "POST",
            "/campaigns",
            {
                "name": profile["name"] + " single reviewed effect",
                "objective": "One fixed code-reviewed effect with native mTLS and cleanup; defensive collection unavailable.",
                "laboratory_id": lab_id,
                "test_ids": [profile["definition_id"]],
            },
        )
        run = request(
            "POST", f"/campaigns/{campaign['id']}/runs", {"idempotency_key": plan["attempt_id"]}
        )
        assert run["scope"]["runner"][profile["review_key"]] == plan["review"]
        assert not run["synthetic"] and run["scope"]["telemetry"]["provider"] == "unavailable"
        persist(
            {
                "attempt_id": plan["attempt_id"],
                "run_id": run["id"],
                "scope_hash": run["scope_hash"],
                "scope": run["scope"],
            }
        )
        emit(
            json.dumps(
                {
                    "event": "run_requested_before_start",
                    "run_id": run["id"],
                    "scope_hash": run["scope_hash"],
                }
            ),
            flush=True,
        )
        login(admin)
        request(
            "POST",
            f"/executions/{run['id']}/approve",
            {
                "confirm_scope_hash": run["scope_hash"],
                "confirm_real_execution": True,
                "max_duration_seconds": 60,
            },
        )
        request("POST", f"/executions/{run['id']}/start", {"confirm": True})
        detail = poll(run["id"])
        assert detail["state"] == "COMPLETED"
        item = detail["executions"][0]
        assert len(detail["executions"]) == 1 and item["executed"] and not item["synthetic"]
        assert item["result"]["outcome"] == "INCONCLUSIVE"
        assert not item["events"] and not item["evidence"]
        receipt = item["runner_receipt"]["content"]
        assert receipt["test_id"] == profile["test_id"] and receipt["artifact_bytes"] == 43
        if profile["issue"] == 80:
            assert receipt["mode_before"] == 0o400 and receipt["mode_after"] == 0o600
        else:
            assert receipt["child_pid"] > 0 and receipt["child_exit_code"] == 0
            output = (item["marker"] + "\n").encode() if profile["name"] == "linux83-shell" else b""
            assert receipt["stdout_bytes"] == len(output)
            assert receipt["stdout_sha256"] == hashlib.sha256(output).hexdigest()
        assert digest(receipt) == item["runner_receipt"]["sha256"]
        cleanup = item["runner_cleanup"]["content"]
        assert digest(cleanup) == item["runner_cleanup"]["sha256"]
        view = JobView.model_validate(cleanup)
        assert view.cleanup_state == "CLEANED" and view.receipt.model_dump(mode="json") == receipt
        report = request("GET", f"/reports/{run['id']}?format=json")
        assert not report["synthetic"]
        result = client.get(f"/reports/{run['id']}?format=html")
        result.raise_for_status()
        assert "COMPROVANTES DO EXECUTOR" in result.text
        assert request("GET", "/executions?mode=linux")["total"] == 1
        return {
            "status": profile["status"],
            "run_id": run["id"],
            "scope_hash": run["scope_hash"],
            "detail": detail,
            "report": report,
            "html_sha256": hashlib.sha256(result.content).hexdigest(),
        }
    finally:
        cleaning = True
        # Independent account/session revocation is also performed by the host's
        # owner-only disable entrypoint, even if API access has failed here.
        if registered:
            login(admin)
            if run:
                detail = request("GET", f"/executions/{run['id']}")
                if detail["state"] not in TERMINAL:
                    request("POST", f"/executions/{run['id']}/cancel", {})
                    detail = poll(run["id"])
                if detail["state"] == "CLEANUP_FAILED":
                    request("POST", f"/labs/{lab_id}/recover", {"confirm": True})
            request("PATCH", f"/labs/{lab_id}/authorization", {"authorized": False})


def main():
    plan = json.loads((SECRETS / "plan").read_text())
    accounts = json.loads((SECRETS / "accounts").read_text())
    with httpx.Client(
        base_url="http://192.168.253.4:8080/api/v1",
        trust_env=False,
        follow_redirects=False,
        timeout=10,
    ) as client:
        result = assay(plan, accounts, client)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            json.dumps({"status": "blocked", "code": "atomic80_client_failed_no_replay"}),
            flush=True,
        )
        raise SystemExit(1) from None
