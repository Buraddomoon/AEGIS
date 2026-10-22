"""One-use authorized Wazuh assay on localhost:18786. See labs/wazuh/ASSAY.md.

Never starts infrastructure. Refuses an existing intent even after a failure:
inspect the original run and recover it instead of executing another marker.
"""

import argparse
import json
import os
import secrets
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
from inspect_wazuh_lab import collect, validate
from wazuh_lab import COMPOSE, PRIVATE, execute

TERMINAL = {"COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED", "CLEANUP_FAILED", "REJECTED"}


class Intent:
    def __init__(self, path: Path):
        self.fd = os.open(
            path, os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def append(self, stage: str, **values):
        line = (
            json.dumps({"at": datetime.now(UTC).isoformat(), "stage": stage, **values}).encode()
            + b"\n"
        )
        if os.write(self.fd, line) != len(line):
            raise OSError("Intent write incomplete; preserve state and do not repeat.")
        os.fsync(self.fd)

    def close(self):
        os.close(self.fd)


def save(name: str, value):
    content = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
    fd = os.open(PRIVATE / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())
    directory = os.open(PRIVATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def accounts_local(accounts: list[dict], *, disable=False):
    # Fixed owner administration in the migration container, never in API/worker.
    # Passwords only on stdin; normal application users still store Argon2 hashes.
    code = """
import json,sys
from sqlalchemy import select
from aegis.db import session_factory
from aegis.models import User
from aegis.security import hasher,audit
values=json.load(sys.stdin)
with session_factory()() as db:
 for item in values:
  user=db.scalar(select(User).where(User.username==item['username']))
  if item['disable']:
   if user:
    user.active=False
    audit(db,user.id,'test.wazuh_account_disabled',user.id,synthetic=False)
  else:
   assert user is None
   user=User(username=item['username'],role=item['role'],password_hash=hasher.hash(item['password']))
   db.add(user);db.flush()
   audit(db,None,'test.wazuh_account_bootstrap',user.id,synthetic=False)
 db.commit()
"""
    execute(
        [*COMPOSE, "run", "--rm", "-T", "--no-deps", "migrate", "python", "-c", code],
        input=json.dumps([{**account, "disable": disable} for account in accounts]),
        capture_output=True,
        text=True,
        timeout=30,
    )


def login(client, account):
    response = client.post(
        "/auth/login",
        json={key: account[key] for key in ("username", "password")},
        headers={"x-aegis-request": "browser"},
    )
    response.raise_for_status()
    client.headers["x-csrf-token"] = response.json()["csrf_token"]


def request(client, method, path, body=None):
    response = client.request(method, path, **({"json": body} if body is not None else {}))
    response.raise_for_status()
    return response.json()


def assay():
    checks = validate(*collect())
    if not checks or not all(checks.values()):
        raise ValueError("Runtime isolation not verified; do not execute marker.")
    intent = Intent(PRIVATE / "assay-intent.jsonl")
    accounts = [
        {
            "username": "wazuh-assay-" + uuid.uuid4().hex[:12],
            "password": secrets.token_urlsafe(32),
            "role": role,
        }
        for role in ("administrator", "operator")
    ]
    lab = run = detail = None
    started = bootstrapped = False
    try:
        intent.append(
            "INTENT_CREATED", project="aegis-wazuh-lab", test="linux-file-marker-v1", max_markers=1
        )
        save("assay-accounts.json", accounts)
        bootstrapped = True
        accounts_local(accounts)
        with (
            httpx.Client(
                base_url="http://localhost:18786/api/v1", timeout=10, trust_env=False
            ) as admin,
            httpx.Client(
                base_url="http://localhost:18786/api/v1", timeout=10, trust_env=False
            ) as operator,
        ):
            try:
                login(admin, accounts[0])
                login(operator, accounts[1])
                if request(admin, "GET", "/executions?limit=1")["total"]:
                    raise ValueError("This assay database already has an execution; do not repeat.")
                connection = request(admin, "POST", "/connectors/wazuh/test")
                if connection["status"] != "connected":
                    raise ValueError("Indexer connection not verified.")
                lab = request(
                    admin,
                    "POST",
                    "/labs/linux/register",
                    {
                        "name": "Wazuh · ensaio local autorizado",
                        "owner": "Operação local autorizada",
                        "isolation_review": "163 controles Docker, mounts tmpfs RW/RO, UID10001/0700, log600, agente001 Active, TLS verificado e ACLs negativas conferidos no projeto próprio.",
                        "confirm_isolation_review": True,
                    },
                )
                intent.append("LAB_REGISTERED", laboratory_id=lab["id"])
                request(
                    admin,
                    "PUT",
                    f"/labs/{lab['id']}/wazuh-binding",
                    {
                        "review": "Agente001 aegis-marker Active no manager próprio, regra100200 sandbox, TLS/scroll/ACL real e política60s revisados; somente pipeline de marcador, sem ATT&CK artificial.",
                        "confirm_read_only_scope": True,
                    },
                )
                verification = request(
                    admin, "POST", f"/labs/{lab['id']}/preflight", {"confirm": True}
                )
                if not verification["success"]:
                    raise ValueError("Runner mTLS preflight failed.")
                request(admin, "PATCH", f"/labs/{lab['id']}/authorization", {"authorized": True})
                campaign = request(
                    operator,
                    "POST",
                    "/campaigns",
                    {
                        "name": "Wazuh · validação única do pipeline",
                        "objective": "Validar arquivo real, observação passiva, alerta Wazuh original, correlação e cleanup; não representa cobertura ATT&CK ou eficácia de EDR.",
                        "laboratory_id": lab["id"],
                        "test_ids": ["linux-file-marker-v1"],
                    },
                )
                key = uuid.uuid4().hex
                intent.append("RUN_REQUEST_INTENT", campaign_id=campaign["id"], idempotency_key=key)
                run = request(
                    operator, "POST", f"/campaigns/{campaign['id']}/runs", {"idempotency_key": key}
                )
                intent.append("RUN_CREATED", run_id=run["id"], scope_hash=run["scope_hash"])
                request(
                    admin,
                    "POST",
                    f"/executions/{run['id']}/approve",
                    {
                        "confirm_scope_hash": run["scope_hash"],
                        "confirm_real_execution": True,
                        "max_duration_seconds": 120,
                    },
                )
                # Durable before the first/only start; never retry an ambiguous response.
                intent.append("START_INTENT", run_id=run["id"])
                started = True
                request(operator, "POST", f"/executions/{run['id']}/start", {"confirm": True})
                until = time.monotonic() + 150
                while time.monotonic() < until:
                    detail = request(admin, "GET", f"/executions/{run['id']}")
                    if detail["state"] in TERMINAL:
                        break
                    time.sleep(0.5)
                save("execution.json", detail)
                report = request(admin, "GET", f"/reports/{run['id']}")
                save("report.json", report)
                html = admin.get(f"/reports/{run['id']}?format=html")
                html.raise_for_status()
                save("report.html", html.text)
                save("coverage.json", request(admin, "GET", "/coverage?mode=linux"))
                if (
                    detail["state"] != "COMPLETED"
                    or detail["synthetic"]
                    or len(detail["executions"]) != 1
                ):
                    raise ValueError("Run did not complete; inspect original execution.")
                item = detail["executions"][0]
                if (
                    not item["executed"]
                    or item["synthetic"]
                    or item["runner_cleanup"]["content"]["cleanup_state"] != "CLEANED"
                ):
                    raise ValueError("Execution/cleanup not confirmed.")
                intent.append(
                    "TERMINAL_CAPTURED",
                    run_id=run["id"],
                    state=detail["state"],
                    outcome=item["result"]["outcome"],
                )
                print(
                    json.dumps(
                        {
                            "run_id": run["id"],
                            "state": detail["state"],
                            "outcome": item["result"]["outcome"],
                            "events": len(item["events"]),
                            "evidence": len(item["evidence"]),
                            "synthetic": False,
                        }
                    )
                )
            finally:
                if lab:
                    request(
                        admin, "PATCH", f"/labs/{lab['id']}/authorization", {"authorized": False}
                    )
                    intent.append("LAB_REVOKED", laboratory_id=lab["id"])
        if item["result"]["outcome"] != "DETECTED" or not item["evidence"]:
            raise ValueError(
                "Original result preserved; detection not confirmed. Do not repeat marker."
            )
    finally:
        try:
            if bootstrapped and (
                not started or (detail and detail["state"] in TERMINAL - {"CLEANUP_FAILED"})
            ):
                accounts_local(accounts, disable=True)
                intent.append("ACCOUNTS_DISABLED")
                (PRIVATE / "assay-accounts.json").unlink()
                intent.append("TEMPORARY_CREDENTIALS_REMOVED")
            elif bootstrapped:
                intent.append("RECOVERY_REQUIRED", run_id=run["id"] if run else None)
        finally:
            intent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-integrated-marker", action="store_true")
    args = parser.parse_args()
    if not args.confirm_integrated_marker:
        parser.error("Requires the existing specific authorization and reviewed runtime checklist.")
    try:
        assay()
    except (OSError, ValueError, KeyError, httpx.HTTPError, subprocess.SubprocessError):
        print(
            "Assay not confirmed. Preserve private intent/artifacts and inspect the original run; never rerun the marker or destroy recovery state."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
