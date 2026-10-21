"""Opt-in integrated assay. No startup, Wazuh, arbitrary target or command input."""

import argparse
import json
import secrets
import subprocess
import time
import uuid
from pathlib import Path

import httpx

COMPOSE = [
    "docker",
    "compose",
    "--env-file",
    ".env",
    "--env-file",
    ".local/linux-lab/ids.env",
    "-p",
    "aegis-linux-lab",
    "-f",
    "docker-compose.yml",
    "-f",
    "labs/linux/compose.yml",
    "-f",
    "labs/linux/platform.yml",
]


def local_accounts(accounts: list[dict], disable: bool = False):
    # Trusted fixed administration code; credentials travel through stdin, never shell/argv/logs.
    code = """
import json, sys
from sqlalchemy import select, text
from aegis.db import session_factory
from aegis.models import User
from aegis.security import hasher, audit
accounts = json.load(sys.stdin)
with session_factory()() as db:
    checks = db.execute(text('''SELECT
      NOT has_table_privilege('aegis_app','runner_receipts','UPDATE'),
      NOT has_table_privilege('aegis_app','runner_cleanups','DELETE'),
      NOT has_table_privilege('aegis_app','lab_verifications','UPDATE'),
      NOT has_column_privilege('aegis_app','runner_dispatches','spec','UPDATE'),
      has_column_privilege('aegis_app','runner_dispatches','generation','UPDATE')''')).one()
    assert all(checks), 'Immutable runner grants differ'
    for item in accounts:
        user = db.scalar(select(User).where(User.username == item['username']))
        if item.get('disable'):
            if user:
                user.active = False
                audit(db, user.id, 'test.linux_account_disabled', user.id)
        else:
            assert user is None
            user = User(username=item['username'], role=item['role'], password_hash=hasher.hash(item['password']))
            db.add(user)
            db.flush()
            audit(db, None, 'test.linux_account_bootstrap', user.id, synthetic=False)
    db.commit()
"""
    values = [{**account, "disable": disable} for account in accounts]
    result = subprocess.run(
        [*COMPOSE, "run", "--rm", "-T", "--no-deps", "migrate", "python", "-c", code],
        input=json.dumps(values),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            "Administração local de contas temporárias falhou; verifique os logs localmente."
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-integrated-marker", action="store_true")
    parser.add_argument("--capture-ui", action="store_true")
    args = parser.parse_args()
    if not args.confirm_integrated_marker:
        parser.error("Exige autorização específica e --confirm-integrated-marker.")
    accounts = [
        {
            "username": "linux-assay-" + uuid.uuid4().hex[:12],
            "password": secrets.token_urlsafe(32),
            "role": role,
        }
        for role in ("administrator", "operator")
    ]
    local_accounts(accounts)
    try:
        with httpx.Client(
            base_url="http://localhost:18785/api/v1", timeout=10, trust_env=False
        ) as client:

            def request(method, path, body=None):
                response = (
                    client.request(method, path, json=body)
                    if body is not None
                    else client.request(method, path)
                )
                response.raise_for_status()
                return response.json()

            def login(account):
                response = client.post(
                    "/auth/login",
                    json={k: account[k] for k in ("username", "password")},
                    headers={"x-aegis-request": "browser"},
                )
                response.raise_for_status()
                client.headers["x-csrf-token"] = response.json()["csrf_token"]

            login(accounts[0])
            lab = request(
                "POST",
                "/labs/linux/register",
                {
                    "name": "Linux Lab · ensaio integrado",
                    "owner": "Operação local autorizada",
                    "isolation_review": "Runner UID 10001, rede internal isolated sem portas host, rootfs read-only, tmpfs 1 MiB e teste fixo revisados no ensaio local.",
                    "confirm_isolation_review": True,
                },
            )
            verification = request("POST", f"/labs/{lab['id']}/preflight", {"confirm": True})
            assert verification["success"], verification["reason"]
            request("PATCH", f"/labs/{lab['id']}/authorization", {"authorized": True})
            login(accounts[1])
            campaign = request(
                "POST",
                "/campaigns",
                {
                    "name": "Linux · ciclo integrado autorizado",
                    "objective": "Comprovar fila, mTLS, efeito de 43 bytes, cleanup e relatório sem SIEM.",
                    "laboratory_id": lab["id"],
                    "test_ids": ["linux-file-marker-v1"],
                },
            )
            run = request(
                "POST", f"/campaigns/{campaign['id']}/runs", {"idempotency_key": uuid.uuid4().hex}
            )
            login(accounts[0])
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
            for _ in range(150):
                detail = request("GET", f"/executions/{run['id']}")
                if detail["state"] in (
                    "COMPLETED",
                    "FAILED",
                    "TIMED_OUT",
                    "CANCELLED",
                    "CLEANUP_FAILED",
                    "REJECTED",
                ):
                    break
                time.sleep(0.3)
            assert detail["state"] == "COMPLETED", detail.get("error") or detail["state"]
            execution = detail["executions"][0]
            assert execution["executed"] and not execution["synthetic"]
            assert execution["result"]["outcome"] == "INCONCLUSIVE"
            assert not execution["events"] and not execution["evidence"]
            assert execution["runner_receipt"]["content"]["artifact_bytes"] == 43
            assert execution["runner_cleanup"]["content"]["cleanup_state"] == "CLEANED"
            report = request("GET", f"/reports/{run['id']}")
            assert not report["synthetic"]
            html = client.get(f"/reports/{run['id']}?format=html")
            html.raise_for_status()
            assert "COMPROVANTES DO EXECUTOR" in html.text
            real = request("GET", "/coverage?mode=linux")
            demo = request("GET", "/coverage?mode=demo")
            assert real["completed_tests"] >= 1 and demo["completed_tests"] == 0
            request("PATCH", f"/labs/{lab['id']}/authorization", {"authorized": False})
            path = Path(".local/linux-lab/platform-assay.json")
            path.write_text(
                json.dumps(
                    {"run_id": run["id"], "synthetic": False, "report": report, "coverage": real},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            path.chmod(0o600)
            if args.capture_ui:
                subprocess.run(
                    ["node", "linux-preview.mjs"],
                    cwd="apps/web",
                    input=json.dumps(
                        {
                            "username": accounts[0]["username"],
                            "password": accounts[0]["password"],
                            "runId": run["id"],
                        }
                    ),
                    text=True,
                    check=True,
                )
            print(
                "PASS: segregated approval + queue + real mTLS + 43 bytes + cleanup + immutable receipts + INCONCLUSIVE + mode separation + reports; local evidence:",
                path,
            )
    finally:
        local_accounts(accounts, disable=True)


if __name__ == "__main__":
    main()
