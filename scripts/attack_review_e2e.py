"""Offline ATT&CK review/browser/CLI acceptance in a disposable Demo schema only."""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
from aegis.catalog import artifacts
from aegis.catalog.document import HEX64
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.models import AttackCatalogRelease, User
from aegis.security import hasher
from aegis.seed import seed
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
CLI = """
import runpy,sys
from pathlib import Path
module=runpy.run_path('scripts/update_attack.py', run_name='attack_review_test_cli')
module['main'].__globals__['CACHE']=Path(sys.argv[1])
module['main'](sys.argv[2:])
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-cache", type=Path, required=True)
    parser.add_argument("--candidate-id", required=True)
    args = parser.parse_args()
    import re

    if not re.fullmatch(HEX64, args.candidate_id):
        parser.error("Use an exact prepared candidate SHA256")
    # Reverify existing source without downloading or changing its original cache.
    document = artifacts.load(args.candidate_cache, args.candidate_id)
    original_files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (args.candidate_cache / args.candidate_id).iterdir()
    }
    parent = ROOT / ".local/attack-admin"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent))
    cache = output / "attack-catalog"
    cache.mkdir(mode=0o700)
    shutil.copytree(args.candidate_cache / args.candidate_id, cache / args.candidate_id)
    processes = []
    admin_engine = create_engine(settings().database_url)
    schema = "aegis_attack_review_" + uuid.uuid4().hex
    url = admin_engine.url.update_query_dict({"options": "-csearch_path=" + schema})
    engine = create_engine(url)
    env = {
        **os.environ,
        "DATABASE_URL": url.render_as_string(hide_password=False),
        "REDIS_URL": settings().redis_url.rsplit("/", 1)[0] + "/15",
        "PUBLIC_ORIGIN": "http://localhost:18786",
        "ATTACK_REVIEW_CACHE": str(cache),
        "DEMO_STEP_SECONDS": "0",
    }
    username, password = "attack-review-" + uuid.uuid4().hex[:8], secrets.token_urlsafe(32)
    summary = {
        "candidate_id": document.identity,
        "version": document.version,
        "source_commit": document.source_commit,
        "source_sha256": document.source_sha256,
        "schema": schema,
        "output": str(output),
        "synthetic_execution": True,
    }

    def cli(*arguments):
        result = subprocess.run(
            [sys.executable, "-c", CLI, str(cache), *arguments],
            env=env,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError("Disposable CLI refused; " + result.stderr)
        return json.loads(result.stdout)

    def browser(phase, plan_id, stale_id=None):
        result = subprocess.run(
            ["node", "attack-review-e2e.mjs"],
            cwd=ROOT / "apps/web",
            env=env,
            input=json.dumps(
                {
                    "username": username,
                    "password": password,
                    "origin": env["PUBLIC_ORIGIN"],
                    "phase": phase,
                    "plan_id": plan_id,
                    "stale_id": stale_id,
                    "output": str(output),
                }
            ),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode:
            raise RuntimeError("Browser acceptance failed; " + result.stderr)
        return json.loads(result.stdout)

    with admin_engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env=env,
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=30,
        )
        with Session(engine) as db:
            seed(db)
            actor = User(
                username=username, password_hash=hasher.hash(password), role="administrator"
            )
            db.add(actor)
            db.commit()
            actor_id = actor.id
            initial_release = db.scalar(select(AttackCatalogRelease)).document
            summary["initial_release_document_sha256"] = digest(initial_release)
        for name, arguments in (
            (
                "api",
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "aegis.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "18786",
                ],
            ),
            ("worker", [sys.executable, "-m", "aegis.worker"]),
        ):
            stream = os.fdopen(
                os.open(output / (name + ".log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
            )
            process = subprocess.Popen(
                arguments, cwd=ROOT, env=env, stdout=stream, stderr=stream, start_new_session=True
            )
            processes.append((process, stream))
        with httpx.Client(base_url=env["PUBLIC_ORIGIN"], timeout=15, trust_env=False) as client:
            for _ in range(100):
                try:
                    if client.get("/api/v1/health/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.15)
            else:
                raise RuntimeError("Disposable API did not become ready")

            def request(method, path, **kwargs):
                response = client.request(method, "/api/v1" + path, **kwargs)
                response.raise_for_status()
                return response

            auth = request(
                "POST",
                "/auth/login",
                json={"username": username, "password": password},
                headers={"x-aegis-request": "browser"},
            ).json()
            client.headers["x-csrf-token"] = auth["csrf_token"]
            lab = next(
                item for item in request("GET", "/labs").json()["items"] if item["kind"] == "demo"
            )
            campaign = request(
                "POST",
                "/campaigns",
                json={
                    "name": "Disposable ATT&CK review acceptance",
                    "objective": "Preserve one synthetic historical report",
                    "laboratory_id": lab["id"],
                    "test_ids": ["demo-powershell"],
                },
            ).json()
            run = request(
                "POST",
                f"/campaigns/{campaign['id']}/runs",
                json={"idempotency_key": uuid.uuid4().hex},
            ).json()
            request(
                "POST",
                f"/executions/{run['id']}/approve",
                json={"confirm_scope_hash": run["scope_hash"]},
            )
            request("POST", f"/executions/{run['id']}/start", json={"confirm": True})
            for _ in range(100):
                state = request("GET", f"/executions/{run['id']}").json()["state"]
                if state == "COMPLETED":
                    break
                time.sleep(0.15)
            else:
                raise RuntimeError("Synthetic Demo run did not complete")
            reports = {
                kind: request("GET", f"/reports/{run['id']}?format={kind}").content
                for kind in ("json", "html", "pdf")
            }
            assert json.loads(reports["json"])["run"]["synthetic"] is True
            plan = cli("plan", document.identity)
            assert not plan["blockers"]
            summary["counts"] = plan["counts"]
            summary["review_before"] = browser("before", plan["plan_sha256"])
            published = cli(
                "apply",
                document.identity,
                "--confirm-plan",
                plan["plan_sha256"],
                "--actor",
                actor_id,
            )
            assert published["status"] == "applied"
            summary["publication"] = published
            assert (
                client.get(
                    "/api/v1/catalog/attack/reviews/" + plan["plan_sha256"] + "/instruction"
                ).status_code
                == 409
            )
            fresh = cli("plan", document.identity)
            assert fresh["action"] == "already_applied"
            summary["review_after"] = browser("after", fresh["plan_sha256"], plan["plan_sha256"])
            for kind, raw in reports.items():
                assert request("GET", f"/reports/{run['id']}?format={kind}").content == raw
            summary["historical_report_sha256"] = {
                kind: hashlib.sha256(raw).hexdigest() for kind, raw in reports.items()
            }
            summary["run_id"] = run["id"]
            with Session(engine) as db:
                releases = list(db.scalars(select(AttackCatalogRelease)))
                assert any(row.document == initial_release for row in releases)
                summary["release_count"] = len(releases)
            summary["status"] = "VERIFIED"
    finally:
        for process, stream in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            stream.close()
        engine.dispose()
        with admin_engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()
        if "actor_id" in locals():
            from aegis.security import token_hash

            Redis.from_url(env["REDIS_URL"]).delete(
                "aegis:limit:" + token_hash("attack-review:" + actor_id),
                "aegis:limit:" + token_hash("login-account:" + username),
            )
        assert original_files == {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (args.candidate_cache / args.candidate_id).iterdir()
        }
        summary["cleanup"] = (
            "processes stopped; disposable schema dropped; original cache preserved"
        )
        artifacts.write(output / "summary.json", artifacts.encode(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
