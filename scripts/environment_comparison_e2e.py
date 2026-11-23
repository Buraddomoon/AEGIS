"""Two Demo laboratories/browser exports in a disposable schema; never starts a Lab."""

import hashlib
import html
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from io import BytesIO
from pathlib import Path

import httpx
from aegis.catalog.artifacts import encode, write
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.models import Asset, Laboratory, User
from aegis.security import hasher, token_hash
from aegis.seed import seed
from pypdf import PdfReader
from redis import Redis
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]


def main():
    parent = ROOT / ".local/environment-comparison"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent))
    admin_engine = create_engine(settings().database_url)
    schema = "aegis_environment_e2e_" + uuid.uuid4().hex
    url = admin_engine.url.update_query_dict({"options": "-csearch_path=" + schema})
    engine = create_engine(url)
    env = {
        **os.environ,
        "DATABASE_URL": url.render_as_string(hide_password=False),
        "REDIS_URL": settings().redis_url.rsplit("/", 1)[0] + "/15",
        "PUBLIC_ORIGIN": "http://localhost:18787",
        "DEMO_STEP_SECONDS": "0",
    }
    username, password = "environment-e2e-" + uuid.uuid4().hex[:10], secrets.token_urlsafe(32)
    processes, summary = [], {"schema": schema, "synthetic": True, "output": str(output)}
    with admin_engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        with (output / "migration.log").open("w") as log:
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                env=env,
                cwd=ROOT,
                stdout=log,
                stderr=log,
                check=True,
                timeout=30,
            )
        with Session(engine) as db:
            first = seed(db)["laboratory_id"]
            lab = Laboratory(
                name="Second Demo",
                description="Disposable synthetic lab",
                owner="Fixture",
                kind="demo",
                authorized=True,
                isolation="In-memory",
            )
            actor = User(
                username=username, password_hash=hasher.hash(password), role="administrator"
            )
            db.add_all([lab, actor])
            db.flush()
            second, actor_id = lab.id, actor.id
            db.add(
                Asset(
                    laboratory_id=second,
                    name="second-demo",
                    external_id=uuid.uuid4().hex,
                    platform="Synthetic",
                    synthetic=True,
                )
            )
            db.commit()
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
                    "18787",
                ],
            ),
            ("worker", [sys.executable, "-m", "aegis.worker"]),
        ):
            stream = (output / (name + ".log")).open("w")
            process = subprocess.Popen(
                arguments, cwd=ROOT, env=env, stdout=stream, stderr=stream, start_new_session=True
            )
            processes.append((process, stream))
        with httpx.Client(base_url=env["PUBLIC_ORIGIN"], timeout=30, trust_env=False) as client:
            for _ in range(100):
                try:
                    if client.get("/api/v1/health/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.15)
            else:
                raise RuntimeError("Disposable API not ready")
            login = client.post(
                "/api/v1/auth/login",
                headers={"x-aegis-request": "browser"},
                json={"username": username, "password": password},
            )
            login.raise_for_status()
            client.headers["x-csrf-token"] = login.json()["csrf_token"]

            def request(method, path, **kwargs):
                response = client.request(method, "/api/v1" + path, **kwargs)
                response.raise_for_status()
                return response

            runs = []
            for lab_id in (first, second):
                campaign = request(
                    "POST",
                    "/campaigns",
                    json={
                        "name": "Environment Demo",
                        "objective": "Verify historical comparison without native effects.",
                        "laboratory_id": lab_id,
                        "test_ids": ["demo-shell"],
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
                for _ in range(200):
                    detail = request("GET", f"/executions/{run['id']}").json()
                    if detail["state"] == "COMPLETED":
                        break
                    if detail["state"] in ("FAILED", "CANCELLED"):
                        raise RuntimeError("Synthetic campaign failed")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Synthetic campaign did not complete")
                runs.append(run)
            historical = {
                kind: request("GET", f"/reports/{runs[0]['id']}?format={kind}").content
                for kind in ("json", "html", "pdf")
            }
            browser = subprocess.run(
                ["node", "environment-comparison-e2e.mjs"],
                cwd=ROOT / "apps/web",
                env=env,
                input=json.dumps(
                    {
                        "username": username,
                        "password": password,
                        "origin": env["PUBLIC_ORIGIN"],
                        "output": str(output),
                        "before": first,
                        "after": second,
                        "campaign": runs[0]["campaign_id"],
                    }
                ),
                capture_output=True,
                text=True,
                timeout=150,
            )
            if browser.returncode:
                raise RuntimeError("Browser acceptance failed: " + browser.stderr)
            summary["browser"] = json.loads(browser.stdout)
            preview = json.loads((output / "preview.json").read_text())
            exported = json.loads((output / "comparison.json").read_text())
            assert preview == exported
            assert summary["browser"]["pdf_source_sha256"] == digest(preview)
            raw_html = (output / "comparison.html").read_text()
            embedded = html.unescape(raw_html.split("<pre>")[1].split("</pre>")[0])
            assert json.loads(embedded) == preview and "<script" not in raw_html
            assert preview["integrity_sha256"] == digest(
                {k: v for k, v in preview.items() if k != "integrity_sha256"}
            )
            pages = PdfReader(BytesIO((output / "comparison.pdf").read_bytes())).pages
            pdf_text = "\n".join(p.extract_text() for p in pages)
            assert all("DADOS SINTÉTICOS" in p.extract_text() for p in pages)
            assert preview["integrity_sha256"] in pdf_text
            assert all(run["id"] in pdf_text for run in runs)
            summary["pdf_pages"] = len(pages)
            for kind, raw in historical.items():
                assert request("GET", f"/reports/{runs[0]['id']}?format={kind}").content == raw
            summary["historical_sha256"] = {
                k: hashlib.sha256(v).hexdigest() for k, v in historical.items()
            }
            summary["snapshot_sha256"] = preview["integrity_sha256"]
            summary["completed_synthetic_runs"] = [r["id"] for r in runs]
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
        with admin_engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()
        if "actor_id" in locals():
            Redis.from_url(env["REDIS_URL"]).delete(
                *[
                    "aegis:limit:" + token_hash(key)
                    for key in (
                        "login-account:" + username,
                        "analysis-report:" + actor_id,
                        "pdf-report:" + actor_id,
                        "campaign-run:" + actor_id,
                    )
                ]
            )
        summary["cleanup"] = (
            "own processes stopped; disposable schema dropped; own rate-limit keys removed"
        )
        write(output / "summary.json", encode(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
