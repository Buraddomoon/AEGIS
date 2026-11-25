"""Two synthetic Demo labs and offline registry UI in an isolated schema/Firefox."""

import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
from aegis.config import settings
from aegis.models import Asset, Laboratory, User
from aegis.security import hasher, token_hash
from aegis.seed import seed
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]


def main():
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", 18789))
    parent = ROOT / ".local/lab-registry"
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent))
    admin_engine = create_engine(settings().database_url)
    schema = "aegis_registry_e2e_" + uuid.uuid4().hex
    url = admin_engine.url.update_query_dict({"options": "-csearch_path=" + schema})
    engine = create_engine(url)
    files = {}
    for field in ("server_ca", "client_cert", "client_key"):
        path = output / field
        path.write_text("Offline fixture bytes; not valid PKI; no transport permitted.")
        path.chmod(0o600)
        files[field] = str(path)
    registry = output / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "format": "aegis-linux-registry/1",
                "entries": [
                    {
                        "id": "offline-reviewed",
                        "revision": 1,
                        "owner": "Offline reviewed owner",
                        "isolation": "Offline UI fixture; no endpoint contacted or execution authorized.",
                        "connection": {
                            "url": "https://192.168.253.2:8443",
                            "runner_id": str(uuid.uuid4()),
                            "laboratory_id": str(uuid.uuid4()),
                            "asset_id": str(uuid.uuid4()),
                            **files,
                        },
                    }
                ],
            }
        )
    )
    registry.chmod(0o600)
    env = {
        **os.environ,
        "DATABASE_URL": url.render_as_string(hide_password=False),
        "REDIS_URL": settings().redis_url.rsplit("/", 1)[0] + "/15",
        "PUBLIC_ORIGIN": "http://localhost:18789",
        "DEMO_STEP_SECONDS": "0",
        "LINUX_RUNNER_REGISTRY": str(registry),
    }
    username, password = "registry-e2e-" + uuid.uuid4().hex[:10], secrets.token_urlsafe(32)
    processes = []
    actor_id = None
    summary = {
        "synthetic": True,
        "deployed": False,
        "native_lab_contacted": False,
        "status": "FAILED",
    }
    with admin_engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        with (output / "migration.log").open("w") as log:
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=log,
                check=True,
                timeout=30,
            )
        with Session(engine) as db:
            first = seed(db)["laboratory_id"]
            second = Laboratory(
                name="Second Demo registry",
                description="Synthetic E2E",
                kind="demo",
                authorized=True,
                owner="Fixture",
                isolation="In-memory synthetic adapters only",
            )
            windows = Laboratory(
                name="Windows unavailable fixture",
                description="No Windows adapter",
                kind="windows",
                authorized=False,
                owner="Fixture",
                isolation="Offline fixture only",
            )
            actor = User(
                username=username, password_hash=hasher.hash(password), role="administrator"
            )
            db.add_all([second, windows, actor])
            db.flush()
            actor_id = actor.id
            db.add_all(
                [
                    Asset(
                        laboratory_id=second.id,
                        name="Second synthetic endpoint",
                        platform="Synthetic",
                        external_id="fixture-" + uuid.uuid4().hex,
                        synthetic=True,
                    ),
                    Asset(
                        laboratory_id=windows.id,
                        name="Windows no adapter",
                        platform="Windows",
                        external_id="fixture-" + uuid.uuid4().hex,
                        synthetic=False,
                    ),
                ]
            )
            db.commit()
            lab_ids = [first, second.id]
            asset_ids = [
                db.scalar(select(Asset.id).where(Asset.laboratory_id == identifier))
                for identifier in lab_ids
            ]
        for name, args in [
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
                    "18789",
                ],
            ),
            ("worker", [sys.executable, "-m", "aegis.worker"]),
        ]:
            stream = (output / (name + ".log")).open("w")
            process = subprocess.Popen(
                args, cwd=ROOT, env=env, stdout=stream, stderr=stream, start_new_session=True
            )
            processes.append((process, stream))
        with httpx.Client(base_url=env["PUBLIC_ORIGIN"], trust_env=False, timeout=2) as client:
            for _ in range(100):
                try:
                    if client.get("/api/v1/health/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.15)
            else:
                raise RuntimeError("Disposable API unavailable")
        browser = subprocess.run(
            ["node", "lab-registry-e2e.mjs"],
            cwd=ROOT / "apps/web",
            env=env,
            input=json.dumps(
                {
                    "username": username,
                    "password": password,
                    "origin": env["PUBLIC_ORIGIN"],
                    "output": str(output),
                    "labs": lab_ids,
                    "assets": asset_ids,
                }
            ),
            text=True,
            capture_output=True,
            timeout=150,
        )
        (output / "browser.log").write_text(browser.stdout + browser.stderr)
        browser.check_returncode()
        summary.update(json.loads((output / "browser-summary.json").read_text()))
        summary["status"] = "VERIFIED"
    finally:
        for process, stream in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            stream.close()
        engine.dispose()
        with admin_engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()
        if actor_id:
            keys = ["login-account:" + username, "login-ip:127.0.0.1"] + [
                prefix + actor_id for prefix in ("linux-register:", "campaign-run:", "pdf-report:")
            ]
            redis = Redis.from_url(env["REDIS_URL"])
            try:
                redis.delete(*["aegis:limit:" + token_hash(key) for key in keys])
            finally:
                redis.close()
        summary["own_processes_stopped"] = all(p.poll() is not None for p, _ in processes)
        summary["schema_removed"] = True
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps({"output": str(output), **summary}))


if __name__ == "__main__":
    main()
