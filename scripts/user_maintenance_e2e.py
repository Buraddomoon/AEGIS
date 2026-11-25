"""Firefox account/RBAC flow against a fresh schema. No Demo or Lab account edits."""

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import httpx
from aegis.config import settings
from aegis.models import User
from aegis.security import hasher, token_hash
from aegis.seed import seed
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]


def main():
    parent = ROOT / ".local/user-maintenance"
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent))
    admin_engine = create_engine(settings().database_url)
    schema = "aegis_users_e2e_" + uuid.uuid4().hex
    url = admin_engine.url.update_query_dict({"options": "-csearch_path=" + schema})
    engine = create_engine(url)
    env = {
        **os.environ,
        "DATABASE_URL": url.render_as_string(hide_password=False),
        "REDIS_URL": settings().redis_url.rsplit("/", 1)[0] + "/15",
        "PUBLIC_ORIGIN": "http://localhost:18788",
    }
    username = "users-e2e-" + uuid.uuid4().hex[:12]
    password, replacement = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    actor_ids, names, process, stream = [], [username], None, None
    schema_ready = False
    summary = {"schema": schema, "synthetic": True, "deployed": False, "status": "FAILED"}
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
        schema_ready = True
        with Session(engine) as db:
            seed(db)
            actor = User(
                username=username, password_hash=hasher.hash(password), role="administrator"
            )
            db.add(actor)
            db.commit()
            actor_ids.append(actor.id)
        stream = (output / "api.log").open("w")
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "aegis.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "18788",
            ],
            cwd=ROOT,
            env=env,
            stdout=stream,
            stderr=stream,
            start_new_session=True,
        )
        with httpx.Client(base_url=env["PUBLIC_ORIGIN"], trust_env=False, timeout=2) as client:
            for _ in range(100):
                try:
                    if client.get("/api/v1/health/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.15)
            else:
                raise RuntimeError("Disposable API not ready")
        result = subprocess.run(
            ["node", "accounts-e2e.mjs"],
            cwd=ROOT / "apps/web",
            env=env,
            input=json.dumps(
                {
                    "username": username,
                    "password": password,
                    "replacement": replacement,
                    "origin": env["PUBLIC_ORIGIN"],
                    "output": str(output),
                }
            ),
            text=True,
            capture_output=True,
            timeout=180,
        )
        (output / "browser.log").write_text(result.stdout + result.stderr)
        result.check_returncode()
        summary.update(json.loads((output / "browser-summary.json").read_text()))
        summary["status"] = "VERIFIED"
    finally:
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            stream.close()
        try:
            if schema_ready:
                with Session(engine) as db:
                    for identifier, name in db.execute(select(User.id, User.username)):
                        actor_ids.append(identifier)
                        names.append(name)
            redis = Redis.from_url(env["REDIS_URL"])
            keys = [
                "aegis:limit:" + token_hash(prefix + value)
                for prefix, values in (
                    ("login-account:", names),
                    ("identity-write:", actor_ids),
                    ("user-create:", actor_ids),
                )
                for value in values
            ]
            # Loopback is exclusive to this harness while tests run sequentially.
            keys.append("aegis:limit:" + token_hash("login-ip:127.0.0.1"))
            try:
                redis.delete(*keys)
                summary["own_limiter_keys_removed"] = True
            finally:
                redis.close()
        finally:
            engine.dispose()
            with admin_engine.begin() as db:
                db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin_engine.dispose()
            summary["schema_removed"] = True
            summary["own_api_stopped"] = process is None or process.poll() is not None
            (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps({"output": str(output), **summary}))


if __name__ == "__main__":
    main()
