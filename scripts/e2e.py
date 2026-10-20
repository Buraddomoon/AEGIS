"""Browser E2E with real API, worker, PostgreSQL and Redis, in a disposable schema."""

import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

from aegis.config import settings
from sqlalchemy import create_engine, text

root = Path(__file__).resolve().parents[1]
schema = "aegis_e2e_" + uuid.uuid4().hex
admin_engine = create_engine(settings().database_url)
url = admin_engine.url.set(query={"options": f"-csearch_path={schema}"}).render_as_string(
    hide_password=False
)
env = {
    **os.environ,
    "DATABASE_URL": url,
    "REDIS_URL": settings().redis_url.rsplit("/", 1)[0] + "/14",
    "PUBLIC_ORIGIN": "http://localhost:18784",
    "DEMO_STEP_SECONDS": "0.1",
}
username, password = "portfolio-demo", secrets.token_urlsafe(24)
processes = []
logs = root / ".local/e2e"
logs.mkdir(parents=True, exist_ok=True)
with admin_engine.begin() as conn:
    conn.execute(text(f'CREATE SCHEMA "{schema}"'))
try:
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"], cwd=root, env=env, check=True
    )
    bootstrap = """
import json,sys
from aegis.db import session_factory
from aegis.models import User
from aegis.security import hasher
from aegis.seed import seed
data=json.load(sys.stdin)
with session_factory()() as db:
    seed(db)
    db.add(User(username=data['username'],password_hash=hasher.hash(data['password']),role='administrator'))
    db.commit()
"""
    subprocess.run(
        [sys.executable, "-c", bootstrap],
        input=json.dumps({"username": username, "password": password}),
        text=True,
        cwd=root,
        env=env,
        check=True,
    )
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
                "18784",
            ],
        ),
        ("worker", [sys.executable, "-m", "aegis.worker"]),
    ]:
        stream = (logs / (name + ".log")).open("w")
        process = subprocess.Popen(
            args, cwd=root, env=env, stdout=stream, stderr=stream, start_new_session=True
        )
        processes.append((process, stream))
    for _ in range(100):
        try:
            with urllib.request.urlopen(
                "http://localhost:18784/api/v1/health/ready", timeout=1
            ) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(0.15)
    else:
        raise RuntimeError("E2E API not ready; see .local/e2e/api.log")
    subprocess.run(
        ["node", "e2e.mjs"],
        input=json.dumps(
            {"username": username, "password": password, "origin": "http://localhost:18784"}
        ),
        text=True,
        cwd=root / "apps/web",
        env=env,
        check=True,
        timeout=180,
    )
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
    with admin_engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    admin_engine.dispose()
