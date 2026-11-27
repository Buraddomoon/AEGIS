"""Firefox/API/TLS acceptance in disposable schema; no native lab or external request."""

import json
import os
import runpy
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from aegis.config import settings
from aegis.models import Asset, Laboratory, User
from aegis.security import hasher, token_hash
from aegis.seed import seed
from redis import Redis
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
PORT = 18790


def serve_fixture():
    """Explicit test process only: translate the asserted pin to our TLS loopback."""
    import uvicorn
    from httpcore._backends.anyio import AnyIOBackend

    original = AnyIOBackend.connect_tcp

    async def connect(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != "192.0.2.10":
            raise RuntimeError("E2E refuses any other outbound destination")
        return await original(
            self,
            "127.0.0.1",
            int(os.environ["AEGIS_FIXTURE_TLS_PORT"]),
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    AnyIOBackend.connect_tcp = connect
    uvicorn.run("aegis.main:app", host="127.0.0.1", port=PORT)


def main():
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", PORT))
    parent = ROOT / ".local/defensive-profiles"
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="acceptance-", dir=parent))
    pki = runpy.run_path(str(ROOT / "scripts/init_linux_lab.py"))["initialize"](output / "pki")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'{"version":{"number":"untrusted-upstream-text-must-not-escape"}}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki / "runner-server.crt", pki / "runner-server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    lab_id, asset_id = str(uuid.uuid4()), str(uuid.uuid4())
    username, password = "profiles-e2e-" + uuid.uuid4().hex[:10], secrets.token_urlsafe(32)
    files = {}
    for name in ("username", "password"):
        path = output / name
        path.write_text(secrets.token_urlsafe(32))
        path.chmod(0o600)
        files[name + "_file"] = str(path)
    registry = output / "profiles.json"
    registry.write_text(
        json.dumps(
            {
                "format": "aegis-defensive-profiles/1",
                "entries": [
                    {
                        "id": "offline-reviewed",
                        "revision": 1,
                        "url": "https://192.168.253.2:9200",
                        "allowed_ip": "192.0.2.10",
                        "ca_file": str(pki / "server-ca.crt"),
                        **files,
                        "policy": {
                            "laboratory_id": lab_id,
                            "asset_id": asset_id,
                            "agent_id": "007",
                            "expected_rule": "100200",
                        },
                    }
                ],
            }
        )
    )
    registry.chmod(0o600)
    admin_engine = create_engine(settings().database_url)
    schema = "aegis_profiles_e2e_" + uuid.uuid4().hex
    url = admin_engine.url.update_query_dict({"options": "-csearch_path=" + schema})
    engine = create_engine(url)
    env = {
        **os.environ,
        "DATABASE_URL": url.render_as_string(hide_password=False),
        "REDIS_URL": settings().redis_url.rsplit("/", 1)[0] + "/15",
        "PUBLIC_ORIGIN": f"http://localhost:{PORT}",
        "DEFENSIVE_PROFILES": str(registry),
        "AEGIS_FIXTURE_TLS_PORT": str(server.server_port),
    }
    summary = {
        "status": "FAILED",
        "synthetic": True,
        "deployed": False,
        "native_lab_contacted": False,
        "tls_fixture_only": True,
    }
    process, actor_id, stream = None, None, None
    created = False
    try:
        with admin_engine.begin() as db:
            db.execute(text(f'CREATE SCHEMA "{schema}"'))
        created = True
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
            seed(db)
            lab = Laboratory(
                id=lab_id,
                name="Offline defensive profile fixture",
                description="TLS loopback fixture only",
                kind="linux",
                authorized=False,
                owner="Fixture",
                isolation="No native runtime; TLS fixture on loopback only",
            )
            actor = User(
                username=username, password_hash=hasher.hash(password), role="administrator"
            )
            db.add_all([lab, actor])
            db.flush()
            actor_id = actor.id
            db.add(
                Asset(
                    id=asset_id,
                    laboratory_id=lab_id,
                    name="Offline defensive asset",
                    platform="Linux",
                    synthetic=False,
                    external_id="007",
                )
            )
            db.commit()
        stream = (output / "api.log").open("w")
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--serve-fixture"],
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
        browser = subprocess.run(
            ["node", "defensive-profiles-e2e.mjs"],
            cwd=ROOT / "apps/web",
            env=env,
            input=json.dumps(
                {
                    "username": username,
                    "password": password,
                    "origin": env["PUBLIC_ORIGIN"],
                    "output": str(output),
                    "lab_id": lab_id,
                }
            ),
            text=True,
            capture_output=True,
            timeout=120,
        )
        (output / "browser.log").write_text(browser.stdout + browser.stderr)
        browser.check_returncode()
        summary.update(json.loads((output / "browser-summary.json").read_text()))
        assert requests == ["/"], requests
        summary["tls_requests"] = requests
        summary["status"] = "VERIFIED"
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if stream:
            stream.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        try:
            if actor_id:
                redis = Redis.from_url(env["REDIS_URL"])
                keys = ["login-account:" + username, "login-ip:127.0.0.1"] + [
                    p + actor_id for p in ("wazuh-binding:", "wazuh-test:")
                ]
                try:
                    redis.delete(*["aegis:limit:" + token_hash(k) for k in keys])
                finally:
                    redis.close()
        finally:
            engine.dispose()
            if created:
                with admin_engine.begin() as db:
                    db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin_engine.dispose()
            summary["schema_removed"] = created
            summary["own_processes_stopped"] = (
                process is None or process.poll() is not None
            ) and not thread.is_alive()
            (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps({"output": str(output), **summary}))


if __name__ == "__main__":
    if sys.argv[1:] == ["--serve-fixture"]:
        serve_fixture()
    elif not sys.argv[1:]:
        main()
    else:
        raise SystemExit("Unexpected arguments")
