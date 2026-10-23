"""Runs only inside the offline rehearsal API container; prints an aggregate receipt."""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

import psycopg

BASE = "http://127.0.0.1:8080"


def require_rehearsal_environment():
    # Refuse direct use against a host/operator DATABASE_URL before any I/O.
    if (
        os.environ.get("OPERATING_MODE") != "recovery"
        or not re.fullmatch(
            r"postgresql\+psycopg://aegis_recovery:[a-f0-9]{64}@127\.0\.0\.1:5432/aegis_restore",
            os.environ.get("DATABASE_URL", ""),
        )
        or not re.fullmatch(r"[a-f0-9]{64}", os.environ.get("RECOVERY_ACCESS_TOKEN", ""))
    ):
        raise RuntimeError("Probe restricted to the offline recovery rehearsal environment")


def request(path, *, method="GET", authenticated=True):
    headers = (
        {"x-aegis-recovery-token": os.environ["RECOVERY_ACCESS_TOKEN"]} if authenticated else {}
    )
    headers["Cookie"] = "aegis_session=restored-session-must-not-authorize"
    req = urllib.request.Request(BASE + path, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as result:
            return result.status, json.load(result)
    except urllib.error.HTTPError as error:
        return error.code, None


def main():
    require_rehearsal_environment()
    for _ in range(60):
        try:
            status, _ = request("/api/v1/health/ready")
            if status == 200:
                break
        except (OSError, ValueError):
            pass
        time.sleep(0.25)
    else:
        raise RuntimeError("Quarantined API did not become ready")
    status, review = request("/api/v1/recovery/review")
    if status != 200 or review.get("format") != "aegis-recovery-review/1":
        raise RuntimeError("Recovery review failed")
    blocked = {}
    for method, path, expected in (
        ("GET", "/api/v1/recovery/review", 401),
        ("GET", "/api/v1/health/ready", 401),
        ("POST", "/api/v1/auth/login", 503),
        ("GET", "/api/v1/auth/me", 503),
        ("POST", "/api/v1/campaigns", 503),
        ("POST", "/api/v1/executions/restored/start", 503),
        ("GET", "/api/v1/schedules", 503),
        ("GET", "/api/openapi.json", 503),
        ("GET", "/", 503),
    ):
        actual, _ = request(path, method=method, authenticated=False)
        if actual != expected:
            raise RuntimeError("Quarantine route fence failed")
        blocked[method + " " + path] = actual

    # Even overriding the read-only default must not grant DML/DDL/TEMP.
    uri = os.environ["DATABASE_URL"].replace("postgresql+psycopg:", "postgresql:", 1)
    denied = []
    with psycopg.connect(uri, connect_timeout=3) as connection:
        for sql in (
            "DELETE FROM sessions WHERE false",
            "CREATE TABLE recovery_forbidden (id int)",
            "CREATE TEMP TABLE recovery_forbidden (id int)",
            "SELECT pg_catalog.lo_create(0)",
        ):
            connection.execute("SET TRANSACTION READ WRITE")
            try:
                connection.execute(sql)
            except psycopg.errors.InsufficientPrivilege:
                denied.append(sql.split()[0] + (" TEMP" if " TEMP " in sql else ""))
                connection.rollback()
            else:
                raise RuntimeError("Recovery role obtained write privileges")
    try:
        psycopg.connect(
            host="127.0.0.1", dbname="aegis_restore", user="postgres", connect_timeout=3
        ).close()
    except psycopg.OperationalError:
        pass
    else:
        raise RuntimeError("Administrative TCP access remained possible")

    entrypoints = [
        ["-m", "aegis.worker"],
        ["-m", "aegis.cli", "seed"],
        ["-m", "aegis.cli", "grant-runtime"],
        [
            "-c",
            "import threading; from aegis.scheduling import scheduler_loop; scheduler_loop(threading.Event())",
        ],
        ["-m", "alembic", "upgrade", "head"],
    ]
    for args in entrypoints:
        result = subprocess.run([sys.executable, *args], capture_output=True, timeout=15)
        if result.returncode == 0 or b"quarentena" not in result.stderr:
            raise RuntimeError("Recovery entrypoint fence failed")
    print(
        json.dumps(
            {
                "review": review,
                "blocked_routes": blocked,
                "database_write_probes_denied": len(denied),
                "administrative_tcp_denied": True,
                "entrypoints_blocked": len(entrypoints),
            }
        )
    )


if __name__ == "__main__":
    main()
