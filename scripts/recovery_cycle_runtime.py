"""Host-only children for the bounded fresh Demo cycle; no network publication."""

import json
import re
import secrets
import tempfile
from datetime import UTC, datetime

from aegis.operations import recovered_demo

REDIS_COMMAND = """umask 077
printf 'bind 127.0.0.1\\nport 6379\\nprotected-mode yes\\nsave ""\\nappendonly no\\nmaxmemory 64mb\\nmaxmemory-policy noeviction\\nrequirepass %s\\n' "$RECOVERY_REDIS_PASSWORD" > /tmp/aegis-redis.conf
unset RECOVERY_REDIS_PASSWORD
exec redis-server /tmp/aegis-redis.conf"""
LABEL = "io.aegis.recovery"


def run_cycle(driver, database_name, token, image, redis_image, intents, plan_hash, cleanup_state):
    from aegis.security import hasher

    fresh = recovered_demo.context(token)
    if database_name != "aegis-recovery-" + token or any(
        not re.fullmatch(r"sha256:[a-f0-9]{64}", v) for v in (image, redis_image)
    ):
        raise ValueError("Fresh cycle clone/image identity refused")
    password, app_password, redis_password = (secrets.token_hex(32) for _ in range(3))
    bootstrap = driver.clone_json(
        database_name,
        token,
        recovered_demo.prepare_sql(token, plan_hash, hasher.hash(password), app_password),
    )
    if bootstrap.get("format") != recovered_demo.FORMAT or any(
        bootstrap.get(key) != fresh[key] for key in ("account_id", "laboratory_id", "asset_id")
    ):
        raise ValueError("Fresh cycle bootstrap identity mismatch")
    driver.configure_hba("aegis_app")
    attempted = []
    names = {
        role: "aegis-recovery-cycle-" + role + "-" + token for role in ("redis", "api", "worker")
    }
    runtime_env = {
        "OPERATING_MODE": "normal",
        "DATABASE_URL": "postgresql+psycopg://aegis_app:"
        + app_password
        + "@127.0.0.1:5432/aegis_restore",
        "REDIS_URL": "redis://:" + redis_password + "@127.0.0.1:6379/0",
        "PUBLIC_ORIGIN": "http://127.0.0.1:8080",
        "SECURE_COOKIES": "false",
        "DEMO_STEP_SECONDS": "0",
    }

    def create(role, selected_image, environment, command, memory):
        name = names[role]
        driver.write_json(
            intents / (token + "-cycle-" + role + ".json"),
            {
                "clone_name": name,
                "ownership_token": token,
                "database_clone": database_name,
                "image_id": selected_image,
                "intent_at": datetime.now(UTC).isoformat(),
            },
        )
        attempted.append(role)
        cleanup_state["attempted"] = True
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as env:
            for key, value in environment.items():
                env.write(key + "=" + value + "\n")
            env.flush()
            args = [
                "create",
                "--pull=never",
                "--name",
                name,
                "--label",
                LABEL + "=" + token,
                "--network=container:" + database_name,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--user=10001:10001",
                "--memory=" + memory,
                "--cpus=1",
                "--pids-limit=64",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--env-file",
                env.name,
            ]
            if role == "redis":
                args += ["--tmpfs", "/data:rw,noexec,nosuid,size=16m", "--entrypoint", "/bin/sh"]
            driver.docker(*args, selected_image, *command)
        driver.docker("start", name)

    def remove(role):
        name = names[role]
        exact = (
            driver.docker("ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}")
            .decode()
            .split()
        )
        if exact:
            if (
                exact != [name]
                or driver.docker(
                    "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name
                )
                .decode()
                .strip()
                != token
            ):
                raise ValueError("Fresh cycle cleanup ownership mismatch")
            driver.docker("stop", "--time=10", name, timeout=25)
        result = driver.remove_clone(name, token)
        driver.write_json(
            intents / (token + "-cycle-" + role + "-cleanup.json"),
            {"clone_name": name, "state": result, "at": datetime.now(UTC).isoformat()},
        )

    try:
        create(
            "redis",
            redis_image,
            {"RECOVERY_REDIS_PASSWORD": redis_password},
            ["-c", REDIS_COMMAND],
            "128m",
        )
        create(
            "api",
            image,
            runtime_env,
            [
                "uvicorn",
                "aegis.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--no-proxy-headers",
                "--no-access-log",
            ],
            "384m",
        )
        create("worker", image, runtime_env, ["python", "-m", "aegis.worker"], "256m")
        with tempfile.TemporaryFile() as stream:
            stream.write(json.dumps({"recovery_id": token, "password": password}).encode())
            stream.seek(0)
            probe = json.loads(
                driver.docker(
                    "exec",
                    "-i",
                    names["api"],
                    "python",
                    "-m",
                    "aegis.operations.recovery_cycle_probe",
                    stdin=stream,
                    timeout=120,
                )
            )
        if (
            probe.get("format") != recovered_demo.FORMAT
            or probe.get("synthetic") is not True
            or probe.get("state") != "COMPLETED"
            or probe.get("fresh_account_id") != fresh["account_id"]
            or probe.get("laboratory_id") != fresh["laboratory_id"]
            or probe.get("new_lab_revoked") is not True
            or probe.get("session_closed") is not True
            or probe.get("outcomes")
            != {"DETECTED": 1, "OBSERVED_NOT_ALERTED": 1, "NO_TELEMETRY": 1, "INCONCLUSIVE": 1}
            or not re.fullmatch(r"[a-f0-9]{64}", probe.get("report_sha256", ""))
        ):
            raise ValueError("Fresh cycle probe assertions failed")
        # Stop/remove the worker before owner-only final integrity/closure locks.
        remove("worker")
        attempted.remove("worker")
        closed = driver.clone_json(
            database_name, token, recovered_demo.close_sql(token, probe["run_id"])
        )
        if (
            closed.get("format") != recovered_demo.FORMAT
            or closed.get("historical_rows_unchanged") is not True
            or closed.get("fresh_account_disabled") is not True
            or closed.get("fresh_sessions_remaining") != 0
            or closed.get("pending_runs") != 0
            or closed.get("baseline_rows") != bootstrap.get("baseline_rows")
        ):
            raise ValueError("Fresh cycle closure assertions failed")
        result = {
            **probe,
            "closure": closed,
            "external_network": False,
            "normal_demo_cycle_verified": True,
        }
    finally:
        # Reverse dependency order. A failure retains remaining dependencies/DB.
        for role in reversed(attempted):
            remove(role)
        cleanup_state["confirmed"] = True
    return result
