"""Closed entrypoints for fresh, separate #80/#83 databases and runtimes.

Never installed in the historical Linux/Wazuh recipes. Host package verification
and human authorization must precede invoking these container entrypoints.
"""

import json
import os
import sys
from pathlib import Path

from aegis.lab_runner.assay_profile import selected
from sqlalchemy import delete, select, text
from sqlalchemy.engine import make_url

SECRETS = Path("/run/secrets")


def profile():
    path = SECRETS / "plan"
    return selected(json.loads(path.read_text()) if path.exists() else {})


def secret(name):
    value = (SECRETS / name).read_text()
    if not 1 <= len(value) <= 65536:
        raise ValueError("Invalid private input")
    return value


def configure(owner=False):
    current = profile()
    uri = secret("owner_url" if owner else "runtime_url")
    url = make_url(uri)
    if (url.host, url.port, url.database, url.username) != (
        "db",
        5432,
        current["database"],
        current["owner"] if owner else "aegis_app",
    ) or url.query:
        raise ValueError("Fresh assay database required")
    os.environ["DATABASE_URL"] = uri
    os.environ["REDIS_URL"] = secret("redis_url")
    os.environ["PUBLIC_ORIGIN"] = "http://192.168.253.4:8080"
    os.environ["LINUX_RUNNER_CONFIG"] = "/run/secrets/runner_connection"
    os.environ["WEB_DIST"] = "/assay/no-web"
    for key in tuple(os.environ):
        if key.startswith("WAZUH_"):
            del os.environ[key]


def accounts():
    rows = json.loads(secret("accounts"))
    if (
        len(rows) != 2
        or {row["role"] for row in rows} != {"administrator", "operator"}
        or len({row["username"] for row in rows}) != 2
        or any(not row["username"].startswith(profile()["prefix"]) for row in rows)
        or any(len(row["password"]) < 32 for row in rows)
    ):
        raise ValueError("Separate fresh accounts required")
    return rows


def bootstrap():
    from aegis.cli import grant_runtime
    from aegis.db import engine, session_factory
    from aegis.models import User
    from aegis.security import audit, hasher
    from aegis.seed import seed
    from alembic import command
    from alembic.config import Config

    # Both the dedicated database name and an empty public schema are mandatory.
    # This refuses originals or a previous ambiguous bootstrap; no repair/reset.
    with engine().connect() as connection:
        if connection.scalar(
            text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
        ):
            raise ValueError("Database not empty; preserve the attempt")
        if connection.scalar(text("SELECT count(*) FROM pg_roles WHERE rolname='aegis_app'")):
            raise ValueError("Runtime role already exists; preserve the attempt")
    command.upgrade(Config("/app/alembic.ini"), "c8e4a6d21f90")
    with session_factory()() as db:
        seed(db)
        for row in accounts():
            user = User(
                username=row["username"],
                role=row["role"],
                password_hash=hasher.hash(row["password"]),
            )
            db.add(user)
            db.flush()
            audit(db, None, profile()["name"] + ".account_created", user.id, synthetic=False)
        db.commit()
    os.environ["APP_DB_PASSWORD"] = secret("app_password")
    try:
        grant_runtime()
    finally:
        del os.environ["APP_DB_PASSWORD"]
    check()


def check():
    from aegis.db import engine

    current = profile()

    with engine().connect() as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "c8e4a6d21f90"
        assert (
            connection.scalar(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
            )
            == 36
        )
        assert connection.scalar(text("SELECT count(*) FROM campaign_runs")) == 0
        assert connection.scalar(text("SELECT count(*) FROM runner_dispatches")) == 0
        assert connection.scalar(text("SELECT count(*) FROM attack_catalog_state")) == 1
        assert connection.scalar(text("SELECT count(*) FROM laboratories WHERE kind<>'demo'")) == 0
        assert connection.scalar(text("SELECT count(*) FROM schedules")) == 0
        assert connection.scalar(text("SELECT count(*) FROM scheduled_reports")) == 0
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM test_definitions WHERE id=:id AND approved AND version=1 AND behavior=:behavior AND technique_id IS NOT DISTINCT FROM :technique"
                ),
                {
                    "id": current["definition_id"],
                    "behavior": current["review"]["behavior"],
                    "technique": current["review"]["technique_id"],
                },
            )
            == 1
        )
        assert all(
            connection.execute(
                text("""SELECT
          NOT has_table_privilege('aegis_app','alembic_version','SELECT'),
          NOT has_table_privilege('aegis_app','runner_receipts','UPDATE'),
          NOT has_table_privilege('aegis_app','runner_cleanups','DELETE'),
          NOT has_column_privilege('aegis_app','runner_dispatches','spec','UPDATE'),
          has_column_privilege('aegis_app','runner_dispatches','generation','UPDATE'),
          NOT has_table_privilege('aegis_app','atomic_reviews','UPDATE'),
          NOT has_table_privilege('aegis_app','atomic_reviews','DELETE')""")
            ).one()
        )
    print(json.dumps({"status": "fresh_c8_readonly_gate_passed", "effects_executed": False}))


def disable():
    from aegis import binding_review
    from aegis.db import session_factory
    from aegis.models import Laboratory, LoginSession, User
    from aegis.security import audit

    plan = json.loads(secret("plan"))
    with session_factory()() as db:
        lab = db.get(Laboratory, plan["identity"]["laboratory_id"])
        if lab and lab.authorized:
            lab.authorized = False
            lab.environment_version += 1
            audit(db, None, profile()["name"] + ".emergency_revoke", lab.id, synthetic=False)
        ids = []
        for row in accounts():
            user = db.scalar(select(User).where(User.username == row["username"]))
            if user:
                assert user.role == row["role"]
                user.active = False
                ids.append(user.id)
                db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
                audit(
                    db, user.id, profile()["name"] + ".account_disabled", user.id, synthetic=False
                )
        db.commit()
        assert all(not db.get(User, identifier).active for identifier in ids)
        assert not db.scalar(select(LoginSession).where(LoginSession.user_id.in_(ids)))
        assert not lab or not lab.authorized
        safe_to_stop = not lab or not binding_review.review(db, lab)["blockers"]
    print(
        json.dumps(
            {
                "status": "own_accounts_sessions_and_authorization_disabled",
                "accounts": len(ids),
                "safe_to_stop": safe_to_stop,
            }
        )
    )


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in {"bootstrap", "check", "api", "worker", "disable"}:
        raise ValueError("Unknown fixed entrypoint")
    configure(owner=action in {"bootstrap", "check", "disable"})
    if action == "api":
        import uvicorn

        uvicorn.run(
            "aegis.main:app", host="0.0.0.0", port=8080, proxy_headers=False, access_log=False
        )
    elif action == "worker":
        from aegis.worker import main as worker

        worker()
    else:
        {"bootstrap": bootstrap, "check": check, "disable": disable}[action]()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "blocked", "code": "atomic80_service_failed"}))
        raise SystemExit(1) from None
