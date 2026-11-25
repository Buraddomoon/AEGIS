"""Fixed helper for the new #104 database only; never an original Lab recipe."""

import json
import os
import sys
import time
from pathlib import Path

from sqlalchemy import delete, func, select, text
from sqlalchemy.engine import make_url

SECRETS = Path("/run/secrets")
SCHEMA = "e2a71c9d064b"


def secret(name):
    raw = (SECRETS / name).read_text()
    if not 1 <= len(raw) <= 128 * 1024:
        raise ValueError("private_input_invalid")
    return raw


def configure(owner):
    plan = json.loads(secret("plan"))
    if (
        plan["format"] != "aegis-scheduling104-native/1"
        or plan["occurrences"] != 2
        or plan["test_id"] != "linux-file-marker/v1"
        or plan["original_volumes"] != []
    ):
        raise ValueError("dedicated_scope_required")
    uri = secret("owner_url" if owner else "runtime_url")
    url = make_url(uri)
    if (url.host, url.port, url.database, url.username) != (
        "db",
        5432,
        "schedule104",
        "schedule104_owner" if owner else "aegis_app",
    ) or url.query:
        raise ValueError("fresh_schedule104_database_required")
    os.environ.update(
        DATABASE_URL=uri,
        REDIS_URL=secret("redis_url"),
        PUBLIC_ORIGIN=plan["origin"],
        LINUX_RUNNER_CONFIG="/run/secrets/runner_connection",
        LINUX_SCHEDULING_ENABLED="true",
        WEB_DIST="/app/apps/web/dist",
        DEMO_STEP_SECONDS="0",
    )
    for name in tuple(os.environ):
        if name.startswith("WAZUH_") or name == "SIGMA_VALIDATION_SCOPE":
            del os.environ[name]
    return plan


def accounts(plan):
    rows = json.loads(secret("accounts"))
    expected = {
        f"schedule104-{plan['workflow_run']}-{role}" for role in ("operator", "administrator")
    }
    if (
        len(rows) != 2
        or {row["username"] for row in rows} != expected
        or {row["role"] for row in rows} != {"operator", "administrator"}
        or any(len(row["password"]) < 32 for row in rows)
    ):
        raise ValueError("two_separate_own_accounts_required")
    return rows


def bootstrap(plan):
    from aegis.cli import grant_runtime
    from aegis.db import engine, session_factory
    from aegis.models import User
    from aegis.security import audit, hasher
    from aegis.seed import seed
    from alembic import command
    from alembic.config import Config

    with engine().connect() as connection:
        if connection.scalar(
            text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
        ) or connection.scalar(text("SELECT count(*) FROM pg_roles WHERE rolname='aegis_app'")):
            raise ValueError("nonempty_database_no_bootstrap_retry")
    command.upgrade(Config("/app/alembic.ini"), SCHEMA)
    with session_factory()() as db:
        seed(db)
        for row in accounts(plan):
            user = User(
                username=row["username"],
                role=row["role"],
                password_hash=hasher.hash(row["password"]),
            )
            db.add(user)
            db.flush()
            audit(db, None, "scheduling104.account_created", user.id, synthetic=False)
        db.commit()
    os.environ["APP_DB_PASSWORD"] = secret("app_password")
    try:
        grant_runtime()
    finally:
        del os.environ["APP_DB_PASSWORD"]
    with engine().connect() as connection:
        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == SCHEMA
        assert (
            connection.scalar(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
            )
            == 36
        )
        assert connection.scalar(text("SELECT count(*) FROM campaign_runs")) == 0
        assert connection.scalar(text("SELECT count(*) FROM schedules")) == 0
        assert all(
            connection.execute(
                text(
                    "SELECT NOT has_table_privilege('aegis_app','runner_receipts','UPDATE'), NOT has_table_privilege('aegis_app','schedule_occurrences','DELETE'), NOT has_column_privilege('aegis_app','schedules','scope','UPDATE')"
                )
            ).one()
        )
    print(
        json.dumps({"status": "FRESH_SCHEMA_AND_GRANTS_VERIFIED", "schema": SCHEMA, "effects": 0})
    )


def disable(plan):
    from aegis import binding_review, scheduling
    from aegis.db import session_factory
    from aegis.models import (
        CampaignRun,
        Laboratory,
        LoginSession,
        RunnerCleanup,
        RunnerDispatch,
        Schedule,
        ScheduleAuthorization,
        TestExecution,
        User,
    )
    from aegis.security import audit

    rows = accounts(plan)
    with session_factory()() as db:
        people = db.scalars(
            select(User).where(User.username.in_([row["username"] for row in rows]))
        ).all()
        assert len(people) == 2
        admin = next(person for person in people if person.role == "administrator")
        for item in db.scalars(
            select(Schedule).where(Schedule.laboratory_id == plan["identity"]["laboratory_id"])
        ):
            scheduling.stop_schedule(db, item.id, admin, revoke=True)
        lab = db.get(Laboratory, plan["identity"]["laboratory_id"])
        if lab and lab.authorized:
            lab.authorized = False
            lab.environment_version += 1
            audit(db, admin.id, "scheduling104.lab_revoked", lab.id, synthetic=False)
        ids = [person.id for person in people]
        for person in people:
            person.active = False
            db.execute(delete(LoginSession).where(LoginSession.user_id == person.id))
            audit(db, None, "scheduling104.account_disabled", person.id, synthetic=False)
        db.commit()
    safe = False
    counts = {}
    for _ in range(35):
        with session_factory()() as db:
            lab = db.get(Laboratory, plan["identity"]["laboratory_id"])
            safe = lab is None or not binding_review.review(db, lab)["blockers"]
            assert all(not db.get(User, identifier).active for identifier in ids)
            assert not db.scalar(select(LoginSession).where(LoginSession.user_id.in_(ids)))
            if safe:
                assert not lab or not lab.authorized and lab.active_run_id is None
                assert not db.scalar(
                    select(ScheduleAuthorization).where(ScheduleAuthorization.revoked_at.is_(None))
                )
                counts = {
                    name: db.scalar(select(func.count()).select_from(model))
                    for name, model in (
                        ("runs", CampaignRun),
                        ("dispatches", RunnerDispatch),
                        ("cleanups", RunnerCleanup),
                        ("tests", TestExecution),
                    )
                }
                break
        time.sleep(1)
    print(
        json.dumps(
            {
                "status": "OWN_AUTHORIZATION_AND_ACCOUNTS_DISABLED",
                "safe_to_stop": safe,
                "accounts_inactive": 2,
                "own_sessions": 0,
                **counts,
            }
        )
    )


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in {"bootstrap", "api", "worker", "disable"}:
        raise ValueError("closed_action_required")
    plan = configure(owner=action in {"bootstrap", "disable"})
    if action == "api":
        import uvicorn

        uvicorn.run(
            "aegis.main:app", host="0.0.0.0", port=8080, access_log=False, proxy_headers=False
        )
    elif action == "worker":
        from aegis.worker import main as worker

        worker()
    else:
        {"bootstrap": bootstrap, "disable": disable}[action](plan)


if __name__ == "__main__":
    main()
