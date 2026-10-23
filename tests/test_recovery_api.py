"""Quarantine routing and a real, disposable PostgreSQL recovery database."""

import json
import uuid
from datetime import timedelta

import pytest
from aegis import db
from aegis.config import Settings, settings
from aegis.main import create_app
from aegis.models import Approval, Campaign, CampaignRun, Laboratory, LoginSession, User, now
from aegis.operations import recovery
from aegis.seed import seed
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

TOKEN = "ephemeral-recovery-test-token-" + "a" * 32


def recovery_app(**overrides):
    return create_app(
        Settings(
            _env_file=None, operating_mode="recovery", recovery_access_token=TOKEN, **overrides
        )
    )


@pytest.mark.parametrize(
    "path,method",
    [
        ("/api/v1/auth/login", "POST"),
        ("/api/v1/auth/me", "GET"),
        ("/api/v1/campaigns", "POST"),
        ("/api/v1/executions/old/start", "POST"),
        ("/api/v1/schedules", "GET"),
        ("/api/docs", "GET"),
        ("/api/openapi.json", "GET"),
        ("/", "GET"),
        ("/api/v1/recovery/review", "POST"),
        ("/api/v1/health/live", "HEAD"),
    ],
)
def test_recovery_does_not_mount_normal_routes_or_accept_old_sessions(path, method, monkeypatch):
    monkeypatch.setattr(db, "engine", lambda: pytest.fail("Normal route reached database"))
    with TestClient(recovery_app()) as client:
        result = client.request(
            method, path, headers={"cookie": "aegis_session=old-restored-session"}
        )
        assert result.status_code == 503
        assert result.headers["cache-control"] == "no-store"


def test_independent_token_required_and_health_does_not_use_redis(monkeypatch):
    monkeypatch.setattr(db, "engine", lambda: pytest.fail("Unauthorized database access"))
    with TestClient(recovery_app()) as client:
        assert client.get("/api/v1/health/live").json() == {"status": "live", "mode": "recovery"}
        for path in ("/api/v1/health/ready", "/api/v1/recovery/review"):
            for token in ("", "old-session", "incorrect-test-token"):
                assert (
                    client.get(path, headers={"x-aegis-recovery-token": token}).status_code == 401
                )


def test_weak_or_absent_token_refuses_boot():
    for token in (None, "short"):
        with pytest.raises(RuntimeError, match="independent"):
            create_app(
                Settings(_env_file=None, operating_mode="recovery", recovery_access_token=token)
            )


@pytest.fixture
def recovered_database(monkeypatch):
    # Separate temporary database, not the live database's schema or PUBLIC grants.
    identifier = "aegis_recovery_test_" + uuid.uuid4().hex
    owner = create_engine(settings().database_url, isolation_level="AUTOCOMMIT")
    owner_url = owner.url.set(database=identifier)
    writer = reader = None
    created = role_created = False
    try:
        with owner.connect() as c:
            c.execute(text(f'CREATE DATABASE "{identifier}" TEMPLATE template0'))
            created = True
            c.execute(text(f'CREATE ROLE "{identifier}" LOGIN NOINHERIT'))
            role_created = True
        writer = create_engine(owner_url)
        monkeypatch.setattr(db, "engine", lambda: writer)
        command.upgrade(Config("alembic.ini"), "head")
        with Session(writer) as session:
            seed(session)
        with writer.begin() as c:
            c.execute(text(f'REVOKE ALL ON DATABASE "{identifier}" FROM PUBLIC'))
            c.execute(text(f'GRANT CONNECT ON DATABASE "{identifier}" TO "{identifier}"'))
            c.execute(text("REVOKE ALL ON SCHEMA public FROM PUBLIC"))
            c.execute(text(f'GRANT USAGE ON SCHEMA public TO "{identifier}"'))
            c.execute(text(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{identifier}"'))
            c.execute(text("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC"))
            recovery.restrict_large_objects(c)
        # A real restricted identity without storing a test password.
        reader = create_engine(
            owner_url, connect_args={"options": "-c default_transaction_read_only=on"}
        )

        @event.listens_for(reader, "connect")
        def use_reader(connection, _):
            previous = connection.autocommit
            connection.autocommit = True
            connection.execute(f'SET SESSION AUTHORIZATION "{identifier}"')
            connection.autocommit = previous

        monkeypatch.setattr(db, "engine", lambda: reader)
        yield writer, reader
    finally:
        if reader:
            reader.dispose()
        if writer:
            writer.dispose()
        with owner.connect() as c:
            if created:
                c.execute(text(f'DROP DATABASE "{identifier}" WITH (FORCE)'))
            if role_created:
                c.execute(text(f'DROP ROLE "{identifier}"'))
        owner.dispose()


def test_boot_review_and_database_privileges_are_real(recovered_database):
    writer, reader = recovered_database
    with Session(writer) as session:
        lab = session.scalar(select(Laboratory))
        user = User(username="restored-operator", role="operator", password_hash="opaque-test-hash")
        session.add(user)
        session.flush()
        campaign = Campaign(
            name="Restored pending fixture",
            objective="Quarantine test",
            laboratory_id=lab.id,
            created_by=user.id,
        )
        session.add(campaign)
        session.flush()
        run = CampaignRun(
            campaign_id=campaign.id,
            laboratory_id=lab.id,
            requested_by=user.id,
            idempotency_key="restored-fixture",
            state="QUEUED",
            scope={},
            scope_hash="a" * 64,
        )
        session.add(run)
        session.flush()
        run_id = run.id
        lab.active_run_id = run_id
        session.add(
            Approval(
                run_id=run_id,
                approved_by=user.id,
                scope_hash=run.scope_hash,
                expires_at=now() + timedelta(hours=1),
                max_duration_seconds=60,
            )
        )
        for token, delta in (("a", 1), ("b", -1)):
            session.add(
                LoginSession(
                    token_hash=token * 64,
                    user_id=user.id,
                    csrf_hash="c" * 64,
                    expires_at=now() + timedelta(hours=delta),
                )
            )
        session.commit()
    with TestClient(recovery_app()) as client:
        headers = {"x-aegis-recovery-token": TOKEN}
        assert client.get("/api/v1/health/ready", headers=headers).status_code == 200
        result = client.get("/api/v1/recovery/review", headers=headers)
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["quarantined"] and not body["reconciliation_applied"]
        assert body["database_read_only"] and not body["normal_operation_permitted"]
        assert body["counts"]["authorized_laboratories"] == 1
        assert body["counts"]["sessions"] == 2
        assert body["counts"]["unexpired_sessions"] == 1
        assert body["counts"]["nonterminal_runs"] == 1
        assert body["counts"]["nonterminal_real_runs"] == 0
        assert body["counts"]["runs_by_state"] == {"QUEUED": 1}
        assert body["counts"]["laboratory_reservations"] == 1
        assert body["counts"]["unused_unexpired_approvals"] == 1
        assert "password" not in json.dumps(body) and TOKEN not in result.text
    with Session(writer) as session:
        assert session.get(CampaignRun, run_id).state == "QUEUED"
        assert session.scalar(select(Laboratory)).active_run_id == run_id
        assert session.scalar(select(Approval)).used_at is None
    with reader.connect() as c:
        c.execute(text("SET TRANSACTION READ WRITE"))
        for sql in (
            "DELETE FROM sessions",
            "CREATE TABLE forbidden (id int)",
            "CREATE TEMP TABLE forbidden (id int)",
            "SELECT pg_catalog.lo_create(0)",
        ):
            with pytest.raises(DBAPIError):
                c.execute(text(sql))
            c.rollback()
            c.execute(text("SET TRANSACTION READ WRITE"))
    with writer.connect() as c, pytest.raises(RuntimeError, match="restricted"):
        recovery.database_guard(c)


def test_incompatible_schema_and_privilege_drift_fail_closed(recovered_database):
    writer, _ = recovered_database
    headers = {"x-aegis-recovery-token": TOKEN}
    with writer.begin() as c:
        c.execute(text("UPDATE alembic_version SET version_num='incompatible'"))
    with TestClient(recovery_app()) as client:
        response = client.get("/api/v1/recovery/review", headers=headers)
        assert response.status_code == 503 and "incompatible" not in response.text
    with writer.begin() as c:
        c.execute(
            text("UPDATE alembic_version SET version_num=:v"), {"v": recovery.required_revision()}
        )
        role = c.scalar(text("SELECT rolname FROM pg_roles WHERE rolname = current_database()"))
        c.execute(text(f'GRANT UPDATE (expires_at) ON sessions TO "{role}"'))
    with TestClient(recovery_app()) as client:
        assert client.get("/api/v1/health/ready", headers=headers).status_code == 503


def test_large_object_function_grant_drift_blocks_readiness(recovered_database):
    writer, _ = recovered_database
    with writer.begin() as c:
        c.execute(text("GRANT EXECUTE ON FUNCTION pg_catalog.lo_create(oid) TO PUBLIC"))
    with TestClient(recovery_app()) as client:
        headers = {"x-aegis-recovery-token": TOKEN}
        assert client.get("/api/v1/health/ready", headers=headers).status_code == 503
        assert client.get("/api/v1/recovery/review", headers=headers).status_code == 503


def test_review_reports_recorded_reconciliation_but_remains_quarantined(recovered_database):
    writer, _ = recovered_database
    from aegis.models import AuditEvent

    with Session(writer) as session:
        session.add(
            AuditEvent(
                action="recovery.demo.reconciled",
                resource_id="a" * 32,
                details={"format": "aegis-demo-reconciliation/1"},
            )
        )
        session.commit()
    with TestClient(recovery_app()) as client:
        response = client.get("/api/v1/recovery/review", headers={"x-aegis-recovery-token": TOKEN})
        assert response.status_code == 200
        body = response.json()
        assert body["reconciliation_applied"] is False
        assert body["counts"]["recorded_demo_reconciliations"] == 1
        assert body["quarantined"] is True and body["normal_operation_permitted"] is False
        assert client.post("/api/v1/auth/login").status_code == 503


@pytest.mark.parametrize(
    "drift", [None, "wrong-id", "wrong-hash", "session", "active-user", "lab-authorized"]
)
def test_current_reconciliation_requires_exact_identity_hash_and_fences(recovered_database, drift):
    from aegis.models import AuditEvent

    writer, _ = recovered_database
    identity, fingerprint = "a" * 32, "b" * 64
    with Session(writer) as session:
        session.add(
            AuditEvent(
                action="recovery.demo.reconciled",
                resource_id=identity,
                details={
                    "format": "aegis-demo-reconciliation/1",
                    "plan_sha256": fingerprint,
                    "reconciliation_applied": True,
                    "normal_operation_permitted": False,
                    "external_cleanup_performed": False,
                },
            )
        )
        lab = session.scalar(select(Laboratory))
        lab.authorized = False
        if drift in {"session", "active-user"}:
            user = User(
                username="restored-drift",
                role="operator",
                password_hash="test",
                active=drift == "active-user",
            )
            session.add(user)
            session.flush()
            if drift == "session":
                session.add(
                    LoginSession(
                        token_hash="c" * 64,
                        csrf_hash="d" * 64,
                        user_id=user.id,
                        expires_at=now() + timedelta(hours=1),
                    )
                )
        if drift == "lab-authorized":
            lab.authorized = True
        session.commit()
    config = {
        "recovery_reconciliation_id": "f" * 32 if drift == "wrong-id" else identity,
        "recovery_reconciliation_hash": "f" * 64 if drift == "wrong-hash" else fingerprint,
    }
    with TestClient(recovery_app(**config)) as client:
        response = client.get("/api/v1/recovery/review", headers={"x-aegis-recovery-token": TOKEN})
        assert response.status_code == (200 if drift is None else 503)
        if drift is None:
            body = response.json()
            assert body["reconciliation_applied"] is True
            assert body["reconciliation_identity"] == identity
            assert body["reconciliation_plan_sha256"] == fingerprint
            assert body["normal_operation_permitted"] is False


def test_reconciliation_boot_requires_both_identity_and_hash():
    for config in (
        {"recovery_reconciliation_id": "a" * 32},
        {"recovery_reconciliation_hash": "b" * 64},
    ):
        with pytest.raises(RuntimeError, match="paired"):
            recovery_app(**config)
