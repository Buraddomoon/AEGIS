"""Real restored-DB cycle with the restricted runtime role and normal API/worker."""

import secrets
import threading
import uuid

import pytest
from aegis import db, worker
from aegis.config import settings
from aegis.main import create_app
from aegis.operations import reconciliation
from aegis.operations import recovered_demo as recovered
from aegis.operations.recovery_cycle_probe import cycle, require_environment
from aegis.security import hasher, redis_client, token_hash
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from test_recovery_api import recovered_database as _recovered_database
from test_recovery_reconciliation import (
    RECOVERY_ID,
    get_inventory,
    get_plan,
    run_sql,
)
from test_recovery_reconciliation import (
    recovered_work as _recovered_work,
)

recovered_database = _recovered_database
recovered_work = _recovered_work


@pytest.fixture
def fresh_destination(recovered_work, monkeypatch):
    writer, _ = recovered_work
    plan = get_plan(writer)
    run_sql(writer, reconciliation.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    token = RECOVERY_ID
    role = "aegis_cycle_test_" + uuid.uuid4().hex
    password = secrets.token_hex(32)
    account_hash = hasher.hash(password)
    runtime = None

    def adapt(statement):
        # Substitute only test deployment names, never change the tested grants.
        return (
            statement.replace("aegis_restore", writer.url.database)
            .replace("aegis_app", role)
            .replace("AUTHORIZATION postgres", 'AUTHORIZATION "' + writer.url.username + '"')
        )

    try:
        prepare = adapt(
            recovered.prepare_sql(token, plan["snapshot_sha256"], account_hash, "a" * 64)
        )
        bootstrap = run_sql(writer, prepare)
        runtime = create_engine(writer.url)

        @event.listens_for(runtime, "connect")
        def identity(connection, _):
            previous = connection.autocommit
            connection.autocommit = True
            connection.execute('SET SESSION AUTHORIZATION "' + role + '"')
            connection.autocommit = previous

        monkeypatch.setattr(db, "engine", lambda: runtime)
        monkeypatch.setattr(settings(), "redis_url", settings().redis_url.rsplit("/", 1)[0] + "/15")
        monkeypatch.setattr(settings(), "demo_step_seconds", 0)
        monkeypatch.setattr(worker, "stop", threading.Event())
        yield {
            "writer": writer,
            "runtime": runtime,
            "token": token,
            "password": password,
            "role": role,
            "adapt": adapt,
            "bootstrap": bootstrap,
            "plan_hash": plan["snapshot_sha256"],
        }
    finally:
        if runtime:
            runtime.dispose()
        with writer.begin() as c:
            if c.scalar(
                text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=:role)"), {"role": role}
            ):
                c.execute(text('DROP OWNED BY "' + role + '"'))
                c.execute(text('DROP ROLE "' + role + '"'))
        client = redis_client()
        client.delete(
            "aegis:limit:" + token_hash("login-ip:recovery-" + token),
            "aegis:limit:" + token_hash("login-account:recovery-" + token),
        )


def complete_cycle(destination):
    def work(_):
        run_id = worker.claim_next()
        if run_id:
            worker.process_run(run_id)

    with TestClient(
        create_app(),
        base_url="http://testserver/api/v1",
        client=("recovery-" + destination["token"], 1234),
    ) as client:
        result = cycle(
            client,
            {"recovery_id": destination["token"], "password": destination["password"]},
            pause=work,
        )
    return result


def test_fresh_cycle_real_api_runtime_worker_reports_and_history(fresh_destination):
    d = fresh_destination
    result = complete_cycle(d)
    assert result["state"] == "COMPLETED" and result["synthetic"] is True
    assert len(result["outcomes"]) == 4 and result["session_closed"] and result["new_lab_revoked"]
    closed = run_sql(d["writer"], d["adapt"](recovered.close_sql(d["token"], result["run_id"])))
    assert closed["historical_rows_unchanged"] and closed["fresh_account_disabled"]
    assert closed["baseline_rows"] == d["bootstrap"]["baseline_rows"]
    with d["runtime"].connect() as c:
        assert c.scalar(text("SELECT current_user")) == d["role"]
        assert not c.scalar(
            text(
                "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls FROM pg_roles WHERE rolname=current_user"
            )
        )
        assert c.scalar(
            text("SELECT NOT has_schema_privilege(current_user,'aegis_recovery_guard','USAGE')")
        )
        for table in (
            "audit_events",
            "telemetry_events",
            "validation_results",
            "runner_dispatches",
        ):
            assert not c.scalar(
                text("SELECT has_table_privilege(current_user,:table,'DELETE')"), {"table": table}
            )


@pytest.mark.parametrize(
    "mutation,expected",
    [
        (
            "UPDATE users SET password_hash='corrupted' WHERE username='restored-admin'",
            "historical rows",
        ),
        ("UPDATE laboratories SET authorized=true WHERE name='Demo Lab'", "close safely"),
    ],
)
def test_final_integrity_refuses_history_drift_and_old_authority(
    fresh_destination, mutation, expected
):
    d = fresh_destination
    result = complete_cycle(d)
    with d["writer"].begin() as c:
        c.execute(text(mutation))
    before = get_inventory(d["writer"])
    with pytest.raises(Exception, match=expected):
        run_sql(d["writer"], d["adapt"](recovered.close_sql(d["token"], result["run_id"])))
    assert get_inventory(d["writer"]) == before


def test_runtime_cannot_read_or_rewrite_private_baseline(fresh_destination):
    d = fresh_destination
    for statement in (
        "SELECT * FROM aegis_recovery_guard.original_rows",
        "DELETE FROM aegis_recovery_guard.original_rows",
    ):
        with d["runtime"].connect() as c, pytest.raises(Exception, match="permission denied"):
            c.execute(text(statement))


def test_bootstrap_needs_exact_reconciliation_and_has_no_partial_effects(recovered_work):
    writer, _ = recovered_work
    before = get_inventory(writer)
    with pytest.raises(Exception, match="receipt missing"):
        run_sql(
            writer,
            recovered.prepare_sql("f" * 32, "a" * 64, hasher.hash("test-password"), "b" * 64),
        )
    assert get_inventory(writer) == before


@pytest.mark.parametrize(
    "change",
    [
        {"OPERATING_MODE": "recovery"},
        {"DATABASE_URL": "postgresql+psycopg://aegis_app:" + "a" * 64 + "@localhost:18782/aegis"},
        {"REDIS_URL": "redis://localhost:18783/0"},
        {"WAZUH_URL": "https://unconfigured.invalid"},
        {"LINUX_RUNNER_CONFIG": "/unconfigured"},
    ],
)
def test_cycle_probe_refuses_other_destination_or_external_configuration(monkeypatch, change):
    for key in list(__import__("os").environ):
        if key.startswith(("WAZUH_", "LINUX_RUNNER_")):
            monkeypatch.delenv(key)
    monkeypatch.setenv("OPERATING_MODE", "normal")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://aegis_app:" + "a" * 64 + "@127.0.0.1:5432/aegis_restore",
    )
    monkeypatch.setenv("REDIS_URL", "redis://:" + "b" * 64 + "@127.0.0.1:6379/0")
    require_environment()
    for key, value in change.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match="restricted"):
        require_environment()


@pytest.mark.parametrize(
    "token,password_hash,role_password",
    [
        ("../", "invalid", "b" * 64),
        ("a" * 32, "invalid", "b" * 64),
        ("a" * 32, "$argon2id$v=19$m=1,t=1,p=1$aaaa$bbbb", "' SQL"),
    ],
)
def test_invalid_identity_and_credentials_refuse_before_sql(token, password_hash, role_password):
    with pytest.raises(ValueError):
        recovered.prepare_sql(token, "a" * 64, password_hash, role_password)


def test_final_closure_rejects_incomplete_or_real_validation(fresh_destination):
    d = fresh_destination
    result = complete_cycle(d)
    with d["writer"].begin() as c:
        c.execute(
            text(
                "UPDATE validation_results SET synthetic=false WHERE execution_id IN (SELECT id FROM test_executions WHERE run_id=:run_id)"
            ),
            {"run_id": result["run_id"]},
        )
    before = get_inventory(d["writer"])
    with pytest.raises(Exception, match="close safely"):
        run_sql(d["writer"], d["adapt"](recovered.close_sql(d["token"], result["run_id"])))
    assert get_inventory(d["writer"]) == before
