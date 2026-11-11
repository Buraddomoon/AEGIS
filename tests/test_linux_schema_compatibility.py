"""Populated a0 -> b7 rehearsal on the fixture schema, never original Lab volumes."""

import subprocess
from uuid import uuid4

import pytest
from aegis import binding_review
from aegis.db import session_factory
from aegis.models import Laboratory
from aegis.operations.runtime_grants import RUNTIME_PERMISSIONS
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from test_binding_review import binding_lab as binding_lab
from test_binding_review import history

OLD = "a0d9c7e21b45"
CURRENT = "b7f3c2d91a06"


def inventory(connection):
    """Compare complete JSON rows, including immutable scopes, receipts and audit."""
    return {
        name: connection.execute(
            text(f'SELECT to_jsonb(t)::text FROM ONLY "{name}" t ORDER BY to_jsonb(t)::text')
        )
        .scalars()
        .all()
        for name in inspect(connection).get_table_names()
        if name != "alembic_version"
    }


def privileges(connection):
    return connection.execute(
        text("""SELECT c.relname, c.relacl::text FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=current_schema() AND c.relkind='r'
        AND c.relname NOT IN ('alembic_version','scheduled_reports') ORDER BY c.relname""")
    ).all()


def test_populated_a0_upgrade_is_additive_and_original_proofs_remain_valid(binding_lab, pg_engine):
    _, identity = binding_lab
    history(identity)
    history(identity, parent="CLEANUP_FAILED", child="CLEANUP_FAILED")
    config = Config("alembic.ini")
    command.downgrade(config, OLD)
    try:
        with pg_engine.connect() as connection:
            before, grants = inventory(connection), privileges(connection)
            assert len(before) == 31  # 32 including Alembic.
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == OLD
            assert "scheduled_reports" not in before
        command.upgrade(config, CURRENT)
        command.check(config)
        with pg_engine.connect() as connection:
            after = inventory(connection)
            assert after.pop("scheduled_reports") == []
            assert after == before
            assert privileges(connection) == grants
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == CURRENT
        with session_factory()() as db:
            lab = db.get(Laboratory, identity["laboratory_id"])
            result = binding_review.review(db, lab)
            assert result["blockers"] == [] and result["dispatches_examined"] == 2
            assert not lab.authorized
    finally:
        command.upgrade(config, "head")


def test_a0_dump_restores_only_its_disposable_schema_before_upgrade(binding_lab, pg_engine):
    """Use pg17 tools in the existing development DB; no container/volume lifecycle.

    Optional where that local container is absent (CI still runs the upgrade test).
    The dump includes only the unpredictable fixture schema, never public/Lab data.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "aegis-db-1",
                "--format",
                '{{index .Config.Labels "com.docker.compose.project"}}',
            ],
            capture_output=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("Existing local development PostgreSQL tools unavailable")
    if result.stdout.strip() != b"aegis":
        pytest.skip("Local development PostgreSQL identity differs")
    _, identity = binding_lab
    history(identity)
    config = Config("alembic.ini")
    command.downgrade(config, OLD)
    try:
        with pg_engine.connect() as connection:
            namespace = connection.scalar(text("SELECT current_schema()"))
            assert namespace.startswith("aegis_test_") and namespace.isidentifier()
            before, grants = inventory(connection), privileges(connection)
        dump = subprocess.run(
            [
                "docker",
                "exec",
                "aegis-db-1",
                "pg_dump",
                "-U",
                "aegis",
                "-d",
                "aegis",
                "-n",
                namespace,
                "--format=custom",
            ],
            capture_output=True,
            timeout=30,
            check=True,
        ).stdout
        # Never DROP/restore a schema selected from operator input.
        with pg_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "aegis-db-1",
                "pg_restore",
                "-U",
                "aegis",
                "-d",
                "aegis",
                "--exit-on-error",
                "--single-transaction",
            ],
            input=dump,
            capture_output=True,
            timeout=30,
            check=True,
        )
        with pg_engine.connect() as connection:
            assert inventory(connection) == before
            assert privileges(connection) == grants
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == OLD
        command.upgrade(config, CURRENT)
        with pg_engine.connect() as connection:
            after = inventory(connection)
            assert after.pop("scheduled_reports") == []
            assert after == before and privileges(connection) == grants
    finally:
        command.upgrade(config, "head")


def test_b7_runtime_grants_preserve_proofs_and_limit_report_updates(db_ready, pg_engine):
    role = "aegis_schema_test_" + uuid4().hex
    with pg_engine.begin() as connection:
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_") and namespace.isidentifier()
        connection.exec_driver_sql(f'CREATE ROLE "{role}" NOLOGIN')
    try:
        with pg_engine.begin() as connection:
            for statement in RUNTIME_PERMISSIONS:
                connection.exec_driver_sql(
                    statement.replace("SCHEMA public", f'SCHEMA "{namespace}"').replace(
                        "aegis_app", f'"{role}"'
                    )
                )

            def allowed(table, privilege):
                return connection.scalar(
                    text("SELECT has_table_privilege(:role,:table,:privilege)"),
                    {"role": role, "table": f"{namespace}.{table}", "privilege": privilege},
                )

            for table in (
                "runner_receipts",
                "runner_cleanups",
                "lab_verifications",
                "audit_events",
            ):
                assert allowed(table, "SELECT") and allowed(table, "INSERT")
                assert not allowed(table, "UPDATE") and not allowed(table, "DELETE")
            assert not allowed("alembic_version", "SELECT")
            assert allowed("scheduled_reports", "SELECT")
            assert not allowed("scheduled_reports", "UPDATE")
            assert not allowed("scheduled_reports", "DELETE")
            for column, expected in (
                ("state", True),
                ("document", True),
                ("run_id", False),
                ("id", False),
            ):
                assert (
                    connection.scalar(
                        text("SELECT has_column_privilege(:role,:table,:column,'UPDATE')"),
                        {"role": role, "table": f"{namespace}.scheduled_reports", "column": column},
                    )
                    is expected
                )
    finally:
        with pg_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP OWNED BY "{role}"')
            connection.exec_driver_sql(f'DROP ROLE "{role}"')
