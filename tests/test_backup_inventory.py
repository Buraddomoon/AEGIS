import copy
import json
from datetime import UTC, datetime, timedelta

import pytest
from aegis.domain.validation import digest
from aegis.operations.backup import compare, fingerprint, identifier, inventory, retention_plan
from aegis.worker import claim_next, process_run
from conftest import create_queued
from sqlalchemy import text
from test_rule_links import import_rule


@pytest.mark.parametrize("name", ["public;DROP TABLE users", "../public", "A", "a'b", "x" * 64])
def test_inventory_rejects_unsafe_identifiers(name):
    with pytest.raises(ValueError, match="identifier"):
        identifier(name)


def test_fingerprints_canonical_rows_without_disclosing_values():
    first = fingerprint(['{"password_hash":"private","username":"demo"}'])
    assert first == fingerprint(['{ "username": "demo", "password_hash": "private" }'])
    assert first["rows"] == 1
    assert "private" not in json.dumps(first)
    assert first != fingerprint(['{"password_hash":"changed","username":"demo"}'])


@pytest.mark.parametrize(
    "table,content,key",
    [
        ("telemetry_events", "raw", "sha256"),
        ("rule_versions", "content", "sha256"),
        ("campaign_runs", "scope", "scope_hash"),
        ("schedules", "scope", "scope_hash"),
    ],
)
def test_existing_integrity_mismatch_fails_closed(table, content, key):
    row = {content: {"nested": "value"} if content != "content" else "Sigma YAML"}
    row[key] = digest(row[content])
    assert fingerprint([json.dumps(row)], table)["rows"] == 1
    row[key] = "0" * 64
    with pytest.raises(ValueError, match="integrity"):
        fingerprint([json.dumps(row)], table)


def test_retention_is_read_only_and_preserves_minimum_and_recent_backups():
    at = datetime(2026, 10, 22, tzinfo=UTC)
    records = [
        {"id": str(i), "created_at": (at - timedelta(days=i * 10)).isoformat()} for i in range(10)
    ]
    original = copy.deepcopy(records)
    plans = retention_plan(records, at)
    assert [p["action"] for p in plans] == ["keep"] * 7 + ["review_only"] * 3
    assert not any(p["deletion_performed"] for p in plans)
    assert records == original
    assert retention_plan(records[:3], at)[-1]["action"] == "keep"
    with pytest.raises(ValueError, match="timezone"):
        retention_plan([{"id": "bad", "created_at": "2026-10-22"}], at)


def test_retention_keeps_recent_beyond_minimum_count():
    at = datetime(2026, 10, 22, tzinfo=UTC)
    records = [
        {"id": str(i), "created_at": (at - timedelta(days=i)).isoformat()} for i in range(31)
    ]
    assert all(r["action"] == "keep" for r in retention_plan(records, at))


def test_inventory_records_real_schema_rows_guards_and_detects_change(admin, pg_engine):
    run = create_queued(admin)
    import_rule(admin)
    assert claim_next() == run["id"]
    process_run(run["id"])
    with pg_engine.connect() as conn:
        conn.execute(text("SET timezone='UTC'"))
        schema = conn.execute(text("SELECT current_schema()")).scalar_one()

        def query(sql):
            return conn.execute(text(sql)).scalars()

        first = inventory(query, schema)
        assert first["tables"]["campaign_runs"]["rows"] == 1
        assert first["tables"]["telemetry_events"]["rows"] > 0
        assert first["tables"]["rule_versions"]["rows"] == 1
        assert first["tables"]["validation_results"]["rows"] == 4
        assert first["structure"]["triggers"]["rows"] > 0
        assert first["migration"]
        compare(first, inventory(query, schema))
        conn.execute(text("UPDATE users SET active=false WHERE username='viewer'"))
        with pytest.raises(ValueError, match="differs"):
            compare(first, inventory(query, schema))
        conn.rollback()


def test_inventory_rejects_sequence_state_outside_snapshot(db_ready, pg_engine):
    with pg_engine.begin() as conn:
        schema = conn.execute(text("SELECT current_schema()")).scalar_one()
        conn.execute(text("CREATE SEQUENCE backup_test_sequence"))
        try:
            with pytest.raises(ValueError, match="Unsupported relation"):
                inventory(lambda sql: conn.execute(text(sql)).scalars(), schema)
        finally:
            conn.execute(text("DROP SEQUENCE backup_test_sequence"))


def test_pg17_constraint_roundtrip_normalizes_only_literal_array_casts():
    from aegis.operations.backup import constraint_rows

    before = "CHECK (((role)::text = ANY ((ARRAY['administrator'::character varying, 'viewer'::character varying])::text[])))"
    after = "CHECK (((role)::text = ANY (ARRAY[('administrator'::character varying)::text, ('viewer'::character varying)::text])))"
    assert list(constraint_rows([json.dumps({"definition": before})])) == list(
        constraint_rows([json.dumps({"definition": after})])
    )
    # Same quoting and exact values are retained, including commas and escaped quotes.
    quoted = "CHECK (x = ANY ((ARRAY['a, b''c'::character varying])::text[]))"
    normalized = json.loads(next(iter(constraint_rows([json.dumps({"definition": quoted})]))))[
        "definition"
    ]
    assert "('a, b''c'::character varying)::text" in normalized
    for expression in [
        "ARRAY[NULL::character varying]",
        "ARRAY[lower('x')::character varying]",
        "ARRAY['x'::varchar]",
        "ARRAY['x'::integer]",
    ]:
        raw = {"definition": f"CHECK (x = ANY (({expression})::text[]))"}
        assert json.loads(next(iter(constraint_rows([json.dumps(raw)])))) == raw
    different = after.replace("viewer", "operator")
    assert list(constraint_rows([json.dumps({"definition": different})])) != list(
        constraint_rows([json.dumps({"definition": before})])
    )


def test_retention_sorts_actual_instants_across_timezone_offsets():
    records = [
        {"id": "later", "created_at": "2026-10-22T08:00:00+00:00"},
        {"id": "earlier", "created_at": "2026-10-22T09:00:00+03:00"},
    ]
    assert [r["id"] for r in retention_plan(records, datetime(2026, 10, 22, tzinfo=UTC))] == [
        "later",
        "earlier",
    ]


def test_exported_snapshot_excludes_later_committed_changes(db_ready, pg_engine):
    import re

    with pg_engine.connect().execution_options(isolation_level="REPEATABLE READ") as source:
        source.execute(text("SET TRANSACTION READ ONLY"))
        snapshot = source.execute(text("SELECT pg_export_snapshot()")).scalar_one()
        assert re.fullmatch(r"[0-9A-Fa-f-]+", snapshot)
        with pg_engine.begin() as writer:
            writer.execute(text("UPDATE users SET active=false WHERE username='viewer'"))
        with pg_engine.connect().execution_options(isolation_level="REPEATABLE READ") as reader:
            # Snapshot is generated by PostgreSQL and constrained to hex/dashes;
            # SET TRANSACTION doesn't accept a server-side bind parameter.
            reader.exec_driver_sql("SET TRANSACTION SNAPSHOT '" + snapshot + "'")
            assert reader.execute(
                text("SELECT active FROM users WHERE username='viewer'")
            ).scalar_one()
        with pg_engine.connect() as current:
            assert not current.execute(
                text("SELECT active FROM users WHERE username='viewer'")
            ).scalar_one()


def test_constraint_roundtrip_uses_postgres_and_preserves_allowed_values(db_ready, pg_engine):
    from aegis.operations.backup import constraint_rows
    from sqlalchemy.exc import IntegrityError

    with pg_engine.connect() as conn:
        definition = conn.execute(
            text("""SELECT pg_get_constraintdef(p.oid)
          FROM pg_constraint p WHERE p.conrelid='users'::regclass AND p.conname='ck_users_role'""")
        ).scalar_one()
        conn.execute(text("CREATE TEMP TABLE backup_role_roundtrip (role varchar(30))"))
        conn.exec_driver_sql(
            "ALTER TABLE backup_role_roundtrip ADD CONSTRAINT copied_role " + definition
        )
        restored = conn.execute(
            text("""SELECT pg_get_constraintdef(p.oid)
          FROM pg_constraint p WHERE p.conrelid='backup_role_roundtrip'::regclass""")
        ).scalar_one()
        before = list(constraint_rows([json.dumps({"definition": definition})]))
        after = list(constraint_rows([json.dumps({"definition": restored})]))
        assert before == after
        conn.execute(text("INSERT INTO backup_role_roundtrip VALUES ('viewer')"))
        with pytest.raises(IntegrityError), conn.begin_nested():
            conn.execute(text("INSERT INTO backup_role_roundtrip VALUES ('unexpected')"))
        conn.rollback()


@pytest.mark.parametrize(
    "create,drop",
    [
        (
            "ALTER TABLE users ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE users DISABLE ROW LEVEL SECURITY",
        ),
        ("CREATE POLICY backup_policy ON users USING (true)", "DROP POLICY backup_policy ON users"),
        ("CREATE TYPE backup_enum AS ENUM ('safe')", "DROP TYPE backup_enum"),
        (
            "CREATE PROCEDURE backup_procedure() LANGUAGE plpgsql AS 'BEGIN NULL; END'",
            "DROP PROCEDURE backup_procedure()",
        ),
    ],
)
def test_inventory_rejects_unsupported_security_and_custom_objects(
    db_ready, pg_engine, create, drop
):
    with pg_engine.begin() as conn:
        schema = conn.execute(text("SELECT current_schema()")).scalar_one()
        conn.execute(text(create))
        try:
            with pytest.raises(ValueError, match="Unsupported database features"):
                inventory(lambda sql: conn.execute(text(sql)).scalars(), schema)
        finally:
            conn.execute(text(drop))


def test_array_element_typmod_change_is_not_silently_equivalent(db_ready, pg_engine):
    with pg_engine.connect() as conn:
        schema = conn.execute(text("SELECT current_schema()")).scalar_one()
        conn.execute(text("CREATE TABLE backup_typmod (items varchar(80)[])"))
        first = inventory(lambda sql: conn.execute(text(sql)).scalars(), schema)
        conn.execute(text("ALTER TABLE backup_typmod ALTER COLUMN items TYPE varchar(90)[]"))
        changed = inventory(lambda sql: conn.execute(text(sql)).scalars(), schema)
        assert first["tables"] == changed["tables"]
        assert first["structure"]["columns"] == changed["structure"]["columns"]
        assert first["structure"]["column_attributes"] != changed["structure"]["column_attributes"]
        with pytest.raises(ValueError, match="differs"):
            compare(first, changed)
        conn.rollback()
