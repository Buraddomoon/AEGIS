"""Fixed DB-probe profiles and real disposable-schema readers; no Linux namespace."""

import io
import json
import os
import subprocess
import sys

import pytest
from aegis import binding_review
from aegis.domain.validation import digest
from aegis.lab_runner import persisted_probe as probe
from aegis.lab_runner.continuity import ContinuityError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_binding_review import binding_lab as binding_lab
from test_binding_review import history
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import arguments
from test_runner_persisted_review import bundle as bundle


def data(bundle):
    return {
        "format": probe.FORMAT,
        "identity": bundle["identity"],
        "old_descriptor_sha256": bundle["old_descriptor_sha256"],
        "database_password": "temporary-driver-secret",
    }


def context_sha(value):
    return digest({key: item for key, item in value.items() if key != "database_password"})


def invoke(value, monkeypatch, *, raw=None, expected=None, container=True):
    output_buffer = io.BytesIO()
    stdout = io.TextIOWrapper(output_buffer, encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "stdin",
        io.TextIOWrapper(io.BytesIO(json.dumps(value).encode() if raw is None else raw)),
    )
    monkeypatch.setattr(sys, "stdout", stdout)
    if container:
        monkeypatch.setattr(probe, "_require_probe_process", lambda: None)
    code = probe.main(["--context-sha256", expected or context_sha(value)])
    stdout.flush()
    raw_output = output_buffer.getvalue()
    return code, json.loads(raw_output), raw_output


def test_public_context_fingerprint_excludes_secret_but_no_target_is_accepted(bundle):
    value = data(bundle)
    identity, descriptor, password = probe.decode(json.dumps(value).encode(), context_sha(value))
    assert identity.model_dump(mode="json") == bundle["identity"]
    assert descriptor == bundle["old_descriptor_sha256"] and password == value["database_password"]
    original = context_sha(value)
    value["database_password"] = "different-credential"
    assert context_sha(value) == original
    value["url"] = "postgresql://untrusted.invalid/other"
    with pytest.raises(ContinuityError):
        probe.decode(json.dumps(value).encode(), context_sha(value))


@pytest.mark.parametrize(
    "scene",
    [
        "hash",
        "format",
        "identity",
        "descriptor",
        "empty_password",
        "long_password",
        "nul",
        "duplicate",
        "excessive",
        "invalid",
        "deep",
    ],
)
def test_invalid_or_oversized_request_fails_before_opening_any_engine(bundle, monkeypatch, scene):
    value = data(bundle)
    raw = None
    expected = None
    if scene == "hash":
        expected = "f" * 64
    elif scene == "format":
        value["format"] = "unknown"
    elif scene == "identity":
        value["identity"] = {"protocol": "unknown"}
    elif scene == "descriptor":
        value["old_descriptor_sha256"] = "private-sensitive-sentinel"
    elif scene == "empty_password":
        value["database_password"] = ""
    elif scene == "long_password":
        value["database_password"] = "x" * 513
    elif scene == "nul":
        value["database_password"] = "secret\0suffix"
    elif scene == "duplicate":
        raw = b'{"identity":{},"identity":{}}'
    elif scene == "excessive":
        raw = b"x" * (probe.MAX_INPUT + 1)
    elif scene == "invalid":
        raw = b"private-sensitive-sentinel"
    else:
        raw = b"[" * 1500 + b"]" * 1500
    monkeypatch.setattr(probe, "_open_engine", lambda *a: pytest.fail("No engine permitted"))
    code, result, encoded = invoke(value, monkeypatch, raw=raw, expected=expected)
    assert code == 1 and result["status"] == "rejected"
    assert all(result[key] is False for key in probe.FLAGS)
    assert b"private-sensitive-sentinel" not in encoded
    if value["database_password"]:
        assert value["database_password"].encode() not in encoded


@pytest.mark.parametrize(
    "key", ["PGHOSTADDR", "PGSERVICE", "PGPASSWORD", "PGOPTIONS", "PGPASSFILE"]
)
def test_ambient_libpq_configuration_is_rejected_not_inherited(monkeypatch, key):
    monkeypatch.setenv(key, "private-sensitive-sentinel")
    with pytest.raises(ContinuityError, match="ambient_libpq") as error:
        probe._open_engine("credential")
    assert "private-sensitive-sentinel" not in str(error.value)


def test_engine_profile_uses_url_object_fixed_loopback_and_safe_connection_options(monkeypatch):
    import sqlalchemy

    for key in tuple(os.environ):
        if key.startswith("PG"):
            monkeypatch.delenv(key)
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://private-sensitive-sentinel@untrusted.invalid/other"
    )
    captured = []
    monkeypatch.setattr(
        sqlalchemy,
        "create_engine",
        lambda url, **kwargs: captured.append((url, kwargs)) or object(),
    )
    secret = "temporary:@/?&= driver secret"
    probe._open_engine(secret)
    url, options = captured[0]
    assert (url.drivername, url.host, url.port, url.database, url.username) == (
        "postgresql+psycopg",
        "127.0.0.1",
        5432,
        "aegis",
        "aegis_app",
    )
    assert url.password == secret and secret not in str(url)
    assert options["echo"] is False and options["hide_parameters"] is True
    args = options["connect_args"]
    assert args["hostaddr"] == "127.0.0.1" and args["connect_timeout"] == 5
    assert args["passfile"] == "/dev/null" and "search_path=public" in args["options"]
    assert (
        "default_transaction_read_only=on" in args["options"]
        and "statement_timeout=15000" in args["options"]
    )
    assert options["poolclass"].__name__ == "NullPool"


class Result:
    def __init__(self, value):
        self.value = value

    def one(self):
        return self.value


class Connection:
    def __init__(self):
        self.profile = (
            "aegis",
            "aegis_app",
            "public",
            "on",
            "170000",
            "127.0.0.1",
            5432,
            "public",
            "repeatable read",
            0,
        )
        self.privileges = (False,) * 5
        self.statements = []

    def connect(self):
        return self

    def execution_options(self, **options):
        assert options == {"isolation_level": "REPEATABLE READ"}
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, statement):
        sql = str(statement)
        self.statements.append(sql)
        return Result(self.profile if "current_database()" in sql else self.privileges)


def test_fixed_connection_profile_and_role_gate_precede_schema_review(monkeypatch):
    connection = Connection()
    calls = []
    monkeypatch.setattr(probe, "_require_schema", lambda conn, schema: calls.append((conn, schema)))
    probe._require_fixed_database(connection)
    assert "current_database()" in connection.statements[0]
    assert calls == [(connection, "public")]


@pytest.mark.parametrize(
    "index,value",
    [
        (0, "other"),
        (1, "owner"),
        (2, "other"),
        (3, "off"),
        (4, "160000"),
        (4, "180000"),
        (5, "192.0.2.1"),
        (6, 5433),
        (7, '"$user", public'),
        (8, "read committed"),
        (9, 42),
    ],
)
def test_wrong_database_role_schema_endpoint_version_or_readonly_state_blocks(
    index, value, monkeypatch
):
    connection = Connection()
    profile = list(connection.profile)
    profile[index] = value
    connection.profile = tuple(profile)
    monkeypatch.setattr(
        probe, "_require_schema", lambda *a: pytest.fail("No schema query permitted")
    )
    with pytest.raises(ContinuityError, match="profile_mismatch"):
        probe._require_fixed_database(connection)


@pytest.mark.parametrize("index", range(5))
def test_elevated_database_role_is_not_accepted(index, monkeypatch):
    connection = Connection()
    connection.privileges = tuple(position == index for position in range(5))
    monkeypatch.setattr(
        probe, "_require_schema", lambda *a: pytest.fail("No schema query permitted")
    )
    with pytest.raises(ContinuityError, match="privileged_database_role"):
        probe._require_fixed_database(connection)


def test_required_schema_is_reviewed_on_real_disposable_postgresql(pg_engine):
    with pg_engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
        connection.execute(text("SET TRANSACTION READ ONLY"))
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_")
        probe._require_schema(connection, namespace)


@pytest.mark.parametrize("change", ["rls", "nullable", "type", "view", "inheritance"])
def test_row_hiding_or_incompatible_schema_is_rejected_with_real_catalogs_and_rolled_back(
    pg_engine, change
):
    with pg_engine.connect() as connection:
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_") and namespace.isidentifier()
        table = f'"{namespace}".laboratories'
        if change == "rls":
            connection.exec_driver_sql(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        elif change == "nullable":
            connection.exec_driver_sql(f"ALTER TABLE {table} ALTER COLUMN name DROP NOT NULL")
        elif change == "type":
            connection.exec_driver_sql(f"ALTER TABLE {table} ALTER COLUMN name TYPE text")
        elif change == "view":
            connection.exec_driver_sql(f"ALTER TABLE {table} RENAME TO probe_original_labs")
            connection.exec_driver_sql(
                f'CREATE VIEW {table} AS SELECT * FROM "{namespace}".probe_original_labs'
            )
        else:
            connection.exec_driver_sql(
                f'CREATE TABLE "{namespace}".probe_child () INHERITS ({table})'
            )
        with pytest.raises(ContinuityError, match="schema_unsupported"):
            probe._require_schema(connection, namespace)
        connection.rollback()
    with pg_engine.connect() as connection:
        probe._require_schema(connection, namespace)


def test_main_reads_real_temporary_history_and_disposes_engine_without_settings_fallback(
    binding_lab, pg_engine, monkeypatch
):
    _, descriptor = binding_lab
    history(descriptor)
    identity, fingerprint = arguments(binding_lab)
    value = {
        "format": probe.FORMAT,
        "identity": identity.model_dump(mode="json"),
        "old_descriptor_sha256": fingerprint,
        "database_password": "temporary-driver-secret",
    }
    observed = []

    def open_engine(secret):
        assert secret == value["database_password"]
        return pg_engine

    def require_disposable(connection):
        # Endpoint/netns/role production profile has separate fixture tests. Here
        # substitute only that external gate, exercising actual schema+history.
        assert connection.scalar(text("SHOW transaction_read_only")) == "on"
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_")
        probe._require_schema(connection, namespace)
        observed.append(True)

    monkeypatch.setattr(probe, "_open_engine", open_engine)
    monkeypatch.setattr(probe, "_require_fixed_database", require_disposable)
    code, result, encoded = invoke(value, monkeypatch)
    assert code == 0 and observed == [True]
    assert result["format"] == "aegis-persisted-journal-proofs/1"
    assert len(result["proofs"]) == 1 and result["old_descriptor_sha256"] == fingerprint
    assert all(result[key] is False for key in probe.FLAGS)
    assert value["database_password"].encode() not in encoded


@pytest.mark.parametrize("scene", ["connect", "profile", "collect", "dispose", "overflow"])
def test_failure_never_prints_driver_diagnostics_secrets_or_partial_proofs(
    bundle, monkeypatch, scene
):
    value = data(bundle)
    events = []

    class Engine:
        def dispose(self):
            events.append("dispose")
            if scene == "dispose":
                raise RuntimeError("private-sensitive-sentinel")

    def connect(secret):
        if scene == "connect":
            raise RuntimeError("private-sensitive-sentinel")
        return Engine()

    def require(engine):
        if scene == "profile":
            raise RuntimeError("private-sensitive-sentinel")

    def collect(engine, identity, descriptor, *, verify):
        verify(engine)
        if scene == "collect":
            raise RuntimeError("private-sensitive-sentinel")
        return bundle

    monkeypatch.setattr(probe, "_open_engine", connect)
    monkeypatch.setattr(probe, "_require_fixed_database", require)
    monkeypatch.setattr(probe, "collect", collect)
    if scene == "overflow":
        monkeypatch.setattr(probe, "MAX_OUTPUT", 1)
    code, result, encoded = invoke(value, monkeypatch)
    assert code == 1 and result["status"] == "rejected" and b"proofs" not in encoded
    assert (
        b"private-sensitive-sentinel" not in encoded
        and value["database_password"].encode() not in encoded
    )
    assert events == ([] if scene == "connect" else ["dispose"])


def test_accidental_host_invocation_is_blocked_before_engine_open(bundle, monkeypatch):
    monkeypatch.setattr(probe.os, "getpid", lambda: 99)
    monkeypatch.setattr(probe, "_open_engine", lambda *a: pytest.fail("No connection permitted"))
    code, result, _ = invoke(data(bundle), monkeypatch, container=False)
    assert code == 1 and result["status"] == "rejected"


def test_cli_help_and_import_do_not_connect_or_read_environment_files():
    result = subprocess.run(
        [sys.executable, "-m", "aegis.lab_runner.persisted_probe", "--help"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0 and "--context-sha256" in result.stdout
    assert all(
        option not in result.stdout
        for option in ("--password", "--url", "--host", "--schema", "--command", "--apply")
    )
    imported = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('No external effects permitted')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('No secrets permitted')
sys.addaudithook(guard)
import aegis.lab_runner.persisted_probe
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
assert 'aegis.lab_runner.engine' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert imported.returncode == 0, imported.stderr


def test_profile_and_history_share_snapshot_and_hold_relation_locks_against_rls_ddl(
    binding_lab, pg_engine, monkeypatch
):
    _, descriptor = binding_lab
    history(descriptor)
    identity, fingerprint = arguments(binding_lab)
    backend = []
    original = binding_review.review

    def verify(connection):
        assert connection.scalar(text("SHOW transaction_read_only")) == "on"
        assert connection.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_") and namespace.isidentifier()
        probe._require_schema(connection, namespace)
        backend.append(connection.scalar(text("SELECT pg_backend_pid()")))
        with pg_engine.connect() as other:
            other.execute(text("SET LOCAL lock_timeout='50ms'"))
            with pytest.raises(DBAPIError) as error:
                other.exec_driver_sql(
                    f'ALTER TABLE "{namespace}".laboratories ENABLE ROW LEVEL SECURITY'
                )
            assert error.value.orig.sqlstate == "55P03"

    def same_snapshot(db, lab, **kwargs):
        assert db.scalar(text("SELECT pg_backend_pid()")) == backend[0]
        return original(db, lab, **kwargs)

    monkeypatch.setattr(binding_review, "review", same_snapshot)
    result = probe.collect(pg_engine, identity, fingerprint, verify=verify)
    assert result["proofs"] and len(backend) == 1


def test_preexisting_ddl_lock_refuses_read_before_schema_or_history(binding_lab, pg_engine):
    identity, fingerprint = arguments(binding_lab)
    with pg_engine.connect() as blocker:
        blocker.execute(text("LOCK TABLE laboratories IN ACCESS EXCLUSIVE MODE"))
        with pytest.raises(DBAPIError) as error:
            probe.collect(
                pg_engine,
                identity,
                fingerprint,
                verify=lambda *a: pytest.fail("No snapshot permitted"),
            )
        assert error.value.orig.sqlstate == "55P03"


def test_late_inheritance_cannot_expand_validated_root_relation_snapshot(binding_lab, pg_engine):
    _, descriptor = binding_lab
    run_id, _ = history(descriptor)
    identity, fingerprint = arguments(binding_lab)
    with pg_engine.begin() as setup:
        namespace = setup.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_") and namespace.isidentifier()
        child = f'"{namespace}".probe_pending_child'
        parent = f'"{namespace}".campaign_runs'
        setup.exec_driver_sql(f"CREATE TABLE {child} (LIKE {parent} INCLUDING ALL)")
        setup.execute(
            text(f"INSERT INTO {child} SELECT * FROM ONLY {parent} WHERE id=:id"), {"id": run_id}
        )
        setup.execute(text(f"UPDATE {child} SET state='QUEUED'"))
    try:

        def verify(connection):
            assert connection.scalar(text("SHOW row_security")) == "off"
            probe._require_schema(connection, namespace)
            with pg_engine.begin() as other:
                other.execute(text("SET LOCAL lock_timeout='100ms'"))
                other.exec_driver_sql(f"ALTER TABLE {child} INHERIT {parent}")
            # The old child row can become visible through inheritance even
            # though no validated root row changed. Strict reads use ONLY.
            assert (
                connection.scalar(text(f"SELECT count(*) FROM {parent} WHERE state='QUEUED'")) == 1
            )

        result = probe.collect(pg_engine, identity, fingerprint, verify=verify)
        assert result["review"]["nonterminal_runs"] == 0 and len(result["proofs"]) == 1
    finally:
        with pg_engine.begin() as cleanup:
            cleanup.exec_driver_sql(f"DROP TABLE IF EXISTS {child}")
