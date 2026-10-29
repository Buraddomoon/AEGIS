"""Fixed PostgreSQL loopback review probe; private stdin/stdout, no free endpoint."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from aegis.domain.validation import digest
from aegis.lab_runner.continuity import ContinuityError
from aegis.lab_runner.persisted_review import collect, expected_proofs
from aegis.lab_runner.protocol import RunnerIdentity

MAX_INPUT = 16384
MAX_OUTPUT = 4 * 1024**2
FORMAT = "aegis-persisted-journal-request/1"
FLAGS = {
    "database_volume_binding_verified": False,
    "journal_verified": False,
    "activation_permitted": False,
    "normal_operation_permitted": False,
}
FAILURE_FORMAT = "aegis-persisted-probe-rejection/1"
FAILURE_PHASES = frozenset(
    {"process", "input", "engine", "collect", "proofs", "encode", "dispose", "output"}
)
CONTINUITY_FAILURES = frozenset(
    {
        "persisted_probe_duplicate_field",
        "persisted_probe_input_limit",
        "persisted_probe_context_hash_required",
        "persisted_probe_input_invalid",
        "persisted_probe_context_mismatch",
        "persisted_probe_context_or_secret_invalid",
        "persisted_probe_ambient_libpq_configuration",
        "persisted_probe_database_profile_mismatch",
        "persisted_probe_privileged_database_role",
        "persisted_probe_schema_unsupported",
        "persisted_probe_private_pipe_required",
        "persisted_probe_output_limit",
        "persisted_probe_container_process_required",
        "persisted_review_inputs_invalid",
        "persisted_original_binding_mismatch",
        "persisted_binding_review_blocked",
        "persisted_complete_known_history_required",
        "persisted_cleanup_unconfirmed",
        "persisted_job_identity_mismatch",
        "persisted_proofs_integrity_mismatch",
        "persisted_proofs_policy_mismatch",
        "persisted_proofs_context_mismatch",
        "persisted_proofs_job_invalid",
        "persisted_proofs_invalid",
    }
)
SQLSTATE_FAILURES = {
    "28P01": "database_authentication_rejected",
    "28000": "database_authorization_rejected",
    "42501": "database_privilege_rejected",
    "42P01": "database_relation_unavailable",
    "25006": "database_readonly_rejected",
    "55P03": "database_lock_unavailable",
    "57014": "database_statement_cancelled",
    "3D000": "database_name_unavailable",
}
FAILURE_REASONS = (
    CONTINUITY_FAILURES
    | frozenset(SQLSTATE_FAILURES.values())
    | {
        "database_driver_rejected",
        "unexpected_error",
    }
)


def _failure_reason(error):
    # Never stringify an arbitrary exception, driver message, statement or URL.
    if (
        isinstance(error, ContinuityError)
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in CONTINUITY_FAILURES
    ):
        return error.args[0]
    # Do not import the database stack merely to reject an invalid input/process.
    sql_error = getattr(sys.modules.get("sqlalchemy.exc"), "DBAPIError", None)
    if sql_error is not None and isinstance(error, sql_error):
        state = getattr(error.orig, "sqlstate", None)
        return (
            SQLSTATE_FAILURES.get(state, "database_driver_rejected")
            if type(state) is str
            else "database_driver_rejected"
        )
    return "unexpected_error"


def decode_failure(payload, expected_context_sha256):
    """Closed failure envelope only; it is neither a proof nor a success response."""
    if type(payload) is not bytes or len(payload) > 4096:
        return None
    try:
        value = json.loads(payload, object_pairs_hook=_unique)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "format",
                "status",
                "code",
                "context_sha256",
                "failure_phase",
                "failure_reason",
                *FLAGS,
            }
            or value["format"] != FAILURE_FORMAT
            or value["status"] != "rejected"
            or value["code"] != "persisted_probe_rejected"
            or not isinstance(expected_context_sha256, str)
            or not re.fullmatch("[a-f0-9]{64}", expected_context_sha256)
            or value["context_sha256"] != expected_context_sha256
            or type(value["failure_phase"]) is not str
            or value["failure_phase"] not in FAILURE_PHASES
            or type(value["failure_reason"]) is not str
            or value["failure_reason"] not in FAILURE_REASONS
            or any(value[key] is not False for key in FLAGS)
        ):
            return None
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return None


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContinuityError("persisted_probe_duplicate_field")
        value[key] = item
    return value


def decode(payload, expected_context_sha256):
    if type(payload) is not bytes or len(payload) > MAX_INPUT:
        raise ContinuityError("persisted_probe_input_limit")
    if not isinstance(expected_context_sha256, str) or not re.fullmatch(
        "[a-f0-9]{64}", expected_context_sha256
    ):
        raise ContinuityError("persisted_probe_context_hash_required")
    try:
        data = json.loads(payload, object_pairs_hook=_unique)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ContinuityError("persisted_probe_input_invalid") from None
    if (
        not isinstance(data, dict)
        or set(data)
        != {
            "format",
            "identity",
            "old_descriptor_sha256",
            "database_password",
        }
        or data["format"] != FORMAT
    ):
        raise ContinuityError("persisted_probe_input_invalid")
    context = {key: value for key, value in data.items() if key != "database_password"}
    if digest(context) != expected_context_sha256:
        raise ContinuityError("persisted_probe_context_mismatch")
    try:
        identity = RunnerIdentity.model_validate(data["identity"])
    except (ValueError, TypeError):
        raise ContinuityError("persisted_probe_context_or_secret_invalid") from None
    if (
        digest(data["identity"]) != digest(identity.model_dump(mode="json"))
        or not isinstance(data["old_descriptor_sha256"], str)
        or not re.fullmatch("[a-f0-9]{64}", data["old_descriptor_sha256"])
        or not isinstance(data["database_password"], str)
        or not 1 <= len(data["database_password"]) <= 512
        or "\0" in data["database_password"]
    ):
        raise ContinuityError("persisted_probe_context_or_secret_invalid")
    # Password intentionally excluded from the public context fingerprint.
    return identity, data["old_descriptor_sha256"], data["database_password"]


def _open_engine(password):
    # Reject ambient libpq overrides rather than silently loading services/files
    # or allowing PGHOSTADDR to override the fixed numeric loopback destination.
    if any(key.startswith("PG") for key in os.environ):
        raise ContinuityError("persisted_probe_ambient_libpq_configuration")
    from sqlalchemy import URL, create_engine
    from sqlalchemy.pool import NullPool

    return create_engine(
        URL.create(
            "postgresql+psycopg",
            username="aegis_app",
            password=password,
            host="127.0.0.1",
            port=5432,
            database="aegis",
        ),
        connect_args={
            "hostaddr": "127.0.0.1",
            "connect_timeout": 5,
            "options": "-c default_transaction_read_only=on -c statement_timeout=15000 -c search_path=public -c row_security=off",
            "passfile": "/dev/null",
            "application_name": "aegis-persisted-review",
        },
        poolclass=NullPool,
        echo=False,
        hide_parameters=True,
    )


def _require_fixed_database(connection):
    from sqlalchemy import text

    row = connection.execute(
        text("""
            SELECT pg_catalog.current_database(), current_user, pg_catalog.current_schema(),
                   pg_catalog.current_setting('transaction_read_only'),
                   pg_catalog.current_setting('server_version_num'),
                   pg_catalog.inet_server_addr()::text, pg_catalog.inet_server_port(),
                   pg_catalog.current_setting('search_path'),
                   pg_catalog.current_setting('transaction_isolation'),
                   pg_catalog.pg_my_temp_schema()
        """)
    ).one()
    if (
        tuple(row[:4]) != ("aegis", "aegis_app", "public", "on")
        or not 170000 <= int(row[4]) < 180000
        or tuple(row[5:]) != ("127.0.0.1", 5432, "public", "repeatable read", 0)
    ):
        raise ContinuityError("persisted_probe_database_profile_mismatch")
    privileges = connection.execute(
        text("""
            SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
            FROM pg_catalog.pg_roles WHERE rolname=current_user
        """)
    ).one()
    if len(privileges) != 5 or any(value is not False for value in privileges):
        raise ContinuityError("persisted_probe_privileged_database_role")
    _require_schema(connection, "public")


def _require_schema(connection, namespace):
    from sqlalchemy import text
    from sqlalchemy.dialects import postgresql

    from aegis.models import (
        Asset,
        CampaignRun,
        Laboratory,
        LinuxLabBinding,
        RunnerCleanup,
        RunnerDispatch,
        TestExecution,
    )

    models = (
        Laboratory,
        Asset,
        LinuxLabBinding,
        CampaignRun,
        TestExecution,
        RunnerDispatch,
        RunnerCleanup,
    )
    required = {
        model.__tablename__: {
            column.name: (
                str(column.type.compile(dialect=postgresql.dialect()))
                .lower()
                .replace("varchar", "character varying"),
                not column.nullable,
            )
            for column in model.__table__.columns
        }
        for model in models
    }
    # Runtime role cannot SELECT alembic_version. Inspect required capabilities,
    # rejecting row hiding, views/foreign tables/inheritance and custom data types.
    rows = connection.execute(
        text("""
            SELECT c.relname::text, a.attname::text,
                   pg_catalog.has_table_privilege(c.oid, 'SELECT'),
                   pg_catalog.format_type(a.atttypid,a.atttypmod), a.attnotnull,
                   c.relrowsecurity OR c.relforcerowsecurity,
                   EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i
                           WHERE i.inhparent=c.oid OR i.inhrelid=c.oid),
                   tn.nspname::text
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
            JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
            JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
            WHERE n.nspname=:namespace AND c.relkind='r'
              AND c.relname::text=ANY(:names) AND a.attnum>0 AND NOT a.attisdropped
            LIMIT 2049
        """),
        {"names": sorted(required), "namespace": namespace},
    ).all()
    if len(rows) > 2048:
        raise ContinuityError("persisted_probe_schema_unsupported")
    columns = {name: set() for name in required}
    for name, column, readable, data_type, not_null, rls, inherited, type_namespace in rows:
        if (
            name not in columns
            or readable is not True
            or rls is not False
            or inherited is not False
            or type_namespace != "pg_catalog"
        ):
            raise ContinuityError("persisted_probe_schema_unsupported")
        if type(not_null) is not bool or (
            column in required[name] and (data_type, not_null) != required[name][column]
        ):
            raise ContinuityError("persisted_probe_schema_unsupported")
        columns[name].add(column)
    if any(not set(expected) <= columns[name] for name, expected in required.items()):
        raise ContinuityError("persisted_probe_schema_unsupported")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context-sha256", required=True)
    args = parser.parse_args(argv)
    phase = "process"
    try:
        if sys.stdout.isatty():
            raise ContinuityError("persisted_probe_private_pipe_required")
        _require_probe_process()
        phase = "input"
        identity, descriptor, password = decode(
            sys.stdin.buffer.read(MAX_INPUT + 1), args.context_sha256
        )
        phase = "engine"
        engine = _open_engine(password)
        try:
            phase = "collect"
            bundle = collect(engine, identity, descriptor, verify=_require_fixed_database)
            phase = "proofs"
            expected_proofs(bundle, digest(bundle))
            phase = "encode"
            encoded = json.dumps(
                bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
            if len(encoded) + 1 > MAX_OUTPUT:
                raise ContinuityError("persisted_probe_output_limit")
        finally:
            previous_phase, phase = phase, "dispose"
            engine.dispose()
            phase = previous_phase
        # Contains original proofs; caller must capture privately, never echo/log.
        phase = "output"
        sys.stdout.buffer.write(encoded + b"\n")
        return 0
    except Exception as error:
        # Driver/SQL/input failures can contain credentials, never echo diagnostics.
        print(
            json.dumps(
                {
                    "format": FAILURE_FORMAT,
                    "status": "rejected",
                    "code": "persisted_probe_rejected",
                    "context_sha256": args.context_sha256
                    if re.fullmatch("[a-f0-9]{64}", args.context_sha256)
                    else None,
                    "failure_phase": phase,
                    "failure_reason": _failure_reason(error),
                    **FLAGS,
                },
                sort_keys=True,
            )
        )
        return 1


def _require_probe_process():
    # Guard accidental host invocation; external runtime inspection must still
    # prove network=container:<owned DB id>. This check is not an authorization.
    if (
        os.getpid() != 1
        or os.getuid() != 10001
        or os.getgid() != 10001
        or not Path("/.dockerenv").is_file()
    ):
        raise ContinuityError("persisted_probe_container_process_required")


if __name__ == "__main__":
    raise SystemExit(main())
