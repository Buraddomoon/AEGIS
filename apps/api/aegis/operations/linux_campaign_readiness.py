"""Read-only schema/grants gate for the opt-in Linux campaign stack.

This replaces the historical automatic migration/seed/grant command. It never
authorizes a laboratory, changes a schema or prepares an executor job.
"""

from sqlalchemy import text

from aegis.db import engine

REVISION = "b7f3c2d91a06"


def check(connection, *, role: str = "aegis_app") -> None:
    connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
    if connection.scalar(text("SELECT version_num FROM alembic_version")) != REVISION:
        raise RuntimeError("Linux campaign requires an explicitly reviewed b7 schema upgrade.")
    checks = connection.execute(
        text("""SELECT
          has_table_privilege(:role, 'scheduled_reports', 'SELECT'),
          has_table_privilege(:role, 'scheduled_reports', 'INSERT'),
          has_column_privilege(:role, 'scheduled_reports', 'state', 'UPDATE'),
          NOT has_column_privilege(:role, 'scheduled_reports', 'run_id', 'UPDATE'),
          NOT has_table_privilege(:role, 'scheduled_reports', 'DELETE'),
          NOT has_table_privilege(:role, 'alembic_version', 'SELECT'),
          NOT has_table_privilege(:role, 'runner_receipts', 'UPDATE'),
          NOT has_table_privilege(:role, 'runner_receipts', 'DELETE'),
          NOT has_table_privilege(:role, 'runner_cleanups', 'UPDATE'),
          NOT has_table_privilege(:role, 'runner_cleanups', 'DELETE'),
          NOT has_table_privilege(:role, 'audit_events', 'UPDATE'),
          NOT has_table_privilege(:role, 'audit_events', 'DELETE'),
          NOT has_column_privilege(:role, 'runner_dispatches', 'spec', 'UPDATE'),
          has_column_privilege(:role, 'runner_dispatches', 'generation', 'UPDATE')"""),
        {"role": role},
    ).one()
    if not all(checks):
        raise RuntimeError("Linux campaign runtime grants require explicit review.")
    if connection.scalar(text("SELECT count(*) FROM laboratories WHERE active_run_id IS NOT NULL")):
        raise RuntimeError("Linux campaign startup blocked by a reserved laboratory.")
    if connection.scalar(
        text("""SELECT count(*) FROM campaign_runs
          WHERE state IN ('QUEUED', 'PREPARING', 'RUNNING', 'COLLECTING',
            'VALIDATING', 'CLEANING_UP', 'CLEANUP_FAILED')""")
    ):
        raise RuntimeError("Linux campaign startup blocked by pending execution or cleanup.")
    if connection.scalar(text("SELECT count(*) FROM schedules WHERE state='ACTIVE'")):
        raise RuntimeError("Linux campaign startup blocked by an active schedule.")
    if connection.scalar(
        text("SELECT count(*) FROM scheduled_reports WHERE state IN ('PENDING', 'PROCESSING')")
    ):
        raise RuntimeError("Linux campaign startup blocked by pending automatic reports.")


def main() -> None:
    # Roll back even the successful read-only transaction. No credentials or
    # database exceptions are echoed by this operator command.
    try:
        with engine().connect() as connection:
            check(connection)
    except Exception:
        raise SystemExit("BLOCKED: schema, grants or pending Linux work require review.") from None
    print("PASS: read-only schema/grants/idle gate; execution authorization remains separate.")


if __name__ == "__main__":
    main()
