"""Fixed SQL for an owned, offline restoration clone; never a normal API action.

The host tool establishes clone ownership/isolation before sending this SQL over
stdin. SQL here has no configurable destination, table name or user input except
validated hexadecimal fingerprints and a generated recovery identity.
"""

import re

# Ensure model registration even when this module is imported by a host script.
from aegis import models as _models  # noqa: F401
from aegis.db import Base
from aegis.domain.states import ACTIVE, TERMINAL, State
from aegis.operations.backup import identifier, structure_queries
from aegis.operations.recovery import required_revision

FORMAT = "aegis-demo-reconciliation/1"
ACTION = "recovery.demo.reconciled"
TABLES = tuple(sorted((*Base.metadata.tables, "alembic_version")))
REASON = "Reconciliação offline Demo: autorização restaurada invalidada; sem retomada ou cleanup externo."
MUTABLE = {
    "users": ("active",),
    "laboratories": ("authorized", "environment_version", "active_run_id"),
    "campaign_runs": (
        "state",
        "cancel_requested",
        "requested_outcome",
        "ended_at",
        "error",
    ),
    "test_executions": ("state", "ended_at"),
    "schedules": ("state", "reason"),
    "schedule_authorizations": ("revoked_at",),
}


def literals(values):
    # All values are internal enums/constants, never supplied by the caller.
    return ",".join("'" + str(value) + "'" for value in sorted(values))


def snapshot_sql():
    sources = [
        ("table:" + table, f"SELECT to_jsonb(t)::text FROM public.{identifier(table)} t")
        for table in TABLES
    ]
    sources.extend(("structure:" + name, sql) for name, sql in structure_queries("public").items())
    parts = []
    for name, query in sources:
        parts.append(f"""SELECT '{name}' AS name,
          encode(sha256(convert_to(COALESCE(string_agg(value, E'\\n' ORDER BY value COLLATE "C"), ''), 'UTF8')), 'hex') AS hash
          FROM ({query}) rows(value)""")
    return (
        """SELECT encode(sha256(convert_to(string_agg(name || ':' || hash, E'\\n' ORDER BY name COLLATE "C"), 'UTF8')), 'hex') FROM ("""
        + " UNION ALL ".join(parts)
        + ") fingerprints"
    )


def plan_sql():
    terminal = literals(TERMINAL)
    states = literals(State)
    # Any ambiguity blocks the entire transaction. Historical real evidence may
    # remain, but no outstanding real work/reservation is treated as Demo.
    blockers = {
        "unknown_states": f"""SELECT (SELECT count(*) FROM public.campaign_runs WHERE state NOT IN ({states}))
          + (SELECT count(*) FROM public.test_executions WHERE state NOT IN ({states}))""",
        "unsafe_pending_runs": f"""SELECT count(*) FROM public.campaign_runs r
          JOIN public.laboratories l ON l.id=r.laboratory_id WHERE r.state NOT IN ({terminal}) AND (
            NOT r.synthetic OR l.kind <> 'demo'
            OR NOT EXISTS (SELECT 1 FROM public.test_executions e WHERE e.run_id=r.id)
            OR EXISTS (SELECT 1 FROM public.test_executions e
              JOIN public.test_definitions t ON t.id=e.test_id JOIN public.assets a ON a.id=e.asset_id
              WHERE e.run_id=r.id AND (NOT e.synthetic OR NOT a.synthetic
                OR a.laboratory_id<>r.laboratory_id OR t.execution_kind<>'demo'))
            OR EXISTS (SELECT 1 FROM public.runner_dispatches d JOIN public.test_executions e
              ON e.id=d.execution_id WHERE e.run_id=r.id))""",
        "inconsistent_executions": f"""SELECT count(*) FROM public.test_executions e
          JOIN public.campaign_runs r ON r.id=e.run_id
          WHERE e.state NOT IN ({terminal}) AND r.state IN ({terminal})""",
        "ambiguous_reservations": f"""SELECT count(*) FROM public.laboratories l
          WHERE l.active_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM public.campaign_runs r WHERE r.id=l.active_run_id
            AND r.laboratory_id=l.id AND r.synthetic AND l.kind='demo'
            AND r.state NOT IN ({terminal}))""",
    }
    counts = {
        "sessions": "SELECT count(*) FROM public.sessions",
        "active_users": "SELECT count(*) FROM public.users WHERE active",
        "authorized_laboratories": "SELECT count(*) FROM public.laboratories WHERE authorized",
        "reservations": "SELECT count(*) FROM public.laboratories WHERE active_run_id IS NOT NULL",
        "pending_demo_runs": f"SELECT count(*) FROM public.campaign_runs WHERE synthetic AND state NOT IN ({terminal})",
        "pending_executions": f"SELECT count(*) FROM public.test_executions WHERE state NOT IN ({terminal})",
        "resumable_schedules": "SELECT count(*) FROM public.schedules WHERE state IN ('ACTIVE','PAUSED','PENDING_APPROVAL')",
        "unrevoked_grants": "SELECT count(*) FROM public.schedule_authorizations WHERE revoked_at IS NULL",
        "retained_unused_approvals": "SELECT count(*) FROM public.approvals WHERE used_at IS NULL",
    }

    def object_sql(items):
        return (
            "jsonb_build_object(" + ",".join(f"'{key}',({sql})" for key, sql in items.items()) + ")"
        )

    return f"""SELECT jsonb_build_object('format','{FORMAT}',
      'snapshot_sha256',({snapshot_sql()}), 'counts',{object_sql(counts)},
      'blockers',{object_sql(blockers)}, 'normal_operation_permitted',false)"""


def guard_sql():
    revision = required_revision()
    if not re.fullmatch(r"[a-z0-9]+", revision):
        raise ValueError("Unsupported schema revision")
    return f"""IF current_database()<>'aegis_restore' OR current_schema()<>'public'
      OR current_user<>'postgres' OR session_user<>'postgres'
      OR current_setting('server_version_num')::int / 10000 <> 17
      OR (SELECT array_agg(version_num::text) FROM public.alembic_version) IS DISTINCT FROM ARRAY['{revision}']
      OR (SELECT array_agg(c.relname::text ORDER BY c.relname::text COLLATE "C")
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relkind='r') IS DISTINCT FROM ARRAY[{literals(TABLES)}]
      THEN RAISE EXCEPTION 'Offline recovery destination/schema refused'; END IF;"""


def all_rows_sql():
    return " UNION ALL ".join(
        f"SELECT '{table}' AS name, to_jsonb(t) AS row FROM public.{identifier(table)} t"
        for table in TABLES
    )


def projected_rows(source):
    cases = []
    for table, columns in MUTABLE.items():
        cases.append(f"WHEN '{table}' THEN row - ARRAY[{literals(columns)}]")
    return f"""SELECT name, CASE name {" ".join(cases)} ELSE row END AS row FROM ({source}) rows
      WHERE name NOT IN ('sessions','audit_events','execution_steps')"""


def apply_sql(expected_hash, recovery_id):
    if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or not re.fullmatch(
        r"[a-f0-9]{32}", recovery_id
    ):
        raise ValueError("Invalid recovery fingerprint/identity")
    locks = ",".join("public." + identifier(table) for table in TABLES)
    transitions = []
    for old_states, target in (
        ((State.CREATED,), State.PENDING_APPROVAL),
        (ACTIVE - {State.CLEANING_UP}, State.CLEANING_UP),
        ((State.PENDING_APPROVAL, State.QUEUED, State.CLEANING_UP), State.CANCELLED),
    ):
        ending = (
            ", cancel_requested=true, requested_outcome='CANCELLED', ended_at=now(), error='"
            + REASON
            + "'"
            if target == State.CANCELLED
            else ""
        )
        transitions.append(f"""WITH changed AS (
          UPDATE public.campaign_runs SET state='{target}' {ending}
          WHERE state IN ({literals(old_states)}) RETURNING id)
          INSERT INTO public.execution_steps (id,created_at,run_id,state,message)
          SELECT gen_random_uuid()::text,now(),id,'{target}','{REASON}' FROM changed;""")
    before = projected_rows("SELECT name,row FROM recovery_original")
    after = projected_rows(all_rows_sql())
    return f"""BEGIN;
      SET LOCAL timezone='UTC'; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='2s';
      LOCK TABLE {locks} IN ACCESS EXCLUSIVE MODE NOWAIT;
      DO $reconcile$
      DECLARE plan jsonb; previous jsonb;
      BEGIN
        {guard_sql()}
        SELECT details INTO previous FROM public.audit_events
          WHERE action='{ACTION}' AND resource_id='{recovery_id}';
        IF previous IS NOT NULL THEN
          IF previous->>'plan_sha256' <> '{expected_hash}' THEN
            RAISE EXCEPTION 'Recovery identity already used'; END IF;
          RETURN;
        END IF;
        plan := ({plan_sql()});
        IF plan->>'snapshot_sha256'<>'{expected_hash}' THEN
          RAISE EXCEPTION 'Recovery plan changed'; END IF;
        IF EXISTS (SELECT 1 FROM jsonb_each_text(plan->'blockers') WHERE value::bigint<>0) THEN
          RAISE EXCEPTION 'Recovery requires manual review'; END IF;
        CREATE TEMP TABLE recovery_original ON COMMIT DROP AS {all_rows_sql()};
        DELETE FROM public.sessions;
        UPDATE public.users SET active=false WHERE active;
        UPDATE public.laboratories SET authorized=false, environment_version=environment_version+1
          WHERE authorized;
        UPDATE public.laboratories SET active_run_id=NULL WHERE active_run_id IS NOT NULL;
        UPDATE public.schedule_authorizations SET revoked_at=now() WHERE revoked_at IS NULL;
        UPDATE public.schedules SET state='REVOKED',reason='{REASON}'
          WHERE state IN ('ACTIVE','PAUSED','PENDING_APPROVAL');
        {" ".join(transitions)}
        UPDATE public.test_executions SET state='CANCELLED',ended_at=now()
          WHERE state NOT IN ({literals(TERMINAL)});
        IF EXISTS (SELECT 1 FROM public.sessions)
          OR EXISTS (SELECT 1 FROM public.users WHERE active)
          OR EXISTS (SELECT 1 FROM public.laboratories WHERE authorized OR active_run_id IS NOT NULL)
          OR EXISTS (SELECT 1 FROM public.campaign_runs WHERE state NOT IN ({literals(TERMINAL)}))
          OR EXISTS (SELECT 1 FROM public.test_executions WHERE state NOT IN ({literals(TERMINAL)}))
          OR EXISTS (SELECT 1 FROM public.schedule_authorizations WHERE revoked_at IS NULL)
          OR EXISTS (SELECT 1 FROM public.schedules WHERE state IN ('ACTIVE','PAUSED','PENDING_APPROVAL'))
          THEN RAISE EXCEPTION 'Recovery postconditions failed'; END IF;
        IF EXISTS (({before}) EXCEPT ALL ({after})) OR EXISTS (({after}) EXCEPT ALL ({before}))
          OR EXISTS (SELECT row FROM recovery_original WHERE name='audit_events'
             EXCEPT ALL SELECT to_jsonb(t) FROM public.audit_events t)
          OR EXISTS (SELECT row FROM recovery_original WHERE name='execution_steps'
             EXCEPT ALL SELECT to_jsonb(t) FROM public.execution_steps t)
          THEN RAISE EXCEPTION 'Recovery changed protected data'; END IF;
        INSERT INTO public.audit_events (id,created_at,actor_id,action,resource_id,details)
          VALUES (gen_random_uuid()::text,now(),NULL,'{ACTION}','{recovery_id}',
          jsonb_build_object('format','{FORMAT}','plan_sha256','{expected_hash}',
            'before_counts',plan->'counts','reconciliation_applied',true,
            'normal_operation_permitted',false,'external_cleanup_performed',false));
      END $reconcile$;
      SELECT details::text FROM public.audit_events
        WHERE action='{ACTION}' AND resource_id='{recovery_id}';
      COMMIT;"""
