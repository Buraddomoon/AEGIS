"""Fixed owner-only SQL for a fresh Demo cycle inside a reconciled offline clone."""

import re
import uuid

from psycopg import sql

from aegis.domain.validation import LOGIC_VERSION
from aegis.operations import reconciliation
from aegis.operations.runtime_grants import RUNTIME_PERMISSIONS
from aegis.seed import DEMO_TESTS

FORMAT = "aegis-recovered-demo-cycle/1"
GUARD_SCHEMA = "aegis_recovery_guard"
TEST_IDS = tuple(item["id"] for item in DEMO_TESTS)


def context(token):
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("Invalid recovery identity")
    namespace = uuid.UUID(hex=token)
    return {
        "reconciliation_id": token,
        "account_id": str(uuid.uuid5(namespace, "account")),
        "username": "recovery-" + token,
        "laboratory_id": str(uuid.uuid5(namespace, "lab")),
        "asset_id": str(uuid.uuid5(namespace, "asset")),
    }


def literal(value):
    return sql.Literal(value).as_string()


def row_hashes():
    return (
        "SELECT name,encode(sha256(convert_to(row::text,'UTF8')),'hex') AS sha256 FROM ("
        + reconciliation.all_rows_sql()
        + ") rows"
    )


def locks():
    return (
        "LOCK TABLE "
        + ",".join('public."' + t + '"' for t in reconciliation.TABLES)
        + " IN ACCESS EXCLUSIVE MODE NOWAIT;"
    )


def prepare_sql(token, plan_hash, account_hash, runtime_password):
    data = context(token)
    if (
        not re.fullmatch(r"[a-f0-9]{64}", plan_hash)
        or not re.fullmatch(r"[a-f0-9]{64}", runtime_password)
        or len(account_hash) > 256
        or not re.fullmatch(
            r"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+", account_hash
        )
    ):
        raise ValueError("Invalid fresh recovery credentials/fingerprint")
    checks = []
    for item in DEMO_TESTS:
        predicates = [
            f"{key} IS NOT DISTINCT FROM {literal(item[key])}"
            for key in ("id", "technique_id", "behavior", "demo_outcome")
        ]
        checks.append(
            "EXISTS (SELECT 1 FROM public.test_definitions WHERE "
            + " AND ".join(predicates)
            + " AND approved AND execution_kind='demo' AND platform='Synthetic' AND version=1 AND risk='synthetic' AND expected_rule="
            + literal("aegis-" + item["id"])
            + ")"
        )
    user, lab, asset = (literal(data[k]) for k in ("account_id", "laboratory_id", "asset_id"))
    return f"""BEGIN; SET LOCAL timezone='UTC'; SET LOCAL statement_timeout='60s';
      {locks()}
      DO $prepare$
      DECLARE p jsonb;
      BEGIN
        {reconciliation.guard_sql()}
        IF (SELECT count(*) FROM public.audit_events WHERE action='{reconciliation.ACTION}'
          AND resource_id='{token}' AND details->>'plan_sha256'='{plan_hash}'
          AND details->'reconciliation_applied'='true'::jsonb)<>1 THEN
          RAISE EXCEPTION 'Current reconciliation receipt missing'; END IF;
        p := ({reconciliation.plan_sql()});
        IF EXISTS (SELECT 1 FROM jsonb_each_text(p->'blockers') WHERE value::bigint<>0)
          OR EXISTS (SELECT 1 FROM jsonb_each_text(p->'counts') WHERE key<>'retained_unused_approvals' AND value::bigint<>0)
          THEN RAISE EXCEPTION 'Recovered destination still has authority or pending work'; END IF;
        IF NOT ({" AND ".join(checks)}) THEN RAISE EXCEPTION 'Reviewed Demo catalog mismatch'; END IF;
      END $prepare$;
      CREATE SCHEMA {GUARD_SCHEMA} AUTHORIZATION postgres;
      REVOKE ALL ON SCHEMA {GUARD_SCHEMA} FROM PUBLIC;
      CREATE TABLE {GUARD_SCHEMA}.original_rows AS {row_hashes()};
      CREATE ROLE aegis_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOREPLICATION NOBYPASSRLS PASSWORD {literal(runtime_password)};
      GRANT CONNECT ON DATABASE aegis_restore TO aegis_app;
      {";".join(RUNTIME_PERMISSIONS)};
      INSERT INTO public.users (id,created_at,username,password_hash,role,active)
        VALUES ({user},now(),{literal(data["username"])},{literal(account_hash)},'administrator',true);
      INSERT INTO public.laboratories (id,created_at,name,description,kind,authorized,owner,environment_version,isolation)
        VALUES ({lab},now(),{literal("Recovered Demo " + token)},'Novo ambiente sintético após reconciliação.',
          'demo',false,'Ensaio local de recuperação',1,'Adaptadores sintéticos, sem alvos externos.');
      INSERT INTO public.assets (id,created_at,laboratory_id,name,platform,external_id,synthetic)
        VALUES ({asset},now(),{lab},'recovered-demo-endpoint','Synthetic',{literal("recovered-demo-" + token)},true);
      INSERT INTO public.audit_events (id,created_at,actor_id,action,resource_id,details)
        VALUES (gen_random_uuid()::text,now(),NULL,'recovery.demo.bootstrap','{token}',
          jsonb_build_object('synthetic',true,'new_account_id',{user},'new_laboratory_id',{lab},'plan_sha256','{plan_hash}'));
      SELECT jsonb_build_object('format','{FORMAT}','account_id',{user},'laboratory_id',{lab},
        'asset_id',{asset},'baseline_rows',(SELECT count(*) FROM {GUARD_SCHEMA}.original_rows))::text;
      COMMIT;"""


def close_sql(token, run_id):
    data = context(token)
    if str(uuid.UUID(run_id)) != run_id:
        raise ValueError("Invalid run identity")
    user, lab = (literal(data[k]) for k in ("account_id", "laboratory_id"))
    return f"""BEGIN; SET LOCAL timezone='UTC'; SET LOCAL statement_timeout='60s';
      {locks()}
      DO $close$ BEGIN
        {reconciliation.guard_sql()}
        IF NOT EXISTS (SELECT 1 FROM public.campaign_runs WHERE id='{run_id}' AND synthetic
          AND state='COMPLETED' AND laboratory_id={lab} AND requested_by={user} AND schedule_id IS NULL)
          OR (SELECT count(*) FROM public.campaign_runs) <> 1+(SELECT count(*) FROM {GUARD_SCHEMA}.original_rows WHERE name='campaign_runs')
          OR (SELECT count(*) FROM public.test_executions WHERE run_id='{run_id}' AND state='COMPLETED' AND executed AND synthetic)<>4
          OR (SELECT array_agg(test_id::text ORDER BY test_id::text COLLATE "C") FROM public.test_executions WHERE run_id='{run_id}') IS DISTINCT FROM ARRAY[{reconciliation.literals(TEST_IDS)}]
          OR (SELECT array_agg(v.outcome::text ORDER BY v.outcome::text COLLATE "C") FROM public.validation_results v
              JOIN public.test_executions e ON e.id=v.execution_id WHERE e.run_id='{run_id}' AND v.synthetic
              AND v.logic_version={literal(LOGIC_VERSION)}) IS DISTINCT FROM ARRAY[{reconciliation.literals(item["demo_outcome"] for item in DEMO_TESTS)}]
          OR NOT EXISTS (SELECT 1 FROM public.approvals a JOIN public.campaign_runs r ON r.id=a.run_id
              WHERE r.id='{run_id}' AND a.approved_by={user} AND a.used_at IS NOT NULL
              AND a.schedule_authorization_id IS NULL AND a.scope_hash=r.scope_hash)
          OR EXISTS (SELECT 1 FROM public.runner_dispatches d JOIN public.test_executions e ON e.id=d.execution_id WHERE e.run_id='{run_id}')
          OR EXISTS (SELECT 1 FROM public.laboratories WHERE authorized OR active_run_id IS NOT NULL)
          OR EXISTS (SELECT 1 FROM public.sessions)
          OR EXISTS (SELECT 1 FROM public.users WHERE active AND id<>{user})
          OR EXISTS (SELECT 1 FROM public.campaign_runs WHERE state NOT IN ({reconciliation.literals(reconciliation.TERMINAL)}))
          OR EXISTS (SELECT 1 FROM public.test_executions WHERE state NOT IN ({reconciliation.literals(reconciliation.TERMINAL)}))
          OR EXISTS (SELECT 1 FROM public.schedule_authorizations WHERE revoked_at IS NULL)
          OR EXISTS (SELECT 1 FROM public.schedules WHERE state IN ('ACTIVE','PAUSED','PENDING_APPROVAL'))
          THEN RAISE EXCEPTION 'Recovered Demo cycle did not close safely'; END IF;
        UPDATE public.users SET active=false WHERE id={user};
        INSERT INTO public.audit_events (id,created_at,actor_id,action,resource_id,details)
          VALUES (gen_random_uuid()::text,now(),NULL,'recovery.demo.cycle.closed','{token}',
            jsonb_build_object('run_id','{run_id}','synthetic',true,'fresh_account_disabled',true));
        IF EXISTS ((SELECT name,sha256 FROM {GUARD_SCHEMA}.original_rows) EXCEPT ALL ({row_hashes()}))
          THEN RAISE EXCEPTION 'Recovered historical rows changed'; END IF;
        IF EXISTS (SELECT 1 FROM public.users WHERE active) THEN RAISE EXCEPTION 'Fresh account remains active'; END IF;
      END $close$;
      SELECT jsonb_build_object('format','{FORMAT}','historical_rows_unchanged',true,
        'baseline_rows',(SELECT count(*) FROM {GUARD_SCHEMA}.original_rows),
        'fresh_account_disabled',true,'fresh_sessions_remaining',0,'pending_runs',0)::text;
      COMMIT;"""
