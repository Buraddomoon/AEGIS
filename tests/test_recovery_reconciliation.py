"""Reconciliation SQL against a disposable PostgreSQL database, never live ACLs."""

import json
import re
from datetime import timedelta

import pytest
from aegis.domain.states import ACTIVE, TERMINAL, State, check_transition
from aegis.models import (
    Approval,
    AuditEvent,
    Campaign,
    CampaignRun,
    CampaignTest,
    ExecutionStep,
    Laboratory,
    LoginSession,
    RunnerDispatch,
    Schedule,
    ScheduleAuthorization,
    User,
    now,
)
from aegis.models import (
    TestExecution as Execution,
)
from aegis.operations import reconciliation as reconcile
from aegis.operations.backup import inventory
from aegis.services import request_run, start_run
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from test_recovery_api import recovered_database as _recovered_database

recovered_database = _recovered_database

RECOVERY_ID = "a" * 32


def run_sql(engine, sql):
    # psycopg exposes the JSON SELECT amidst a multi-statement transaction.
    with engine.raw_connection() as connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql, prepare=False)
                results = []
                while True:
                    if cursor.description:
                        results.extend(row[0] for row in cursor.fetchall())
                    if not cursor.nextset():
                        break
            connection.commit()
            return json.loads(results[-1]) if results else None
        except Exception:
            connection.rollback()
            raise


def get_plan(engine):
    with engine.connect() as c:
        return c.scalar(text(reconcile.plan_sql()))


def get_inventory(engine):
    with engine.connect() as c:
        return inventory(lambda sql: c.scalars(text(sql)))


@pytest.fixture
def recovered_work(recovered_database, monkeypatch):
    writer, _ = recovered_database
    # Keep the production checks, replacing only the fixed clone DB/user with
    # this disposable test identity. The unmodified destination is tested below.
    assert re.fullmatch(r"[a-z0-9_]+", writer.url.database)
    assert re.fullmatch(r"[a-z0-9_]+", writer.url.username)
    guard = reconcile.guard_sql().replace(
        "current_database()<>'aegis_restore'", "current_database()<>'" + writer.url.database + "'"
    )
    guard = guard.replace(
        "current_user<>'postgres' OR session_user<>'postgres'",
        "current_user<>'"
        + writer.url.username
        + "' OR session_user<>'"
        + writer.url.username
        + "'",
    )
    monkeypatch.setattr(reconcile, "guard_sql", lambda: guard)
    with Session(writer) as db:
        lab = db.scalar(select(Laboratory))
        user = User(username="restored-admin", role="administrator", password_hash="test-hash")
        db.add(user)
        db.flush()
        campaign = Campaign(
            name="Recovered Demo",
            objective="Offline test",
            laboratory_id=lab.id,
            created_by=user.id,
        )
        db.add(campaign)
        db.flush()
        db.add(CampaignTest(campaign_id=campaign.id, test_id="demo-shell"))
        db.flush()
        run = request_run(db, campaign.id, user, "recovery-snapshot")
        run.state = "QUEUED"
        lab.active_run_id = run.id
        execution = db.scalar(select(Execution).where(Execution.run_id == run.id))
        execution.state = "QUEUED"
        db.add(
            Approval(
                run_id=run.id,
                approved_by=user.id,
                scope_hash=run.scope_hash,
                expires_at=now() + timedelta(hours=1),
                max_duration_seconds=60,
            )
        )
        db.add(
            LoginSession(
                token_hash="b" * 64,
                csrf_hash="c" * 64,
                user_id=user.id,
                expires_at=now() + timedelta(hours=1),
            )
        )
        schedule = Schedule(
            campaign_id=campaign.id,
            laboratory_id=lab.id,
            created_by=user.id,
            state="ACTIVE",
            scope=run.scope,
            scope_hash=run.scope_hash,
            plan_hash="d" * 64,
            interval_seconds=60,
            max_occurrences=2,
            max_duration_seconds=60,
            starts_at=now(),
            ends_at=now() + timedelta(hours=1),
            next_due_at=now(),
        )
        db.add(schedule)
        db.flush()
        db.add(
            ScheduleAuthorization(
                schedule_id=schedule.id,
                approved_by=user.id,
                plan_hash=schedule.plan_hash,
                expires_at=schedule.ends_at,
            )
        )
        db.commit()
        ids = {
            "run": run.id,
            "lab": lab.id,
            "user": user.id,
            "execution": execution.id,
            "schedule": schedule.id,
        }
    return writer, ids


def test_fixed_destination_guard_rejects_test_database_before_mutation(recovered_database):
    writer, _ = recovered_database
    before = get_inventory(writer)
    with pytest.raises(Exception, match="destination/schema refused"):
        run_sql(writer, reconcile.apply_sql(get_plan(writer)["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_reconciliation_preserves_history_revokes_access_and_is_idempotent(recovered_work):
    writer, ids = recovered_work
    before = get_inventory(writer)
    plan = get_plan(writer)
    assert not any(plan["blockers"].values())
    assert plan["counts"]["sessions"] == plan["counts"]["pending_demo_runs"] == 1
    result = run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    assert result["reconciliation_applied"] is True
    assert result["normal_operation_permitted"] is False
    assert result["external_cleanup_performed"] is False
    after = get_inventory(writer)
    assert after["structure"] == before["structure"]
    for table in (
        before["tables"].keys()
        - reconcile.MUTABLE.keys()
        - {"sessions", "audit_events", "execution_steps"}
    ):
        assert after["tables"][table] == before["tables"][table], table
    with Session(writer) as db:
        assert not list(db.scalars(select(LoginSession)))
        user = db.get(User, ids["user"])
        lab = db.get(Laboratory, ids["lab"])
        run = db.get(CampaignRun, ids["run"])
        assert not user.active and not lab.authorized and lab.active_run_id is None
        assert lab.environment_version == 2
        assert run.state == "CANCELLED" and run.cancel_requested and run.ended_at
        assert db.get(Execution, ids["execution"]).state == "CANCELLED"
        assert db.get(Schedule, ids["schedule"]).state == "REVOKED"
        assert db.scalar(select(ScheduleAuthorization)).revoked_at
        approval = db.scalar(select(Approval))
        assert approval.used_at is None and approval.expires_at > now()
        with pytest.raises(HTTPException, match="409"):
            start_run(db, run.id, user)
        audit = db.scalar(select(AuditEvent).where(AuditEvent.action == reconcile.ACTION))
        assert audit.actor_id is None and audit.details["plan_sha256"] == plan["snapshot_sha256"]
    assert run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID)) == result
    assert get_inventory(writer) == after


@pytest.mark.parametrize("state", sorted(set(State) - TERMINAL))
def test_pending_demo_transitions_are_valid_without_claiming_cleanup(recovered_work, state):
    writer, ids = recovered_work
    with writer.begin() as c:
        c.execute(
            text("UPDATE campaign_runs SET state=:state WHERE id=:id"),
            {"state": state, "id": ids["run"]},
        )
        c.execute(
            text("UPDATE test_executions SET state=:state WHERE id=:id"),
            {"state": state, "id": ids["execution"]},
        )
    result = run_sql(writer, reconcile.apply_sql(get_plan(writer)["snapshot_sha256"], RECOVERY_ID))
    assert not result["external_cleanup_performed"]
    with Session(writer) as db:
        steps = list(db.scalars(select(ExecutionStep).where(ExecutionStep.run_id == ids["run"])))
        added = [s for s in steps if s.message == reconcile.REASON and s.execution_id is None]
        children = [
            s for s in steps if s.message == reconcile.REASON and s.execution_id == ids["execution"]
        ]
        expected = []
        if state == State.CREATED:
            expected.append(State.PENDING_APPROVAL)
        elif state in ACTIVE - {State.CLEANING_UP}:
            expected.append(State.CLEANING_UP)
        expected.append(State.CANCELLED)
        assert sorted(s.state for s in added) == sorted(expected)
        assert sorted(s.state for s in children) == sorted(expected)
        for target in expected:
            check_transition(state, target)
            state = target


@pytest.mark.parametrize(
    "change",
    [
        "UPDATE campaign_runs SET synthetic=false",
        "UPDATE laboratories SET kind='linux'",
        "UPDATE assets SET synthetic=false",
        "UPDATE test_definitions SET execution_kind='linux_marker' WHERE id='demo-shell'",
        "UPDATE laboratories SET active_run_id='unknown'",
        "UPDATE campaign_runs SET state='COMPLETED'",
        "UPDATE campaign_runs SET state='UNRECOGNIZED'",
        "UPDATE test_executions SET state='UNRECOGNIZED'",
        "DELETE FROM test_executions",
    ],
)
def test_ambiguity_blocks_every_change(recovered_work, change):
    writer, _ = recovered_work
    with writer.begin() as c:
        if change == "DELETE FROM test_executions":
            c.execute(text("DELETE FROM execution_steps"))
        c.execute(text(change))
    before = get_inventory(writer)
    plan = get_plan(writer)
    assert any(plan["blockers"].values())
    with pytest.raises(Exception, match="manual review"):
        run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_pending_dispatch_never_replayed(recovered_work):
    writer, ids = recovered_work
    with Session(writer) as db:
        db.add(RunnerDispatch(execution_id=ids["execution"], spec={}, spec_hash="e" * 64))
        db.commit()
    before = get_inventory(writer)
    plan = get_plan(writer)
    assert plan["blockers"]["unsafe_pending_runs"] == 1
    with pytest.raises(Exception, match="manual review"):
        run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_plan_drift_refuses_and_rolls_back(recovered_work):
    writer, _ = recovered_work
    plan = get_plan(writer)
    with writer.begin() as c:
        c.execute(text("UPDATE users SET username='changed-after-plan'"))
    before = get_inventory(writer)
    with pytest.raises(Exception, match="plan changed"):
        run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_late_failure_rolls_back_sessions_users_runs_and_grants(recovered_work):
    writer, _ = recovered_work
    with writer.begin() as c:
        c.execute(
            text("""CREATE FUNCTION fail_recovery() RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN RAISE EXCEPTION 'Injected final audit failure'; END $$""")
        )
        c.execute(
            text(
                "CREATE TRIGGER fail_recovery BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_recovery()"
            )
        )
    before = get_inventory(writer)
    with pytest.raises(Exception, match="Injected final audit failure"):
        run_sql(writer, reconcile.apply_sql(get_plan(writer)["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_locks_refuse_competing_writer_without_mutation(recovered_work):
    writer, _ = recovered_work
    plan = get_plan(writer)
    with writer.connect() as other, other.begin():
        other.execute(text("LOCK TABLE public.sessions IN ROW EXCLUSIVE MODE"))
        with pytest.raises(Exception, match="could not obtain lock"):
            run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    assert get_plan(writer) == plan


@pytest.mark.parametrize(
    "fingerprint,identity", [("' SQL", "a" * 32), ("b" * 64, "../"), ("b" * 63, "a" * 32)]
)
def test_untrusted_identifiers_rejected_before_sql(fingerprint, identity):
    with pytest.raises(ValueError):
        reconcile.apply_sql(fingerprint, identity)


def test_existing_execution_end_and_terminal_history_are_preserved(recovered_work):
    writer, ids = recovered_work
    stamp = now() - timedelta(minutes=2)
    with writer.begin() as c:
        c.execute(text("UPDATE campaign_runs SET state='COLLECTING'"))
        c.execute(
            text("UPDATE test_executions SET state='COLLECTING',executed=true,ended_at=:stamp"),
            {"stamp": stamp},
        )
    run_sql(writer, reconcile.apply_sql(get_plan(writer)["snapshot_sha256"], RECOVERY_ID))
    with Session(writer) as db:
        item = db.get(Execution, ids["execution"])
        assert item.ended_at == stamp and item.executed and item.state == "CANCELLED"


def test_terminal_runs_and_executions_unchanged(recovered_work):
    writer, _ = recovered_work
    with writer.begin() as c:
        c.execute(text("UPDATE campaign_runs SET state='COMPLETED'"))
        c.execute(text("UPDATE test_executions SET state='COMPLETED',executed=true,ended_at=now()"))
        c.execute(text("UPDATE laboratories SET active_run_id=NULL"))
    before = get_inventory(writer)
    run_sql(writer, reconcile.apply_sql(get_plan(writer)["snapshot_sha256"], RECOVERY_ID))
    after = get_inventory(writer)
    for table in ("campaign_runs", "test_executions", "approvals"):
        assert after["tables"][table] == before["tables"][table]


def test_structure_drift_refused_by_scope_hash(recovered_work):
    writer, _ = recovered_work
    plan = get_plan(writer)
    with writer.begin() as c:
        c.execute(text("ALTER TABLE users ADD COLUMN test_drift text"))
    before = get_inventory(writer)
    with pytest.raises(Exception, match="plan changed"):
        run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_extra_tables_refuse_before_reconciliation(recovered_work):
    writer, _ = recovered_work
    with writer.begin() as c:
        c.execute(text("CREATE TABLE unreviewed_extra (id text)"))
    before = get_inventory(writer)
    with pytest.raises(Exception, match="destination/schema refused"):
        run_sql(writer, reconcile.apply_sql(get_plan(writer)["snapshot_sha256"], RECOVERY_ID))
    assert get_inventory(writer) == before


def test_current_review_refuses_pending_child_after_reconciliation(recovered_work):
    from aegis.operations.recovery import review

    writer, ids = recovered_work
    plan = get_plan(writer)
    run_sql(writer, reconcile.apply_sql(plan["snapshot_sha256"], RECOVERY_ID))
    expected = (RECOVERY_ID, plan["snapshot_sha256"])
    assert review(expected)["reconciliation_applied"] is True
    with writer.begin() as c:
        c.execute(
            text("UPDATE test_executions SET state='RUNNING' WHERE id=:id"),
            {"id": ids["execution"]},
        )
    with pytest.raises(RuntimeError, match="no longer fenced"):
        review(expected)
