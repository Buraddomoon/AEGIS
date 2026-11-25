"""API account revocation against retained Linux recurrence; fixture, no Lab effect."""

import pytest
from aegis import queries, scheduling, worker
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.main import app
from aegis.models import CampaignRun, Laboratory, RunnerDispatch, Schedule, ScheduleAuthorization
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_linux_campaigns import linux as linux
from test_linux_scheduling import enabled as enabled
from test_linux_scheduling import ready
from test_user_maintenance import edit, login, second_admin, users


@pytest.mark.parametrize("subject", ["operator", "administrator"])
@pytest.mark.parametrize("phase", ["before_emission", "queued"])
def test_account_api_revocation_blocks_existing_recurrence_without_effect(enabled, subject, phase):
    client, lab, runner = enabled
    item, instant = ready(enabled)
    maintainer = second_admin(client)
    accounts = users(client)
    if phase == "queued":
        assert scheduling.dispatch_one(instant)
    with session_factory()() as db:
        grant = db.scalar(select(ScheduleAuthorization))
        before = digest(queries.record(grant))
        plan_hash, scope_hash = db.get(Schedule, item["id"]).plan_hash, item["scope_hash"]
    with TestClient(app) as previous:
        assert login(previous, subject).status_code == 200
        assert edit(maintainer, accounts[subject], role="viewer").status_code == 200
        assert previous.get("/api/v1/auth/me").status_code == 401
    if phase == "queued":
        assert worker.claim_next() is None
    else:
        assert scheduling.dispatch_one(instant)
    with session_factory()() as db:
        current = db.get(Schedule, item["id"])
        assert current.plan_hash == plan_hash and current.scope_hash == scope_hash
        assert digest(queries.record(db.scalar(select(ScheduleAuthorization)))) == before
        assert db.scalar(select(func.count()).select_from(RunnerDispatch)) == 0
        assert db.get(Laboratory, lab["id"]).active_run_id is None
        if phase == "queued":
            assert db.scalar(select(CampaignRun)).state == "REJECTED"
        else:
            assert current.state == "INVALIDATED"
            assert db.scalar(select(func.count()).select_from(CampaignRun)) == 0
    assert not list(runner.workspace.root.iterdir())
