import uuid

from aegis.db import session_factory
from aegis.models import CampaignRun, Laboratory, User
from aegis.services import request_run, start_run
from conftest import create_queued
from sqlalchemy import select


def test_request_run_can_participate_in_outer_rollback(admin):
    queued = create_queued(admin, ["demo-shell"])
    with session_factory()() as db:
        actor = db.scalar(select(User).where(User.username == "administrator"))
        pending = request_run(db, queued["campaign_id"], actor, uuid.uuid4().hex, commit=False)
        run_id = pending.id
        assert db.get(CampaignRun, run_id)
        db.rollback()
    with session_factory()() as db:
        assert db.get(CampaignRun, run_id) is None


def test_start_rollback_preserves_approval_and_lab_reservation(admin):
    queued = create_queued(admin, ["demo-shell"])
    admin.post(f"/api/v1/executions/{queued['id']}/cancel")
    pending = admin.post(
        f"/api/v1/campaigns/{queued['campaign_id']}/runs",
        json={"idempotency_key": uuid.uuid4().hex},
    ).json()
    admin.post(
        f"/api/v1/executions/{pending['id']}/approve",
        json={"confirm_scope_hash": pending["scope_hash"]},
    )
    with session_factory()() as db:
        actor = db.scalar(select(User).where(User.username == "administrator"))
        run = start_run(db, pending["id"], actor, commit=False)
        assert run.state == "QUEUED"
        db.rollback()
    with session_factory()() as db:
        assert db.get(CampaignRun, pending["id"]).state == "PENDING_APPROVAL"
        assert db.get(Laboratory, pending["laboratory_id"]).active_run_id is None
