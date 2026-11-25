"""Account changes retain approval/report history and never suppress cleanup."""

import uuid

import pytest
from aegis import worker
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.integrations.demo import DemoExecutionAdapter
from aegis.main import app
from aegis.models import Approval, CampaignRun, Laboratory, ValidationResult
from conftest import create_queued
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_user_maintenance import edit, login, second_admin, users


@pytest.mark.parametrize("subject", ["operator", "administrator"])
@pytest.mark.parametrize("phase", ["before_start", "queued"])
def test_distinct_requester_and_approver_rechecked(admin, subject, phase):
    maintainer = second_admin(admin)
    accounts = users(admin)
    requester = TestClient(app)
    login(requester, "operator")
    lab = requester.get("/api/v1/labs").json()["items"][0]
    campaign = requester.post(
        "/api/v1/campaigns",
        json={
            "name": "Disposable lifecycle",
            "objective": "Check permissions without native effects.",
            "laboratory_id": lab["id"],
            "test_ids": ["demo-shell"],
        },
    )
    assert campaign.status_code == 201
    run = requester.post(
        f"/api/v1/campaigns/{campaign.json()['id']}/runs",
        json={"idempotency_key": uuid.uuid4().hex},
    ).json()
    assert (
        admin.post(
            f"/api/v1/executions/{run['id']}/approve",
            json={"confirm_scope_hash": run["scope_hash"]},
        ).status_code
        == 200
    )
    if phase == "queued":
        assert (
            requester.post(
                f"/api/v1/executions/{run['id']}/start", json={"confirm": True}
            ).status_code
            == 200
        )
    with session_factory()() as db:
        approval = db.scalar(select(Approval).where(Approval.run_id == run["id"]))
        before = (
            approval.id,
            approval.approved_by,
            approval.scope_hash,
            approval.expires_at,
            approval.used_at,
        )
    assert edit(maintainer, accounts[subject], role="viewer").status_code == 200
    if phase == "queued":
        assert worker.claim_next() is None
    else:
        assert (
            maintainer.post(
                f"/api/v1/executions/{run['id']}/start", json={"confirm": True}
            ).status_code
            == 409
        )
    with session_factory()() as db:
        approval = db.scalar(select(Approval).where(Approval.run_id == run["id"]))
        assert (
            approval.id,
            approval.approved_by,
            approval.scope_hash,
            approval.expires_at,
            approval.used_at,
        ) == before
        current = db.get(CampaignRun, run["id"])
        assert (
            current.scope_hash == run["scope_hash"] and digest(current.scope) == run["scope_hash"]
        )
        assert current.state == ("REJECTED" if phase == "queued" else "PENDING_APPROVAL")
        assert db.get(Laboratory, lab["id"]).active_run_id is None
        assert not db.scalars(select(ValidationResult)).all()


def test_revocation_inside_cleanup_preserves_result_and_finishes_cleanup(admin):
    maintainer = second_admin(admin)
    account = users(admin)["administrator"]
    run = create_queued(admin, ["demo-shell"])
    snapshots, cleanups = [], []

    class Adapter(DemoExecutionAdapter):
        def cleanup(self, context):
            super().cleanup(context)
            cleanups.append(context.execution_id)
            with session_factory()() as db:
                result = db.scalar(select(ValidationResult))
                snapshots.append((result.id, result.outcome, result.reason, result.synthetic))
            assert edit(maintainer, account, active=False).status_code == 200

    assert worker.claim_next() == run["id"]
    worker.process_run(run["id"], Adapter())
    assert len(cleanups) == 1
    with session_factory()() as db:
        result = db.scalar(select(ValidationResult))
        assert [(result.id, result.outcome, result.reason, result.synthetic)] == snapshots
        assert result.synthetic is True
        current = db.get(CampaignRun, run["id"])
        assert current.state == "CANCELLED"
        assert current.error == "Identidade revogada durante cleanup."
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id is None
