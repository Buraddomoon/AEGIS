import copy
from datetime import timedelta
from uuid import uuid4

import pytest
from aegis import binding_review, linux_labs
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.lab_runner.protocol import JobSpec, JobView
from aegis.models import (
    AuditEvent,
    Campaign,
    CampaignRun,
    Laboratory,
    LinuxLabBinding,
    RunnerCleanup,
    RunnerDispatch,
    User,
    now,
)
from aegis.models import TestExecution as Execution
from sqlalchemy import func, select

REGISTRATION = {
    "name": "Laboratório para revisão do vínculo",
    "owner": "Responsável local",
    "isolation_review": "Escopo de fixture PostgreSQL; nenhum runner ou efeito externo.",
    "confirm_isolation_review": True,
}


@pytest.fixture
def binding_lab(admin, monkeypatch):
    identity = {
        "runner_id": str(uuid4()),
        "laboratory_id": str(uuid4()),
        "asset_id": str(uuid4()),
        "url": "https://172.30.88.2:8443",
        "server_ca_sha256": "a" * 64,
        "client_cert_sha256": "b" * 64,
        "protocol": "aegis-linux-runner/1",
        "test_id": "linux-file-marker/v1",
    }
    monkeypatch.setattr(linux_labs, "descriptor", lambda: copy.deepcopy(identity))

    def forbidden():
        raise AssertionError("Review must not create a runner client")

    monkeypatch.setattr(linux_labs, "client", forbidden)
    result = admin.post("/api/v1/labs/linux/register", json=REGISTRATION)
    assert result.status_code == 201, result.text
    return admin, identity


def history(identity, *, parent="COMPLETED", child="COMPLETED", dispatch=True, cleaned=True):
    """Persist proofs only. Never prepare/start a job or write an artifact."""
    with session_factory()() as db:
        actor = db.scalar(select(User).where(User.username == "administrator"))
        campaign = Campaign(
            name="Historical fixture",
            objective="Review persisted state without a runner",
            laboratory_id=identity["laboratory_id"],
            created_by=actor.id,
        )
        db.add(campaign)
        db.flush()
        scope = {"runner": identity, "mode": "linux", "synthetic": False}
        run = CampaignRun(
            campaign_id=campaign.id,
            laboratory_id=identity["laboratory_id"],
            requested_by=actor.id,
            idempotency_key=uuid4().hex,
            state=parent,
            scope=scope,
            scope_hash=digest(scope),
            synthetic=False,
            deadline_at=now() + timedelta(seconds=60),
        )
        db.add(run)
        db.flush()
        item = Execution(
            run_id=run.id,
            test_id="linux-file-marker-v1",
            asset_id=identity["asset_id"],
            state=child,
            marker="aegis-" + str(uuid4()),
            synthetic=False,
        )
        db.add(item)
        db.flush()
        if dispatch:
            spec = JobSpec(
                job_id=item.id,
                runner_id=identity["runner_id"],
                laboratory_id=identity["laboratory_id"],
                asset_id=item.asset_id,
                marker=item.marker,
                scope_hash=run.scope_hash,
                deadline_at=run.deadline_at,
            )
            value = spec.model_dump(mode="json")
            generation = uuid4()
            db.add(
                RunnerDispatch(
                    execution_id=item.id,
                    spec=value,
                    spec_hash=digest(value),
                    generation=str(generation),
                )
            )
            if cleaned:
                view = JobView(
                    spec=spec,
                    spec_hash=digest(value),
                    generation=generation,
                    state="CANCELLED",
                    cleanup_state="CLEANED",
                    reason="Fixture only: no process created",
                    receipt=None,
                    receipt_sha256=None,
                ).model_dump(mode="json")
                db.add(RunnerCleanup(execution_id=item.id, content=view, sha256=digest(view)))
        db.commit()
        return run.id, item.id


def read_review(identity):
    with session_factory()() as db:
        lab = db.get(Laboratory, identity["laboratory_id"])
        return binding_review.review(db, lab)


def test_valid_history_is_only_a_persisted_prerequisite_and_does_not_mutate(binding_lab):
    _, identity = binding_lab
    history(identity)
    history(identity, parent="CLEANUP_FAILED", child="CLEANUP_FAILED")
    with session_factory()() as db:
        audits = db.scalar(select(func.count()).select_from(AuditEvent))
        binding = db.get(LinuxLabBinding, identity["laboratory_id"])
        original = binding.configuration_hash
    result = read_review(identity)
    assert result["status"] == "persisted_prerequisites_satisfied"
    assert result["dispatches_examined"] == 2 and result["dispatch_history_complete"]
    assert not result["blockers"]
    assert all(
        result[key] is False
        for key in (
            "runner_contacted",
            "journal_verified",
            "activation_permitted",
            "normal_operation_permitted",
        )
    )
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == audits
        assert db.get(LinuxLabBinding, identity["laboratory_id"]).configuration_hash == original


@pytest.mark.parametrize("side", ["parent", "child"])
@pytest.mark.parametrize("state", ["PENDING_APPROVAL", "QUEUED", "RUNNING", "UNKNOWN"])
def test_pending_or_unknown_states_block_even_without_reservation(binding_lab, side, state):
    _, identity = binding_lab
    history(identity, **{side: state}, dispatch=False)
    result = read_review(identity)
    assert result["status"] == "blocked"
    assert ("nonterminal_runs" if side == "parent" else "nonterminal_tests") in result["blockers"]


@pytest.mark.parametrize("field", ["authorized", "active_run_id"])
def test_authorization_and_reservation_are_independent_blockers(binding_lab, field):
    _, identity = binding_lab
    with session_factory()() as db:
        setattr(
            db.get(Laboratory, identity["laboratory_id"]),
            field,
            True if field == "authorized" else str(uuid4()),
        )
        db.commit()
    assert read_review(identity)["status"] == "blocked"


@pytest.mark.parametrize(
    "problem",
    [
        "missing",
        "hash",
        "payload",
        "generation",
        "scope",
        "spec",
        "runner",
        "marker",
        "synthetic",
        "running",
        "prepared",
        "cleanup_pending",
        "receipt_missing",
    ],
)
def test_unconfirmed_or_drifted_cleanup_blocks_without_repair(binding_lab, problem):
    _, identity = binding_lab
    run_id, execution_id = history(identity, cleaned=problem != "missing")
    with session_factory()() as db:
        run = db.get(CampaignRun, run_id)
        item = db.get(Execution, execution_id)
        dispatch = db.scalar(select(RunnerDispatch))
        cleanup = db.scalar(select(RunnerCleanup))
        if problem == "hash":
            cleanup.sha256 = "0" * 64
        elif problem == "generation":
            dispatch.generation = str(uuid4())
        elif problem == "scope":
            run.scope_hash = "0" * 64
        elif problem == "spec":
            dispatch.spec_hash = "0" * 64
        elif problem == "synthetic":
            item.synthetic = True
        elif problem == "marker":
            item.marker = "aegis-" + str(uuid4())
        elif problem == "runner":
            scope = copy.deepcopy(run.scope)
            scope["runner"]["runner_id"] = str(uuid4())
            run.scope, run.scope_hash = scope, digest(scope)
        elif problem not in {"missing"}:
            value = copy.deepcopy(cleanup.content)
            if problem == "payload":
                value = {"cleanup_state": "CLEANED"}
            elif problem in {"running", "prepared"}:
                value["state"] = problem.upper()
            elif problem == "cleanup_pending":
                value["cleanup_state"] = "PENDING"
            elif problem == "receipt_missing":
                value["state"] = "SUCCEEDED"
            cleanup.content, cleanup.sha256 = value, digest(value)
        db.commit()
    result = read_review(identity)
    assert result["status"] == "blocked"
    assert result["unconfirmed_cleanup_count"] == 1
    assert result["unconfirmed_execution_ids"] == [execution_id]


def test_no_dispatch_means_no_intent_not_a_cleanup_attestation(binding_lab):
    _, identity = binding_lab
    history(identity, parent="REJECTED", child="REJECTED", dispatch=False)
    result = read_review(identity)
    assert not result["blockers"] and result["dispatches_examined"] == 0
    assert not result["journal_verified"]


def test_dispatch_budget_and_sample_limits_fail_closed(binding_lab, monkeypatch):
    _, identity = binding_lab
    for _ in range(3):
        history(identity, cleaned=False)
    monkeypatch.setattr(binding_review, "HISTORY_LIMIT", 2)
    monkeypatch.setattr(binding_review, "SAMPLE_LIMIT", 1)
    result = read_review(identity)
    assert result["status"] == "blocked" and "dispatch_history_limit" in result["blockers"]
    assert result["dispatches_examined"] == result["unconfirmed_cleanup_count"] == 2
    assert not result["dispatch_history_complete"] and result["unconfirmed_sample_truncated"]
    assert len(result["unconfirmed_execution_ids"]) == 1


def test_asset_history_cannot_hide_behind_a_different_parent_laboratory(binding_lab):
    _, identity = binding_lab
    run_id, _ = history(identity, child="RUNNING")
    with session_factory()() as db:
        demo = db.scalar(select(Laboratory).where(Laboratory.kind == "demo"))
        db.get(CampaignRun, run_id).laboratory_id = demo.id
        db.commit()
    result = read_review(identity)
    assert "nonterminal_tests" in result["blockers"]
    assert "unconfirmed_cleanup" in result["blockers"]


def test_unrelated_laboratory_does_not_block_review(binding_lab):
    _, identity = binding_lab
    with session_factory()() as db:
        demo = db.scalar(select(Laboratory).where(Laboratory.kind == "demo"))
        # Persist a pending parent only, with the other laboratory's identity.
        actor = db.scalar(select(User).where(User.username == "administrator"))
        campaign = Campaign(
            name="Other", objective="Other lab", laboratory_id=demo.id, created_by=actor.id
        )
        db.add(campaign)
        db.flush()
        db.add(
            CampaignRun(
                campaign_id=campaign.id,
                laboratory_id=demo.id,
                requested_by=actor.id,
                idempotency_key=uuid4().hex,
                scope={},
                scope_hash=digest({}),
                state="RUNNING",
            )
        )
        db.commit()
    assert not read_review(identity)["blockers"]
