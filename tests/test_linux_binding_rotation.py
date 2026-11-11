"""Revoked trust replacement and preflight races on disposable PostgreSQL only."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from aegis import linux_labs, schemas
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.lab_runner import activation_review
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.models import (
    AuditEvent,
    CampaignRun,
    Laboratory,
    LabVerification,
    LinuxLabBinding,
    RunnerCleanup,
    RunnerDispatch,
    User,
    now,
)
from fastapi import HTTPException
from sqlalchemy import select
from test_binding_review import REGISTRATION, history
from test_binding_review import binding_lab as binding_lab
from test_runner_activation_review import journal as journal


def actor(db):
    return db.scalar(select(User).where(User.username == "administrator"))


def snapshots(db):
    from aegis.queries import record

    return {
        model.__tablename__: [record(row) for row in db.scalars(select(model).order_by(model.id))]
        for model in (CampaignRun, RunnerDispatch, RunnerCleanup, LabVerification)
    }


def test_registration_revokes_and_preserves_old_proofs_while_exposing_current_trust(binding_lab):
    admin, identity = binding_lab
    history(identity)
    with session_factory()() as db:
        lab = db.get(Laboratory, identity["laboratory_id"])
        version = lab.environment_version
        db.add(
            LabVerification(
                laboratory_id=lab.id,
                checked_by=actor(db).id,
                configuration_hash=digest(identity),
                environment_version=version,
                success=True,
                expires_at=now() + timedelta(minutes=5),
                reason="Fixture verification only",
            )
        )
        db.commit()
        original = snapshots(db)
    identity["server_ca_sha256"] = "f" * 64
    response = admin.post("/api/v1/labs/linux/register", json=REGISTRATION)
    assert response.status_code == 201, response.text
    assert response.json()["authorized"] is False
    assert response.json()["environment_version"] == version + 1
    with session_factory()() as db:
        assert snapshots(db) == original
        assert not linux_labs.verified(db, db.get(Laboratory, identity["laboratory_id"]))
        audit = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "lab.linux_register")
            .order_by(AuditEvent.created_at.desc())
        ).first()
        assert audit.details["environment_version"] == version + 1
        assert audit.details["authorized"] is False
    current = next(
        item
        for item in admin.get("/api/v1/labs").json()["items"]
        if item["id"] == identity["laboratory_id"]
    )
    assert current["trust"]["configuration_hash"] == digest(identity)
    assert current["trust"]["matches_deployment"] is True
    assert current["trust"]["reviewed_at"]
    assert current["connection_status"] == "disconnected"


def test_changed_deployment_exposes_mismatch_without_presenting_old_preflight_as_current(
    binding_lab,
):
    admin, identity = binding_lab
    old = digest(identity)
    identity["client_cert_sha256"] = "f" * 64
    current = next(
        item
        for item in admin.get("/api/v1/labs").json()["items"]
        if item["id"] == identity["laboratory_id"]
    )
    assert current["trust"]["configuration_hash"] == old
    assert current["trust"]["deployment_configuration_hash"] == digest(identity)
    assert not current["trust"]["matches_deployment"]


def test_preflight_records_failure_if_environment_rotates_during_handshake(
    binding_lab, monkeypatch
):
    admin, identity = binding_lab

    def changed():
        with session_factory()() as db:
            lab = db.get(Laboratory, identity["laboratory_id"])
            lab.environment_version += 1
            db.commit()
        return RunnerIdentity(
            **{key: identity[key] for key in ("runner_id", "laboratory_id", "asset_id")}
        )

    monkeypatch.setattr(
        linux_labs, "client", lambda: SimpleNamespace(preflight=changed, close=lambda: None)
    )
    response = admin.post(
        f"/api/v1/labs/{identity['laboratory_id']}/preflight", json={"confirm": True}
    )
    assert response.status_code == 200
    assert not response.json()["success"]
    assert "mudou" in response.json()["reason"]
    with session_factory()() as db:
        lab = db.get(Laboratory, identity["laboratory_id"])
        assert not linux_labs.verified(db, lab) and not lab.authorized


def test_registration_refreshes_an_already_loaded_laboratory_under_lock(binding_lab):
    _, identity = binding_lab
    with session_factory()() as stale:
        lab = stale.get(Laboratory, identity["laboratory_id"])
        assert not lab.authorized
        with session_factory()() as peer:
            peer.get(Laboratory, lab.id).authorized = True
            peer.commit()
        with pytest.raises(HTTPException, match="409"):
            linux_labs.register(stale, schemas.LinuxRegistration(**REGISTRATION), actor(stale))
        stale.rollback()
    with session_factory()() as db:
        assert db.get(Laboratory, identity["laboratory_id"]).authorized


def test_registration_consumes_in_process_continuity_review(binding_lab, pg_engine, journal):
    _, identity = binding_lab
    reviewed = activation_review.collect(pg_engine, journal[0], journal[1], digest(identity))
    identity["server_ca_sha256"] = "f" * 64
    with session_factory()() as db:
        lab = linux_labs.register(
            db, schemas.LinuxRegistration(**REGISTRATION), actor(db), continuity_review=reviewed
        )
        assert lab.environment_version == reviewed.environment_version + 1
        assert not lab.authorized


def test_stale_continuity_review_never_commits_a_replacement(binding_lab, pg_engine, journal):
    _, identity = binding_lab
    original = digest(identity)
    reviewed = activation_review.collect(pg_engine, journal[0], journal[1], original)
    history(identity)
    identity["server_ca_sha256"] = "f" * 64
    with session_factory()() as db:
        with pytest.raises(HTTPException, match="Continuidade mudou"):
            linux_labs.register(
                db, schemas.LinuxRegistration(**REGISTRATION), actor(db), continuity_review=reviewed
            )
        db.rollback()
        assert db.get(LinuxLabBinding, identity["laboratory_id"]).configuration_hash == original
