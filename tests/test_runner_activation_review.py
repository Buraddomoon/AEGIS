"""Actual temporary PostgreSQL/SQLite reviewers integrated without native resources."""

import copy

import pytest
from aegis.db import session_factory
from aegis.lab_runner import activation_review as rotation
from aegis.lab_runner.journal import Journal
from aegis.models import Laboratory, LinuxLabBinding
from sqlalchemy import select
from test_binding_review import binding_lab as binding_lab
from test_binding_review import history
from test_runner_persisted_review import arguments
from test_runner_persisted_review import bundle as bundle


@pytest.fixture
def journal(binding_lab, pg_engine, tmp_path):
    history(binding_lab[1])
    identity, descriptor = arguments(binding_lab)
    collected = rotation.persisted_review.collect(pg_engine, identity, descriptor)
    _, proofs = rotation.persisted_review.expected_proofs(collected, rotation.digest(collected))
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    writer = Journal(root)
    with writer.connection() as db:
        db.execute(
            "INSERT INTO metadata VALUES ('identity',?)",
            (rotation.digest(identity.model_dump(mode="json")),),
        )
        for proof in proofs.values():
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(proof.spec.job_id),
                    proof.spec.model_dump_json(),
                    proof.spec_hash,
                    str(proof.generation),
                    proof.state,
                    proof.cleanup_state,
                    proof.reason,
                    None,
                    None,
                ),
            )
            for action in ("PREPARED", "CANCELLED", "CLEANED"):
                writer.event(db, proof.spec.job_id, action)
    writer.close()
    return root, identity, proofs


def test_review_joins_readonly_sql_and_wal_aware_journal_then_rechecks_under_lock(
    binding_lab, pg_engine, journal
):
    identity, descriptor = arguments(binding_lab)
    result = rotation.collect(pg_engine, journal[0], identity, descriptor)
    assert result.proofs_examined == 1
    with session_factory()() as db:
        lab = db.scalar(
            select(Laboratory).where(Laboratory.id == str(identity.laboratory_id)).with_for_update()
        )
        current = rotation.require_current(db, lab, result)
        assert not current["activation_permitted"] and not lab.authorized
        assert result.stable_bundle_sha256 == rotation.stable_sha256(current)


@pytest.mark.parametrize("change", ["binding", "version", "authorized", "history", "reservation"])
def test_change_after_review_cannot_be_consumed_for_binding(
    binding_lab, pg_engine, journal, change
):
    identity, descriptor = arguments(binding_lab)
    reviewed = rotation.collect(pg_engine, journal[0], identity, descriptor)
    if change == "history":
        history(binding_lab[1])
    with session_factory()() as db:
        lab = db.get(Laboratory, str(identity.laboratory_id))
        if change == "binding":
            db.get(LinuxLabBinding, lab.id).configuration_hash = "f" * 64
        elif change == "version":
            lab.environment_version += 1
        elif change == "authorized":
            lab.authorized = True
        elif change == "reservation":
            lab.active_run_id = current_run(db)
        db.commit()
    with session_factory()() as db:
        from fastapi import HTTPException

        with pytest.raises((rotation.continuity.ContinuityError, HTTPException)):
            rotation.require_current(db, db.get(Laboratory, str(identity.laboratory_id)), reviewed)


def current_run(db):
    from aegis.models import CampaignRun

    return db.scalar(select(CampaignRun.id).where(CampaignRun.synthetic.is_(False)))


def test_history_changed_between_readonly_snapshots_is_rejected(
    binding_lab, pg_engine, journal, monkeypatch
):
    identity, descriptor = arguments(binding_lab)
    original = rotation.continuity.review
    calls = 0

    def changed(*args, **kwargs):
        nonlocal calls
        calls += 1
        value = original(*args, **kwargs)
        if calls == 2:
            history(binding_lab[1])
        return value

    monkeypatch.setattr(rotation.continuity, "review", changed)
    with pytest.raises(rotation.continuity.ContinuityError, match="continuity_changed"):
        rotation.collect(pg_engine, journal[0], identity, descriptor)


def test_unknown_or_corrupt_journal_blocks_before_registration(
    binding_lab, pg_engine, journal, monkeypatch
):
    identity, descriptor = arguments(binding_lab)

    def broken(*args, **kwargs):
        raise rotation.continuity.ContinuityError("fixture_corrupt_journal")

    monkeypatch.setattr(rotation.continuity, "review", broken)
    with pytest.raises(rotation.continuity.ContinuityError, match="corrupt_journal"):
        rotation.collect(pg_engine, journal[0], identity, descriptor)


def test_only_timestamp_is_volatile(bundle):
    changed = copy.deepcopy(bundle)
    changed["review"]["reviewed_at"] = "2030-01-01T00:00:00+00:00"
    assert rotation.unchanged(bundle, changed)
    changed["environment_version"] += 1
    assert not rotation.unchanged(bundle, changed)
