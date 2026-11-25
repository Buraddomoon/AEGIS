"""Explicit adoption against disposable PostgreSQL schemas, never a lab DB."""

import copy
import sys
from pathlib import Path

import pytest
from aegis.catalog import store
from aegis.domain.validation import digest
from aegis.models import AttackTechnique, CampaignRun, Laboratory, User, now, uid
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_cycle_catalog as adoption  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / "fixtures/attack/enterprise.json").read_bytes()
LICENSE = (ROOT / "fixtures/attack/LICENSE.txt").read_bytes()


@pytest.fixture
def legacy(db_ready, pg_engine):
    config = Config("alembic.ini")
    command.downgrade(config, adoption.REVISION)
    try:
        # Model the upgraded historical DB with its existing technique projection,
        # while clearing only this test's version metadata and revoking its Demo lab.
        with pg_engine.begin() as connection:
            connection.execute(text("TRUNCATE attack_catalog_state, attack_catalog_releases"))
            connection.execute(text("UPDATE laboratories SET authorized=false"))
        with Session(pg_engine) as db, db.begin():
            actor = db.query(User).filter_by(role="administrator").one()
            lab = db.query(Laboratory).first()
            # Freeze the b7 physical projection: the current ORM has additive
            # campaign columns which must not be inserted into a historical schema.
            campaign_id = uid()
            db.execute(
                text(
                    "INSERT INTO campaigns (id, created_at, name, objective, laboratory_id, created_by) "
                    "VALUES (:id, :created_at, :name, :objective, :laboratory_id, :created_by)"
                ),
                {
                    "id": campaign_id,
                    "created_at": now(),
                    "name": "Historical fixture only",
                    "objective": "Preserve the existing scope during explicit adoption.",
                    "laboratory_id": lab.id,
                    "created_by": actor.id,
                },
            )
            scope = {"historical_fixture": True, "synthetic": False}
            db.add(
                CampaignRun(
                    campaign_id=campaign_id,
                    laboratory_id=lab.id,
                    requested_by=actor.id,
                    idempotency_key=uid(),
                    state="COMPLETED",
                    synthetic=False,
                    scope=scope,
                    scope_hash=digest(scope),
                )
            )
        yield pg_engine
    finally:
        command.upgrade(config, "head")


def proposal(engine):
    with Session(engine) as db:
        result = adoption.plan(db, RAW, LICENSE)
        assert db.scalar(text("SHOW transaction_read_only")) == "on"
        assert db.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        return result


def test_adoption_preserves_existing_projection_users_and_every_historical_table(legacy):
    reviewed = proposal(legacy)
    with Session(legacy) as db:
        assert db.scalar(text("SELECT count(*) FROM attack_catalog_state")) == 0
        assert adoption._snapshot(db) == reviewed["preserved_tables"]
    with Session(legacy) as db, db.begin():
        result = adoption.apply(db, RAW, LICENSE, reviewed, digest(reviewed))
        assert result["techniques_rewritten"] is result["general_seed_executed"] is False
    with Session(legacy) as db:
        assert store.reference(db)["release_id"] == reviewed["release_id"]
        after = adoption._snapshot(db)
        assert {key: value for key, value in after.items() if key != "audit_events"} == {
            key: value
            for key, value in reviewed["preserved_tables"].items()
            if key != "audit_events"
        }
    with Session(legacy) as db, pytest.raises(ValueError, match="uninitialized"):
        adoption.apply(db, RAW, LICENSE, reviewed, digest(reviewed))


@pytest.mark.parametrize("change", ["technique", "account", "authorization", "proposal", "hash"])
def test_stale_or_changed_inputs_abort_without_publication(legacy, change):
    reviewed = proposal(legacy)
    with Session(legacy) as db, db.begin():
        if change == "technique":
            db.get(AttackTechnique, "T1059").name += " changed in disposable test"
        elif change == "account":
            db.query(User).first().password_hash = "changed-test-verifier"
        elif change == "authorization":
            db.query(Laboratory).first().authorized = True
    expected = digest(reviewed)
    if change == "proposal":
        reviewed = copy.deepcopy(reviewed)
        reviewed["schema"] = "old"
    elif change == "hash":
        expected = "0" * 64
    with Session(legacy) as db, pytest.raises(ValueError):
        adoption.apply(db, RAW, LICENSE, reviewed, expected)
    with Session(legacy) as db:
        assert db.scalar(text("SELECT count(*) FROM attack_catalog_state")) == 0
        assert db.scalar(text("SELECT count(*) FROM attack_catalog_releases")) == 0


def test_apply_leaves_commit_under_explicit_owner_control(legacy):
    reviewed = proposal(legacy)
    with Session(legacy) as db:
        adoption.apply(db, RAW, LICENSE, reviewed, digest(reviewed))
        db.rollback()
    assert proposal(legacy) == reviewed


def test_adoption_rejects_current_head_without_migration_or_publication(db_ready, pg_engine):
    with Session(pg_engine) as db:
        before = db.scalar(text("SELECT version_num FROM alembic_version"))
    from aegis.operations.recovery import required_revision

    assert before == required_revision()
    with Session(pg_engine) as db, pytest.raises(ValueError, match="explicit_b7_upgrade"):
        adoption.plan(db, RAW, LICENSE)
    with Session(pg_engine) as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == before


def test_b7_inventory_refuses_extra_table_even_with_b7_version(legacy):
    with legacy.begin() as conn:
        conn.execute(text("CREATE TABLE unexpected_history (id integer)"))
    try:
        with pytest.raises(ValueError, match="table_inventory_mismatch"):
            proposal(legacy)
    finally:
        with legacy.begin() as conn:
            conn.execute(text("DROP TABLE unexpected_history"))


def test_b7_inventory_does_not_follow_current_orm_metadata(legacy, monkeypatch):
    from aegis.models import Base

    monkeypatch.setattr(Base, "metadata", None)
    assert len(proposal(legacy)["preserved_tables"]) == 30
