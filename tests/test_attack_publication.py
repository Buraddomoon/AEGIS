"""Real PostgreSQL publication tests. The 19.2 baseline is synthetic test data.

It reuses existing identifiers to exercise upgrades; it does not claim to be the
MITRE 19.2 release. The live seed always uses the reviewed bundled 20.0 snapshot.
"""

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from aegis.catalog import store
from aegis.catalog.document import BASE, Document, normalize
from aegis.db import Base
from aegis.models import (
    AttackCatalogRelease,
    AttackCatalogState,
    AuditEvent,
    Campaign,
    CampaignRun,
    Laboratory,
    Schedule,
    User,
    now,
)
from aegis.seed import seed
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
LICENSE = (ROOT / "fixtures/attack/LICENSE.txt").read_bytes()
LICENSE_HASH = hashlib.sha256(LICENSE).hexdigest()
COMMIT = "a" * 40


def candidate():
    return normalize(
        (ROOT / "fixtures/attack/synthetic-enterprise-test.json").read_bytes(),
        "20.0",
        COMMIT,
        LICENSE,
    )


@pytest.fixture
def catalog_db(pg_engine):
    with pg_engine.begin() as c:
        c.execute(
            text(
                "TRUNCATE "
                + ",".join('"' + name + '"' for name in Base.metadata.tables)
                + " CASCADE"
            )
        )
    baseline = json.loads((ROOT / "fixtures/attack/enterprise.json").read_bytes())
    baseline["version"] = "19.2"
    baseline["source_url"] = BASE + "master/enterprise-attack/enterprise-attack-19.2.json"
    baseline["source_sha256"] = "b" * 64
    for technique in baseline["techniques"]:
        technique["dataset_version"] = "19.2"
    with Session(pg_engine) as db:
        store.initialize(db, json.dumps(baseline).encode(), LICENSE)
        seed(db)  # Must not overwrite an initialized catalog with bundled 20.0.
        actor = User(
            username="catalog-admin", role="administrator", password_hash="invalid-login-fixture"
        )
        db.add(actor)
        db.commit()
        actor_id = actor.id
    return pg_engine, actor_id


def publish(engine, actor, document=None, confirmed=None):
    document = document or candidate()
    with Session(engine) as db, db.begin():
        reviewed = store.plan(db, document, LICENSE_HASH)
        return store.apply(db, document, confirmed or reviewed["plan_sha256"], actor, LICENSE_HASH)


def fingerprint(engine):
    with Session(engine) as db:
        return (
            store.projection(db),
            list(db.scalars(select(AttackCatalogRelease.id).order_by(AttackCatalogRelease.id))),
            db.get(AttackCatalogState, 1).release_id,
            db.scalar(select(func.count()).select_from(AuditEvent)),
        )


def test_seed_keeps_adopted_catalog_and_plan_is_read_only(catalog_db):
    engine, _ = catalog_db
    before = fingerprint(engine)
    with Session(engine) as db:
        assert store.reference(db)["version"] == "19.2"
        reviewed = store.plan(db, candidate(), LICENSE_HASH)
        assert reviewed["format"] == store.PLAN_FORMAT and reviewed["counts"]["active"] == 3
        assert reviewed["tests_requiring_review"][0]["id"] == "demo-shell"
        assert not reviewed["blockers"]
    assert fingerprint(engine) == before


def test_publication_preserves_ids_records_absence_and_is_idempotent(catalog_db):
    engine, actor = catalog_db
    before = fingerprint(engine)
    result = publish(engine, actor)
    with Session(engine) as db:
        assert result["status"] == "applied"
        assert store.reference(db)["version"] == "20.0"
        assert db.get(AttackCatalogRelease, before[2]).document["version"] == "19.2"
        rows = store.projection(db)
        assert rows["T1059.004"]["present_in_current"] is False
        assert rows["T1059.004"]["dataset_version"] == "19.2"
        assert not rows["T1059.004"]["revoked"] and not rows["T1059.004"]["deprecated"]
        assert rows["T1066"]["revoked"] and rows["T1153"]["deprecated"]
        assert rows["T1059.001"]["parent_id"] == "T1059"
        assert db.scalar(select(func.count()).select_from(AttackCatalogRelease)) == 2
        assert (
            db.scalar(select(AuditEvent).where(AuditEvent.action == "catalog.apply")).actor_id
            == actor
        )
    after = fingerprint(engine)
    assert publish(engine, actor)["status"] == "already_applied"
    assert fingerprint(engine) == after
    different_commit = candidate().model_dump()
    different_commit["source_commit"] = "c" * 40
    different_commit["source_url"] = (
        BASE + "c" * 40 + "/enterprise-attack/enterprise-attack-20.0.json"
    )
    assert (
        publish(engine, actor, Document.model_validate(different_commit))["status"]
        == "already_applied"
    )
    assert fingerprint(engine) == after


@pytest.mark.parametrize("role,active", [("operator", True), ("administrator", False)])
def test_active_administrator_attribution_required(catalog_db, role, active):
    engine, actor = catalog_db
    with engine.begin() as c:
        c.execute(
            text("UPDATE users SET role=:role,active=:active WHERE id=:id"),
            {"role": role, "active": active, "id": actor},
        )
    before = fingerprint(engine)
    with pytest.raises(store.CatalogError, match="administrador ativo"):
        publish(engine, actor)
    assert fingerprint(engine) == before


def test_review_hash_cannot_be_reused_after_test_scope_changes(catalog_db):
    engine, actor = catalog_db
    with Session(engine) as db:
        reviewed = store.plan(db, candidate(), LICENSE_HASH)
    with engine.begin() as c:
        c.execute(text("UPDATE test_definitions SET version=version+1 WHERE id='demo-powershell'"))
    before = fingerprint(engine)
    with pytest.raises(store.CatalogError, match="Plano mudou"):
        publish(engine, actor, confirmed=reviewed["plan_sha256"])
    assert fingerprint(engine) == before


@pytest.mark.parametrize(
    "kind", ["projection", "license", "identity", "pending", "reservation", "schedule"]
)
def test_blockers_prevent_all_catalog_writes(catalog_db, kind):
    engine, actor = catalog_db
    document = candidate()
    with Session(engine) as db, db.begin():
        if kind == "projection":
            db.execute(text("UPDATE attack_techniques SET name='Owner drift' WHERE id='T1057'"))
        elif kind in ("pending", "schedule"):
            lab = db.scalar(select(Laboratory))
            campaign = Campaign(
                name="Catalog guard fixture",
                objective="No execution",
                laboratory_id=lab.id,
                created_by=actor,
            )
            db.add(campaign)
            db.flush()
            if kind == "pending":
                db.add(
                    CampaignRun(
                        campaign_id=campaign.id,
                        laboratory_id=lab.id,
                        requested_by=actor,
                        idempotency_key="catalog-guard-fixture",
                        state="PENDING_APPROVAL",
                        scope={},
                        scope_hash="f" * 64,
                    )
                )
            else:
                db.add(
                    Schedule(
                        campaign_id=campaign.id,
                        laboratory_id=lab.id,
                        created_by=actor,
                        state="PAUSED",
                        scope={},
                        scope_hash="f" * 64,
                        plan_hash="e" * 64,
                        interval_seconds=60,
                        max_occurrences=1,
                        max_duration_seconds=60,
                        starts_at=now(),
                        ends_at=now() + timedelta(hours=1),
                        next_due_at=now(),
                    )
                )
        elif kind == "reservation":
            db.scalar(select(Laboratory)).active_run_id = "ambiguous-fixture"
    if kind in ("license", "identity"):
        data = document.model_dump()
        if kind == "license":
            data["license_sha256"] = "f" * 64
        else:
            data["techniques"][0]["stix_id"] = (
                "attack-pattern--11111111-1111-4111-8111-111111111111"
            )
        document = Document.model_validate(data)
    before = fingerprint(engine)
    with Session(engine) as db:
        assert store.plan(db, document, LICENSE_HASH)["blockers"]
    with pytest.raises(store.CatalogError, match="bloqueado"):
        publish(engine, actor, document)
    assert fingerprint(engine) == before


def test_downgrade_and_rewriting_published_version_are_blocked(catalog_db):
    engine, actor = catalog_db
    publish(engine, actor)
    data = candidate().model_dump()
    data["source_sha256"] = "f" * 64
    with pytest.raises(store.CatalogError, match="bloqueado"):
        publish(engine, actor, Document.model_validate(data))
    data = candidate().model_dump()
    data["version"] = "19.2"
    data["source_url"] = BASE + COMMIT + "/enterprise-attack/enterprise-attack-19.2.json"
    for item in data["techniques"]:
        item["dataset_version"] = "19.2"
    with Session(engine) as db:
        assert (
            "catalog_downgrade"
            in store.plan(db, Document.model_validate(data), LICENSE_HASH)["blockers"]
        )


def test_reader_and_writer_locks_fail_without_deadlock_or_partial_update(catalog_db):
    engine, actor = catalog_db
    before = fingerprint(engine)
    with Session(engine) as reader:
        store.shared(reader)
        with pytest.raises(store.CatalogError, match="em uso"):
            publish(engine, actor)
    with engine.connect() as writer, writer.begin():
        writer.execute(text("UPDATE laboratories SET owner=owner"))
        with pytest.raises(DBAPIError, match="could not obtain lock"):
            publish(engine, actor)
    assert fingerprint(engine) == before


def test_audit_failure_rolls_back_projection_release_and_state(catalog_db):
    engine, actor = catalog_db
    with engine.begin() as c:
        c.execute(
            text(
                "CREATE FUNCTION fail_catalog_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Injected catalog audit failure'; END $$"
            )
        )
        c.execute(
            text(
                "CREATE TRIGGER fail_catalog_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_catalog_audit()"
            )
        )
    before = fingerprint(engine)
    try:
        with pytest.raises(DBAPIError, match="Injected catalog audit failure"):
            publish(engine, actor)
        assert fingerprint(engine) == before
    finally:
        with engine.begin() as c:
            c.execute(text("DROP TRIGGER fail_catalog_audit ON audit_events"))
            c.execute(text("DROP FUNCTION fail_catalog_audit()"))


def test_review_is_bound_to_the_configured_database_scope(catalog_db):
    from sqlalchemy import create_engine

    engine, actor = catalog_db
    with Session(engine) as db:
        reviewed = store.plan(db, candidate(), LICENSE_HASH)
        schema = db.scalar(text("SELECT current_schema()"))
    alias = create_engine(
        engine.url.set(host="127.0.0.1"), connect_args={"options": "-csearch_path=" + schema}
    )
    try:
        with Session(alias) as db, db.begin():
            current = store.plan(db, candidate(), LICENSE_HASH)
            assert current["database_scope"]["schema"] == schema
            if reviewed["database_scope"]["host"] == current["database_scope"]["host"]:
                pytest.skip("Already connected using this loopback alias")
            with pytest.raises(store.CatalogError, match="Plano mudou"):
                store.apply(db, candidate(), reviewed["plan_sha256"], actor, LICENSE_HASH)
    finally:
        alias.dispose()
