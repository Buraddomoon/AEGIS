from aegis.db import session_factory
from aegis.models import CampaignRun, RuleVersion
from alembic import command
from alembic.config import Config
from conftest import create_queued
from test_rule_links import import_rule


def test_upgrade_preserves_populated_campaign_runs(admin):
    run = create_queued(admin, ["demo-shell"])
    _, version = import_rule(admin)
    config = Config("alembic.ini")
    command.downgrade(config, "556175fd2f09")
    command.upgrade(config, "head")
    command.check(config)
    with session_factory()() as db:
        stored = db.get(CampaignRun, run["id"])
        assert stored.state == "QUEUED"
        assert stored.processing_started is False
        assert db.get(RuleVersion, version["id"]).sha256 == version["sha256"]


def test_catalog_release_history_and_legacy_projection(db_ready):
    import pytest
    from aegis.models import AttackCatalogRelease, AttackTechnique
    from sqlalchemy import func, select, text
    from sqlalchemy.exc import DBAPIError

    with session_factory()() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AttackTechnique)
                .where(
                    AttackTechnique.present_in_current,
                    ~AttackTechnique.revoked,
                    ~AttackTechnique.deprecated,
                )
            )
            == 706
        )
        # Synthetic migration fixture, never presented as official source data.
        db.add(
            AttackCatalogRelease(
                id="f" * 64,
                dataset_version="20.0",
                provenance="bundled",
                source_url="https://attack.mitre.org/",
                source_sha256="0" * 64,
                license_sha256="0" * 64,
                document={"fixture": True},
            )
        )
        db.commit()
        for statement in (
            "UPDATE attack_catalog_releases SET document='{}'::jsonb WHERE id=:id",
            "DELETE FROM attack_catalog_releases WHERE id=:id",
        ):
            with pytest.raises(DBAPIError, match="history is immutable"):
                db.execute(text(statement), {"id": "f" * 64})
            db.rollback()
        assert db.get(AttackCatalogRelease, "f" * 64).document == {"fixture": True}
