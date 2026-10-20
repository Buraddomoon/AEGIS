from aegis.db import session_factory
from aegis.models import CampaignRun
from alembic import command
from alembic.config import Config
from conftest import create_queued


def test_upgrade_preserves_populated_campaign_runs(admin):
    run = create_queued(admin, ["demo-shell"])
    config = Config("alembic.ini")
    command.downgrade(config, "556175fd2f09")
    command.upgrade(config, "head")
    command.check(config)
    with session_factory()() as db:
        stored = db.get(CampaignRun, run["id"])
        assert stored.state == "QUEUED"
        assert stored.processing_started is False
