"""Recovery entrypoints must fail before connecting or spawning threads."""

import threading

import pytest
from aegis import cli, scheduling, worker
from aegis.catalog import store as catalog_store
from aegis.config import Settings, settings
from alembic import command
from alembic.config import Config
from pydantic import ValidationError


@pytest.mark.parametrize(
    "entrypoint",
    [
        worker.main,
        worker.claim_next,
        worker.recover_abandoned,
        lambda: worker.process_run("never-dispatched"),
        scheduling.dispatch_one,
        lambda: scheduling.scheduler_loop(threading.Event()),
        cli.main,
        cli.grant_runtime,
        lambda: catalog_store.apply(None, None, "unused", "unused", "unused"),
        lambda: command.upgrade(Config("alembic.ini"), "head"),
    ],
)
def test_recovery_blocks_automatic_and_admin_entrypoints(monkeypatch, entrypoint):
    monkeypatch.setattr(settings(), "operating_mode", "recovery")
    for module in (worker, scheduling, cli):
        monkeypatch.setattr(
            module, "session_factory", lambda: pytest.fail("Database must not be opened")
        )
    monkeypatch.setattr(threading.Thread, "start", lambda *a: pytest.fail("Thread must not start"))
    with pytest.raises(RuntimeError, match="quarentena"):
        entrypoint()


def test_mode_is_explicit_and_token_is_not_in_settings_repr():
    assert Settings(_env_file=None).operating_mode == "normal"
    token = "private-test-token-not-for-production"
    assert token not in repr(Settings(_env_file=None, recovery_access_token=token))
    with pytest.raises(ValidationError):
        Settings(_env_file=None, operating_mode="typo")
