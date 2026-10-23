"""CLI exercises cached fixture -> real PostgreSQL review/apply, no internet."""

import importlib.util
import json
from pathlib import Path

import pytest
from aegis.catalog import artifacts
from aegis.config import settings
from sqlalchemy.orm import sessionmaker
from test_attack_artifacts import source_client
from test_attack_document import COMMIT
from test_attack_publication import catalog_db as _catalog_db
from test_attack_publication import fingerprint

catalog_db = _catalog_db
SPEC = importlib.util.spec_from_file_location(
    "update_attack", Path(__file__).resolve().parents[1] / "scripts/update_attack.py"
)
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


def test_cli_requires_hash_actor_and_private_candidate(catalog_db, tmp_path, monkeypatch, capsys):
    engine, actor = catalog_db
    cache = tmp_path / ".local/attack-catalog"
    with source_client() as client:
        identity = artifacts.prepare(cache, "20.0", COMMIT, client=client)
    monkeypatch.setattr(cli, "CACHE", cache)
    monkeypatch.setattr(cli, "session_factory", lambda: sessionmaker(engine))
    before = fingerprint(engine)
    cli.main(["plan", identity])
    planned = json.loads(capsys.readouterr().out)
    assert Path(planned["review_file"]).exists() and not planned["blockers"]
    assert fingerprint(engine) == before
    with pytest.raises(SystemExit, match="Plano mudou"):
        cli.main(["apply", identity, "--actor", actor, "--confirm-plan", "f" * 64])
    assert not capsys.readouterr().out
    assert fingerprint(engine) == before
    cli.main(["apply", identity, "--actor", actor, "--confirm-plan", planned["plan_sha256"]])
    applied = json.loads(capsys.readouterr().out)
    assert applied["status"] == "applied"
    cli.main(["plan", identity])
    reviewed = json.loads(capsys.readouterr().out)
    assert reviewed["action"] == "already_applied"


def test_recovery_blocks_catalog_cli_before_fs_network_or_database(monkeypatch):
    monkeypatch.setattr(settings(), "operating_mode", "recovery")
    monkeypatch.setattr(cli.artifacts, "prepare", lambda *a, **kw: pytest.fail("Network reached"))
    monkeypatch.setattr(cli, "session_factory", lambda: pytest.fail("Database reached"))
    with pytest.raises(RuntimeError, match="quarentena"):
        cli.main(["prepare", "--version", "20.0", "--commit", COMMIT])


@pytest.mark.parametrize(
    "args",
    [
        ["plan", "../"],
        ["apply", "a" * 64, "--actor", "invalid", "--confirm-plan", "b" * 64],
        ["--version", "20.0"],
    ],
)
def test_invalid_or_old_inplace_interface_never_reads_or_writes(args, monkeypatch):
    monkeypatch.setattr(cli.artifacts, "load", lambda *a: pytest.fail("Candidate read"))
    monkeypatch.setattr(cli, "session_factory", lambda: pytest.fail("Database reached"))
    with pytest.raises(SystemExit):
        cli.main(args)
