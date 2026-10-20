import runpy

import pytest
from aegis.db import session_factory
from aegis.models import AuditEvent, Campaign, TelemetryEvent, User
from aegis.worker import claim_next, process_run
from conftest import create_queued
from sqlalchemy import func, select


def test_demo_cleanup_preserves_identity_and_audit(admin, monkeypatch):
    run = create_queued(admin)
    assert claim_next() == run["id"]
    process_run(run["id"])
    with session_factory()() as db:
        audit_count = db.scalar(select(func.count()).select_from(AuditEvent))
    monkeypatch.setattr("builtins.input", lambda _: "LIMPAR DEMO")
    runpy.run_path("scripts/clean_demo.py")
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(Campaign)) == 0
        assert db.scalar(select(func.count()).select_from(TelemetryEvent)) == 0
        assert db.scalar(select(func.count()).select_from(User)) == 3
        assert db.scalar(select(func.count()).select_from(AuditEvent)) > audit_count


def test_demo_cleanup_refuses_reserved_laboratories(admin, monkeypatch):
    create_queued(admin)
    monkeypatch.setattr("builtins.input", lambda _: "LIMPAR DEMO")
    with pytest.raises(SystemExit, match="reservado"):
        runpy.run_path("scripts/clean_demo.py")
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(Campaign)) == 1
