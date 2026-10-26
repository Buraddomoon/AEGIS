from datetime import timedelta

import pytest
from aegis import analytics, queries
from aegis.db import session_factory
from aegis.models import CampaignRun
from aegis.worker import claim_next, process_run
from conftest import create_queued
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def test_scope_snapshot_boundaries_and_empty_denominator(admin):
    run = create_queued(admin)
    assert claim_next() == run["id"]
    process_run(run["id"])
    with session_factory()() as db:
        original = db.get(CampaignRun, run["id"])
        created = original.created_at
        with analytics.read_snapshot(db) as snapshot:
            assert snapshot.scalar(text("SHOW transaction_isolation")) == "repeatable read"
            assert snapshot.scalar(text("SHOW transaction_read_only")) == "on"
            data = queries.coverage(
                snapshot,
                include_members=True,
                selection=analytics.Selection(
                    requested_from=created, requested_before=created + timedelta(seconds=1)
                ),
            )
            assert data["total_runs"] == 1 and data["valid_tests"] == 3
            assert data["detected_percentage"] == 33.3
            assert data["evaluated_techniques"] == 3
            assert len(data["members"]) == 1 and len(data["members"][0]["results"]) == 4
            assert all(len(r["result_sha256"]) == 64 for r in data["members"][0]["results"])
        with analytics.read_snapshot(db) as snapshot:
            data = queries.coverage(
                snapshot, selection=analytics.Selection(requested_before=created)
            )
            assert data["total_runs"] == data["completed_tests"] == 0
            assert data["detected_percentage"] is None
        with analytics.read_snapshot(db) as snapshot, pytest.raises(DBAPIError, match="read-only"):
            snapshot.execute(text("UPDATE campaigns SET name=name"))


def test_snapshot_does_not_mix_a_concurrent_run_completion(admin):
    run = create_queued(admin, ["demo-shell"])
    with session_factory()() as db, analytics.read_snapshot(db) as snapshot:
        first = queries.coverage(snapshot)
        assert first["run_states"] == {"QUEUED": 1}
        assert claim_next() == run["id"]
        process_run(run["id"])
        second = queries.coverage(snapshot)
        assert first == second
    with session_factory()() as db, analytics.read_snapshot(db) as snapshot:
        current = queries.coverage(snapshot)
        assert current["run_states"] == {"COMPLETED": 1}
        assert current["outcomes"] == {"DETECTED": 1}


def test_scope_limit_refuses_instead_of_truncating(admin, monkeypatch):
    create_queued(admin)
    monkeypatch.setattr(analytics, "MAX_RUNS", 0)
    from fastapi import HTTPException

    with session_factory()() as db, pytest.raises(HTTPException) as error:
        queries.coverage(db)
    assert error.value.status_code == 422
