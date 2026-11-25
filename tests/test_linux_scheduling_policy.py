"""Offline contract checks; no database, runner, marker or network."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from aegis.config import settings
from aegis.models import Schedule
from aegis.scheduled_reports import source_origin_valid
from aegis.scheduling import plan, real_scope_allowed


def marker_scope():
    return {
        "mode": "linux",
        "synthetic": False,
        "runner": {"test_id": "linux-file-marker/v1"},
        "test_definitions": [{"id": "linux-file-marker-v1", "execution_kind": "linux_marker"}],
    }


def test_real_scheduling_is_opt_in(monkeypatch):
    monkeypatch.setattr(settings(), "linux_scheduling_enabled", False)
    assert not real_scope_allowed(marker_scope())
    monkeypatch.setattr(settings(), "linux_scheduling_enabled", True)
    assert real_scope_allowed(marker_scope())


@pytest.mark.parametrize("synthetic", [False, True])
@pytest.mark.parametrize("change", [None, "scope", "execution", "result", "event", "empty"])
def test_automatic_snapshots_require_consistent_origin(synthetic, change):
    source = {
        "synthetic": synthetic,
        "scope": {"synthetic": synthetic, "mode": "demo" if synthetic else "linux"},
        "executions": [
            {
                "synthetic": synthetic,
                "result": {"synthetic": synthetic},
                "events": [{"synthetic": synthetic}],
            }
        ],
    }
    if change == "scope":
        source["scope"]["synthetic"] = not synthetic
    elif change == "execution":
        source["executions"][0]["synthetic"] = not synthetic
    elif change in ("result", "event"):
        child = source["executions"][0]
        (child["result"] if change == "result" else child["events"][0])["synthetic"] = not synthetic
    elif change == "empty":
        source["executions"] = []
    assert source_origin_valid(source) is (change is None)


@pytest.mark.parametrize(
    "change", ["mode", "synthetic", "missing", "mixed", "atomic", "shell", "executor", "definition"]
)
def test_closed_scope_cannot_expand_the_executor(monkeypatch, change):
    monkeypatch.setattr(settings(), "linux_scheduling_enabled", True)
    scope = deepcopy(marker_scope())
    if change == "mode":
        scope["mode"] = "wazuh"
    elif change == "synthetic":
        scope["synthetic"] = True
    elif change == "missing":
        scope["test_definitions"] = []
    elif change == "mixed":
        scope["test_definitions"] *= 2
    elif change in ("atomic", "shell"):
        scope["runner"]["test_id"] = change
    elif change == "executor":
        scope["test_definitions"][0]["execution_kind"] = "shell"
    else:
        scope["test_definitions"][0]["id"] = "imported-test"
    assert not real_scope_allowed(scope)


def test_policy_seals_mode_concurrency_budget_and_duration_without_changing_demo():
    start = datetime(2026, 11, 24, tzinfo=UTC)
    item = Schedule(
        campaign_id="campaign",
        laboratory_id="lab",
        created_by="requester",
        scope=marker_scope(),
        scope_hash="a" * 64,
        interval_seconds=60,
        max_occurrences=2,
        max_duration_seconds=30,
        starts_at=start,
        ends_at=start + timedelta(hours=1),
    )
    real = plan(item)
    assert real["version"] == "aegis-linux-schedule/1"
    assert real["max_concurrency"] == 1
    assert real["missed_slots_consume_budget"] is True
    assert real["max_occurrences"] == 2 and real["max_duration_seconds"] == 30
    item.scope = {"mode": "demo", "synthetic": True}
    demo = plan(item)
    assert demo["version"] == "aegis-demo-schedule/1.0"
    assert "max_concurrency" not in demo
