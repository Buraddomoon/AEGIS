from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from aegis.domain.contracts import Collection, ExecutionContext
from aegis.domain.states import TERMINAL, check_transition
from aegis.domain.validation import Outcome, digest, validate
from aegis.integrations.demo import DemoTelemetryProvider


@pytest.fixture
def context():
    instant = datetime.now(UTC)
    return ExecutionContext("exec", "lab", "asset", "marker", "shell", instant, instant, True, "rule")


@pytest.mark.parametrize("outcome", ["DETECTED", "OBSERVED_NOT_ALERTED", "NO_TELEMETRY", "INCONCLUSIVE"])
def test_demo_classification(context, outcome):
    result = validate(context, DemoTelemetryProvider(outcome).collect(context), True)
    assert result.outcome == outcome


@pytest.mark.parametrize("change", [
    {"laboratory_id": "other"}, {"asset_id": "other"}, {"execution_id": "other"},
    {"marker": "other"}, {"behavior": "other"}, {"synthetic": False},
    {"rule_id": "unrelated"}, {"timestamp": datetime.now(UTC) + timedelta(hours=1)},
    {"timestamp": datetime.now(UTC) - timedelta(hours=1)},
])
def test_unrelated_alert_never_detects(context, change):
    event = DemoTelemetryProvider("DETECTED").collect(context).events[-1]
    collection = Collection((replace(event, **change),), True, True)
    assert validate(context, collection, True).outcome != Outcome.DETECTED


def test_incomplete_alert_search_is_inconclusive(context):
    event = DemoTelemetryProvider("OBSERVED_NOT_ALERTED").collect(context).events[0]
    assert validate(context, Collection((event,), True, False), True).outcome == Outcome.INCONCLUSIVE
    assert validate(context, Collection((event,), True, True, False), True).outcome == Outcome.INCONCLUSIVE


def test_failed_execution_cannot_be_detected(context):
    assert validate(context, DemoTelemetryProvider("DETECTED").collect(context), False).outcome == Outcome.EXECUTION_FAILED


def test_terminal_states_cannot_restart():
    for state in TERMINAL:
        with pytest.raises(ValueError):
            check_transition(state, "RUNNING")
    with pytest.raises(ValueError):
        check_transition("PENDING_APPROVAL", "RUNNING")


def test_integrity_is_canonical():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    assert digest({"a": 1}) != digest({"a": 2})
