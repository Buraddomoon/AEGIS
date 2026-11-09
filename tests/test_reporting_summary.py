"""Summary denominators must not promote pending, failed or incomplete runs to evaluated tests."""

from copy import deepcopy

import pytest
from aegis.domain.states import State
from aegis.domain.validation import digest
from aegis.reporting import build_report, summarize_execution


def execution(state, outcome=None):
    return {"state": state, "result": {"outcome": outcome} if outcome else None}


def test_completed_summary_counts_only_eligible_outcomes_without_mutating_evidence():
    run = {
        "synthetic": True,
        "state": "COMPLETED",
        "executions": [
            execution("COMPLETED", "DETECTED"),
            execution("COMPLETED", "OBSERVED_NOT_ALERTED"),
            execution("COMPLETED", "NO_TELEMETRY"),
            execution("COMPLETED", "INCONCLUSIVE"),
            execution("FAILED", "EXECUTION_FAILED"),
            execution("CANCELLED"),
        ],
    }
    before = deepcopy(run)
    report = build_report(run)
    summary = report["summary"]
    assert report["report_version"] == "1.2"
    assert summary["planned_tests"] == 6
    assert summary["completed_tests"] == 4
    assert summary["valid_tests"] == 3
    assert summary["detected_tests"] == 1
    assert summary["excluded_tests"] == 3
    assert summary["detected_percentage"] == 33.3
    assert summary["outcomes"]["NOT_TESTED"] == 1
    assert summary["test_states"] == {"CANCELLED": 1, "COMPLETED": 4, "FAILED": 1}
    assert report["integrity_sha256"] == digest(before)
    assert run == before


@pytest.mark.parametrize("state", [state.value for state in State if state != State.COMPLETED])
def test_incomplete_or_unsuccessful_parent_never_contributes_to_rate(state):
    summary = summarize_execution(
        {"state": state, "executions": [execution("COMPLETED", "DETECTED")]}
    )
    assert summary["completed_tests"] == 1
    assert summary["outcomes"] == {"DETECTED": 1}  # Preserve the recorded fact.
    assert summary["valid_tests"] == summary["detected_tests"] == 0
    assert summary["excluded_tests"] == 1
    assert summary["detected_percentage"] is None


@pytest.mark.parametrize("state", [state.value for state in State if state != State.COMPLETED])
def test_incomplete_or_unsuccessful_child_never_contributes_even_with_recorded_detection(state):
    summary = summarize_execution(
        {"state": "COMPLETED", "executions": [execution(state, "DETECTED")]}
    )
    assert summary["completed_tests"] == summary["valid_tests"] == summary["detected_tests"] == 0
    assert summary["detected_percentage"] is None


@pytest.mark.parametrize(
    "outcome", [None, "INCONCLUSIVE", "EXECUTION_FAILED", "NOT_TESTED", "UNKNOWN"]
)
def test_no_eligible_results_means_no_rate_instead_of_zero_percent(outcome):
    summary = summarize_execution(
        {"state": "COMPLETED", "executions": [execution("COMPLETED", outcome)]}
    )
    assert summary["valid_tests"] == 0 and summary["detected_percentage"] is None


def test_empty_run_and_confirmed_zero_detection_have_distinct_rates():
    assert (
        summarize_execution({"state": "COMPLETED", "executions": []})["detected_percentage"] is None
    )
    summary = summarize_execution(
        {"state": "COMPLETED", "executions": [execution("COMPLETED", "OBSERVED_NOT_ALERTED")]}
    )
    assert summary["valid_tests"] == 1 and summary["detected_percentage"] == 0.0
