"""Advice consumes recorded facts, never produces new defensive evidence."""

from copy import deepcopy

import pytest
from aegis.domain.recommendations import POLICY_VERSION, analyze_recommendations
from aegis.domain.validation import Outcome, digest


def source(outcome="NO_TELEMETRY"):
    return {
        "id": "fixture-run",
        "state": "COMPLETED",
        "synthetic": True,
        "scope": {"environment_version": 1},
        "executions": [
            {
                "id": "fixture-execution",
                "test_id": "fixture-test",
                "state": "COMPLETED",
                "synthetic": True,
                "executed": True,
                "result": {
                    "id": "fixture-result",
                    "outcome": outcome,
                    "reason": "Justificativa original.",
                    "collection_complete": True,
                    "telemetry_available": True,
                    "alerts_available": True,
                },
                "events": [
                    {
                        "id": "linked",
                        "source": "demo",
                        "kind": "telemetry",
                        "sha256": "a" * 64,
                        "synthetic": True,
                    },
                    {"id": "unlinked", "source": "demo", "kind": "alert"},
                ],
                "evidence": [{"id": "link", "event_id": "linked", "reason": "Registrado."}],
            }
        ],
    }


@pytest.mark.parametrize("outcome", list(Outcome))
def test_every_outcome_has_proportional_advice_without_mutation(outcome):
    detail = source(outcome)
    original = deepcopy(detail)
    analysis = analyze_recommendations(detail)
    assert analysis == analyze_recommendations(deepcopy(detail))
    assert detail == original
    assert analysis["input_sha256"] == digest(detail)
    assert analysis["policy"]["version"] == POLICY_VERSION
    assert analysis["policy_sha256"] == digest(analysis["policy"])
    assert analysis["integrity_sha256"] == digest(
        {key: value for key, value in analysis.items() if key != "integrity_sha256"}
    )
    (item,) = analysis["items"]
    assert item["code"] == outcome.lower()
    assert item["facts"]["result"] == original["executions"][0]["result"]
    assert item["evidence"] == [
        {
            "link_id": "link",
            "event_id": "linked",
            "reason": "Registrado.",
            "source": "demo",
            "kind": "telemetry",
            "sha256": "a" * 64,
            "synthetic": True,
            "event_present": True,
        }
    ]
    assert "não severidade ou risco de negócio" in " ".join(analysis["limitations"])
    # Mutating a returned projection cannot rewrite the source or future policy.
    item["facts"]["result"]["outcome"] = "changed"
    analysis["policy"]["rules"][item["code"]]["action"] = "changed"
    assert detail == original
    assert analyze_recommendations(detail)["policy_sha256"] != digest(analysis["policy"])


@pytest.mark.parametrize("field", ["telemetry_available", "alerts_available"])
def test_unavailable_capability_is_an_investigation_not_absence(field):
    detail = source("INCONCLUSIVE")
    detail["executions"][0]["result"][field] = False
    items = analyze_recommendations(detail)["items"]
    assert [item["code"] for item in items] == ["collection_unavailable", "inconclusive"]
    assert "não interpretar consulta indisponível como ausência" in items[0]["action"]


def test_window_collection_and_cleanup_are_separate_prioritized_facts():
    detail = source("DETECTED")
    execution = detail["executions"][0]
    execution["state"] = "CLEANUP_FAILED"
    execution["collection"] = {"window_satisfied": False, "complete": False, "provider": "fixture"}
    items = analyze_recommendations(detail)["items"]
    assert [item["code"] for item in items] == [
        "cleanup_failed",
        "window_incomplete",
        "collection_incomplete",
        "detected",
    ]
    assert all(item["facts"]["outcome"] == "DETECTED" for item in items)
    assert items[0]["priority"] < items[-1]["priority"]


@pytest.mark.parametrize("state", ["FAILED", "TIMED_OUT"])
def test_failed_state_does_not_reclassify_an_existing_verdict(state):
    detail = source("OBSERVED_NOT_ALERTED")
    detail["executions"][0]["state"] = state
    assert [r["code"] for r in analyze_recommendations(detail)["items"]] == [
        "execution_failed",
        "observed_not_alerted",
    ]
    assert detail["executions"][0]["result"]["outcome"] == "OBSERVED_NOT_ALERTED"


def test_parent_cleanup_failure_remains_priority_over_completed_child():
    detail = source()
    detail["state"] = "CLEANUP_FAILED"
    assert analyze_recommendations(detail)["items"][0]["code"] == "cleanup_failed"


def test_missing_fields_are_unknown_and_receipts_are_never_defensive_evidence():
    detail = source()
    execution = detail["executions"][0]
    execution["result"] = None
    execution["evidence"] = []
    execution["runner_receipt"] = {"content": {"executed": True}, "sha256": "b" * 64}
    (item,) = analyze_recommendations(detail)["items"]
    assert item["code"] == "not_tested" and item["evidence"] == []
    assert item["facts"]["collection"] is None
    assert "consumidas" in item["action"]


def test_orphan_link_and_unknown_outcome_are_not_filled_retroactively():
    detail = source("FUTURE_OUTCOME")
    detail["executions"][0]["evidence"] = [{"event_id": "missing"}]
    (item,) = analyze_recommendations(detail)["items"]
    assert item["code"] == "unknown"
    assert item["evidence"][0]["event_present"] is False
    assert item["evidence"][0]["sha256"] is None


def test_input_change_is_visible_in_hash_and_synthetic_origin_is_preserved():
    detail = source()
    original = analyze_recommendations(detail)
    detail["executions"][0]["result"]["reason"] = "Nova justificativa."
    current = analyze_recommendations(detail)
    assert current["input_sha256"] != original["input_sha256"]
    assert current["integrity_sha256"] != original["integrity_sha256"]
    assert current["synthetic"] is True and current["items"][0]["synthetic"] is True


def test_priority_across_tests_is_technical_and_not_source_order():
    detail = source("DETECTED")
    second = deepcopy(source("EXECUTION_FAILED")["executions"][0])
    second["id"] = "second"
    detail["executions"].append(second)
    assert [item["execution_id"] for item in analyze_recommendations(detail)["items"]] == [
        "second",
        "fixture-execution",
    ]


def test_empty_scope_has_no_invented_test():
    detail = source()
    detail["executions"] = []
    assert analyze_recommendations(detail)["items"] == []
