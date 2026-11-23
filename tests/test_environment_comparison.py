"""Pure, explicitly synthetic facts: no database, runner or network."""

from copy import deepcopy

import pytest
from aegis.domain.validation import digest
from aegis.environment_comparison import cohort, compare_cohorts


def facts(lab="lab-a", outcome="DETECTED"):
    scope = {
        "campaign_id": lab,
        "laboratory_id": lab,
        "asset_id": lab,
        "environment_version": 1,
        "mode": "demo",
        "synthetic": True,
        "logic_version": "test/1",
        "attack_catalog": {"release_id": "a" * 64, "version": "test"},
        "attack_techniques": [],
        "clock_skew_seconds": 5,
        "ingestion_window_seconds": 120,
        "test_definitions": [{"id": "test", "version": 1}],
        "rule_versions": {},
        "rule_test_links": [],
    }
    return [
        {
            "id": lab,
            "laboratory_id": lab,
            "synthetic": True,
            "state": "COMPLETED",
            "scope": scope,
            "scope_hash": digest(scope),
            "executions": [
                {
                    "id": lab,
                    "test_id": "test",
                    "asset_id": lab,
                    "synthetic": True,
                    "state": "COMPLETED",
                    "events": [],
                    "result": {
                        "outcome": outcome,
                        "synthetic": True,
                        "logic_version": "test/1",
                        "collection_complete": True,
                    },
                }
            ],
        }
    ]


def test_equivalent_recorded_configs_across_labs_have_explicit_denominators():
    a, b = cohort(facts(), True), cohort(facts("lab-b", "NO_TELEMETRY"), True)
    result = compare_cohorts(a, b)
    assert result["classification"] == "equivalent"
    assert result["detected_rate_delta_percentage_points"] == -100
    assert a["valid_tests"] == b["valid_tests"] == 1
    assert a["members"][0]["laboratory_id"] != b["members"][0]["laboratory_id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("attack_catalog", {"release_id": "b" * 64, "version": "different"}),
        ("environment_version", 2),
        ("rule_versions", {"rule": 2}),
        ("test_definitions", [{"id": "test", "version": 2}]),
        ("telemetry", {"provider": "other"}),
    ],
)
def test_known_differences_are_descriptive_without_delta(field, value):
    runs = facts("lab-b")
    runs[0]["scope"][field] = value
    runs[0]["scope_hash"] = digest(runs[0]["scope"])
    result = compare_cohorts(cohort(facts(), True), cohort(runs, True))
    assert result["classification"] == "descriptive"
    assert result["detected_rate_delta_percentage_points"] is None


@pytest.mark.parametrize(
    "field", ["attack_catalog", "rule_test_links", "logic_version", "test_definitions"]
)
def test_legacy_missing_context_never_proves_equality(field):
    runs = facts()
    del runs[0]["scope"][field]
    runs[0]["scope_hash"] = digest(runs[0]["scope"])
    result = compare_cohorts(cohort(runs, True), cohort(deepcopy(runs), True))
    assert not result["comparable"]
    assert result["detected_rate_delta_percentage_points"] is None


@pytest.mark.parametrize("damage", ["partial", "missing", "manifest", "hash", "mixed", "logic"])
def test_partial_corrupt_or_mixed_facts_cannot_yield_delta(damage):
    runs = facts()
    if damage == "partial":
        runs[0]["state"] = "RUNNING"
    elif damage == "missing":
        runs[0]["executions"][0]["result"] = None
    elif damage == "manifest":
        runs[0]["executions"] = []
    elif damage == "hash":
        runs[0]["scope_hash"] = "f" * 64
    elif damage == "mixed":
        runs[0]["executions"][0]["result"]["synthetic"] = False
    else:
        runs[0]["executions"][0]["result"]["logic_version"] = "other"
    a = cohort(runs, True)
    assert not compare_cohorts(a, a)["comparable"]
    if damage in ("partial", "missing", "manifest", "mixed"):
        assert a["detected_percentage"] is None


def test_inconclusive_heterogeneous_and_unequal_frequencies():
    a = cohort(facts(), True)
    for b in (
        cohort([], True),
        cohort(facts(outcome="INCONCLUSIVE"), True),
        cohort(facts() + facts("lab-b"), True),
    ):
        assert compare_cohorts(a, b)["detected_rate_delta_percentage_points"] is None
    different = facts("lab-b")
    different[0]["scope"]["environment_version"] = 2
    different[0]["scope_hash"] = digest(different[0]["scope"])
    assert "heterogeneous_contexts" in cohort(facts() + different, True)["reasons"]


def test_modes_remain_separate_and_incomparable():
    a, b = cohort(facts(), True), cohort([], False)
    result = compare_cohorts(a, b)
    assert result["classification"] == "incomparable" and "different_modes" in result["reasons"]
