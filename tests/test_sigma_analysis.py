import sys

import pytest
import yaml
from aegis.domain.validation import digest
from aegis.integrations.sigma_analysis import analyze
from test_integrations import SIGMA


def test_analysis_is_deterministic_and_does_not_imply_detection():
    result = analyze(SIGMA)
    assert result == analyze(SIGMA)
    assert result["sha256"] == digest(SIGMA)
    assert result["analyzer_version"] == "sigma-static/1"
    assert result["pysigma_version"] == "2.0.1"
    assert result["status"] == "no_findings_in_selected_checks"
    assert result["facts"]["declared_fields"] == ["CommandLine"]
    assert result["facts"]["logsource"]["product"] == "linux"
    assert result["compatibility"] == {
        "status": "not_configured",
        "backend": None,
        "pipeline": None,
        "conversion_performed": False,
        "deployment_performed": False,
    }
    assert "diskcache" not in sys.modules


def test_unused_selection_and_wildcard_condition_resolution():
    content = SIGMA.replace(
        "  condition: selection", "  unused:\n    Image: /bin/sh\n  condition: selection"
    )
    result = analyze(content)
    assert result["findings"][0]["code"] == "unused_selection"
    assert result["findings"][0]["selection"] == "unused"
    assert not analyze(content.replace("condition: selection", "condition: 1 of them"))["findings"]


@pytest.mark.parametrize("condition", ["absent", "selection and (", "1 of missing_*"])
def test_unresolved_condition_does_not_report_clean(condition):
    result = analyze(SIGMA.replace("condition: selection", f"condition: {condition}"))
    assert result["status"] == "findings"
    assert {f["code"] for f in result["findings"]} & {"condition_resolution"}


def test_modifiers_and_values_are_checked_without_executing_regex():
    content = SIGMA.replace(
        "CommandLine|contains: aegis-marker", "CommandLine|all: [first, second]"
    )
    assert "all_without_contains" in {f["code"] for f in analyze(content)["findings"]}
    content = SIGMA.replace("aegis-marker", "aegis**marker")
    assert "consecutive_wildcards" in {f["code"] for f in analyze(content)["findings"]}
    content = SIGMA.replace("aegis-marker", '"aegis\\tmarker"')
    assert "control_character" in {f["code"] for f in analyze(content)["findings"]}


def test_nested_and_keyword_selections_are_facts_not_required_telemetry():
    content = SIGMA.replace(
        "  selection:\n    CommandLine|contains: aegis-marker",
        "  selection:\n    - Image: /bin/sh\n    - CommandLine|contains: aegis-marker\n  keywords: [marker, lab]",
    )
    facts = analyze(content)["facts"]
    assert facts["declared_fields"] == ["CommandLine", "Image"]
    assert facts["keyword_selections"] == ["keywords"]


@pytest.mark.parametrize(
    "content",
    [
        "a: &a 1\nb: *a",
        "!!python/object/apply:os.system [id]",
        "a: " + "x" * 65536,
        SIGMA.replace("condition: selection", "condition: " + "selection or " * 200 + "selection"),
    ],
)
def test_analysis_rejects_unsafe_or_over_budget_content(content):
    with pytest.raises((ValueError, yaml.YAMLError)):
        analyze(content)
