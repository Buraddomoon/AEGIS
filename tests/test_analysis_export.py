from aegis.domain.validation import digest
from aegis.queries import scope_changes
from aegis.reporting import build_comparison_report, export_analysis_html


def test_mixed_export_labels_synthetic_data_escapes_payload_and_has_no_empty_delta():
    comparison = {
        "comparable": True,
        "before_id": "a",
        "after_id": "b",
        "tests": [],
        "limitation": "No inference of protection.",
    }
    before = {
        "synthetic": True,
        "run": {"state": "COMPLETED", "executions": [], "raw_fixture": "<script>alert(1)</script>"},
        "limitations": ["Synthetic fixture."],
    }
    after = {**before, "synthetic": False}
    report = build_comparison_report(comparison, before, after)
    assert report["contains_synthetic"] and report["synthetic"] is False
    assert report["summary"]["detected_rate_delta_percentage_points"] is None
    assert report["integrity_sha256"] == digest(
        {k: v for k, v in report.items() if k != "integrity_sha256"}
    )
    html = export_analysis_html(report)
    assert "ESCOPO MISTO" in html and "&lt;script&gt;" in html and "<script>" not in html


def test_null_catalog_context_is_unknown_not_equivalence():
    scope = {"test_definitions": [], "rule_test_links": [], "attack_catalog": None}
    assert scope_changes(scope, scope)["catalog_context_recorded"] is False
