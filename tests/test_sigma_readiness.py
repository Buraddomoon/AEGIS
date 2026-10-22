import json
import sys
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from aegis.integrations import sigma_readiness as readiness
from test_integrations import SIGMA

MARKER = (
    SIGMA.replace(
        "product: linux\n  category: process_creation", "product: aegis\n  service: marker_observer"
    )
    .replace(
        "CommandLine|contains: aegis-marker",
        "AegisSchema: aegis-json/1\n    AegisObservation: marker_file_read",
    )
    .replace("tags:\n  - attack.execution\n  - attack.t1059.004\n", "")
)


def test_official_published_requirements_conflict_with_current_runtime():
    result = readiness.backend_status()
    assert result["status"] == "blocked"
    assert result["snapshot_reviewed_at"] == "2026-10-22"
    for package in result["packages"]:
        requirement = next(r for r in package["requirements"] if r["name"] == "pysigma")
        assert requirement["installed"] == "2.0.1" and not requirement["satisfied"]
        assert package["installed"] is None
        assert package["license"] == "LGPL-3.0-only"
        assert len(package["wheel_sha256"]) == len(package["metadata_sha256"]) == 64
    assert any(b["code"] == "dependency_unsatisfied" for b in result["blockers"])
    assert "sigma.backends.opensearch" not in sys.modules and "diskcache" not in sys.modules


def test_marker_mapping_is_candidate_only_and_not_an_executable_query():
    result = readiness.assess(MARKER)
    assert result == readiness.assess(MARKER)
    assert result["sha256"] == digest(MARKER)
    assert result["field_mapping_complete"] and result["logsource_matches"]
    assert result["mappings"] == [
        {"source_field": "AegisObservation", "target_field": "data.aegis.observation"},
        {"source_field": "AegisSchema", "target_field": "data.aegis.schema"},
    ]
    assert result["status"] == "blocked" and not result["can_convert"]
    assert not result["conversion_performed"] and not result["deployment_performed"]
    assert {b["code"] for b in result["blockers"]} >= {
        "conversion_pipeline_unimplemented",
        "index_mapping_unverified",
    }
    assert "query" not in result


def test_profile_paths_exist_in_recorded_alert_without_assuming_index_types():
    profile = readiness.marker_profile()
    alert = json.loads(Path("docs/evidence/wazuh-2026-10-22/alert.json").read_text())["_source"]
    for path in profile["fields"].values():
        value = alert
        for part in path.split("."):
            value = value[part]
        assert isinstance(value, str)
    assert not profile["index_mapping_verified"]
    assert alert["data"]["aegis"]["artifact_bytes"] == "43"  # Decoder value is string, not integer.


def test_no_mapping_is_invented_for_process_or_windows_rules():
    result = readiness.assess(SIGMA)
    assert not result["logsource_matches"] and not result["field_mapping_complete"]
    assert result["mappings"] == [{"source_field": "CommandLine", "target_field": None}]
    assert {b["code"] for b in result["blockers"]} >= {"logsource_mismatch", "unmapped_fields"}


@pytest.mark.parametrize(
    "content,code",
    [
        (MARKER.replace("AegisSchema:", "UnknownField:"), "unmapped_fields"),
        (
            MARKER.replace(
                "  condition: selection",
                "  keywords: [marker]\n  condition: selection and keywords",
            ),
            "keyword_mapping_unspecified",
        ),
        (MARKER.replace("condition: selection", "condition: absent"), "static_review_required"),
        (
            MARKER.replace(
                "  service: marker_observer",
                "  service: marker_observer\n  category: process_creation",
            ),
            "logsource_mismatch",
        ),
    ],
)
def test_explicit_mapping_and_analysis_blockers(content, code):
    result = readiness.assess(content)
    assert code in {b["code"] for b in result["blockers"]}
    assert not result["can_convert"]


def test_even_satisfied_requirements_cannot_enable_a_missing_pipeline(monkeypatch):
    installed = {
        "pysigma": "1.4.0",
        "pysigma-backend-opensearch": "2.0.3",
        "pysigma-backend-elasticsearch": "2.1.1",
    }
    monkeypatch.setattr(readiness, "installed_version", lambda name: installed[name.lower()])
    result = readiness.assess(MARKER)
    assert result["backend"]["status"] == "declared_requirements_satisfied_only"
    assert result["status"] == "blocked" and not result["can_convert"]


def test_unreviewed_backend_and_unknown_profile_fail_closed(monkeypatch):
    monkeypatch.setattr(readiness, "installed_version", lambda name: "9.9.9")
    assert "backend_version_unreviewed" in {
        b["code"] for b in readiness.backend_status()["blockers"]
    }
    with pytest.raises(LookupError):
        readiness.assess(MARKER, "../../other")
