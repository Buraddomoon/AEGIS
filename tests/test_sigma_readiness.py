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


def test_readiness_api_pins_history_and_does_not_change_coverage_or_audit(admin):
    from aegis.db import session_factory
    from aegis.models import AuditEvent
    from sqlalchemy import func, select

    rule = admin.post("/api/v1/rules", json={"content": MARKER}).json()
    version = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    url = f"/api/v1/rules/{rule['id']}/versions/{version['id']}/conversion-readiness"
    first = admin.get(url)
    assert first.status_code == 200, first.text
    assert first.json()["field_mapping_complete"] and not first.json()["can_convert"]
    assert first.json()["sha256"] == version["sha256"]
    assert (
        admin.get("/api/v1/sigma/conversion-profiles").json()["items"][0]["id"]
        == readiness.PROFILE_ID
    )
    changed = admin.post(
        "/api/v1/rules", json={"content": MARKER.replace("AegisSchema:", "UnknownField:")}
    )
    assert changed.status_code == 201
    coverage = admin.get("/api/v1/coverage").json()
    with session_factory()() as db:
        count = db.scalar(select(func.count()).select_from(AuditEvent))
    assert admin.get(url).json() == first.json()
    assert admin.get("/api/v1/coverage").json() == coverage
    assert admin.get(url, params={"profile_id": "absent"}).status_code == 404
    assert admin.get(url.replace(rule["id"], "other")).status_code == 404
    assert admin.get(url.replace(version["id"], "absent")).status_code == 404
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == count


def test_readiness_viewer_session_and_integrity(admin):
    from aegis.db import session_factory
    from aegis.models import RuleVersion

    rule = admin.post("/api/v1/rules", json={"content": MARKER}).json()
    version = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    url = f"/api/v1/rules/{rule['id']}/versions/{version['id']}/conversion-readiness"
    admin.post("/api/v1/auth/logout")
    assert admin.get(url).status_code == 401
    assert admin.get("/api/v1/sigma/conversion-profiles").status_code == 401
    admin.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    ).raise_for_status()
    admin.headers.pop("x-csrf-token", None)
    assert admin.get(url).status_code == 200
    with session_factory()() as db:
        db.get(RuleVersion, version["id"]).content = "changed"
        db.commit()
    assert admin.get(url).status_code == 409


def test_readiness_limits_and_missing_metadata(admin, monkeypatch, tmp_path):
    from aegis.config import settings
    from aegis.db import session_factory
    from aegis.models import User
    from aegis.security import redis_client, token_hash
    from sqlalchemy import select

    rule = admin.post("/api/v1/rules", json={"content": MARKER}).json()
    version = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    url = f"/api/v1/rules/{rule['id']}/versions/{version['id']}/conversion-readiness"
    monkeypatch.setattr(settings(), "fixtures_path", tmp_path)
    assert admin.get(url).status_code == 503
    assert admin.get("/api/v1/sigma/conversion-profiles").status_code == 503
    with session_factory()() as db:
        user_id = db.scalar(select(User.id).where(User.username == "administrator"))
    redis_client().set("aegis:limit:" + token_hash("sigma-readiness:" + user_id), 30, ex=60)
    response = admin.get(url)
    assert response.status_code == 429 and response.headers["retry-after"] == "60"


def test_malformed_snapshot_is_unavailable_not_compatible(admin, monkeypatch, tmp_path):
    from aegis.config import settings

    (tmp_path / "sigma").mkdir()
    (tmp_path / "sigma/backend-metadata.json").write_text('{"schema_version":1,"packages":[]}')
    monkeypatch.setattr(settings(), "fixtures_path", tmp_path)
    with pytest.raises(readiness.BackendMetadataUnavailable):
        readiness.backend_status()
    assert admin.get("/api/v1/sigma/conversion-profiles").status_code == 503
