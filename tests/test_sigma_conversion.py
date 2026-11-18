import copy
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from aegis.domain.validation import digest
from aegis.integrations import sigma_conversion as conversion
from aegis.integrations import sigma_converter_worker as worker
from test_sigma_converter_worker import DOCUMENT

CONTENT = Path("fixtures/sigma/aegis-marker-candidate.yml").read_text()


def test_real_conversion_has_exact_provenance_and_no_siem_effect():
    result = conversion.convert(CONTENT)
    assert result == conversion.convert(CONTENT)
    assert result["status"] == "converted"
    assert result["sha256"] == digest(CONTENT)
    assert (
        result["query"]
        == r"data.aegis.schema:aegis\-json\/1 AND data.aegis.observation:marker_file_read"
    )
    assert result["query_sha256"] == hashlib.sha256(result["query"].encode()).hexdigest()
    assert result["document_sha256"] == digest(
        {k: v for k, v in result.items() if k != "document_sha256"}
    )
    assert result["contract"]["sha256"] == digest(worker.definition())
    assert result["conversion_performed"]
    assert not any(
        result[k] for k in ("siem_queried", "deployment_performed", "index_mapping_verified")
    )


@pytest.mark.parametrize(
    "change,code",
    [
        (
            lambda s: s.replace("    AegisSchema:", "    AegisSchema: discarded\n    AegisSchema:"),
            "ambiguous_yaml_keys",
        ),
        (
            lambda s: s.replace("  condition:", "  condition: discarded\n  condition:"),
            "ambiguous_yaml_keys",
        ),
        (
            lambda s: s.replace(
                "    AegisSchema:", "    <<: {AegisSchema: discarded}\n    AegisSchema:"
            ),
            "ambiguous_yaml_keys",
        ),
        (
            lambda s: s.replace("AegisSchema:", "AegisSchema|fieldref:"),
            "field_or_modifier_unsupported",
        ),
        (lambda s: s.replace("AegisSchema:", "Unknown:"), "field_or_modifier_unsupported"),
        (
            lambda s: s.replace("condition: selection", "condition: 1 of sele*"),
            "condition_unsupported",
        ),
        (lambda s: s + "\ncustom: {pipeline: http://example.invalid}\n", "metadata_unsupported"),
        (
            lambda s: s.replace("condition: selection", "condition: selection and"),
            "static_review_required",
        ),
    ],
)
def test_unsupported_semantics_never_start_the_worker(monkeypatch, change, code):
    def forbidden(*args):
        raise AssertionError("No child for unsupported input")

    monkeypatch.setattr(conversion, "execute", forbidden)
    result = conversion.convert(change(CONTENT))
    assert result["status"] == "unsupported" and result["blockers"][0]["code"] == code
    assert (
        result["query"] is None
        and result["query_sha256"] is None
        and not result["conversion_performed"]
    )


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(returncode=1, stdout=b"private-input-sentinel", stderr=b"Traceback"),
        SimpleNamespace(returncode=0, stdout=b"not-json", stderr=b""),
        SimpleNamespace(returncode=0, stdout=b"[]", stderr=b""),
        SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"query": "ok", "definition_sha256": "wrong"}).encode(),
            stderr=b"",
        ),
        SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"query": "x" * 8193, "definition_sha256": conversion.contract()["sha256"]}
            ).encode(),
            stderr=b"",
        ),
        SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"query": "x\ny", "definition_sha256": conversion.contract()["sha256"]}
            ).encode(),
            stderr=b"",
        ),
    ],
)
def test_bad_worker_responses_fail_closed_and_release_capacity(monkeypatch, response):
    monkeypatch.setattr(conversion.subprocess, "run", lambda *args, **kwargs: response)
    for _ in range(3):
        with pytest.raises(conversion.ConversionUnavailable):
            conversion.execute(DOCUMENT, conversion.contract()["sha256"])


@pytest.mark.parametrize(
    "failure", [FileNotFoundError(), subprocess.TimeoutExpired("fixed-python", 5)]
)
def test_absence_timeout_and_slots_fail_closed(monkeypatch, failure):
    def failed(*args, **kwargs):
        raise failure

    monkeypatch.setattr(conversion.subprocess, "run", failed)
    with pytest.raises(conversion.ConversionUnavailable):
        conversion.execute(DOCUMENT, conversion.contract()["sha256"])
    assert conversion.SLOTS.acquire(blocking=False)
    assert conversion.SLOTS.acquire(blocking=False)
    try:
        with pytest.raises(conversion.ConversionUnavailable):
            conversion.execute(DOCUMENT, conversion.contract()["sha256"])
    finally:
        conversion.SLOTS.release()
        conversion.SLOTS.release()


def test_command_and_environment_are_fixed_not_taken_from_input(monkeypatch):
    document = copy.deepcopy(DOCUMENT)

    def recorded(args, **kwargs):
        assert args == [str(conversion.interpreter()), "-I", "-B", str(conversion.SCRIPT)]
        assert kwargs["cwd"] == "/" and kwargs["timeout"] == 5
        assert kwargs["env"] == {"LANG": "C.UTF-8", "PYSIGMA_ALLOW_VARS_EXECUTION": "false"}
        assert json.loads(kwargs["input"]) == document
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"query": "fixed", "definition_sha256": conversion.contract()["sha256"]}
            ).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(conversion.subprocess, "run", recorded)
    assert conversion.execute(document, conversion.contract()["sha256"]) == "fixed"


def test_query_api_pins_history_and_preserves_audit_coverage_and_versions(admin):
    from aegis.db import session_factory
    from aegis.models import AuditEvent
    from sqlalchemy import func, select
    from test_sigma_mapping_api import imported

    rule, saved, url = imported(admin)
    url = url.replace("mapping-preview", "query")
    profiles = admin.get("/api/v1/sigma/query-profiles").json()
    assert profiles["configured"] and profiles["items"][0] == conversion.contract()
    first = admin.get(url)
    assert first.status_code == 200, first.text
    first = first.json()
    assert first["status"] == "converted" and first["rule_version_id"] == saved["id"]
    assert first["document_sha256"] == digest(
        {k: v for k, v in first.items() if k != "document_sha256"}
    )
    _, other, new_url = imported(admin, CONTENT.replace("AegisSchema:", "Unknown:"))
    versions = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()
    coverage = admin.get("/api/v1/coverage").json()
    with session_factory()() as db:
        audits = db.scalar(select(func.count()).select_from(AuditEvent))
    assert other["version"] == 2
    assert admin.get(new_url.replace("mapping-preview", "query")).json()["status"] == "unsupported"
    assert admin.get(url).json() == first
    assert admin.get(f"/api/v1/rules/{rule['id']}/versions").json() == versions
    after = admin.get("/api/v1/coverage").json()
    assert {k: v for k, v in after.items() if k != "snapshot_at"} == {
        k: v for k, v in coverage.items() if k != "snapshot_at"
    }
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == audits


def test_query_api_viewer_allowed_anonymous_denied_and_context_guarded(admin, monkeypatch):
    from aegis.db import session_factory
    from aegis.models import RuleVersion
    from test_sigma_mapping_api import imported

    rule, saved, url = imported(admin)
    url = url.replace("mapping-preview", "query")
    admin.post("/api/v1/auth/logout")
    assert admin.get(url).status_code == 401
    assert admin.get("/api/v1/sigma/query-profiles").status_code == 401
    admin.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    ).raise_for_status()
    admin.headers.pop("x-csrf-token", None)
    assert admin.get(url).json()["status"] == "converted"

    def forbidden(*args):
        raise AssertionError("Guard before conversion")

    monkeypatch.setattr(conversion, "convert", forbidden)
    assert admin.get(url, params={"profile_id": "../../unknown"}).status_code == 404
    assert admin.get(url.replace(rule["id"], "other-rule")).status_code == 404
    assert admin.get(url.replace(saved["id"], "other-version")).status_code == 404
    with session_factory()() as db:
        db.get(RuleVersion, saved["id"]).content = "private-sentinel"
        db.commit()
    response = admin.get(url)
    assert response.status_code == 409 and "private-sentinel" not in response.text


def test_api_failure_and_rate_limit_never_return_stale_queries(admin, monkeypatch):
    from aegis.db import session_factory
    from aegis.models import User
    from aegis.security import redis_client, token_hash
    from sqlalchemy import select
    from test_sigma_mapping_api import imported

    _, _, url = imported(admin)
    url = url.replace("mapping-preview", "query")
    monkeypatch.setattr(conversion, "interpreter", lambda: Path("/missing/fixed-converter"))
    response = admin.get(url)
    assert response.status_code == 503 and '"query"' not in response.text
    with session_factory()() as db:
        user_id = db.scalar(select(User.id).where(User.username == "administrator"))
    redis_client().set("aegis:limit:" + token_hash("sigma-query:" + user_id), 30, ex=60)
    assert admin.get(url).status_code == 429


def test_query_redis_failure_and_invalid_legacy_content_are_not_success(admin, monkeypatch):
    import aegis.security as security
    import redis
    from aegis.db import session_factory
    from aegis.models import RuleVersion
    from test_sigma_mapping_api import imported

    _, saved, url = imported(admin)
    url = url.replace("mapping-preview", "query")
    with session_factory()() as db:
        record = db.get(RuleVersion, saved["id"])
        record.content = "private-invalid-content"
        record.sha256 = digest(record.content)
        db.commit()
    response = admin.get(url)
    assert response.status_code == 422 and "private-invalid-content" not in response.text

    def failed():
        raise redis.ConnectionError("private-connection")

    monkeypatch.setattr(security, "redis_client", failed)
    response = admin.get(url)
    assert response.status_code == 503 and "private-connection" not in response.text


def test_query_budget_is_rejected_before_a_process_starts(monkeypatch):
    import yaml

    document = copy.deepcopy(DOCUMENT)
    document["detection"]["selection"] = {"AegisSchema": ["x" * 512] * 8}

    def forbidden(*args):
        raise AssertionError("No process for oversized query")

    monkeypatch.setattr(conversion, "execute", forbidden)
    assert (
        conversion.convert(yaml.safe_dump(document))["blockers"][0]["code"]
        == "query_expansion_limit"
    )
