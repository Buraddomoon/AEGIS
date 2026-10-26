import pytest
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.integrations import sigma_mapping
from aegis.models import AuditEvent, RuleVersion, User
from aegis.security import redis_client, token_hash
from sqlalchemy import func, select
from test_sigma_mapping import CONTENT


def imported(admin, content=CONTENT):
    response = admin.post("/api/v1/rules", json={"content": content})
    assert response.status_code == 201, response.text
    rule = response.json()
    saved = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    return rule, saved, f"/api/v1/rules/{rule['id']}/versions/{saved['id']}/mapping-preview"


def test_mapping_preview_preserves_version_history_audit_and_coverage(admin):
    rule, saved, url = imported(admin)
    first = admin.get(url)
    assert first.status_code == 200, first.text
    first = first.json()
    assert first["status"] == "previewed"
    assert first["rule_id"] == rule["id"] and first["rule_version_id"] == saved["id"]
    assert first["sha256"] == saved["sha256"]
    assert first["document_sha256"] == digest(
        {k: v for k, v in first.items() if k != "document_sha256"}
    )
    new_rule, new_saved, new_url = imported(admin, CONTENT.replace("AegisSchema:", "UnknownField:"))
    assert new_rule["id"] == rule["id"] and new_saved["version"] == 2
    versions = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()
    coverage = admin.get("/api/v1/coverage").json()
    with session_factory()() as db:
        audits = db.scalar(select(func.count()).select_from(AuditEvent))
    assert admin.get(new_url).json()["status"] == "unsupported"
    assert admin.get(url).json() == first
    assert admin.get(f"/api/v1/rules/{rule['id']}/versions").json() == versions
    latest = admin.get("/api/v1/coverage").json()
    assert {k: v for k, v in latest.items() if k != "snapshot_at"} == {
        k: v for k, v in coverage.items() if k != "snapshot_at"
    }
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == audits
        assert db.get(RuleVersion, saved["id"]).content == saved["content"]


def test_read_only_preview_allows_viewer_but_not_anonymous(admin):
    rule, saved, url = imported(admin)
    admin.post("/api/v1/auth/logout")
    assert admin.get(url).status_code == 401
    admin.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
    ).raise_for_status()
    admin.headers.pop("x-csrf-token", None)
    response = admin.get(url)
    assert response.status_code == 200
    assert response.json()["status"] == "previewed"
    assert not response.json()["can_convert"]


def test_context_integrity_and_profile_are_checked_before_preview(admin, monkeypatch):
    rule, saved, url = imported(admin)

    def forbidden(*args, **kwargs):
        raise AssertionError("Preview must not run")

    monkeypatch.setattr(sigma_mapping, "preview", forbidden)
    assert admin.get(url, params={"profile_id": "../../arbitrary"}).status_code == 404
    assert admin.get(url.replace(rule["id"], "other-rule")).status_code == 404
    assert admin.get(url.replace(saved["id"], "other-version")).status_code == 404
    with session_factory()() as db:
        db.get(RuleVersion, saved["id"]).content = "private-content-mismatch"
        db.commit()
    response = admin.get(url)
    assert response.status_code == 409
    assert "private-content-mismatch" not in response.text


def test_preview_rate_limit_and_redis_failure_fail_closed(admin, monkeypatch):
    rule, saved, url = imported(admin)
    with session_factory()() as db:
        user_id = db.scalar(select(User.id).where(User.username == "administrator"))
    redis_client().set("aegis:limit:" + token_hash("sigma-mapping:" + user_id), 30, ex=60)
    response = admin.get(url)
    assert response.status_code == 429 and response.headers["retry-after"] == "60"
    import aegis.security as security
    import redis

    def unavailable():
        raise redis.ConnectionError("private-connection-sentinel")

    monkeypatch.setattr(security, "redis_client", unavailable)
    response = admin.get(url)
    assert response.status_code == 503
    assert "private-connection-sentinel" not in response.text


@pytest.mark.parametrize("problem,status", [("core", 503), ("invariant", 503), ("input", 422)])
def test_preview_drift_and_invalid_history_never_echo_internal_details(
    admin, monkeypatch, problem, status
):
    rule, saved, url = imported(admin)
    if problem == "core":
        monkeypatch.setattr(sigma_mapping, "version", lambda _: "9.9.9")
    elif problem == "invariant":
        monkeypatch.setattr(sigma_mapping.ProcessingPipeline, "apply", lambda self, rule: rule)
    else:
        with session_factory()() as db:
            record = db.get(RuleVersion, saved["id"])
            record.content = "private-invalid-history"
            record.sha256 = digest(record.content)
            db.commit()
    response = admin.get(url)
    assert response.status_code == status, response.text
    assert "private-invalid-history" not in response.text
    assert "Traceback" not in response.text
