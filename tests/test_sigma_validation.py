import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations import sigma_conversion as conversion
from aegis.integrations import sigma_validation as validation
from test_sigma_index import INDEX, metadata, profile, provider_for

CONTENT = Path("fixtures/sigma/aegis-marker-candidate.yml").read_text()
NOW = datetime.now(UTC)
TIME = "2026-11-16T12:00:00+00:00"


@pytest.fixture
def assay(monkeypatch):
    artifact = conversion.convert(CONTENT)
    scope = validation.Scope(
        index_profile=profile(),
        connection_sha256="a" * 64,
        rule_id="a" * 36,
        rule_version_id="b" * 36,
        content_sha256=digest(CONTENT),
        contract_sha256=conversion.contract()["sha256"],
        query_sha256=artifact["query_sha256"],
        agent_id="001",
        start=TIME,
        end="2026-11-16T12:01:00+00:00",
        approved_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    monkeypatch.setattr(validation, "load_scope", lambda: scope)
    return scope


def hit(identifier="original", **overrides):
    source = {
        "timestamp": TIME,
        "agent": {"id": "001"},
        "data": {"aegis": {"schema": "aegis-json/1", "observation": "marker_file_read"}},
    }
    source.update(overrides)
    return {"_id": identifier, "_index": INDEX, "_source": source}


def page(batch, total=None, cursor="fixture-cursor", **overrides):
    result = {
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {
            "hits": batch,
            "total": {"value": len(batch) if total is None else total, "relation": "eq"},
        },
    }
    if cursor:
        result["_scroll_id"] = cursor
    result.update(overrides)
    return result


def run(monkeypatch, scope, pages, cleanup=None, mutate_metadata=None):
    requests = []
    responses = metadata()
    sequence = iter(pages)

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=responses[request.url.path])
        if request.method == "DELETE":
            if mutate_metadata:
                mutate_metadata(responses)
            return httpx.Response(200, json=cleanup or {"succeeded": True, "num_freed": 1})
        response = next(sequence)
        if isinstance(response, Exception):
            raise response
        return httpx.Response(200, json=response)

    provider = provider_for(handler)

    def factory(**kwargs):
        provider.guard, provider.budget_end = kwargs["guard"], kwargs["budget_end"]
        return provider

    monkeypatch.setattr(validation, "configured_provider", factory)
    result = validation.validate_query(
        CONTENT, scope.rule_id, scope.rule_version_id, digest(scope.model_dump(mode="json"))
    )
    assert provider.closed
    return result, requests


def test_bounded_query_keeps_original_and_provenance(monkeypatch, assay):
    original = hit()
    result, requests = run(monkeypatch, assay, [page([original], 1, "first"), page([], 1, "last")])
    assert result["complete"] and result["index_mapping_verified"] and result["cleanup_confirmed"]
    assert result["hits"] == [original] and result["total"] == 1 and result["pages"] == 2
    assert result["conversion"]["query_sha256"] == assay.query_sha256
    assert result["document_sha256"] == digest(
        {k: v for k, v in result.items() if k != "document_sha256"}
    )
    searches = [r for r in requests if r.method == "POST"]
    first = json.loads(searches[0].content)
    assert searches[0].url.path == f"/{INDEX}/_search"
    assert first["query"]["bool"]["filter"][0] == {"term": {"agent.id": "001"}}
    assert first["size"] == 100 and first["timeout"] == "2000ms"
    assert json.loads(searches[1].content)["scroll_id"] == "first"
    delete = next(r for r in requests if r.method == "DELETE")
    assert json.loads(delete.content)["scroll_id"] == ["last"]
    assert not result["synthetic"] and not result["historical_classification_changed"]


def test_complete_scoped_negative_is_not_absence_of_telemetry(monkeypatch, assay):
    result, _ = run(monkeypatch, assay, [page([])])
    assert result["complete"] and result["total"] == 0 and result["hits"] == []
    assert "telemetry_available" not in result and "verdict" not in result


@pytest.mark.parametrize(
    "bad",
    [
        hit(agent={"id": "002"}),
        hit(timestamp="2026-11-16T13:00:00Z"),
        hit(timestamp="2026-11-16T12:00:00"),
        hit(data={"aegis": {"schema": "aegis-json/1", "observation": "false-positive"}}),
        {**hit(), "_index": "unscoped"},
    ],
)
def test_false_positives_are_not_evidence(monkeypatch, assay, bad):
    result, _ = run(monkeypatch, assay, [page([bad])])
    assert not result["complete"] and result["hits"] == []


@pytest.mark.parametrize(
    "response",
    [
        page([], timed_out=True),
        page([], terminated_early=True),
        page([], _shards={"total": 0, "successful": 0, "failed": 0}),
        page([], _shards={"total": 1, "successful": True, "failed": 0}),
        page([], _shards={"total": 2, "successful": 1, "failed": 1}),
        page([], hits={"hits": [], "total": {"value": 0, "relation": "gte"}}),
        page([], total=True),
        page([], total=1),
        page([], cursor=None),
        page([], _scroll_id=False),
        httpx.ReadTimeout("secret upstream endpoint"),
    ],
)
def test_incomplete_never_becomes_clean_negative(monkeypatch, assay, response):
    result, _ = run(monkeypatch, assay, [response])
    assert not result["complete"] and "secret upstream" not in str(result)


def test_conflicting_duplicate_removed_and_cursor_cleaned(monkeypatch, assay):
    changed = copy.deepcopy(hit())
    changed["_source"]["other"] = "changed"
    result, _ = run(
        monkeypatch, assay, [page([hit()], 1, "one"), page([changed], 1, "two"), page([], 1)]
    )
    assert not result["complete"] and result["conflicts"] == 1 and result["hits"] == []
    assert result["cleanup_confirmed"]


def test_page_limit_cleanup_failure_and_metadata_drift(monkeypatch, assay):
    result, requests = run(monkeypatch, assay, [page([hit()], 1, "cursor")] * 11)
    assert not result["complete"] and result["pages"] == 10
    # No eleventh search is issued beyond the page budget.
    assert len([r for r in requests if r.method == "POST"]) == 10
    result, _ = run(monkeypatch, assay, [page([], 0, "cursor")], cleanup={"succeeded": False})
    assert not result["complete"] and not result["cleanup_confirmed"]
    result, _ = run(
        monkeypatch,
        assay,
        [page([], 0, "cursor")],
        mutate_metadata=lambda r: r["/"]["version"].update(number="8.0.0"),
    )
    assert not result["complete"] and not result["index_mapping_verified"]


def test_no_network_for_unreviewed_artifact_or_scope(monkeypatch, assay):
    def forbidden(**kwargs):
        raise AssertionError("No unreviewed network effect")

    monkeypatch.setattr(validation, "configured_provider", forbidden)
    for content, rule, version, confirmed in [
        (CONTENT, assay.rule_id, assay.rule_version_id, "f" * 64),
        (
            CONTENT + "\n",
            assay.rule_id,
            assay.rule_version_id,
            digest(assay.model_dump(mode="json")),
        ),
        (CONTENT, "c" * 36, assay.rule_version_id, digest(assay.model_dump(mode="json"))),
    ]:
        with pytest.raises(validation.ValidationBlocked):
            validation.validate_query(content, rule, version, confirmed)


def test_private_scope_expiry_drift_and_recovery_fail_closed(tmp_path, monkeypatch):
    # Do not use assay fixture: test the real private-file gate.
    source = {
        "index_profile": profile().model_dump(),
        "connection_sha256": "a" * 64,
        "rule_id": "a" * 36,
        "rule_version_id": "b" * 36,
        "content_sha256": "b" * 64,
        "contract_sha256": "c" * 64,
        "query_sha256": "d" * 64,
        "agent_id": "001",
        "start": TIME,
        "end": TIME,
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
    }
    source["end"] = "2026-11-16T12:01:00Z"
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(source))
    path.chmod(0o600)
    monkeypatch.setattr(settings(), "sigma_validation_scope", path)
    monkeypatch.setattr(validation, "connection_hash", lambda: "a" * 64)
    assert validation.load_scope().agent_id == "001"
    path.chmod(0o644)
    with pytest.raises(validation.ValidationBlocked):
        validation.load_scope()
    path.chmod(0o600)
    source["expires_at"] = (NOW - timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps(source))
    with pytest.raises(validation.ValidationBlocked):
        validation.load_scope()
    path.unlink()
    path.symlink_to(tmp_path / "absent")
    with pytest.raises(validation.ValidationBlocked):
        validation.load_scope()
    monkeypatch.setattr(settings(), "operating_mode", "recovery")
    with pytest.raises(validation.ValidationBlocked):
        validation.load_scope()


def test_boolean_literal_check_is_independent_of_query_result():
    document = {
        "detection": {
            "a": {"AgentId": ["001", "002"]},
            "b": {"RuleId": "100200"},
            "condition": "a and not b",
        }
    }
    assert validation.matches({"agent": {"id": "001"}}, document)
    assert not validation.matches({"agent": {"id": "001"}, "rule": {"id": "100200"}}, document)
    assert not validation.matches({"agent": {"id": 1}}, document)


def test_api_uses_saved_version_and_does_not_rewrite_history(admin, monkeypatch, assay):
    from aegis.db import session_factory
    from aegis.models import AuditEvent, RuleVersion
    from sqlalchemy import func, select
    from test_sigma_mapping_api import imported

    rule, saved, url = imported(admin, CONTENT)
    scope = assay.model_copy(
        update={
            "rule_id": rule["id"],
            "rule_version_id": saved["id"],
            "content_sha256": saved["sha256"],
        }
    )
    monkeypatch.setattr(validation, "load_scope", lambda: scope)
    responses = metadata()

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=responses[request.url.path])
        if request.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True, "num_freed": 1})
        assert request.method == "POST"
        if request.url.path == f"/{INDEX}/_search":
            return httpx.Response(200, json=page([hit()]))
        assert request.url.path == "/_search/scroll"
        return httpx.Response(200, json=page([], total=1))

    def factory(**kwargs):
        provider = provider_for(handler)
        provider.guard, provider.budget_end = kwargs["guard"], kwargs["budget_end"]
        return provider

    monkeypatch.setattr(validation, "configured_provider", factory)
    url = url.replace("mapping-preview", "query-validation")
    body = {"confirm_scope_sha256": digest(scope.model_dump(mode="json"))}
    versions = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()
    coverage = admin.get("/api/v1/coverage").json()
    with session_factory()() as db:
        audits = db.scalar(select(func.count()).select_from(AuditEvent))
    response = admin.post(url, json=body)
    assert response.status_code == 200, response.text
    assert response.json()["complete"] and response.json()["rule_version_id"] == saved["id"]
    assert admin.get(f"/api/v1/rules/{rule['id']}/versions").json() == versions
    after = admin.get("/api/v1/coverage").json()
    assert {k: v for k, v in coverage.items() if k != "snapshot_at"} == {
        k: v for k, v in after.items() if k != "snapshot_at"
    }
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == audits
        assert db.get(RuleVersion, saved["id"]).content == saved["content"]
    assert admin.post(url, json={**body, "query": "arbitrary"}).status_code == 422
    assert admin.post(url, json=body).status_code == 200
    assert admin.post(url, json=body).status_code == 429


def test_api_denies_missing_scope_csrf_roles_and_anonymous(admin, monkeypatch):
    from test_sigma_mapping_api import imported

    _, _, url = imported(admin, CONTENT)
    url = url.replace("mapping-preview", "query-validation")
    body = {"confirm_scope_sha256": "a" * 64}
    monkeypatch.setattr(settings(), "sigma_validation_scope", None)

    def forbidden(**kwargs):
        raise AssertionError("Network forbidden without authorization")

    monkeypatch.setattr(validation, "configured_provider", forbidden)
    assert admin.post(url, json=body).status_code == 409
    token = admin.headers.pop("x-csrf-token")
    assert admin.post(url, json=body).status_code == 403
    admin.headers["x-csrf-token"] = token
    admin.post("/api/v1/auth/logout")
    assert admin.post(url, json=body).status_code == 401
    for role in ("operator", "viewer"):
        login = admin.post(
            "/api/v1/auth/login",
            headers={"x-aegis-request": "browser"},
            json={"username": role, "password": "Test-only-randomized-scope-23!"},
        )
        assert login.status_code == 200
        admin.headers["x-csrf-token"] = login.json()["csrf_token"]
        assert admin.post(url, json=body).status_code == 403
        admin.post("/api/v1/auth/logout")


def test_api_integrity_and_transport_errors_do_not_echo_secrets(admin, monkeypatch, assay):
    from aegis.db import session_factory
    from aegis.models import RuleVersion
    from test_sigma_mapping_api import imported

    _, saved, url = imported(admin, CONTENT)
    url = url.replace("mapping-preview", "query-validation")
    body = {"confirm_scope_sha256": "a" * 64}

    def failed(*args):
        raise httpx.ConnectError("private-upstream-sentinel")

    monkeypatch.setattr(validation, "validate_query", failed)
    response = admin.post(url, json=body)
    assert response.status_code == 503 and "private-upstream-sentinel" not in response.text
    with session_factory()() as db:
        db.get(RuleVersion, saved["id"]).content = "private-content-sentinel"
        db.commit()
    response = admin.post(url, json=body)
    assert response.status_code == 409 and "private-content-sentinel" not in response.text


def test_revocation_between_pages_still_cleans_cursor(monkeypatch, assay):
    calls = 0

    def revoke():
        nonlocal calls
        calls += 1
        # scope load, four metadata requests (before + body), first search and
        # first page body: revoke when advancing the cursor.
        if calls >= 12:
            raise validation.ValidationBlocked()
        return assay

    monkeypatch.setattr(validation, "load_scope", revoke)
    result, requests = run(monkeypatch, assay, [page([hit()], 1, "cursor"), page([], 1)])
    assert not result["complete"] and not result["cleanup_confirmed"]
    assert any(r.method == "DELETE" for r in requests)


def test_ambiguous_scroll_response_is_not_confirmed_cleanup(monkeypatch, assay):
    result, requests = run(
        monkeypatch,
        assay,
        [page([hit()], 1, "old-cursor"), httpx.ReadTimeout("private-response-sentinel")],
    )
    assert not result["complete"] and not result["cleanup_confirmed"]
    assert result["hits"] == [hit()]  # Partial positive remains explicitly partial.
    assert any(r.method == "DELETE" for r in requests)
    assert "private-response-sentinel" not in str(result)


def test_mapping_drift_prevents_every_search(monkeypatch, assay):
    responses = metadata()
    responses[f"/{INDEX}/_mapping"][INDEX]["mappings"]["extra"] = "drift"
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        return httpx.Response(200, json=responses[request.url.path])

    provider = provider_for(handler)
    monkeypatch.setattr(validation, "configured_provider", lambda **kwargs: provider)
    from aegis.integrations.sigma_index import IndexMismatch

    with pytest.raises(IndexMismatch):
        validation.validate_query(
            CONTENT, assay.rule_id, assay.rule_version_id, digest(assay.model_dump(mode="json"))
        )
    assert provider.closed and len(requests) == 4


def test_range_delimiters_refused_before_network(monkeypatch, assay):
    content = CONTENT.replace("marker_file_read", ">1")
    artifact = conversion.convert(content)
    scope = assay.model_copy(
        update={"content_sha256": digest(content), "query_sha256": artifact["query_sha256"]}
    )
    monkeypatch.setattr(validation, "load_scope", lambda: scope)

    def forbidden(**kwargs):
        raise AssertionError("Range syntax must not reach the Indexer")

    monkeypatch.setattr(validation, "configured_provider", forbidden)
    with pytest.raises(validation.ValidationBlocked):
        validation.validate_query(
            content, scope.rule_id, scope.rule_version_id, digest(scope.model_dump(mode="json"))
        )


def test_selection_name_may_be_python_keyword():
    document = {"detection": {"class": {"AgentId": "001"}, "condition": " ( class ) "}}
    assert validation.matches({"agent": {"id": "001"}}, document)


def test_validation_redis_failure_prevents_effect(admin, monkeypatch):
    import aegis.security as security
    import redis
    from test_sigma_mapping_api import imported

    _, _, url = imported(admin, CONTENT)

    def failed():
        raise redis.ConnectionError("private-redis-sentinel")

    def forbidden(*args):
        raise AssertionError("No effect without rate limiting")

    monkeypatch.setattr(security, "redis_client", failed)
    monkeypatch.setattr(validation, "validate_query", forbidden)
    response = admin.post(
        url.replace("mapping-preview", "query-validation"), json={"confirm_scope_sha256": "a" * 64}
    )
    assert response.status_code == 503 and "private-redis-sentinel" not in response.text
