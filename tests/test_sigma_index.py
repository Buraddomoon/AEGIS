import copy

import httpx
import pytest
from aegis.domain.validation import digest
from aegis.integrations.sigma_converter_worker import FIELDS
from aegis.integrations.sigma_index import IndexMismatch, IndexProfile, verify_index
from aegis.integrations.wazuh import WazuhIndexerProvider
from test_wazuh_tls import indexer_tls  # noqa: F401

INDEX = "wazuh-alerts-4.x-2026.11.16"


def metadata():
    mapping = {"properties": {"timestamp": {"type": "date"}}}
    for path in FIELDS.values():
        node = mapping
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault("properties", {}).setdefault(part, {"properties": {}})
        node.setdefault("properties", {})[parts[-1]] = {"type": "keyword", "ignore_above": 1024}
    return {
        "/": {"version": {"number": "7.10.2"}},
        f"/{INDEX}/_mapping": {INDEX: {"mappings": mapping}},
        f"/{INDEX}/_settings": {
            INDEX: {"settings": {"index": {"uuid": "fixture", "version": {"created": "fixture"}}}}
        },
        f"/{INDEX}/_alias": {INDEX: {"aliases": {}}},
    }


def profile(responses=None):
    responses = responses or metadata()
    return IndexProfile(
        index=INDEX,
        server_version="7.10.2",
        mapping_sha256=digest(responses[f"/{INDEX}/_mapping"]),
        settings_sha256=digest(responses[f"/{INDEX}/_settings"]),
    )


def provider_for(handler):
    return WazuhIndexerProvider(
        "https://indexer.example.test:9200",
        "fixture-reader",
        "fixture-password",
        "192.0.2.10",
        transport=httpx.MockTransport(handler),
    )


def test_physical_metadata_not_source_and_fixed_destination(monkeypatch):
    responses, requests = metadata(), []
    monkeypatch.setenv("HTTPS_PROXY", "http://secret.invalid")

    def handler(request):
        requests.append(request)
        assert request.method == "GET" and not request.content
        assert request.url.host == "192.0.2.10"
        assert request.headers["host"] == "indexer.example.test:9200"
        assert request.extensions["sni_hostname"] == "indexer.example.test"
        return httpx.Response(200, json=responses[request.url.path])

    provider = provider_for(handler)
    try:
        result = verify_index(provider, profile(), set(FIELDS.values()))
        assert result["index_mapping_verified"] and result["aliases"] == []
        assert len(requests) == 4
        assert "fixture-password" not in str(result)
    finally:
        provider.close()


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["/"]["version"].update(number="8.0.0"),
        lambda r: r[f"/{INDEX}/_alias"][INDEX]["aliases"].update(unreviewed={}),
        lambda r: r[f"/{INDEX}/_settings"][INDEX]["settings"]["index"].update(uuid="other"),
        lambda r: r[f"/{INDEX}/_mapping"][INDEX]["mappings"].update(runtime={"x": {}}),
        lambda r: r[f"/{INDEX}/_mapping"].update(other={}),
    ],
)
def test_any_metadata_drift_refused(change):
    responses = metadata()
    change(responses)
    provider = provider_for(lambda request: httpx.Response(200, json=responses[request.url.path]))
    try:
        with pytest.raises(IndexMismatch):
            verify_index(provider, profile(), {"agent.id"})
    finally:
        provider.close()


@pytest.mark.parametrize(
    "override",
    [
        {"type": "text"},
        {"type": "alias", "path": "other"},
        {"normalizer": "lowercase"},
        {"ignore_above": 511},
        {"ignore_above": True},
        {"index": False},
        {"split_queries_on_whitespace": True},
        {"null_value": "missing"},
        {"script": {}},
    ],
)
def test_reviewed_hash_does_not_override_semantic_gate(override):
    responses = metadata()
    node = responses[f"/{INDEX}/_mapping"][INDEX]["mappings"]["properties"]
    node["agent"]["properties"]["id"].update(override)
    provider = provider_for(lambda request: httpx.Response(200, json=responses[request.url.path]))
    try:
        with pytest.raises(IndexMismatch):
            verify_index(provider, profile(responses), {"agent.id"})
    finally:
        provider.close()


@pytest.mark.parametrize("code", [301, 401, 403, 404, 500])
def test_http_errors_not_physical_compatibility(code):
    provider = provider_for(lambda request: httpx.Response(code, json={"secret": "sentinel"}))
    try:
        with pytest.raises((httpx.HTTPError, ValueError)):
            verify_index(provider, profile(), {"agent.id"})
    finally:
        provider.close()


@pytest.mark.parametrize("mutation", ["nested", "disabled", "missing", "date", "source"])
def test_ancestors_source_and_timestamp_checked(mutation):
    responses = copy.deepcopy(metadata())
    mapping = responses[f"/{INDEX}/_mapping"][INDEX]["mappings"]
    if mutation == "nested":
        mapping["properties"]["data"].update(type="nested")
    elif mutation == "disabled":
        mapping["properties"]["data"].update(enabled=False)
    elif mutation == "missing":
        del mapping["properties"]["data"]
    elif mutation == "source":
        mapping["_source"] = {"enabled": False}
    else:
        mapping["properties"]["timestamp"]["type"] = "keyword"
    provider = provider_for(lambda request: httpx.Response(200, json=responses[request.url.path]))
    try:
        with pytest.raises(IndexMismatch):
            verify_index(provider, profile(responses), {"data.aegis.schema"})
    finally:
        provider.close()


@pytest.mark.parametrize("condition", ["trusted", "untrusted", "hostname"])
def test_mapping_gate_uses_real_tls_and_fails_before_search(request, condition):
    from aegis.lab_runner.network_profile import LINUX_RUNNER_IP

    port, pki = request.getfixturevalue("indexer_tls")
    provider = WazuhIndexerProvider(
        f"https://{'invalid.example' if condition == 'hostname' else LINUX_RUNNER_IP}:{port}",
        "fixture-reader",
        "fixture-password",
        "192.0.2.10",
        ca_bundle=None if condition == "untrusted" else str(pki / "server-ca.crt"),
    )
    try:
        # The HTTPS fixture advertises an incompatible version. Trusted TLS must
        # reach that physical gate; TLS failures must never reach metadata/search.
        with pytest.raises(IndexMismatch if condition == "trusted" else httpx.HTTPError):
            verify_index(provider, profile(), {"agent.id"})
    finally:
        provider.close()
