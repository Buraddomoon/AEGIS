import copy
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from aegis.domain.validation import digest
from aegis.integrations import sigma_conversion, sigma_validation
from test_sigma_index import INDEX, provider_for
from test_sigma_index import metadata as index_metadata

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sigma_index_probe as probe  # noqa: E402

PAYLOAD = {
    "username": "aegis_reader",
    "password": "private-fixture-sentinel",
    "expected_certificate_der_sha256": "a" * 64,
}
PEER = {"certificate_der_sha256": "a" * 64, "tls_version": "TLSv1.3"}


@pytest.mark.parametrize("denied", [False, True])
def test_metadata_is_fixed_read_only_and_requires_acl(denied):
    calls = []

    def handle(request):
        calls.append(request)
        assert request.method == "GET"
        path = request.url.path
        if path == "/_plugins/_security/authinfo":
            value = {"user_name": "aegis_reader", "roles": ["aegis_reader"]}
        elif path == "/_plugins/_security/api/permissionsinfo":
            value = {"has_api_access": False}
        elif path.startswith("/.opendistro_security"):
            return httpx.Response(403, json={})
        elif denied and path.endswith("_mapping"):
            return httpx.Response(403, json={"private": "upstream-body"})
        else:
            value = index_metadata()[path]
        return httpx.Response(200, json=value)

    reader = provider_for(handle)
    if denied:
        with pytest.raises(httpx.HTTPStatusError):
            probe.metadata(PAYLOAD, factory=lambda *a, **kw: reader, peer=lambda: PEER)
    else:
        result = probe.metadata(PAYLOAD, factory=lambda *a, **kw: reader, peer=lambda: PEER)
        assert result["mapping"] == index_metadata()[f"/{INDEX}/_mapping"]
        assert result["security_index_denied"] and not result["write_acl_verified"]
        assert PAYLOAD["password"] not in json.dumps(result)
    assert reader.closed
    assert not any(r.method in {"POST", "PUT", "DELETE"} for r in calls)


def test_credentials_and_peer_checked_before_authenticated_effect():
    def forbidden(*a, **kw):
        pytest.fail("No authenticated effect before identity check")

    with pytest.raises(ValueError):
        probe.metadata({**PAYLOAD, "username": "admin"}, factory=forbidden, peer=forbidden)
    with pytest.raises(ValueError):
        probe.metadata(
            PAYLOAD, factory=forbidden, peer=lambda: {**PEER, "certificate_der_sha256": "b" * 64}
        )


def test_two_phase_scope_uses_reviewed_metadata_saved_versions_and_real_converter(
    tmp_path, monkeypatch
):
    from aegis.config import Settings
    from test_sigma_index import profile

    cfg = Settings(_env_file=None)
    monkeypatch.setattr(probe, "settings", lambda: cfg)
    monkeypatch.setattr(sigma_validation, "settings", lambda: cfg)
    content = Path("fixtures/sigma/aegis-marker-candidate.yml").read_text().strip()
    versions = {}
    for i, name in enumerate(("positive", "negative")):
        text = (
            content
            if i == 0
            else content.replace("marker_file_read", "sigma_validation_negative_no_event")
        )
        versions[name] = {
            "rule_id": "a" * 36,
            "id": str(i) * 36,
            "content": text,
            "sha256": digest(text),
            "query_sha256": sigma_conversion.convert(text)["query_sha256"],
        }
    monkeypatch.setattr(probe, "Path", lambda value: tmp_path / "scope.json")
    monkeypatch.setattr(sigma_validation, "connection_hash", lambda: "a" * 64)
    original = json.loads(Path("docs/evidence/wazuh-cycle-2026-11-16/alert.json").read_text())
    calls = []

    def validate(content, rule, version, confirmed):
        scope = sigma_validation.load_scope()
        assert confirmed == digest(scope.model_dump(mode="json"))
        assert scope.rule_id == rule and scope.rule_version_id == version
        assert scope.content_sha256 == digest(content)
        assert scope.query_sha256 == sigma_conversion.convert(content)["query_sha256"]
        calls.append(scope)
        return {
            "complete": True,
            "cleanup_confirmed": True,
            "total": int(len(calls) == 1),
            "hits": [original] if len(calls) == 1 else [],
        }

    now = datetime.now(UTC)
    approval = {
        "index_profile": profile().model_dump(),
        "approved_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=15)).isoformat(),
    }
    result = probe.queries(PAYLOAD, versions, approval, validate=validate, peer=lambda: PEER)
    assert result["status"] == "sigma_native_query_verified" and len(calls) == 2
    assert calls[0].start == calls[1].start and calls[0].query_sha256 != calls[1].query_sha256
    assert not (tmp_path / "scope.json").exists()
    broken = copy.deepcopy(versions)
    broken["positive"]["sha256"] = "b" * 64
    with pytest.raises(ValueError):
        probe.queries(PAYLOAD, broken, approval, validate=validate, peer=lambda: PEER)
