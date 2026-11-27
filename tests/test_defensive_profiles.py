"""Host-only profiles and drift; no external network or native laboratory."""

import json
import runpy
import uuid
from pathlib import Path

import pytest
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations import defensive_profiles as profiles
from aegis.integrations.wazuh_config import descriptor


@pytest.fixture
def profile_registry(tmp_path, monkeypatch):
    pki = runpy.run_path("scripts/init_linux_lab.py")["initialize"](tmp_path / "pki")
    files = {}
    for name, content in {
        "username": "private-fixture-principal",
        "password": "private-fixture-password",
        "ca": (pki / "server-ca.crt").read_text(),
    }.items():
        path = tmp_path / name
        path.write_text(content)
        path.chmod(0o600)
        files[name + "_file"] = str(path)
    entry = {
        "id": "reviewed-one",
        "revision": 1,
        "url": "https://indexer.fixture:9200",
        "allowed_ip": "192.0.2.10",
        **files,
        "policy": {
            "laboratory_id": str(uuid.uuid4()),
            "asset_id": str(uuid.uuid4()),
            "agent_id": "007",
            "expected_rule": "100200",
        },
    }
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"format": "aegis-defensive-profiles/1", "entries": [entry]}))
    path.chmod(0o600)
    monkeypatch.setattr(settings(), "defensive_profiles", path)
    return path, entry


def save(path, entry):
    path.write_text(json.dumps({"format": "aegis-defensive-profiles/1", "entries": [entry]}))


def test_public_candidates_and_descriptor_never_contain_credentials_or_paths(profile_registry):
    _, entry = profile_registry
    result = profiles.candidates(entry["policy"]["laboratory_id"])
    raw = json.dumps(result) + json.dumps(descriptor(entry["id"]))
    for private in ("private-fixture", entry["password_file"], entry["ca_file"]):
        assert private not in raw
    assert result[0]["configuration_hash"] == digest(descriptor(entry["id"]))
    with pytest.raises(ValueError):
        descriptor()
    with pytest.raises(ValueError):
        descriptor("unknown")


@pytest.mark.parametrize(
    "field,value", [("revision", 2), ("url", "https://other.fixture"), ("allowed_ip", "192.0.2.11")]
)
def test_review_invalidated_by_profile_drift(profile_registry, field, value):
    path, entry = profile_registry
    previous = digest(descriptor(entry["id"]))
    entry[field] = value
    save(path, entry)
    assert digest(descriptor(entry["id"])) != previous


@pytest.mark.parametrize("fault", ["mode", "symlink", "fifo", "oversize", "empty"])
def test_private_references_fail_closed(profile_registry, fault, tmp_path):
    _, entry = profile_registry
    path = Path(entry["password_file"])
    if fault == "mode":
        path.chmod(0o644)
    elif fault == "symlink":
        target = tmp_path / "target"
        path.rename(target)
        path.symlink_to(target)
    elif fault == "fifo":
        import os

        path.unlink()
        os.mkfifo(path, 0o600)
    else:
        path.write_text("x" * 4097 if fault == "oversize" else "")
    assert not profiles.candidates(entry["policy"]["laboratory_id"])[0]["available"]


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "0.0.0.0"])
def test_profile_cannot_bypass_destination_policy(profile_registry, ip):
    path, entry = profile_registry
    entry["allowed_ip"] = ip
    save(path, entry)
    with pytest.raises(ValueError):
        descriptor(entry["id"])


def test_duplicate_profile_ids_and_json_keys_rejected(profile_registry):
    path, entry = profile_registry
    path.write_text(json.dumps({"format": "aegis-defensive-profiles/1", "entries": [entry, entry]}))
    with pytest.raises(ValueError):
        profiles.load()
    path.write_text('{"format":"aegis-defensive-profiles/1","entries":[],"entries":[]}')
    with pytest.raises(ValueError):
        profiles.load()


def test_provider_uses_captured_profile_and_rejects_last_moment_drift(
    profile_registry, monkeypatch
):
    import httpx
    from aegis.integrations.wazuh import configured_provider

    path, entry = profile_registry
    reviewed_hash = digest(descriptor(entry["id"]))
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"version": {"number": "fixture-only"}})

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/environment-ca")
    remote = configured_provider(
        profile_id=entry["id"], expected_hash=reviewed_hash, transport=httpx.MockTransport(handle)
    )
    assert remote.test_connection() == "fixture-only"
    assert remote.closed and len(requests) == 1
    assert requests[0].url.host == "192.0.2.10"
    assert requests[0].headers["Host"] == "indexer.fixture:9200"
    assert requests[0].extensions["sni_hostname"] == "indexer.fixture"
    entry["revision"] += 1
    save(path, entry)
    with pytest.raises(ValueError, match="mudou"):
        configured_provider(
            profile_id=entry["id"],
            expected_hash=reviewed_hash,
            transport=httpx.MockTransport(lambda _: pytest.fail("No send")),
        )
