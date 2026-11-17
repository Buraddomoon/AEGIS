"""Closed historical query probe using HTTP fixtures, not native SIEM evidence."""

import copy
import json
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_schema_probe as probe  # noqa: E402


def execute(fault=None):
    document = json.loads(Path("docs/evidence/wazuh-cycle-2026-11-16/alert.json").read_text())
    remaining = {"total": 1}
    calls = []

    def response(hits=(), total=0, cursor=None):
        value = {
            "timed_out": False,
            "_shards": {"total": 3, "successful": 3, "failed": 0},
            "hits": {"total": {"value": total, "relation": "eq"}, "hits": list(hits)},
        }
        if cursor:
            value["_scroll_id"] = cursor
        return value

    def handle(request):
        calls.append(request)
        path = request.url.path
        if path == "/":
            value = {"version": {"number": "7.10.2"}}
        elif path == "/_plugins/_security/authinfo":
            value = {"user_name": "aegis_reader", "roles": ["aegis_reader"]}
        elif path == "/_plugins/_security/api/permissionsinfo":
            value = {"has_api_access": False}
        elif path.startswith("/.opendistro_security"):
            return httpx.Response(403, json={})
        elif path.startswith("/wazuh-archives-"):
            return httpx.Response(
                404 if fault == "archive_404" else 403, json={"error": "private-data"}
            )
        elif request.method == "DELETE":
            value = {"succeeded": fault != "cleanup", "num_freed": 1}
        elif path == "/_search/scroll":
            value = response(total=remaining["total"], cursor="latest-private-cursor")
        elif request.method == "GET":
            value = response()
        else:
            filters = json.loads(request.content)["query"]["bool"]["filter"]
            negative = filters[2]["match_phrase"]["data.aegis.marker"].endswith("-not-this-event")
            remaining["total"] = 0 if negative else 1
            changed = copy.deepcopy(document)
            if fault == "content":
                changed["_source"]["rule"]["description"] = "changed source content"
            if fault == "id":
                changed["_id"] = "different-id"
            value = response(
                [] if negative else [changed],
                total=remaining["total"],
                cursor="first-private-cursor",
            )
            if fault == "shards":
                value["_shards"]["failed"] = 1
        return httpx.Response(200, json=value)

    def factory(*args, **kwargs):
        assert kwargs["ca_bundle"] == "/run/secrets/wazuh_ca"
        kwargs["ca_bundle"] = None  # HTTP fixture; production CA must remain mandatory.
        return probe.AuditedReader(*args, transport=httpx.MockTransport(handle), **kwargs)

    result = probe.probe(
        {
            "username": "aegis_reader",
            "password": "private-fixture-secret",
            "expected_certificate_der_sha256": "a" * 64,
        },
        provider_factory=factory,
        peer=lambda: {"certificate_der_sha256": "a" * 64, "tls_version": "TLSv1.3"},
    )
    return result, calls


def test_probe_verifies_original_identity_complete_scroll_and_redacted_diagnostics():
    result, calls = execute()
    assert result["status"] == "historical_native_profile_query_verified"
    assert result["schema_id"] == "wazuh-4.14.9/1"
    assert result["positive_complete"] and result["negative_marker_complete_empty"]
    assert result["scroll_cleanup_verified"] and result["archives"]["http_status"] == 403
    encoded = json.dumps(result)
    for private in ("private-fixture-secret", "private-cursor", "private-data"):
        assert private not in encoded
    assert not result["new_marker_executed"] and not result["new_run_requested"]
    assert not result["new_detection_verdict_created"]
    assert not result["document_write_request_performed"]
    assert sum(request.method == "DELETE" for request in calls) == 3
    assert all(request.method in {"GET", "POST", "DELETE"} for request in calls)
    assert not any("/_doc" in request.url.path or "/_bulk" in request.url.path for request in calls)


@pytest.mark.parametrize("fault", ["content", "id", "shards", "cleanup", "archive_404"])
def test_probe_refuses_partial_or_changed_source_and_unverified_cleanup(fault):
    with pytest.raises(ValueError):
        execute(fault)


def test_credentials_are_validated_before_network():
    with pytest.raises(ValueError, match="invalid_probe_scope"):
        probe.probe({"username": "other"}, peer=lambda: pytest.fail("TLS must not be attempted"))


def test_startup_wait_retries_only_connection_readiness(monkeypatch):
    calls = []

    def peer():
        calls.append(True)
        if len(calls) == 1:
            raise ConnectionRefusedError()
        return {"certificate_der_sha256": "a" * 64}

    monkeypatch.setattr(probe, "peer_identity", peer)
    monkeypatch.setattr(probe, "readiness_status", lambda: 401)
    monkeypatch.setattr(probe.time, "sleep", lambda _: None)
    assert probe.wait_for_peer() == {"certificate_der_sha256": "a" * 64}
    assert len(calls) == 2


def test_startup_waits_for_http_after_tls_without_sending_credentials(monkeypatch):
    statuses = iter([503, 401])
    monkeypatch.setattr(probe, "peer_identity", lambda: {"certificate_der_sha256": "a" * 64})
    monkeypatch.setattr(probe, "readiness_status", lambda: next(statuses))
    monkeypatch.setattr(probe.time, "sleep", lambda _: None)
    assert probe.wait_for_peer() == {"certificate_der_sha256": "a" * 64}


def test_startup_refuses_unexpected_http_status(monkeypatch):
    monkeypatch.setattr(probe, "peer_identity", lambda: {})
    monkeypatch.setattr(probe, "readiness_status", lambda: 302)
    with pytest.raises(ValueError, match="http_readiness_unexpected"):
        probe.wait_for_peer()


def test_readiness_is_a_fixed_verified_request_without_authorization(monkeypatch):
    real_client = httpx.Client
    real_context = ssl.create_default_context
    calls = []

    def context(*, cafile):
        assert cafile == "/run/secrets/wazuh_ca"
        return real_context()

    def handle(request):
        calls.append(request)
        assert request.url.host == "192.168.253.18" and request.url.path == "/"
        assert request.headers["host"] == "wazuh.indexer:9200"
        assert request.extensions["sni_hostname"] == "wazuh.indexer"
        assert "authorization" not in request.headers
        return httpx.Response(401)

    def client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        assert kwargs["verify"].check_hostname
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(probe.ssl, "create_default_context", context)
    monkeypatch.setattr(probe.httpx, "Client", client)
    assert probe.readiness_status() == 401 and len(calls) == 1


def test_startup_wait_never_retries_certificate_failure(monkeypatch):
    def peer():
        raise ssl.SSLCertVerificationError("fixture-certificate-mismatch")

    monkeypatch.setattr(probe, "peer_identity", peer)
    monkeypatch.setattr(probe.time, "sleep", lambda _: pytest.fail("Must not retry trust failure"))
    with pytest.raises(ssl.SSLCertVerificationError):
        probe.wait_for_peer()


def test_startup_wait_has_a_deadline(monkeypatch):
    instants = iter([0, 91])
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(instants))
    monkeypatch.setattr(
        probe, "peer_identity", lambda: (_ for _ in ()).throw(ConnectionRefusedError())
    )
    with pytest.raises(TimeoutError, match="readiness_timeout"):
        probe.wait_for_peer()


def test_cli_consumes_one_bounded_line_without_waiting_for_compose_stdin_eof(monkeypatch, capsys):
    payload = {
        "username": "aegis_reader",
        "password": "private-line-secret",
        "expected_certificate_der_sha256": "a" * 64,
    }

    class OpenPipe:
        def readline(self, limit):
            assert limit == 4097
            return json.dumps(payload).encode() + b"\n"

        def read(self, limit):
            pytest.fail("An open Compose pipe has no EOF; read() would block")

    monkeypatch.setattr(probe.sys, "stdin", SimpleNamespace(buffer=OpenPipe()))

    def verified(value, **kwargs):
        assert value == payload and kwargs["peer"] is probe.wait_for_peer
        return {"status": "fixture-only"}

    monkeypatch.setattr(probe, "probe", verified)
    assert probe.main() == 0
    output = capsys.readouterr().out
    assert json.loads(output) == {"status": "fixture-only"}
    assert "private-line-secret" not in output


@pytest.mark.parametrize("raw", [b"x" * 4097, b'{"username":"one","username":"two"}\n'])
def test_cli_rejects_oversized_or_duplicate_input_before_network(monkeypatch, capsys, raw):
    monkeypatch.setattr(
        probe.sys, "stdin", SimpleNamespace(buffer=SimpleNamespace(readline=lambda limit: raw))
    )
    monkeypatch.setattr(
        probe,
        "probe",
        lambda *args, **kwargs: pytest.fail("Invalid input must not reach the network"),
    )
    assert probe.main() == 1
    assert json.loads(capsys.readouterr().out)["status"] == "inconclusive"
