import copy
import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from aegis.lab_runner.wazuh_network_profile import INDEXER_IP, INDEXER_URL

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_tls_probe as probe  # noqa: E402

PAYLOAD = {
    "username": "aegis_reader",
    "password": "fixture-private-do-not-echo",
    "expected_certificate_der_sha256": "a" * 64,
}
PEER = {"certificate_der_sha256": "a" * 64, "tls_version": "TLSv1.3"}


class Provider:
    def __init__(self, *args, **kwargs):
        assert args == (INDEXER_URL, "aegis_reader", PAYLOAD["password"], INDEXER_IP)
        assert kwargs["ca_bundle"] == "/run/secrets/wazuh_ca"
        self.calls, self.closed = [], False
        self.responses = {
            probe.PATHS[0]: {"version": {"number": "fixture-only"}},
            probe.PATHS[1]: {"user_name": "aegis_reader", "roles": ["aegis_reader"]},
            probe.PATHS[2]: {"has_api_access": False},
            probe.PATHS[3]: {
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
                "hits": {"hits": []},
            },
        }

    def _request(self, method, path):
        self.calls.append((method, path))
        assert method == "GET" and path in probe.PATHS
        if path == probe.PATHS[4]:
            response = httpx.Response(403, request=httpx.Request("GET", "https://fixture.invalid"))
            response.raise_for_status()
        return self.responses[path]

    def close(self):
        self.closed = True


def test_fixed_probe_uses_existing_connector_get_only_and_redacts_results():
    provider = Provider(
        INDEXER_URL, "aegis_reader", PAYLOAD["password"], INDEXER_IP, ca_bundle=probe.CA
    )
    result = probe.probe(PAYLOAD, provider_factory=lambda *a, **k: provider, peer=lambda: PEER)
    assert provider.closed
    assert provider.calls == [("GET", path) for path in probe.PATHS]
    assert result["status"] == "tls_identity_and_read_acl_verified"
    assert (
        result["write_acl_verified"]
        is result["write_request_performed"]
        is result["marker_executed"]
        is result["normal_operation_permitted"]
        is False
    )
    assert PAYLOAD["password"] not in json.dumps(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "principal",
        "roles",
        "api-access",
        "missing-permissions",
        "timeout",
        "failed-shard",
        "partial-shards",
        "empty-shards",
        "unexpected-document",
        "version",
    ],
)
def test_bad_identity_permissions_or_partial_read_is_inconclusive_and_closes(mutation):
    provider = Provider(
        INDEXER_URL, "aegis_reader", PAYLOAD["password"], INDEXER_IP, ca_bundle=probe.CA
    )
    responses = provider.responses
    if mutation == "principal":
        responses[probe.PATHS[1]]["user_name"] = "admin"
    elif mutation == "roles":
        responses[probe.PATHS[1]]["roles"].append("all_access")
    elif mutation == "api-access":
        responses[probe.PATHS[2]]["has_api_access"] = True
    elif mutation == "missing-permissions":
        responses[probe.PATHS[2]] = {}
    elif mutation == "timeout":
        responses[probe.PATHS[3]]["timed_out"] = True
    elif mutation == "failed-shard":
        responses[probe.PATHS[3]]["_shards"]["failed"] = 1
    elif mutation == "partial-shards":
        responses[probe.PATHS[3]]["_shards"]["successful"] = 0
    elif mutation == "empty-shards":
        responses[probe.PATHS[3]]["_shards"]["total"] = 0
    elif mutation == "unexpected-document":
        responses[probe.PATHS[3]]["hits"]["hits"] = [{"private": "must-not-print"}]
    else:
        responses[probe.PATHS[0]] = {}
    with pytest.raises(ValueError):
        probe.probe(PAYLOAD, provider_factory=lambda *a, **k: provider, peer=lambda: PEER)
    assert provider.closed


@pytest.mark.parametrize("status", [200, 401, 404, 500])
def test_only_exact_403_proves_security_index_read_denial(status):
    provider = Provider(
        INDEXER_URL, "aegis_reader", PAYLOAD["password"], INDEXER_IP, ca_bundle=probe.CA
    )
    original = provider._request

    def request(method, path):
        if path == probe.PATHS[4]:
            response = httpx.Response(
                status, request=httpx.Request("GET", "https://fixture.invalid")
            )
            response.raise_for_status()
            return {"not": "denied"}
        return original(method, path)

    provider._request = request
    with pytest.raises(ValueError):
        probe.probe(PAYLOAD, provider_factory=lambda *a, **k: provider, peer=lambda: PEER)
    assert provider.closed


@pytest.mark.parametrize(
    "change",
    [
        {"username": "admin"},
        {"url": "https://unreviewed.invalid"},
        {"password": ""},
        {"password": "x" * 257},
        {"expected_certificate_der_sha256": "invalid"},
    ],
)
def test_unreviewed_input_rejected_before_network(change):
    payload = {**copy.deepcopy(PAYLOAD), **change}
    with pytest.raises(ValueError):
        probe.probe(payload, peer=lambda: pytest.fail("No network for invalid scope"))


@pytest.mark.parametrize(
    "peer", [{**PEER, "certificate_der_sha256": "b" * 64}, {**PEER, "tls_version": "TLSv1"}]
)
def test_wrong_peer_stops_before_credentials_are_sent(peer):
    with pytest.raises(ValueError):
        probe.probe(
            PAYLOAD,
            peer=lambda: peer,
            provider_factory=lambda *a, **k: pytest.fail("No credentials"),
        )


def test_cli_rejects_secret_bearing_bad_input_without_echo_or_traceback():
    result = subprocess.run(
        [sys.executable, "scripts/wazuh_tls_probe.py"],
        input=(PAYLOAD["password"] + "!").encode(),
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert PAYLOAD["password"].encode() not in result.stdout + result.stderr
    assert not result.stderr
    assert json.loads(result.stdout)["status"] == "inconclusive"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", None),
        ("_shards", None),
        ("_shards", {"total": 1, "successful": 1, "failed": False}),
    ],
)
def test_malformed_nested_schema_fails_closed(field, value):
    provider = Provider(
        INDEXER_URL, "aegis_reader", PAYLOAD["password"], INDEXER_IP, ca_bundle=probe.CA
    )
    provider.responses[probe.PATHS[0] if field == "version" else probe.PATHS[3]][field] = value
    with pytest.raises(ValueError):
        probe.probe(PAYLOAD, provider_factory=lambda *a, **k: provider, peer=lambda: PEER)
    assert provider.closed


def test_duplicate_probe_input_fields_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        json.loads(
            '{"username":"admin","username":"aegis_reader"}', object_pairs_hook=probe.unique_fields
        )


@pytest.mark.parametrize("condition", ["trusted", "wrong-ca", "wrong-hostname"])
def test_real_tls_peer_identity_uses_pinned_address_ca_and_sni(tmp_path, monkeypatch, condition):
    import hashlib
    import socket
    import ssl
    import threading

    import wazuh_pki

    root = tmp_path / "server"
    root.mkdir(mode=0o700)
    wazuh_pki.generate(root)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "pki/indexer.pem", root / "pki/indexer-key.pem")

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                with context.wrap_socket(conn, server_side=True):
                    pass
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    connect = socket.create_connection

    def pinned(address, **kwargs):
        assert address == (INDEXER_IP, 9200)
        return connect(listener.getsockname(), **kwargs)

    monkeypatch.setattr(probe.socket, "create_connection", pinned)
    monkeypatch.setattr(probe, "CA", str(root / "pki/root-ca.pem"))
    if condition == "wrong-ca":
        other = tmp_path / "other"
        other.mkdir(mode=0o700)
        wazuh_pki.generate(other)
        monkeypatch.setattr(probe, "CA", str(other / "pki/root-ca.pem"))
    elif condition == "wrong-hostname":
        monkeypatch.setattr(probe, "HOSTNAME", "unreviewed.invalid")
    try:
        if condition == "trusted":
            observed = probe.peer_identity()
            expected = hashlib.sha256(
                wazuh_pki.fs.openssl(
                    "x509", "-outform", "DER", data=(root / "pki/indexer.pem").read_bytes()
                )
            ).hexdigest()
            assert observed["certificate_der_sha256"] == expected
            assert observed["tls_version"] in {"TLSv1.2", "TLSv1.3"}
        else:
            with pytest.raises(ssl.SSLError):
                probe.peer_identity()
    finally:
        thread.join(timeout=4)
        listener.close()
        assert not thread.is_alive()
