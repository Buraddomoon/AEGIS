"""Per-connection TLS facts from a real loopback transport, not HTTP identity headers."""

import asyncio
import hashlib
import ssl
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from aegis.lab_runner import server, tls_peer
from aegis.lab_runner.protocol import RunnerIdentity
from fastapi.testclient import TestClient
from test_runner_identity_probe import request_context as request_context
from test_runner_identity_probe import serving
from test_runner_transport import pki as pki
from uvicorn.server import ServerState


def test_real_tls_peer_fingerprint_is_bound_to_the_verified_client_certificate(
    request_context, pki, monkeypatch
):
    context = ssl.create_default_context(cafile=str(pki / "server-ca.crt"))
    context.load_cert_chain(str(pki / "runner-client.crt"), str(pki / "runner-client.key"))
    der = ssl.PEM_cert_to_DER_cert((pki / "runner-client.crt").read_text())
    expected = hashlib.sha256(der).hexdigest()
    with serving(request_context, pki, monkeypatch, protocol=tls_peer.IdentityTLSProtocol):
        from aegis.lab_runner import identity_probe

        with httpx.Client(verify=context, trust_env=False, timeout=2) as client:
            response = client.get(
                f"https://127.0.0.1:{identity_probe.PORT}/v1/identity",
                headers={"X-AEGIS-Client-Cert-SHA256": "f" * 64},
            )
    assert response.status_code == 200 and response.json() == request_context["identity"]
    assert response.headers["x-aegis-client-cert-sha256"] == expected
    assert response.headers["x-aegis-client-cert-policy"] == "required"
    assert response.headers["x-aegis-tls-version"] in {"TLSv1.2", "TLSv1.3"}


def test_http_headers_without_transport_evidence_cannot_claim_a_verified_client(request_context):
    identity = RunnerIdentity.model_validate(request_context["identity"])
    with TestClient(server.create_identity_app(identity), base_url="https://testserver") as client:
        result = client.get(
            "/v1/identity",
            headers={
                "X-AEGIS-Client-Cert-SHA256": "f" * 64,
                "X-AEGIS-Client-Cert-Policy": "required",
                "X-AEGIS-TLS-Version": "TLSv1.3",
            },
        )
    assert result.status_code == 200 and "x-aegis-client-cert-sha256" not in result.headers


class Transport:
    def __init__(self, *, data=b"fixture-client-der", mode=ssl.CERT_REQUIRED, version="TLSv1.3"):
        self.closed = False
        self.context = SimpleNamespace(
            context=SimpleNamespace(verify_mode=mode),
            getpeercert=lambda **kwargs: data,
            version=lambda: version,
        )

    def get_extra_info(self, key):
        return {
            "ssl_object": self.context,
            "sslcontext": self.context.context if self.context else None,
            "sockname": ("127.0.0.1", 8443),
            "peername": ("127.0.0.1", 45000),
        }.get(key)

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    "scene", ["plaintext", "none", "optional", "empty", "type", "oversize", "legacy_tls"]
)
def test_missing_unverified_or_unsupported_transport_is_not_evidence(scene):
    transport = Transport()
    if scene == "plaintext":
        transport.context = None
    elif scene == "none":
        transport.context.context.verify_mode = ssl.CERT_NONE
    elif scene == "optional":
        transport.context.context.verify_mode = ssl.CERT_OPTIONAL
    elif scene == "legacy_tls":
        transport.context.version = lambda: "TLSv1"
    else:
        data = {"empty": b"", "type": "not DER bytes", "oversize": b"x" * 65537}[scene]
        transport.context.getpeercert = lambda **kwargs: data
    assert tls_peer.certificate(transport) is None


def test_wrapper_binds_each_scope_to_its_own_connection_even_if_scope_contains_a_forged_proof():
    async def check():
        received = []

        async def app(scope, receive, send):
            received.append(scope["extensions"][tls_peer.EXTENSION])

        config = uvicorn.Config(app, log_level="critical")
        state = ServerState()
        first = tls_peer.IdentityTLSProtocol(config, state, {}, _loop=asyncio.get_running_loop())
        second = tls_peer.IdentityTLSProtocol(config, state, {}, _loop=asyncio.get_running_loop())
        first.connection_made(Transport(data=b"first-client"))
        second.connection_made(Transport(data=b"second-client"))
        scope = {"type": "http", "extensions": {tls_peer.EXTENSION: "untrusted"}}
        await first.app(scope, None, None)
        await second.app(scope, None, None)
        await first.app(scope, None, None)
        assert [value.sha256 for value in received] == [
            hashlib.sha256(data).hexdigest()
            for data in (b"first-client", b"second-client", b"first-client")
        ]
        assert scope["extensions"][tls_peer.EXTENSION] == "untrusted"
        reused = Transport()
        with pytest.raises(RuntimeError, match="connection_reused"):
            first.connection_made(reused)
        assert reused.closed

    asyncio.run(check())


def test_unreviewed_backend_version_blocks_identity_start_before_runner_or_server_boot(
    request_context, monkeypatch
):
    for name in ("runner_id", "laboratory_id", "asset_id"):
        monkeypatch.setenv("AEGIS_RUNNER_" + name.upper(), request_context["identity"][name])
    monkeypatch.setenv("AEGIS_RUNNER_IDENTITY_ONLY", "true")
    monkeypatch.setattr(tls_peer.uvicorn, "__version__", "unreviewed")
    monkeypatch.setattr(server, "Runner", lambda *a: pytest.fail("No journal access permitted"))
    monkeypatch.setattr(server.uvicorn, "run", lambda *a, **k: pytest.fail("No listen permitted"))
    with pytest.raises(RuntimeError, match="version_unreviewed"):
        server.main()
