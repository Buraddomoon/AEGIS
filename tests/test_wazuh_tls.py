"""Real HTTPS handshake on a disposable loopback fixture, not a Wazuh deployment."""

import json
import runpy
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from aegis.integrations.wazuh import WazuhIndexerProvider
from aegis.lab_runner.network_profile import LINUX_RUNNER_IP
from httpcore._backends.anyio import AnyIOBackend

initialize = runpy.run_path("scripts/init_linux_lab.py")["initialize"]


@pytest.fixture
def indexer_tls(tmp_path, monkeypatch):
    pki = initialize(tmp_path / "pki")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"version": {"number": "fixture-https-only"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(pki / "runner-server.crt", pki / "runner-server.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    original = AnyIOBackend.connect_tcp

    async def connect(self, host, port, timeout=None, local_address=None, socket_options=None):
        assert (
            host == "192.0.2.10"
        )  # Production pin is asserted; only this test substitutes loopback.
        return await original(
            self,
            "127.0.0.1",
            server.server_port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    monkeypatch.setattr(AnyIOBackend, "connect_tcp", connect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, pki
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("condition", ["trusted", "untrusted_ca", "wrong_hostname"])
def test_default_httpx_transport_verifies_ca_and_original_sni(indexer_tls, condition):
    port, pki = indexer_tls
    hostname = "indexer.invalid" if condition == "wrong_hostname" else LINUX_RUNNER_IP
    ca = None if condition == "untrusted_ca" else str(pki / "server-ca.crt")
    provider = WazuhIndexerProvider(
        f"https://{hostname}:{port}",
        "fixture-readonly",
        "fixture-password",
        "192.0.2.10",
        ca_bundle=ca,
    )
    if condition == "trusted":
        assert provider.test_connection() == "fixture-https-only"
    else:
        with pytest.raises(httpx.HTTPError):
            provider.test_connection()
    assert provider.closed
