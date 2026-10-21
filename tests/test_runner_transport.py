import runpy
import socket
import ssl
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import uvicorn
from aegis.domain.contracts import ExecutionContext
from aegis.integrations.linux_runner import (
    LinuxMarkerAdapter,
    LinuxRunnerClient,
    RunnerConnection,
    RunnerUnavailable,
)
from aegis.lab_runner.protocol import PROTOCOL
from aegis.lab_runner.server import create_app
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_runner_engine import prepare

utilities = runpy.run_path("scripts/init_linux_lab.py")
initialize, openssl = utilities["initialize"], utilities["openssl"]


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    root = initialize(tmp_path_factory.mktemp("tls") / "pki")
    # Local-only TLS transport fixture. Production cert remains pinned to the lab's private IP.
    ext = root / "test-localhost.cnf"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(root / "runner-server.csr"),
        "-CA",
        str(root / "server-ca.crt"),
        "-CAkey",
        str(root / "server-ca.key"),
        "-CAcreateserial",
        "-out",
        str(root / "test-server.crt"),
        "-days",
        "1",
        "-sha256",
        "-extfile",
        str(ext),
    )
    return root


def connection(runner, pki):
    return RunnerConnection(
        url="https://172.30.88.2:8443",
        runner_id=runner.identity.runner_id,
        laboratory_id=runner.identity.laboratory_id,
        asset_id=runner.identity.asset_id,
        server_ca=pki / "server-ca.crt",
        client_cert=pki / "runner-client.crt",
        client_key=pki / "runner-client.key",
    )


def test_protocol_api_rejects_plaintext_extra_commands_and_excessive_body(runner):
    app = create_app(runner)
    plain = TestClient(app)
    assert plain.get("/v1/identity").status_code == 403
    client = TestClient(app, base_url="https://testserver")
    view = prepare(runner)
    data = view.spec.model_dump(mode="json")
    assert client.post("/v1/jobs", json=data).status_code == 403
    client.headers["x-aegis-runner-protocol"] = PROTOCOL
    assert client.post("/v1/jobs", json={**data, "command": "anything"}).status_code == 422
    assert client.post("/v1/jobs", content=b"x" * 8193).status_code == 413
    assert client.post("/v1/jobs", json=data).json()["generation"] == str(view.generation)
    assert client.get("/v1/jobs/" + str(uuid4())).status_code == 404


@pytest.mark.parametrize(
    "url",
    [
        "http://172.30.88.2:8443",
        "https://127.0.0.1:8443",
        "https://169.254.169.254:8443",
        "https://example.com:8443",
        "https://8.8.8.8:8443",
        "https://172.30.88.2:8443/path",
        "https://user:pass@172.30.88.2:8443",
        "https://172.30.88.2:8443?redirect=anything",
        "https://172.30.88.2:443",
    ],
)
def test_endpoint_is_literal_deployment_pinned_rfc1918(url):
    with pytest.raises(ValidationError):
        RunnerConnection(
            url=url,
            runner_id=uuid4(),
            laboratory_id=uuid4(),
            asset_id=uuid4(),
            server_ca=Path("unused"),
            client_cert=Path("unused"),
            client_key=Path("unused"),
        )


def test_actual_mutual_tls_rejects_missing_wrong_certificate_and_untrusted_server(runner, pki):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    configuration = uvicorn.Config(
        create_app(runner),
        log_level="critical",
        ssl_certfile=str(pki / "test-server.crt"),
        ssl_keyfile=str(pki / "runner-server.key"),
        ssl_ca_certs=str(pki / "client-ca.crt"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        proxy_headers=False,
    )
    server = uvicorn.Server(configuration)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{port}/v1/identity"
    valid = ssl.create_default_context(cafile=str(pki / "server-ca.crt"))
    valid.load_cert_chain(str(pki / "runner-client.crt"), str(pki / "runner-client.key"))
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.02)
        assert server.started
        with httpx.Client(verify=valid, trust_env=False, timeout=2) as client:
            result = client.get(url)
            assert result.status_code == 200
            assert result.json()["runner_id"] == str(runner.identity.runner_id)
        missing = ssl.create_default_context(cafile=str(pki / "server-ca.crt"))
        wrong = ssl.create_default_context(cafile=str(pki / "server-ca.crt"))
        wrong.load_cert_chain(str(pki / "runner-server.crt"), str(pki / "runner-server.key"))
        untrusted = ssl.create_default_context(cafile=str(pki / "client-ca.crt"))
        untrusted.load_cert_chain(str(pki / "runner-client.crt"), str(pki / "runner-client.key"))
        for context in (missing, wrong, untrusted):
            with httpx.Client(verify=context, trust_env=False, timeout=2) as client:
                with pytest.raises(httpx.HTTPError):
                    client.get(url)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive()


def test_client_adapter_roundtrip_uses_actual_fixed_child_but_no_defensive_claim(runner, pki):
    # ASGI contract transport, separate from the real TLS handshake test above.
    asgi = TestClient(create_app(runner), base_url="https://testserver")

    def dispatch(request):
        response = asgi.request(
            request.method, request.url.path, content=request.content, headers=dict(request.headers)
        )
        return httpx.Response(response.status_code, content=response.content)

    client = LinuxRunnerClient(connection(runner, pki), transport=httpx.MockTransport(dispatch))
    instant = datetime.now(UTC)
    ctx = ExecutionContext(
        str(uuid4()),
        str(runner.identity.laboratory_id),
        str(runner.identity.asset_id),
        "aegis-" + str(uuid4()),
        "temporary-marker",
        instant,
        instant,
        False,
        "",
    )
    adapter = LinuxMarkerAdapter(client, instant + timedelta(seconds=20), "c" * 64, lambda: None)
    try:
        with pytest.raises(ValueError):
            adapter.prepare(replace(ctx, synthetic=True))
        adapter.prepare(ctx)
        assert adapter.execute(ctx)
        adapter.cleanup(ctx)
        view = adapter.jobs[ctx.execution_id]
        assert view.cleanup_state == "CLEANED"
        assert view.receipt.kind == "execution_receipt" and view.receipt.synthetic is False
        assert not (runner.workspace.root / view.spec.job_id.hex).exists()
    finally:
        client.close()


@pytest.mark.parametrize("scenario", ["wrong_identity", "redirect", "huge"])
def test_client_refuses_other_identity_redirects_and_large_response(runner, pki, scenario):
    def dispatch(request):
        if scenario == "wrong_identity":
            wrong = runner.identity.model_copy(update={"asset_id": uuid4()})
            return httpx.Response(200, json=wrong.model_dump(mode="json"))
        if scenario == "redirect":
            return httpx.Response(302, headers={"Location": "https://example.com"})
        return httpx.Response(200, content=b"x" * 32769)

    client = LinuxRunnerClient(connection(runner, pki), transport=httpx.MockTransport(dispatch))
    try:
        with pytest.raises(RunnerUnavailable):
            client.preflight()
    finally:
        client.close()


def test_lost_prepare_response_never_claims_cleanup_without_checking_remote_state(runner, pki):
    asgi = TestClient(create_app(runner), base_url="https://testserver")

    def dispatch(request):
        response = asgi.request(
            request.method, request.url.path, content=request.content, headers=dict(request.headers)
        )
        if request.method == "POST" and request.url.path == "/v1/jobs":
            raise httpx.ReadTimeout("Injected lost preparation response")
        return httpx.Response(response.status_code, content=response.content)

    client = LinuxRunnerClient(connection(runner, pki), transport=httpx.MockTransport(dispatch))
    instant = datetime.now(UTC)
    ctx = ExecutionContext(
        str(uuid4()),
        str(runner.identity.laboratory_id),
        str(runner.identity.asset_id),
        "aegis-" + str(uuid4()),
        "temporary-marker",
        instant,
        instant,
        False,
        "",
    )
    adapter = LinuxMarkerAdapter(client, instant + timedelta(seconds=20), "c" * 64, lambda: None)
    try:
        with pytest.raises(RunnerUnavailable):
            adapter.prepare(ctx)
        adapter.cleanup(ctx)
        result = adapter.jobs[ctx.execution_id]
        assert result.cleanup_state == "CLEANED" and result.state == "CANCELLED"
        assert result.receipt is None
    finally:
        client.close()
