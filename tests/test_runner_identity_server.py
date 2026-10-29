"""Identity-only ASGI/boot and real loopback mTLS; no runner, journal or marker."""

import socket
import ssl
import threading
import time
from uuid import uuid4

import httpx
import pytest
import uvicorn
from aegis.integrations.linux_runner import LinuxRunnerClient, RunnerConnection, RunnerUnavailable
from aegis.lab_runner import server
from aegis.lab_runner.protocol import PROTOCOL, RunnerIdentity
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_runner_transport import pki as pki


@pytest.fixture
def identity():
    return RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4())


def expected(identity):
    return identity.model_copy(update={"tests": ()}).model_dump(mode="json")


def test_identity_surface_has_no_job_routes_and_rejects_plaintext(identity):
    app = server.create_identity_app(identity)
    assert [(route.path, route.methods) for route in app.routes] == [("/v1/identity", {"GET"})]
    with TestClient(app) as plaintext:
        assert plaintext.get("/v1/identity").status_code == 403
    with TestClient(app, base_url="https://testserver") as client:
        result = client.get("/v1/identity")
        assert result.json() == expected(identity)
        assert result.headers["x-aegis-runner-mode"] == "identity-only"
        assert result.headers["cache-control"] == "no-store"
        for path in ("/v1/jobs", "/v1/jobs/" + str(uuid4()), "/docs", "/openapi.json"):
            assert client.get(path).status_code == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_mutating_methods_are_denied_before_body_parsing_or_any_job_handler(identity, method):
    with TestClient(server.create_identity_app(identity), base_url="https://testserver") as client:
        for suffix in ("", "/start", "/renew", "/cancel", "/cleanup"):
            response = client.request(
                method,
                "/v1/jobs/" + str(uuid4()) + suffix,
                headers={"x-aegis-runner-protocol": PROTOCOL},
                content=b"x" * 8193,
            )
            assert response.status_code == 503
            assert response.headers["x-aegis-runner-mode"] == "identity-only"
            assert response.headers["cache-control"] == "no-store"


def configure_identity(monkeypatch, identity):
    for field in ("runner_id", "laboratory_id", "asset_id"):
        monkeypatch.setenv("AEGIS_RUNNER_" + field.upper(), str(getattr(identity, field)))


def test_identity_only_boot_never_instantiates_runner_and_keeps_mtls_required(
    monkeypatch, tmp_path, identity
):
    configure_identity(monkeypatch, identity)
    monkeypatch.setenv("AEGIS_RUNNER_IDENTITY_ONLY", "true")
    state, work = tmp_path / "state-not-created", tmp_path / "work-not-created"
    monkeypatch.setenv("AEGIS_RUNNER_STATE_DIR", str(state))
    monkeypatch.setenv("AEGIS_RUNNER_WORK_DIR", str(work))
    monkeypatch.setattr(server, "Runner", lambda *a: pytest.fail("Runner must never open state"))
    calls = []
    monkeypatch.setattr(server.uvicorn, "run", lambda app, **kwargs: calls.append((app, kwargs)))
    server.main()
    assert not state.exists() and not work.exists()
    app, config = calls[0]
    assert config["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert config["proxy_headers"] is False and config["workers"] == 1
    assert config["ssl_ca_certs"] == "/run/secrets/runner_client_ca"
    with TestClient(app, base_url="https://testserver") as client:
        assert client.get("/v1/identity").json() == expected(identity)
        assert client.post("/v1/jobs").status_code == 503


def test_invalid_identity_mode_configuration_does_not_fall_back_to_execution(monkeypatch, identity):
    configure_identity(monkeypatch, identity)
    monkeypatch.setenv("AEGIS_RUNNER_IDENTITY_ONLY", "unreviewed")
    monkeypatch.setattr(server, "Runner", lambda *a: pytest.fail("No runner permitted"))
    with pytest.raises(ValidationError):
        server.main()


def test_normal_entrypoint_still_selects_execution_surface_by_default(monkeypatch, identity):
    configure_identity(monkeypatch, identity)
    monkeypatch.delenv("AEGIS_RUNNER_IDENTITY_ONLY", raising=False)
    instance, app, selected = object(), object(), []
    monkeypatch.setattr(server, "Runner", lambda *a: selected.append(a) or instance)

    def create(value):
        assert value is instance
        return app

    monkeypatch.setattr(server, "create_app", create)
    monkeypatch.setattr(server, "create_identity_app", lambda *a: pytest.fail("Wrong mode"))
    monkeypatch.setattr(server.uvicorn, "run", lambda value, **kwargs: selected.append(value))
    server.main()
    assert selected[0][0] == identity and selected[1] is app


def test_real_loopback_mtls_exposes_only_identity_and_denies_clients_without_certificate(
    identity, pki
):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    configuration = uvicorn.Config(
        server.create_identity_app(identity),
        log_level="critical",
        ssl_certfile=str(pki / "test-server.crt"),
        ssl_keyfile=str(pki / "runner-server.key"),
        ssl_ca_certs=str(pki / "client-ca.crt"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        proxy_headers=False,
    )
    instance = uvicorn.Server(configuration)
    thread = threading.Thread(target=instance.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    valid = ssl.create_default_context(cafile=str(pki / "server-ca.crt"))
    valid.load_cert_chain(str(pki / "runner-client.crt"), str(pki / "runner-client.key"))
    url = f"https://127.0.0.1:{port}"
    try:
        for _ in range(100):
            if instance.started:
                break
            time.sleep(0.02)
        assert instance.started
        with httpx.Client(verify=valid, trust_env=False, timeout=2) as client:
            result = client.get(url + "/v1/identity")
            assert result.status_code == 200
            assert result.json() == expected(identity)
            assert result.headers["x-aegis-runner-mode"] == "identity-only"
            assert client.post(url + "/v1/jobs", json={}).status_code == 503
        missing = ssl.create_default_context(cafile=str(pki / "server-ca.crt"))
        with httpx.Client(verify=missing, trust_env=False, timeout=2) as client:
            with pytest.raises(httpx.HTTPError):
                client.get(url + "/v1/identity")
    finally:
        instance.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive()


def test_normal_execution_client_refuses_identity_only_surface_before_preparing_job(identity, pki):
    config = RunnerConnection(
        url="https://172.30.88.2:8443",
        runner_id=identity.runner_id,
        laboratory_id=identity.laboratory_id,
        asset_id=identity.asset_id,
        server_ca=pki / "server-ca.crt",
        client_cert=pki / "runner-client.crt",
        client_key=pki / "runner-client.key",
    )
    requests = []
    with TestClient(server.create_identity_app(identity), base_url="https://testserver") as asgi:

        def dispatch(request):
            requests.append((request.method, request.url.path))
            response = asgi.request(request.method, request.url.path)
            return httpx.Response(response.status_code, content=response.content)

        client = LinuxRunnerClient(config, transport=httpx.MockTransport(dispatch))
        try:
            with pytest.raises(RunnerUnavailable, match="allowlist"):
                client.preflight()
        finally:
            client.close()
    assert requests == [("GET", "/v1/identity")]
