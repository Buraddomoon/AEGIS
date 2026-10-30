"""Fixed GET-only probe with real loopback TLS and temporary certificates, never a lab."""

import asyncio
import copy
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from uuid import uuid4

import pytest
import uvicorn
from aegis.lab_runner import identity_probe as probe
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.lab_runner.server import create_identity_app
from fastapi import FastAPI
from fastapi.responses import Response
from test_runner_transport import initialize
from test_runner_transport import pki as pki


@pytest.fixture
def request_context(pki, tmp_path, monkeypatch):
    previous = initialize(tmp_path / "previous-pki")
    files = {
        "candidate_server_ca": pki / "server-ca.crt",
        "candidate_client_cert": pki / "runner-client.crt",
        "previous_server_ca": previous / "server-ca.crt",
    }
    monkeypatch.setattr(probe, "FILES", files)
    monkeypatch.setattr(probe, "CLIENT_KEY", pki / "runner-client.key")
    identity = RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4(), tests=())
    leaf = ssl.PEM_cert_to_DER_cert((pki / "test-server.crt").read_text())
    return {
        "format": "aegis-identity-tls-request/1",
        "operation_id": uuid4().hex,
        "plan_sha256": "a" * 64,
        "scope_sha256": "b" * 64,
        "identity": identity.model_dump(mode="json"),
        "server_leaf_sha256": hashlib.sha256(leaf).hexdigest(),
        "certificate_sha256": {
            key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in files.items()
        },
    }


@contextmanager
def serving(value, pki, monkeypatch, *, require_client=True, application=None, protocol="auto"):
    identity = RunnerIdentity.model_validate(value["identity"])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    monkeypatch.setattr(probe, "HOST", "127.0.0.1")
    monkeypatch.setattr(probe, "PORT", listener.getsockname()[1])
    instance = uvicorn.Server(
        uvicorn.Config(
            application or create_identity_app(identity),
            log_level="critical",
            ssl_certfile=str(pki / "test-server.crt"),
            ssl_keyfile=str(pki / "runner-server.key"),
            ssl_ca_certs=str(pki / "client-ca.crt"),
            ssl_cert_reqs=ssl.CERT_REQUIRED if require_client else ssl.CERT_NONE,
            proxy_headers=False,
            http=protocol,
        )
    )
    thread = threading.Thread(target=instance.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if instance.started:
                break
            time.sleep(0.02)
        assert instance.started
        yield
    finally:
        instance.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive()


def test_actual_tls_proves_candidate_identity_required_client_and_rejection_of_previous_ca(
    request_context, pki, monkeypatch
):
    with serving(request_context, pki, monkeypatch):
        result = asyncio.run(probe.check(request_context))
    conclusive = result["missing_client_control_outcome"] == "certificate_required_alert"
    assert result["status"] == (
        "identity_tls_controls_verified" if conclusive else "identity_tls_controls_inconclusive"
    )
    assert result["client_certificate_requirement_verified"] is conclusive
    assert result["context_sha256"] == probe.digest(request_context)
    assert result["tls_version"] == "TLSv1.3"
    assert all(
        result[key] is True
        for key in (
            "identity_with_candidate_material_verified",
            "previous_ca_rejected",
            "identity_revalidated",
        )
    )
    assert all(result[key] is False for key in probe.FLAGS)
    assert len(json.dumps(result)) < 4096


def test_server_that_does_not_require_client_certificate_cannot_pass_controls(
    request_context, pki, monkeypatch
):
    with serving(request_context, pki, monkeypatch, require_client=False):
        with pytest.raises(probe.ProbeError, match="missing_client_rejection_unconfirmed"):
            asyncio.run(probe.check(request_context))


@pytest.mark.parametrize("outcome", ["explicit_alert", "reset", "eof"])
def test_only_an_explicit_tls_reason_can_confirm_certificate_requirement(
    request_context, monkeypatch, outcome
):
    calls = 0

    async def exchange(context):
        nonlocal calls
        calls += 1
        if calls in {1, 4}:
            return request_context["identity"], request_context["server_leaf_sha256"]
        if calls == 2:
            if outcome == "reset":
                raise ConnectionResetError("private-sensitive-sentinel")
            if outcome == "eof":
                raise asyncio.IncompleteReadError(b"private-sensitive-sentinel", None)
            error = ssl.SSLError("private-sensitive-sentinel")
            error.reason = "TLSV13_ALERT_CERTIFICATE_REQUIRED"
            raise error
        error = ssl.SSLCertVerificationError("private-sensitive-sentinel")
        error.verify_code = 20
        raise error

    monkeypatch.setattr(probe, "_exchange", exchange)
    result = asyncio.run(probe.check(request_context))
    assert calls == 4 and result["previous_ca_rejected"]
    assert result["client_certificate_requirement_verified"] is (outcome == "explicit_alert")
    assert result["status"] == (
        "identity_tls_controls_verified"
        if outcome == "explicit_alert"
        else "identity_tls_controls_inconclusive"
    )
    assert all(result[key] is False for key in probe.FLAGS)
    assert "private-sensitive-sentinel" not in json.dumps(result)


@pytest.mark.parametrize(
    "scene",
    ["redirect", "encoding", "oversize", "wrong_mode", "duplicate_header", "duplicate_json"],
)
def test_fixed_http_reader_rejects_redirect_compression_oversize_and_ambiguous_responses(
    request_context, pki, monkeypatch, scene
):
    app = FastAPI()

    @app.get("/v1/identity")
    def response():
        body = json.dumps(request_context["identity"]).encode()
        headers = {"X-AEGIS-Runner-Mode": "identity-only"}
        status = 200
        if scene == "redirect":
            status, headers["Location"] = 301, "https://external.invalid/"
        elif scene == "encoding":
            headers["Content-Encoding"] = "gzip"
        elif scene == "oversize":
            body = b"x" * (probe.MAX_RESPONSE + 1)
        elif scene == "wrong_mode":
            headers["X-AEGIS-Runner-Mode"] = "execution"
        elif scene == "duplicate_json":
            body = b'{"tests":[],"tests":[]}'
        value = Response(body, status_code=status, headers=headers, media_type="application/json")
        if scene == "duplicate_header":
            value.raw_headers.append((b"content-type", b"application/json"))
        return value

    with serving(request_context, pki, monkeypatch, application=app):
        with pytest.raises(probe.ProbeError):
            asyncio.run(probe.check(request_context))


def test_failure_output_never_stringifies_unexpected_exception_arguments(monkeypatch, capsys):
    def fail():
        raise probe.ProbeError({"private-sensitive-sentinel": "not-a-static-code"})

    monkeypatch.setattr(probe, "_process", fail)
    assert probe.main(["--context-sha256", "a" * 64]) == 1
    output = capsys.readouterr().out
    assert "private-sensitive-sentinel" not in output
    assert json.loads(output)["code"] == "identity_tls_probe_rejected"


@pytest.mark.parametrize("name", ["SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_ambient_tls_overrides_are_refused_before_context_creation(
    request_context, tmp_path, monkeypatch, name
):
    destination = tmp_path / "must-not-be-created"
    monkeypatch.setenv(name, str(destination))
    with pytest.raises(probe.ProbeError, match="ambient_tls_configuration"):
        probe._context(probe.FILES["candidate_server_ca"], authenticated=True)
    assert not destination.exists()


def test_certificate_reader_refuses_fifo_symlink_and_oversize_without_blocking(tmp_path):
    certificate = tmp_path / "certificate.crt"
    certificate.write_bytes(b"x" * 65537)
    with pytest.raises(probe.ProbeError, match="certificate_inputs_unconfirmed"):
        probe._public(certificate)
    link = tmp_path / "symlink.crt"
    link.symlink_to(certificate)
    with pytest.raises(OSError):
        probe._public(link)
    fifo = tmp_path / "fifo.crt"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(probe.ProbeError, match="certificate_inputs_unconfirmed"):
        probe._public(fifo)


@pytest.mark.parametrize("field", ["identity", "server_leaf_sha256", "certificate_sha256"])
def test_authenticated_tls_alone_cannot_accept_another_identity_or_certificate(
    request_context, pki, monkeypatch, field
):
    expected = copy.deepcopy(request_context)
    if field == "identity":
        expected["identity"]["asset_id"] = str(uuid4())
    elif field == "server_leaf_sha256":
        expected[field] = "f" * 64
    else:
        expected[field]["candidate_server_ca"] = "f" * 64
    with serving(request_context, pki, monkeypatch):
        with pytest.raises(probe.ProbeError):
            asyncio.run(probe.check(expected))


@pytest.mark.parametrize(
    "scene", ["no_certificate_any_error", "expired_previous_ca", "other_ssl_alert", "timeout"]
)
def test_network_failure_or_expiration_is_not_misreported_as_trust_or_client_requirement(
    request_context, monkeypatch, scene
):
    calls = 0

    async def exchange(context):
        nonlocal calls
        calls += 1
        if scene == "timeout":
            await asyncio.sleep(1)
        if calls in {1, 4}:
            return request_context["identity"], request_context["server_leaf_sha256"]
        if calls == 2:
            if scene == "no_certificate_any_error":
                raise ConnectionRefusedError("private-sensitive-sentinel")
            error = ssl.SSLError("private-sensitive-sentinel")
            error.reason = (
                "UNEXPECTED_EOF_WHILE_READING"
                if scene == "other_ssl_alert"
                else "TLSV13_ALERT_CERTIFICATE_REQUIRED"
            )
            raise error
        error = ssl.SSLCertVerificationError("private-sensitive-sentinel")
        error.verify_code = 10
        raise error

    monkeypatch.setattr(probe, "_exchange", exchange)
    monkeypatch.setattr(probe, "DEADLINE_SECONDS", 0.02)
    with pytest.raises((probe.ProbeError, ConnectionRefusedError)):
        asyncio.run(probe.check(request_context))


@pytest.mark.parametrize(
    "scene",
    [
        "url",
        "tests",
        "unknown_identity_field",
        "integer_limit",
        "same_ca",
        "hash",
        "duplicate",
        "oversize",
    ],
)
def test_context_is_closed_hashed_and_never_accepts_arbitrary_endpoint_or_executable_test(
    request_context, scene
):
    value = copy.deepcopy(request_context)
    if scene == "url":
        value["url"] = "https://external.invalid/"
    elif scene == "tests":
        value["identity"]["tests"] = ["linux-file-marker/v1"]
    elif scene == "unknown_identity_field":
        value["identity"]["command"] = "unreviewed"
    elif scene == "integer_limit":
        value["identity"]["max_concurrency"] = True
    elif scene == "same_ca":
        value["certificate_sha256"]["previous_server_ca"] = value["certificate_sha256"][
            "candidate_server_ca"
        ]
    payload = json.dumps(value).encode()
    expected = probe.digest(value)
    if scene == "hash":
        expected = "f" * 64
    elif scene == "duplicate":
        payload = payload[:-1] + b',"format":"duplicate"}'
    elif scene == "oversize":
        payload += b" " * probe.MAX_INPUT
    with pytest.raises(probe.ProbeError, match="context_invalid"):
        probe.decode(payload, expected)


def test_valid_context_and_accidental_host_invocation_are_separate_guards(request_context):
    payload = json.dumps(request_context).encode()
    expected = probe.digest(request_context)
    assert probe.decode(payload, expected) == request_context
    result = subprocess.run(
        [sys.executable, "-m", "aegis.lab_runner.identity_probe", "--context-sha256", expected],
        input=payload,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 1 and result.stderr == b""
    reply = json.loads(result.stdout)
    assert reply["status"] == "rejected" and reply["code"] == "process_required"
    assert all(reply[key] is False for key in probe.FLAGS)
