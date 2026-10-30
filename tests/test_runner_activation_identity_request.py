"""Host public-PKI request through actual loopback mTLS; no native lab effects."""

import asyncio
import copy
import json
import socket
import ssl
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
import uvicorn
from aegis.lab_runner import identity_probe as probe
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.lab_runner.server import create_identity_app
from aegis.lab_runner.tls_peer import IdentityTLSProtocol
from test_runner_activation_image_source import git
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_request as builder  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def confirmed(material, code, tmp_path):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        yield ConfirmedPlan(
            Path(prepared["plan_path"]),
            prepared["plan_sha256"],
            store,
            prepared["scope_sha256"],
            (builder.plan.pki.clock() + timedelta(seconds=290)).isoformat(),
        )


def test_public_request_preserves_material_and_never_reads_private_keys_or_environment(
    confirmed, material, monkeypatch
):
    source, candidate, _ = material
    before = {
        str(path): (path.read_bytes(), path.stat().st_mtime_ns)
        for folder in (source, candidate)
        for path in folder.iterdir()
    }
    read = builder.plan.pki.read
    visited = []

    def restricted(path, **kwargs):
        assert path.suffix != ".key" and path.name not in {".env", "ids.env"}
        visited.append(path.name)
        return read(path, **kwargs)

    monkeypatch.setattr(builder.plan.pki, "read", restricted)
    raw, expected = builder.request(confirmed)
    value = probe.decode(raw, expected)
    assert value["operation_id"] == confirmed.operation
    assert value["scope_sha256"] == confirmed.scope
    assert value["plan_sha256"] == confirmed.plan_sha256
    assert value["expires_at"] == confirmed.expires.isoformat()
    assert value["identity"]["tests"] == []
    assert "rotation.json" in visited
    assert b"private-sensitive-sentinel" not in raw
    assert before == {
        str(path): (path.read_bytes(), path.stat().st_mtime_ns)
        for folder in (source, candidate)
        for path in folder.iterdir()
    }


def test_json_assertion_cannot_replace_live_confirmation():
    with pytest.raises(builder.ActivationError, match="confirmed_plan_required"):
        builder.request({"confirmed": True})


def test_expired_confirmation_blocks_before_public_pki_reads(confirmed, monkeypatch):
    monkeypatch.setattr(builder.plan.pki, "clock", lambda: confirmed.expires)
    monkeypatch.setattr(builder.plan.pki, "inventory", lambda *a, **kw: pytest.fail("no IO"))
    with pytest.raises(builder.ActivationError, match="scope_or_budget_unconfirmed"):
        builder.request(confirmed)


@pytest.mark.parametrize("during_io", [False, True])
def test_changed_clean_executor_commit_is_rejected(confirmed, code, monkeypatch, during_io):
    def change():
        (code / "changed.py").write_text("# fixture revision\n")
        git(code, "add", "changed.py")
        git(code, "commit", "-m", "fixture: change executor")

    if during_io:
        inventory = builder.plan.pki.inventory
        changed = []

        def inventory_changed(*args, **kwargs):
            result = inventory(*args, **kwargs)
            if not changed:
                changed.append(True)
                change()
            return result

        monkeypatch.setattr(builder.plan.pki, "inventory", inventory_changed)
    else:
        change()
    with pytest.raises(builder.ActivationError, match="executor_drift|inputs_changed"):
        builder.request(confirmed)


@pytest.mark.parametrize("scene", ["manifest", "source", "candidate", "second_snapshot"])
def test_public_input_drift_before_or_during_review_cannot_publish_request(
    confirmed, material, monkeypatch, scene
):
    source, candidate, _ = material
    inventory = builder.plan.pki.inventory
    document = builder.document
    calls = []

    def changed_inventory(path, **kwargs):
        result, validity = inventory(path, **kwargs)
        calls.append(path)
        if (
            (scene == "source" and path == source)
            or (scene == "candidate" and path == candidate)
            or (scene == "second_snapshot" and len(calls) > 2)
        ):
            result = copy.deepcopy(result)
            result["descriptor_sha256"] = "0" * 64
        return result, validity

    monkeypatch.setattr(builder.plan.pki, "inventory", changed_inventory)
    if scene == "manifest":

        def altered(raw):
            result = document(raw)
            result["source"]["descriptor_sha256"] = "0" * 64
            return result

        monkeypatch.setattr(builder, "document", altered)
    with pytest.raises(builder.ActivationError, match="public_pki_drift|inputs_changed"):
        builder.request(confirmed)


def test_original_window_expiring_during_public_review_blocks_request(confirmed, monkeypatch):
    inventory = builder.plan.pki.inventory

    def expired(*args, **kwargs):
        result = inventory(*args, **kwargs)
        monkeypatch.setattr(builder.plan.pki, "clock", lambda: confirmed.expires)
        return result

    monkeypatch.setattr(builder.plan.pki, "inventory", expired)
    with pytest.raises(builder.ActivationError, match="scope_or_budget_unconfirmed"):
        builder.request(confirmed)


def test_host_request_probe_and_decoder_use_actual_pinned_certificates_over_loopback(
    confirmed, material, monkeypatch
):
    raw, expected = builder.request(confirmed)
    context = probe.decode(raw, expected)
    source, candidate, _ = material
    monkeypatch.setattr(
        probe,
        "FILES",
        {
            "candidate_server_ca": candidate / "server-ca.crt",
            "candidate_client_cert": candidate / "runner-client.crt",
            "previous_server_ca": source / "server-ca.crt",
        },
    )
    monkeypatch.setattr(probe, "CLIENT_KEY", candidate / "runner-client.key")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    native_open = asyncio.open_connection
    connections = []

    async def routed(host, requested_port, **kwargs):
        # Test-only TCP route: preserve production TLS name/SAN and both DER pins.
        assert (host, requested_port) == ("172.30.88.2", 8443)
        assert kwargs["server_hostname"] == "172.30.88.2"
        connections.append((host, requested_port))
        return await native_open("127.0.0.1", port, **kwargs)

    monkeypatch.setattr(probe.asyncio, "open_connection", routed)
    server = uvicorn.Server(
        uvicorn.Config(
            create_identity_app(RunnerIdentity.model_validate(context["identity"])),
            log_level="critical",
            ssl_certfile=str(candidate / "runner-server.crt"),
            ssl_keyfile=str(candidate / "runner-server.key"),
            ssl_ca_certs=str(candidate / "client-ca.crt"),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            proxy_headers=False,
            http=IdentityTLSProtocol,
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.02)
        assert server.started
        result = asyncio.run(probe.check(context))
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        assert not thread.is_alive()
    assert len(connections) == 4
    assert result["candidate_client_certificate_verified"] is True
    assert result["server_client_certificate_policy_verified"] is True
    assert result["previous_ca_rejected"] is True
    assert result["context_sha256"] == expected
    assert all(result[key] is False for key in probe.FLAGS)
    assert probe.decode_result(json.dumps(result).encode(), context, expected) == result
