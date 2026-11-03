"""Computed client gates with actual temporary PKI and read-only fixture daemon projections."""

import copy
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import test_runner_activation_identity_client_network as network_fixture
from test_runner_activation_identity_client_inspection import projected
from test_runner_activation_identity_client_runtime import ready as ready
from test_runner_activation_identity_inspection import projection
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_identity_client_active_plan import setup

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_client_gates as gates  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402


@pytest.fixture
def prepared(ready, monkeypatch, request):
    phase = getattr(request, "param", "start")
    c = ConfirmedPlan(
        ready.path,
        ready.sha,
        ready.store,
        ready.store.review()["header"]["scope_sha256"],
        (gates.plan.pki.clock() + timedelta(seconds=260)).isoformat(),
    )
    payload, expected = gates.request.request(c)
    monkeypatch.setattr(network_fixture, "CONTEXT", expected)
    world = setup(ready, phase, attached=phase == "start")
    spec = gates.runtime.recipe(ready.store, ready.path, ready.sha, expected)
    parent_spec = gates.runtime.server.recipe(ready.store, ready.path, ready.sha)
    parent = projection(parent_spec, "running")
    client = projected(spec, "exited" if phase == "exited" else "created")
    image = {
        "id": spec["image"],
        "user": "10001:10001",
        "volumes": None,
        "ports": None,
        "onbuild": None,
        "environment": [{"key": key, "valid": True} for key in gates.parent.probe.ENV_FIXED],
    }
    calls = []

    class Physical:
        def query(self, kind, selected, **kwargs):
            assert selected == spec["image"]
            role = kwargs["spec"]["role"] if kind == "container" else "image"
            calls.append(role)
            return json.dumps(
                image if kind == "image" else parent if role == "runner" else client
            ).encode()

    # Real file/receipt/image binding is covered separately; no native image is
    # adopted or built by this composition fixture.
    sealed = {
        "native_image_id": spec["image"],
        "tool_commit": c.artifact["tool_commit"],
        "package_and_dependency_sources_current": True,
        "build_client_exit_verified": True,
    }
    monkeypatch.setattr(gates.image, "review", lambda *a, **kw: copy.deepcopy(sealed))
    value = gates.IdentityClientGates(
        c,
        {"fixture": "sealed boundary only"},
        payload,
        expected,
        docker=world.meta,
        ownership_docker=world,
        runtime_docker=Physical(),
        network_docker=world,
    )
    return value, world, spec, parent, client, sealed, calls


@pytest.mark.parametrize("prepared", ["create", "start", "exited"], indirect=True)
def test_client_gate_composes_independent_live_reviews_in_the_same_lease(prepared):
    value, world, spec, _parent, _client, _sealed, calls = prepared
    before = world.ready.store.summary()
    result = value.review(world.phase, spec)
    assert set(result["checks"]) == gates.CHECKS
    assert all(item is True for item in result["checks"].values())
    assert result["request_context_sha256"] == value.context_sha256
    assert result["operation_id"] == value.confirmation.operation
    assert result["runner_resource_id"] == spec["runner_resource_id"]
    assert before == world.ready.store.summary()
    assert calls == (
        ["image", "runner"] if world.phase == "create" else ["image", "runner", gates.runtime.ROLE]
    )
    assert world.calls == 2 and len(value.evidence) == 1
    assert value.evidence[0]["gate_sha256"] == gates.digest(result)
    assert value._last_gate == result and value._last_gate is not result
    assert value.context["expires_at"] == value.confirmation.expires.isoformat()
    assert value.confirmation.artifact["profile"]["executor_implemented"] is False


@pytest.mark.parametrize(
    "scene",
    [
        "worker",
        "volume",
        "parent_mode",
        "parent_argv",
        "client_key",
        "old_source",
        "recipe",
        "expired",
        "request",
        "cached_context",
    ],
)
def test_client_gate_cannot_replace_live_facts_with_cached_positive_claims(
    prepared, scene, monkeypatch
):
    value, world, spec, parent, client, sealed, _calls = prepared
    if scene == "worker":
        world.meta.responses["containers", None] += ("f" * 64 + "\n").encode()
    elif scene == "volume":
        world.meta.responses["consumers", "postgres-data"] = ("f" * 64 + "\n").encode()
    elif scene == "parent_mode":
        next(item for item in parent["environment"] if item["key"] == "AEGIS_RUNNER_IDENTITY_ONLY")[
            "valid"
        ] = False
    elif scene == "parent_argv":
        parent["arguments"] = ["-c", "unreviewed"]
    elif scene == "client_key":
        next(
            item
            for item in client["mounts"]
            if item["target"] == "/run/secrets/controller_client_key"
        )["writable"] = True
    elif scene == "old_source":
        sealed["package_and_dependency_sources_current"] = False
    elif scene == "recipe":
        spec["arguments"] = ["-c", "unreviewed"]
    elif scene == "expired":
        monkeypatch.setattr(gates.plan.pki, "clock", lambda: value.confirmation.expires)
    elif scene == "request":
        value._payload = b"{}"
    else:
        value.context["scope_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        value.review("start", spec)
    assert value.evidence == []


@pytest.mark.parametrize("prepared", ["exited"], indirect=True)
def test_start_requested_client_cannot_receive_another_start_gate(prepared):
    value, _world, spec, *_ = prepared
    with pytest.raises(gates.ActivationError, match="no_replay_mismatch"):
        value.review("start", spec)
    assert value.evidence == []


@pytest.mark.parametrize("scene", ["intent", "deadline", "pki"])
def test_change_during_physical_read_blocks_publishing_gate(prepared, monkeypatch, scene):
    value, world, spec, *_ = prepared
    query = value.runtime_docker.query

    def changed(*args, **kwargs):
        raw = query(*args, **kwargs)
        if kwargs.get("spec", {}).get("role") == gates.runtime.ROLE:
            if scene == "intent":
                world.ready.store.request("redis")
            elif scene == "pki":
                read = gates.plan.pki.read

                def altered(path, **options):
                    raw = read(path, **options)
                    if path.name == "rotation.json":
                        value = json.loads(raw)
                        value["format"] = "tampered"
                        return json.dumps(value).encode()
                    return raw

                monkeypatch.setattr(gates.plan.pki, "read", altered)
            else:
                later = gates.time.monotonic() + 21
                monkeypatch.setattr(gates.time, "monotonic", lambda: later)
        return raw

    monkeypatch.setattr(value.runtime_docker, "query", changed)
    with pytest.raises(ValueError):
        value.review("start", spec)
    assert value.evidence == []


@pytest.mark.parametrize("scene", ["resource", "context", "parent", "boolean", "stale"])
def test_consumer_rejects_rebound_gate_context_and_nonliteral_positive_values(prepared, scene):
    value, world, spec, *_ = prepared
    result = value.review("start", spec)
    if scene in {"resource", "context", "parent"}:
        field = {
            "resource": "resource_id",
            "context": "request_context_sha256",
            "parent": "runner_resource_id",
        }[scene]
        result[field] = "f" * 64
    elif scene == "boolean":
        result["checks"]["worker_stopped"] = 1
    else:
        result["checked_at"] = (gates.plan.pki.clock() - timedelta(seconds=11)).isoformat()
        result["expires_at"] = (gates.plan.pki.clock() + timedelta(seconds=1)).isoformat()
    c = value.confirmation
    with pytest.raises(gates.ActivationError):
        gates.validate(
            result,
            "start",
            spec,
            world.ready.store.review(),
            c.operation,
            c.artifact["pki"]["manifest_sha256"],
        )


def test_asserted_json_does_not_replace_a_shared_confirmed_plan():
    with pytest.raises(gates.ActivationError, match="confirmed_plan_required"):
        gates.IdentityClientGates({"confirmed": True}, {}, b"{}", "a" * 64)
