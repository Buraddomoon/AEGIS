"""Compose real PKI/ownership/physical reviews with a sealed-build boundary fixture."""

import copy
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_identity_inspection import projection
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_identity_active_plan import setup

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_gates as gates  # noqa: E402
from runner_activation_confirmation import ConfirmedPlan  # noqa: E402


@pytest.fixture
def prepared(context, monkeypatch, request):
    phase = getattr(request, "param", "start")
    world = setup(context, phase)
    spec = gates.runtime.recipe(world.store, world.path, world.sha)
    config = projection(spec, "running" if phase == "running" else "created")
    image = {
        "id": spec["image"],
        "user": "10001:10001",
        "volumes": None,
        "environment": [{"key": key, "valid": True} for key in gates.inspection.probe.ENV_FIXED],
        "ports": None,
        "onbuild": None,
    }
    calls = []

    class Physical:
        def query(self, kind, selected, **kwargs):
            calls.append(kind)
            assert selected == spec["image"]
            return json.dumps(image if kind == "image" else config).encode()

    # Build verification itself has real sealed-source/receipt regressions in
    # test_runner_activation_identity_image; do not invoke a native build here.
    sealed = {
        "native_image_id": spec["image"],
        "tool_commit": gates.plan.tool_state(),
        "package_and_dependency_sources_current": True,
        "build_client_exit_verified": True,
    }
    monkeypatch.setattr(gates.image, "review", lambda *a, **kw: copy.deepcopy(sealed))
    c = ConfirmedPlan(
        world.path,
        world.sha,
        world.store,
        world.store.review()["header"]["scope_sha256"],
        (gates.plan.pki.clock() + timedelta(seconds=280)).isoformat(),
    )
    value = gates.IdentityGates(
        c,
        {"fixture": "sealed boundary only"},
        docker=world.meta,
        ownership_docker=world,
        runtime_docker=Physical(),
        network_docker=world,
    )
    return value, world, spec, config, image, sealed, calls


@pytest.mark.parametrize("prepared", ["create", "start", "running"], indirect=True)
def test_gate_reuses_original_confirmation_and_composes_independent_live_reviews(prepared):
    value, world, spec, _config, _image, _sealed, calls = prepared
    phase = world.phase
    original = world.store.summary()
    result = value.review(phase, spec)
    assert set(result["checks"]) == gates.CHECKS
    assert all(item is True for item in result["checks"].values())
    assert result["operation_id"] == value.confirmation.operation
    assert result["network_resource_id"] == spec["network_resource_id"]
    assert world.store.summary() == original
    assert calls == (["image"] if phase == "create" else ["image", "container"])
    assert len(value.evidence) == 1 and world.calls == 2
    assert value.evidence[0]["gate_sha256"] == gates.digest(result)
    assert b"private-sensitive-sentinel" not in json.dumps(value.evidence).encode()
    assert value.confirmation.artifact["profile"]["executor_implemented"] is False


@pytest.mark.parametrize(
    "scene",
    [
        "worker",
        "journal_consumer",
        "database_consumer",
        "foreign_endpoint",
        "writable_mount",
        "published_port",
        "missing_mode",
        "unreviewed_image",
        "old_source",
        "integer_receipt",
        "another_image",
        "recipe",
        "expired",
    ],
)
def test_combined_gate_refuses_independent_drift_instead_of_trusting_saved_checks(
    prepared, scene, monkeypatch
):
    value, world, spec, config, image, sealed, _calls = prepared
    if scene == "worker":
        world.meta.responses["containers", None] += ("f" * 64 + "\n").encode()
    elif scene.endswith("consumer"):
        name = "journal" if scene == "journal_consumer" else "postgres-data"
        world.meta.responses["consumers", name] = ("f" * 64 + "\n").encode()
    elif scene == "foreign_endpoint":
        from test_runner_activation_identity_network import member

        world.item["containers"] = {"f" * 64: member(spec)}
        world.owners["network-isolated"].details["member_count"] = 1
    elif scene == "writable_mount":
        config["mounts"][0]["writable"] = True
    elif scene == "published_port":
        config["ports"] = {"8443/tcp": [{"HostPort": "8443"}]}
    elif scene == "missing_mode":
        config["environment"] = [
            item for item in config["environment"] if item["key"] != "AEGIS_RUNNER_IDENTITY_ONLY"
        ]
    elif scene == "unreviewed_image":
        image["volumes"] = {"/state": {}}
    elif scene == "old_source":
        sealed["package_and_dependency_sources_current"] = False
    elif scene == "integer_receipt":
        sealed["build_client_exit_verified"] = 1
    elif scene == "another_image":
        sealed["native_image_id"] = "sha256:" + "f" * 64
    elif scene == "recipe":
        spec["arguments"] = ["-c", "unreviewed"]
    else:
        monkeypatch.setattr(gates.plan.pki, "clock", lambda: value.confirmation.expires)
    with pytest.raises(gates.ActivationError):
        value.review("start", spec)
    assert value.evidence == []


@pytest.mark.parametrize("scene", ["intent", "clock", "metadata"])
def test_change_during_review_does_not_publish_new_gate(prepared, monkeypatch, scene):
    value, world, spec, _config, _image, _sealed, _calls = prepared
    original = value.runtime_docker.query

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[0] == "container":
            if scene == "intent":
                world.store.request("redis")
            elif scene == "clock":
                later = gates.time.monotonic() + 21
                monkeypatch.setattr(gates.time, "monotonic", lambda: later)
            else:
                world.meta.responses["consumers", "postgres-data"] = ("f" * 64 + "\n").encode()
        return result

    monkeypatch.setattr(value.runtime_docker, "query", changed)
    with pytest.raises(gates.ActivationError):
        value.review("start", spec)
    assert value.evidence == []


def test_running_or_start_requested_runner_cannot_receive_another_start_gate(prepared, monkeypatch):
    value, world, spec, *_ = prepared
    world.store.append(
        "identity_start_requested",
        {
            "role": "runner",
            "mode": "identity-only",
            "recipe_sha256": gates.digest(spec),
            "gates_sha256": "1" * 64,
            "pki_manifest_sha256": value.confirmation.artifact["pki"]["manifest_sha256"],
            "network_resource_id": spec["network_resource_id"],
        },
    )
    monkeypatch.setattr(gates.active, "recheck", lambda *a, **kw: pytest.fail("no IO"))
    with pytest.raises(gates.ActivationError, match="no_replay_mismatch"):
        value.review("start", spec)


def test_saved_json_confirmation_is_not_accepted():
    with pytest.raises(gates.ActivationError, match="confirmed_plan_required"):
        gates.IdentityGates({"confirmed": True}, {})


@pytest.mark.parametrize("scene", ["bool", "extra", "phase", "scope", "stale"])
def test_consumer_rejects_tampered_gate_context_types_or_freshness(prepared, scene):
    value, world, spec, *_ = prepared
    result = value.review("start", spec)
    if scene == "bool":
        result["checks"]["plan_current"] = 1
    elif scene == "extra":
        result["checks"]["unchecked"] = True
    elif scene == "phase":
        result["phase"] = "running"
    elif scene == "scope":
        result["scope_sha256"] = "f" * 64
    else:
        result["checked_at"] = (gates.plan.pki.clock() - timedelta(seconds=11)).isoformat()
        result["expires_at"] = (gates.plan.pki.clock() + timedelta(seconds=1)).isoformat()
    with pytest.raises(gates.ActivationError):
        gates.validate(
            result,
            "start",
            spec,
            world.store.review(),
            value.confirmation.operation,
            value.confirmation.artifact["pki"]["manifest_sha256"],
        )
