"""Fixed client compilation over temporary PKI/plan/intents; no native RPC or key read."""

import copy
import json
import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_identity_active_plan import setup

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_client_runtime as client  # noqa: E402

CONTEXT = "a" * 64


@pytest.fixture
def ready(context):
    return setup(context, "running")


def invoke(world):
    return client.create_arguments(world.store, world.path, world.sha, CONTEXT)


def test_recipe_mounts_only_candidate_client_and_previous_public_ca_on_fixed_ip(ready, monkeypatch):
    read = client.plan.pki.read

    def public_only(path, **kwargs):
        assert path.suffix != ".key" and path.name not in {".env", "ids.env"}
        return read(path, **kwargs)

    monkeypatch.setattr(client.plan.pki, "read", public_only)
    before = ready.store.summary()
    spec = client.recipe(ready.store, ready.path, ready.sha, CONTEXT)
    artifact = client.plan.load_plan(ready.path, ready.sha)
    assert spec["ipv4_address"] == "172.30.88.3"
    assert spec["network_resource_id"] == "c" * 64
    assert spec["image"] == artifact["metadata"]["images"]["runner"]["id"]
    assert spec["stdin_open"] is True and spec["user"] == "10001:10001"
    assert spec["mount_sources"] == {
        **{k: str(Path(artifact["candidate_path"]) / v) for k, v in client.SECRETS.items()},
        client.PREVIOUS_CA: str(Path(artifact["source_path"]) / "server-ca.crt"),
    }
    assert len(spec["mount_sources"]) == 4
    assert spec["arguments"] == [
        "-I",
        "-B",
        "-m",
        "aegis.lab_runner.identity_probe",
        "--context-sha256",
        CONTEXT,
    ]
    assert spec["host"]["ReadonlyRootfs"] and spec["host"]["CapDrop"] == ["ALL"]
    assert "AEGIS_RUNNER_IDENTITY_ONLY" not in spec["environment"]
    assert "journal" not in json.dumps(spec) and "server-ca.key" not in json.dumps(spec)
    assert ready.store.summary() == before


def test_compiler_requires_new_role_and_produces_fixed_pipe_without_tty_or_free_command(ready):
    with pytest.raises(client.ActivationError, match="new_intent_required"):
        invoke(ready)
    ready.store.request(client.ROLE)
    args = invoke(ready)
    assert args[:2] == ("container", "create")
    assert args[args.index("--ip") + 1] == "172.30.88.3"
    assert args[args.index("--network") + 1] == "c" * 64
    assert "--interactive" in args and args[args.index("--pull") + 1] == "never"
    assert not {"--tty", "--publish", "--volume", "--env-file", "--privileged", "--init"} & set(
        args
    )
    mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
    assert len(mounts) == 4 and all(
        v.endswith(",readonly,bind-propagation=rprivate") for v in mounts
    )
    assert args[-6:] == (
        "-I",
        "-B",
        "-m",
        "aegis.lab_runner.identity_probe",
        "--context-sha256",
        CONTEXT,
    )
    ready.store.append("observed", {"role": client.ROLE, "resource_id": "e" * 64})
    with pytest.raises(client.ActivationError, match="new_intent_required"):
        invoke(ready)


@pytest.mark.parametrize("value", [None, False, "x", "a" * 63, "https://example.invalid"])
def test_request_requires_only_an_explicit_hash_before_any_plan_read(ready, monkeypatch, value):
    monkeypatch.setattr(client.plan, "load_plan", lambda *a: pytest.fail("no IO"))
    with pytest.raises(client.ActivationError, match="hash_required"):
        client.recipe(ready.store, ready.path, ready.sha, value)


@pytest.mark.parametrize(
    "scene", ["source_comma", "source_newline", "source_nul", "candidate_secret"]
)
def test_mount_injection_or_wrong_candidate_source_is_rejected(ready, monkeypatch, scene):
    artifact = copy.deepcopy(client.plan.load_plan(ready.path, ready.sha))
    if scene == "candidate_secret":
        artifact["expected_mount_sources"]["api"]["/run/secrets/controller_client_key"] = (
            "/other/key"
        )
    else:
        artifact["source_path"] += {
            "source_comma": ",bind",
            "source_newline": "\n",
            "source_nul": "\0",
        }[scene]
    monkeypatch.setattr(client.plan, "load_plan", lambda *a: artifact)
    with pytest.raises((client.ActivationError, ValueError)):
        client.recipe(ready.store, ready.path, ready.sha, CONTEXT)


@pytest.mark.parametrize("field", ["recipe_sha256", "pki_manifest_sha256"])
def test_server_start_fence_must_match_actual_pinned_recipe_and_manifest(context, field):
    world = setup(context, "start")
    spec = client.server.recipe(world.store, world.path, world.sha)
    artifact = client.plan.load_plan(world.path, world.sha)
    data = {
        "role": "runner",
        "mode": "identity-only",
        "recipe_sha256": client.digest(spec),
        "gates_sha256": "1" * 64,
        "pki_manifest_sha256": artifact["pki"]["manifest_sha256"],
        "network_resource_id": spec["network_resource_id"],
    }
    data[field] = "f" * 64
    world.store.append("identity_start_requested", data)
    world.store.append(
        "identity_runtime_observed", {"role": "runner", "runtime_evidence_sha256": "9" * 64}
    )
    with pytest.raises(client.ActivationError, match="server_binding_mismatch"):
        client.recipe(world.store, world.path, world.sha, CONTEXT)


def test_operation_change_during_shared_compilation_blocks_publication(ready, monkeypatch):
    ready.store.request(client.ROLE)
    compile_args = client.server._create_arguments

    def changed(spec):
        args = compile_args(spec)
        ready.store.request("redis")
        return args

    monkeypatch.setattr(client.server, "_create_arguments", changed)
    with pytest.raises(client.ActivationError, match="operation_changed"):
        invoke(ready)


def test_expired_plan_cannot_compile_a_client(ready, monkeypatch):
    artifact = client.plan.load_plan(ready.path, ready.sha)
    expires = client.plan.datetime.fromisoformat(artifact["expires_at"])
    monkeypatch.setattr(client.plan.pki, "clock", lambda: expires)
    with pytest.raises(client.ActivationError, match="expired_or_invalid_time"):
        client.recipe(ready.store, ready.path, ready.sha, CONTEXT)
