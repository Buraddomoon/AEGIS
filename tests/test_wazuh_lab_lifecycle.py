import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def lifecycle(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    module = importlib.import_module("wazuh_lab")
    monkeypatch.setattr(module, "PRIVATE", tmp_path)
    return module


def test_missing_confirmation_never_calls_docker(lifecycle, monkeypatch):
    calls = []
    monkeypatch.setattr(lifecycle, "execute", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(sys, "argv", ["wazuh_lab.py", "up"])
    with pytest.raises(SystemExit) as error:
        lifecycle.main()
    assert error.value.code == 2 and not calls


def test_insufficient_resources_never_start_or_download(lifecycle, monkeypatch):
    calls = []
    monkeypatch.setattr(lifecycle, "execute", lambda *args, **kwargs: calls.append(args))
    # Exercise the real gate with a known low-resource snapshot.
    from wazuh_host_preflight import Resources

    monkeypatch.setattr(lifecycle, "inspect", lambda: Resources(4, 1, 1, 1))
    monkeypatch.setattr(lifecycle.platform, "machine", lambda: "x86_64")
    for action in ("pull", "hash-users", "build", "up"):
        monkeypatch.setattr(sys, "argv", ["wazuh_lab.py", action, "--confirm-local-wazuh"])
        with pytest.raises(ValueError, match="Preflight recusou"):
            lifecycle.main()
    assert not calls


def test_shutdown_bypasses_resource_gate_and_preserves_volumes(lifecycle, monkeypatch):
    calls = []
    monkeypatch.setattr(lifecycle, "execute", lambda command, **kwargs: calls.append(command))
    monkeypatch.setattr(
        lifecycle, "resource_gate", lambda: pytest.fail("Cleanup must not depend on RAM")
    )
    monkeypatch.setattr(sys, "argv", ["wazuh_lab.py", "down", "--confirm-local-wazuh"])
    lifecycle.main()
    assert calls == [[*lifecycle.COMPOSE, "down"]]
    assert "-v" not in calls[0] and "prune" not in calls[0]


def test_official_hash_tool_receives_secrets_only_on_stdin(lifecycle, monkeypatch):
    credentials = {
        key: "test-fixture-secret-" + key for key in ("admin", "aegis_reader", "aegis_ingest")
    }
    (lifecycle.PRIVATE / "indexer-passwords.json").write_text(json.dumps(credentials))
    calls = []

    def hash_tool(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "$2y$12$" + "A" * 53 + "\n", "")

    monkeypatch.setattr(lifecycle, "execute", hash_tool)
    lifecycle.hash_users()
    assert len(calls) == 3
    for command, kwargs in calls:
        assert not any(secret in " ".join(command) for secret in credentials.values())
        assert kwargs["input"].strip() in credentials.values()
        assert command[command.index("--network") + 1] == "none"
        assert "--read-only" in command
    users = yaml.safe_load((lifecycle.PRIVATE / "internal_users.yml").read_text())
    assert set(users) == {"_meta", "admin", "aegis_reader", "aegis_ingest"}
    with pytest.raises(ValueError, match="já existem"):
        lifecycle.hash_users()
    assert len(calls) == 3


def test_shell_environment_cannot_override_private_destination(lifecycle, monkeypatch):
    (lifecycle.PRIVATE / "lab.env").write_text(
        "WAZUH_URL=https://private.example\nPOSTGRES_PASSWORD=fixture\n"
    )
    monkeypatch.setenv("WAZUH_URL", "https://unrelated.example")
    monkeypatch.setenv("POSTGRES_PASSWORD", "unrelated")
    monkeypatch.setenv("COMPOSE_PROFILES", "manual")
    monkeypatch.setenv("DOCKER_CONTEXT", "unrelated-remote")
    received = {}
    monkeypatch.setattr(
        lifecycle.subprocess, "run", lambda command, **kwargs: received.update(kwargs)
    )
    lifecycle.execute([*lifecycle.COMPOSE, "config", "--quiet"])
    assert not set(received["env"]).intersection(
        {"WAZUH_URL", "POSTGRES_PASSWORD", "COMPOSE_PROFILES", "DOCKER_CONTEXT"}
    )


def test_subnet_collision_fails_before_any_creation(lifecycle, monkeypatch):
    responses = iter(
        [
            "other-network",
            json.dumps(
                [
                    {
                        "Labels": {"com.docker.compose.project": "other-project"},
                        "IPAM": {"Config": [{"Subnet": "172.30.89.0/24"}]},
                    }
                ]
            ),
        ]
    )
    calls = []

    def docker_read(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, next(responses), "")

    monkeypatch.setattr(lifecycle, "execute", docker_read)
    with pytest.raises(ValueError, match="conflita"):
        lifecycle.network_gate()
    assert len(calls) == 2
    assert not any("create" in command or "up" in command for command in calls)
