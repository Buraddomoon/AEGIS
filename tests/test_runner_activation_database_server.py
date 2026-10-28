"""Fixed server command compiler and local HBA only; no Docker or PostgreSQL IO."""

import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_database_server as server  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402

IMAGE = "sha256:" + "c" * 64


@pytest.fixture
def prepared(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        root = tmp_path / "runtime"
        server.policy.prepare(store, root=root)
        yield store, root


def test_recipe_pins_original_volume_loopback_and_direct_nonroot_binary_without_initialization(
    prepared,
):
    store, root = prepared
    spec = server.recipe(store, IMAGE, policy_root=root)
    assert spec["user"] == "70:70" and spec["host"]["NetworkMode"] == "none"
    assert spec["host"]["ReadonlyRootfs"] and spec["host"]["Memory"] == 384 * 1024**2
    assert spec["volume"] == "aegis-linux-lab_postgres-data"
    assert spec["entrypoint"] == ["/usr/local/bin/postgres"]
    assert spec["arguments"][:2] == ["-D", "/var/lib/postgresql/data"]
    settings = [
        spec["arguments"][index + 1]
        for index, value in enumerate(spec["arguments"])
        if value == "-c"
    ]
    assert "listen_addresses=127.0.0.1" in settings
    assert "hba_file=" + server.HBA in settings
    assert "data_directory=" + server.DATA in settings
    assert "default_transaction_read_only=on" in settings
    assert not any(
        value.startswith(("ssl=", "autovacuum=", "shared_preload_libraries=", "logging_collector="))
        for value in settings
    )
    spec["host"]["CapDrop"].append("mutated")
    assert server.recipe(store, IMAGE, policy_root=root)["host"]["CapDrop"] == ["ALL"]


def test_create_compilation_requires_durable_ownership_and_has_only_two_exact_mounts(prepared):
    store, root = prepared
    with pytest.raises(server.ActivationError, match="create_intent_required"):
        server.create_arguments(store, IMAGE, policy_root=root)
    store.request("db")
    args = server.create_arguments(store, IMAGE, policy_root=root)
    mounts = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
    assert mounts == [
        "type=volume,source=aegis-linux-lab_postgres-data,target=/var/lib/postgresql/data,volume-nocopy",
        "type=bind,source="
        + str(root / store.summary()["id"] / server.policy.FILENAME)
        + ",target="
        + server.HBA
        + ",readonly,bind-propagation=rprivate",
    ]
    assert args[args.index("--pull") + 1] == "never"
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--entrypoint") + 1] == server.ENTRYPOINT
    assert args[args.index("--user") + 1] == "70:70"
    assert args[args.index("--memory") + 1] == args[args.index("--memory-swap") + 1] == "384m"
    assert not {
        "--interactive",
        "--init",
        "--publish",
        "--privileged",
        "--env-file",
        "--volume",
        "--rm",
        "exec",
        "sh",
        "initdb",
        "chown",
        "docker-entrypoint.sh",
    } & set(args)
    assert not any(
        "PASSWORD" in value or "docker.sock" in value or ".key" in value for value in args
    )
    assert args.count("--env") == 2 and args.count("--mount") == 2
    assert args[-len(server.recipe(store, IMAGE, policy_root=root)["arguments"]) - 1] == IMAGE
    store.append("observed", {"role": "db", "resource_id": "d" * 64})
    with pytest.raises(server.ActivationError, match="create_intent_required"):
        server.create_arguments(store, IMAGE, policy_root=root)


@pytest.mark.parametrize("image", ["latest", "postgres:17-alpine", "sha256:abc", "--privileged"])
def test_image_is_immutable_local_id_only(prepared, image):
    store, root = prepared
    with pytest.raises(server.ActivationError):
        server.recipe(store, image, policy_root=root)


def test_recipe_refuses_changed_hba_before_any_command_is_available(prepared):
    store, root = prepared
    path = root / store.summary()["id"] / server.policy.FILENAME
    path.chmod(0o600)
    path.write_text("host all all all trust\n")
    path.chmod(0o444)
    with pytest.raises(server.ActivationError):
        server.recipe(store, IMAGE, policy_root=root)


def test_mount_csv_cannot_reinterpret_an_artifact_path_as_options(prepared, tmp_path):
    store, _ = prepared
    root = tmp_path / "runtime,readonly=false"
    server.policy.prepare(store, root=root)
    with pytest.raises(server.ActivationError, match="mount_path_invalid"):
        server.recipe(store, IMAGE, policy_root=root)


def test_import_has_no_lifecycle_database_configuration_or_network_effect():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('effect forbidden')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.conf')):
        raise AssertionError('configuration forbidden')
sys.addaudithook(guard)
import runner_activation_database_server
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
