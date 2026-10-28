"""Private durable journals + adversarial Docker fixtures, never a real lab."""

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_database_runtime as runtime  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402
from test_runner_activation_ownership import FakeDocker as Owner  # noqa: E402
from test_runner_activation_probe_runtime import projection as journal_projection  # noqa: E402

IMAGE, PLAN, CONTEXT, READER, DATABASE = (
    "sha256:" + "c" * 64,
    "a" * 64,
    "d" * 64,
    "b" * 64,
    "e" * 64,
)


@pytest.fixture
def store(tmp_path):
    with ActivationIntents(tmp_path / "intents") as value:
        value.begin(uuid4().hex, PLAN, "f" * 64)
        value.request("db")
        value.append("observed", {"role": "db", "resource_id": DATABASE})
        yield value


def own_reader(store, role="database-review-before", phase="created"):
    store.request(role)
    store.append("observed", {"role": role, "resource_id": READER})
    if phase == "exited":
        store.append(
            "database_review_start_requested",
            {
                "role": role,
                "recipe_sha256": "1" * 64,
                "gates_sha256": "2" * 64,
                "request_context_sha256": CONTEXT,
            },
        )


def projection(spec, phase="created"):
    item = journal_projection(spec, phase)
    item.update(
        arguments=spec["arguments"],
        mounts=[],
        configured_mounts=None,
        network_names=[None],
        init=None,
        exposed_ports=None,
    )
    return item


class Docker:
    def __init__(self, store, role="database-review-before", phase="created"):
        spec = runtime.recipe(store, role, IMAGE, CONTEXT)
        self.item = projection(spec, phase)
        self.image = {
            "id": IMAGE,
            "user": "10001:10001",
            "volumes": None,
            "exposed_ports": None,
            "environment": self.item["environment"],
        }
        self.calls, self.owners = [], {}
        for key, object_id in [(role, READER), ("db", DATABASE)]:
            obj = Owner(store.summary()["id"], key)
            obj.named = obj.labelled = obj.known = (object_id + "\n").encode()
            obj.details.update(id=object_id, running=key == "db")
            self.owners[key] = obj

    def query(self, kind, *args):
        if kind in {"image", "container"}:
            self.calls.append(runtime.command(kind, *args))
            return json.dumps(self.image if kind == "image" else self.item).encode()
        role = args[2]
        return self.owners[role].query(kind, *args)


def review(store, docker, role="database-review-before", phase="created"):
    return runtime.review(
        store, role, IMAGE, CONTEXT, READER, phase, docker=docker, ownership_docker=docker
    )


@pytest.mark.parametrize("role", ["database-review-before", "database-review-after"])
def test_fixed_recipe_uses_only_owned_database_namespace_and_no_mount_or_secret(store, role):
    args = runtime.create_arguments(store, role, IMAGE, CONTEXT)
    assert args[:2] == ("container", "create")
    assert args[args.index("--network") + 1] == "container:" + DATABASE
    assert args[args.index("--memory") + 1] == args[args.index("--memory-swap") + 1] == "256m"
    assert args[-7:] == (
        IMAGE,
        "-I",
        "-B",
        "-m",
        "aegis.lab_runner.persisted_probe",
        "--context-sha256",
        CONTEXT,
    )
    assert args[args.index("--tmpfs") + 1] == "/tmp:" + runtime.TMPFS
    assert args.count("--env") == 2
    assert not {
        "--mount",
        "--volume",
        "--publish",
        "--env-file",
        "--init",
        "--rm",
        "--privileged",
        "exec",
        "sh",
    } & set(args)
    assert not any("password" in value or "docker.sock" in value for value in args)
    first = runtime.recipe(store, role, IMAGE, CONTEXT)
    first["host"]["CapDrop"].append("mutated")
    assert runtime.recipe(store, role, IMAGE, CONTEXT)["host"]["CapDrop"] == ["ALL"]


@pytest.mark.parametrize("role", ["journal-before", "runner", "api", "worker", "db", "unknown"])
def test_other_roles_cannot_compile(store, role):
    with pytest.raises(runtime.ActivationError, match="reader_role_required"):
        runtime.create_arguments(store, role, IMAGE, CONTEXT)


@pytest.mark.parametrize(
    "image,context", [("latest", CONTEXT), (IMAGE, "x"), ("--privileged", CONTEXT)]
)
def test_no_unpinned_image_or_context(store, image, context):
    with pytest.raises(runtime.ActivationError):
        runtime.create_arguments(store, "database-review-before", image, context)


@pytest.mark.parametrize("phase", ["created", "exited"])
@pytest.mark.parametrize("role", ["database-review-before", "database-review-after"])
def test_review_checks_namespace_and_repeats_reader_and_database_ownership(store, phase, role):
    own_reader(store, role, phase)
    docker = Docker(store, role, phase)
    before = store.summary()
    receipt = review(store, docker, role, phase)
    assert (
        receipt["owned_database_namespace_verified"]
        and receipt["persistent_mounts_absent_verified"]
    )
    assert receipt["runtime_configuration_verified"]
    assert receipt["database_resource_id"] == DATABASE
    assert all(
        receipt[key] is False
        for key in (
            "database_volume_binding_verified",
            "database_isolation_verified",
            "database_profile_verified",
            "image_provenance_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    assert store.summary() == before
    assert len(docker.calls) == 1
    assert all(len(value.calls) == 14 for value in docker.owners.values())
    for template in (runtime.IMAGE_FORMAT, runtime.CONTAINER_FORMAT):
        assert "{{json .Config.Env}}" not in template
        assert "{{json .HostConfig}}" not in template
        assert "$m.Source" not in runtime.journal.EFFECTIVE_MOUNTS


@pytest.mark.parametrize(
    "field,value",
    [
        ("init", True),
        ("init", 0),
        ("exposed_ports", {"8080/tcp": {}}),
        ("mounts", [{"type": "bind", "target": "/host", "writable": True}]),
        ("configured_mounts", [{}]),
        ("network_names", ["none", None]),
        ("network_names", ["backend", None]),
        ("ports", {"5432/tcp": [{}]}),
        ("arguments", ["-m", "aegis.lab_runner.server"]),
        ("user", "0:0"),
        ("entrypoint", ["sh"]),
        ("tty", True),
        ("stdin_open", False),
        ("running", True),
        ("status", "running"),
        ("exit_code", False),
        ("oom_killed", True),
        ("error_present", True),
        ("label_count", 6),
        ("environment", [{"key": "PGHOST", "valid": False}]),
    ],
)
def test_unsafe_projection_refused_without_echo(store, field, value):
    own_reader(store)
    docker = Docker(store)
    docker.item[field] = value
    with pytest.raises(runtime.ActivationError) as caught:
        review(store, docker)
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkMode", "host"),
        ("NetworkMode", "container:" + "f" * 64),
        ("Memory", 0),
        ("MemorySwap", -1),
        ("NanoCpus", 0),
        ("PidsLimit", 0),
        ("ReadonlyRootfs", False),
        ("CapAdd", False),
        ("Binds", False),
        ("Privileged", True),
        ("CapDrop", []),
        ("Tmpfs", {}),
        ("SecurityOpt", []),
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("LogConfig", {"Type": "json-file"}),
    ],
)
def test_host_configuration_cannot_widen_profile(store, field, value):
    own_reader(store)
    docker = Docker(store)
    docker.item["host"][field] = value
    with pytest.raises(runtime.ActivationError):
        review(store, docker)


@pytest.mark.parametrize(
    "field,value",
    [
        ("volumes", {"/state": {}}),
        ("user", "0:0"),
        ("exposed_ports", {"8080/tcp": {}}),
        ("id", "sha256:" + "e" * 64),
        ("environment", [{"key": "LD_PRELOAD", "valid": False}]),
    ],
)
def test_reader_image_rejects_inherited_volume_port_or_environment(store, field, value):
    docker = Docker(store)
    docker.image[field] = value
    with pytest.raises(runtime.ActivationError):
        runtime.review_image(store, "database-review-before", IMAGE, CONTEXT, docker=docker)


def test_image_review_and_optional_tmpfs_projection(store):
    own_reader(store)
    docker = Docker(store)
    result = runtime.review_image(store, "database-review-before", IMAGE, CONTEXT, docker=docker)
    assert result["anonymous_volumes_excluded"] and result["exposed_ports_excluded"]
    assert result["image_provenance_verified"] is False
    docker.item["init"] = False
    docker.item["mounts"] = [
        {"type": "tmpfs", "name": None, "target": "/tmp", "writable": True, "propagation": ""}
    ]
    docker.item["configured_mounts"] = []
    assert review(store, docker)["persistent_mounts_absent_verified"]


@pytest.mark.parametrize(
    "scene", ["db_stopped", "db_renamed", "reader_image", "reader_renamed", "unknown_id"]
)
def test_uncertain_owner_blocks(store, scene):
    own_reader(store)
    docker = Docker(store)
    if scene == "db_stopped":
        docker.owners["db"].details["running"] = False
    elif scene == "db_renamed":
        docker.owners["db"].details["name"] = "/private-sentinel"
    elif scene == "reader_image":
        docker.owners["database-review-before"].details["image"] = "sha256:" + "f" * 64
    elif scene == "reader_renamed":
        docker.owners["database-review-before"].details["name"] = "/private-sentinel"
    else:
        store.append("removal_requested", {"role": "database-review-before"})
    with pytest.raises(runtime.ActivationError) as caught:
        review(store, docker)
    assert "private-sentinel" not in str(caught.value)


def test_database_drift_during_probe_query_blocks(store):
    own_reader(store)
    docker = Docker(store)
    original = docker.query

    def change(kind, *args):
        result = original(kind, *args)
        if kind == "container":
            docker.owners["db"].details["image"] = "sha256:" + "f" * 64
        return result

    docker.query = change
    with pytest.raises(runtime.ActivationError, match="ownership_changed"):
        review(store, docker)


def test_closed_query_catalog_rejects_lifecycle_and_foreign_ids(store):
    own_reader(store)
    for kind, known_id in [("start", None), ("exec", READER), ("container", "f" * 64)]:
        with pytest.raises(runtime.ActivationError, match="query_not_allowed"):
            runtime.command(kind, store, "database-review-before", IMAGE, CONTEXT, known_id)


def test_import_does_not_connect_or_start_anything():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys, subprocess, socket
sys.path.insert(0, 'scripts')
def denied(*a, **k): raise AssertionError('unexpected effect')
subprocess.Popen=denied
class DeniedSocket(socket.socket):
    def __new__(cls, *a, **k): return denied(*a, **k)
socket.socket=DeniedSocket
import runner_activation_database_runtime
assert 'aegis.settings' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
