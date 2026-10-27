"""Closed probe recipe and adversarial runtime fixtures; no daemon or lab effects."""

import copy
import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_probe_runtime as runtime  # noqa: E402
from test_runner_activation_ownership import FakeDocker as OwnershipDocker  # noqa: E402

PLAN, PROOFS, OBJECT = "a" * 64, "d" * 64, "b" * 64
IMAGE = "sha256:" + "c" * 64


def projection(spec, phase="created"):
    return {
        "id": OBJECT,
        "name": "/" + spec["name"],
        "image": IMAGE,
        "image_reference": IMAGE,
        "user": "10001:10001",
        "entrypoint": ["/usr/local/bin/python"],
        "arguments": [
            "-I",
            "-B",
            "-m",
            "aegis.lab_runner.journal_probe",
            "--expected-sha256",
            PROOFS,
        ],
        "working_directory": "/app",
        "stdin_open": True,
        "tty": False,
        "healthcheck": ["NONE"],
        "stop_timeout": 5,
        "labels": dict(spec["labels"]),
        "label_count": 5,
        "host": copy.deepcopy(spec["host"]),
        "mounts": [
            {
                "type": "volume",
                "name": "aegis-linux-lab_journal",
                "target": "/state",
                "writable": False,
                "propagation": "",
            }
        ],
        "configured_mounts": [
            {
                "type": "volume",
                "source_name": "aegis-linux-lab_journal",
                "target": "/state",
                "readonly": True,
                "no_copy": True,
            }
        ],
        "network_names": ["none", None],
        "ports": {},
        "status": phase,
        "running": False,
        "restarting": False,
        "paused": False,
        "oom_killed": False,
        "exit_code": 0,
        "error_present": False,
        "environment": [{"key": key, "valid": True} for key in runtime.ENV_FIXED],
    }


class Docker:
    def __init__(self, spec, phase="created"):
        self.image = {
            "id": IMAGE,
            "user": "10001:10001",
            "volumes": None,
            "environment": [
                {"key": key, "valid": True} for key in runtime.ENV_FIXED if key != "TMPDIR"
            ],
        }
        self.item = projection(spec, phase)
        self.calls = []

    def query(self, kind, *args):
        self.calls.append(runtime.command(kind, *args))
        return json.dumps(self.image if kind == "image" else self.item).encode()


@pytest.mark.parametrize("role", ["journal-before", "journal-after"])
def test_fixed_recipe_excludes_server_shell_network_secrets_and_automatic_volume_copy(role):
    operation = uuid4().hex
    args = runtime.create_arguments(operation, PLAN, role, IMAGE, PROOFS)
    assert args[:2] == ("container", "create") and args[args.index("--pull") + 1] == "never"
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--entrypoint") + 1] == "/usr/local/bin/python"
    assert args[args.index("--user") + 1] == "10001:10001"
    assert args[args.index("--memory") + 1] == args[args.index("--memory-swap") + 1] == "192m"
    assert args[args.index("--mount") + 1] == (
        "type=volume,source=aegis-linux-lab_journal,target=/state,readonly,volume-nocopy"
    )
    assert args[-7:] == (
        IMAGE,
        "-I",
        "-B",
        "-m",
        "aegis.lab_runner.journal_probe",
        "--expected-sha256",
        PROOFS,
    )
    assert args[args.index("--log-driver") + 1] == "none"
    assert not any(
        flag in args
        for flag in (
            "--privileged",
            "--rm",
            "--publish",
            "--env-file",
            "exec",
            "--volume",
            "--force",
        )
    )
    assert args.count("--mount") == 1 and args.count("--env") == 2
    assert not any(".key" in value or "docker.sock" in value for value in args)
    spec = runtime.recipe(operation, PLAN, role, IMAGE, PROOFS)
    spec["host"]["CapDrop"].append("mutated")
    assert runtime.recipe(operation, PLAN, role, IMAGE, PROOFS)["host"]["CapDrop"] == ["ALL"]


@pytest.mark.parametrize(
    "role", ["runner", "worker", "db", "api", "controller", "migrate", "unknown"]
)
def test_non_probe_role_cannot_compile_or_query(role):
    with pytest.raises(runtime.ActivationError, match="probe_role_required"):
        runtime.create_arguments(uuid4().hex, PLAN, role, IMAGE, PROOFS)


@pytest.mark.parametrize(
    "field,value", [("image", "latest"), ("image", "--privileged"), ("proof", "f" * 63)]
)
def test_no_free_image_or_proof_argument(field, value):
    with pytest.raises(runtime.ActivationError):
        runtime.create_arguments(
            uuid4().hex,
            PLAN,
            "journal-before",
            value if field == "image" else IMAGE,
            value if field == "proof" else PROOFS,
        )


@pytest.mark.parametrize("phase", ["created", "exited"])
def test_runtime_review_checks_config_and_repeats_exact_ownership(phase):
    operation = uuid4().hex
    spec = runtime.recipe(operation, PLAN, "journal-before", IMAGE, PROOFS)
    docker, owned = Docker(spec, phase), OwnershipDocker(operation, "journal-before")
    result = runtime.review(
        operation,
        PLAN,
        "journal-before",
        IMAGE,
        PROOFS,
        OBJECT,
        phase,
        docker=docker,
        ownership_docker=owned,
    )
    assert result["journal_readonly_mount_verified"] and result["network_none_verified"]
    assert result["runtime_configuration_verified"]
    assert (
        result["effects_authorized"]
        is result["volume_contents_verified"]
        is result["normal_operation_permitted"]
        is False
    )
    assert len(owned.calls) == 14 and len(docker.calls) == 1
    assert "{{json .Config.Env}}" not in runtime.CONTAINER_FORMAT
    assert "$m.Source" not in runtime.EFFECTIVE_MOUNTS
    assert '{{if eq $m.Type "volume"}}{{json $m.Source}}' in runtime.CONFIGURED_MOUNTS


@pytest.mark.parametrize(
    "field,value",
    [
        ("user", "0:0"),
        ("entrypoint", ["sh"]),
        ("arguments", ["-m", "aegis.lab_runner.server"]),
        ("stdin_open", False),
        ("tty", True),
        ("healthcheck", ["CMD", "evil"]),
        ("stop_timeout", 60),
        ("image", "sha256:" + "e" * 64),
        ("image_reference", "latest"),
        ("labels", {}),
        ("label_count", 6),
        ("name", "/foreign"),
        ("id", "e" * 64),
        ("working_directory", "/state"),
        ("running", True),
        ("restarting", True),
        ("paused", True),
        ("oom_killed", True),
        ("exit_code", 1),
        ("exit_code", False),
        ("error_present", True),
        ("status", "running"),
        ("ports", {"1/tcp": [{}]}),
        ("network_names", ["bridge", None]),
        ("network_names", ["none", "bridge", None]),
    ],
)
def test_runtime_drift_blocks_without_echoing_projected_values(field, value):
    spec = runtime.recipe(uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS)
    item = projection(spec)
    item[field] = value
    with pytest.raises(runtime.ActivationError, match="journal_probe_"):
        runtime.validate(spec, item, OBJECT, "created")


@pytest.mark.parametrize(
    "field,value",
    [
        ("Privileged", True),
        ("ReadonlyRootfs", False),
        ("NetworkMode", "host"),
        ("IpcMode", "host"),
        ("PidMode", "host"),
        ("CgroupnsMode", "host"),
        ("UsernsMode", "host"),
        ("UTSMode", "host"),
        ("Memory", 0),
        ("MemorySwap", -1),
        ("NanoCpus", 0),
        ("PidsLimit", 0),
        ("ShmSize", 0),
        ("CapDrop", []),
        ("SecurityOpt", []),
        ("PublishAllPorts", True),
        ("AutoRemove", True),
        ("RestartPolicy", {"Name": "always"}),
        ("LogConfig", {"Type": "json-file", "Config": {}}),
        ("Tmpfs", {"/tmp": "rw"}),
        *[(field, False) for field in runtime.HOST_EMPTY],
    ],
)
def test_unsafe_host_namespace_devices_mounts_or_unbounded_resources_are_rejected(field, value):
    spec = runtime.recipe(uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS)
    item = projection(spec)
    item["host"][field] = value
    with pytest.raises(runtime.ActivationError, match="host_mismatch"):
        runtime.validate(spec, item, OBJECT, "created")


@pytest.mark.parametrize(
    "scene", ["writable", "bool_as_int", "foreign", "extra", "bind", "copy", "missing"]
)
def test_mount_guard_requires_original_readonly_nocopy_volume_and_no_extra_mounts(scene):
    spec = runtime.recipe(uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS)
    item = projection(spec)
    if scene in {"writable", "bool_as_int"}:
        item["mounts"][0]["writable"] = True if scene == "writable" else 0
    elif scene == "foreign":
        item["mounts"][0]["name"] = "aegis_journal"
    elif scene == "extra":
        item["mounts"].append(dict(item["mounts"][0]))
    elif scene == "bind":
        item["configured_mounts"][0]["type"] = "bind"
    elif scene == "copy":
        item["configured_mounts"][0]["no_copy"] = False
    else:
        item["mounts"] = []
    with pytest.raises(runtime.ActivationError, match="mount"):
        runtime.validate(spec, item, OBJECT, "created")


def test_created_can_have_no_endpoint_but_exited_requires_only_none_and_success():
    spec = runtime.recipe(uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS)
    item = projection(spec)
    item["network_names"] = [None]
    runtime.validate(spec, item, OBJECT, "created")
    item["status"] = "exited"
    with pytest.raises(runtime.ActivationError, match="network"):
        runtime.validate(spec, item, OBJECT, "exited")
    with pytest.raises(runtime.ActivationError, match="phase_invalid"):
        runtime.validate(spec, item, OBJECT, "running")


@pytest.mark.parametrize("scene", ["volume", "user", "id", "extra"])
def test_image_declared_volume_or_wrong_identity_blocks_before_create(scene):
    op = uuid4().hex
    docker = Docker(runtime.recipe(op, PLAN, "journal-before", IMAGE, PROOFS))
    if scene == "volume":
        docker.image["volumes"] = {"/hidden": {}}
    elif scene == "user":
        docker.image["user"] = "root"
    elif scene == "id":
        docker.image["id"] = "sha256:" + "e" * 64
    else:
        docker.image["extra"] = "private-sensitive-sentinel"
    with pytest.raises(runtime.ActivationError, match="image_mismatch") as error:
        runtime.review_image(op, PLAN, "journal-before", IMAGE, PROOFS, docker=docker)
    assert "private-sensitive-sentinel" not in str(error.value)
    assert len(docker.calls) == 1 and docker.calls[0][:2] == ("image", "inspect")


def test_image_metadata_gate_does_not_claim_provenance_and_runtime_refuses_ownership_drift():
    op = uuid4().hex
    spec = runtime.recipe(op, PLAN, "journal-before", IMAGE, PROOFS)
    docker, owned = Docker(spec), OwnershipDocker(op, "journal-before")
    result = runtime.review_image(op, PLAN, "journal-before", IMAGE, PROOFS, docker=docker)
    assert result["anonymous_volumes_excluded"] and not result["image_provenance_verified"]
    owned.details["image"] = "sha256:" + "f" * 64
    with pytest.raises(runtime.ActivationError, match="ownership_changed"):
        runtime.review(
            op,
            PLAN,
            "journal-before",
            IMAGE,
            PROOFS,
            OBJECT,
            "created",
            docker=docker,
            ownership_docker=owned,
        )


def test_query_errors_are_redacted_and_arbitrary_inspect_or_lifecycle_is_rejected(monkeypatch):
    for kind in ("start", "create", "stop", "rm", "volume"):
        with pytest.raises(runtime.ActivationError, match="query_not_allowed"):
            runtime.command(kind, uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS)

    def fail(*args):
        raise OSError("private-sensitive-sentinel")

    monkeypatch.setattr(runtime, "_execute", fail)
    with pytest.raises(runtime.ActivationError, match="query_failed") as error:
        runtime.ProbeRuntimeDocker().query(
            "image", uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS
        )
    assert "private-sensitive-sentinel" not in str(error.value)


def test_import_and_recipe_are_inert_in_fresh_process():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('No external effects permitted')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('No secrets permitted')
sys.addaudithook(guard)
import runner_activation_probe_runtime as r
r.create_arguments('0' * 32, 'a' * 64, 'journal-before', 'sha256:' + 'b' * 64, 'c' * 64)
assert 'aegis.config' not in sys.modules
assert 'aegis.lab_runner.engine' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "scene", ["loader", "audit", "path", "temp", "extra", "duplicate", "missing", "boolean"]
)
def test_environment_cannot_override_loader_paths_temp_or_add_hidden_variables(scene):
    spec = runtime.recipe(uuid4().hex, PLAN, "journal-before", IMAGE, PROOFS)
    item = projection(spec)
    values = item["environment"]
    if scene in {"loader", "audit", "extra"}:
        values.append(
            {
                "key": {"loader": "LD_PRELOAD", "audit": "LD_AUDIT", "extra": "PYTHONPATH"}[scene],
                "valid": True,
            }
        )
    elif scene == "duplicate":
        values.append(dict(values[0]))
    elif scene == "missing":
        values.pop()
    else:
        key = "PATH" if scene == "path" else "TMPDIR"
        next(value for value in values if value["key"] == key)["valid"] = (
            1 if scene == "boolean" else False
        )
    with pytest.raises(runtime.ActivationError, match="environment_mismatch"):
        runtime.validate(spec, item, OBJECT, "created")


def test_base_image_can_omit_lang_but_recipe_sets_it_and_runtime_requires_it():
    op = uuid4().hex
    spec = runtime.recipe(op, PLAN, "journal-before", IMAGE, PROOFS)
    docker = Docker(spec)
    docker.image["environment"] = [
        item for item in docker.image["environment"] if item["key"] != "LANG"
    ]
    assert runtime.review_image(op, PLAN, "journal-before", IMAGE, PROOFS, docker=docker)[
        "anonymous_volumes_excluded"
    ]
    args = runtime.create_arguments(op, PLAN, "journal-before", IMAGE, PROOFS)
    assert "LANG=C.UTF-8" in args and "TMPDIR=/tmp" in args
    item = projection(spec)
    item["environment"] = [value for value in item["environment"] if value["key"] != "LANG"]
    with pytest.raises(runtime.ActivationError, match="environment_mismatch"):
        runtime.validate(spec, item, OBJECT, "created")
    assert 'index .HostConfig "Mounts"' in runtime.CONFIGURED_MOUNTS
    assert "{{json .Config.Env}}" not in runtime.IMAGE_FORMAT
