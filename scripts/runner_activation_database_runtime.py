"""Closed PostgreSQL-reader runtime; compilation/inspection only, no lifecycle."""

import copy
import subprocess

import runner_activation_probe_runtime as journal
from aegis.domain.validation import digest
from runner_activation_intents import DATABASE_REVIEW_ROLES, _hash, resource
from runner_activation_metadata import ActivationError, _execute, document, image_id
from runner_activation_ownership import identifier, observe

TMPFS = "rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=10001,gid=10001"
MEMORY = 256 * 1024**2
IMAGE_FORMAT = (
    journal.IMAGE_FORMAT[:-1] + ',"exposed_ports":{{json (index .Config "ExposedPorts")}}}'
)
CONTAINER_FORMAT = (
    journal.CONTAINER_FORMAT[:-1]
    + ',"init":{{json (index .HostConfig "Init")}},'
    + '"exposed_ports":{{json (index .Config "ExposedPorts")}}}'
)


def _context(store, role):
    state = store.review()
    database = state["resources"].get("db")
    if role not in DATABASE_REVIEW_ROLES:
        raise ActivationError("database_reader_role_required")
    if (
        state["closed"]
        or database is None
        or database["state"] != "OBSERVED"
        or database["resource_id"] is None
    ):
        raise ActivationError("database_reader_observed_database_required")
    return state, store.summary()["id"], identifier(database["resource_id"])


def recipe(store, role, image, context_sha256):
    state, operation, database = _context(store, role)
    image_id(image)
    _hash(context_sha256)
    expected = resource(operation, state["header"]["plan_sha256"], role)
    host = {
        **journal.HOST_EXACT,
        **dict.fromkeys(journal.HOST_EMPTY, True),
        "NetworkMode": "container:" + database,
        "Memory": MEMORY,
        "MemorySwap": MEMORY,
        "Tmpfs": {"/tmp": TMPFS},
    }
    return {
        "format": "aegis-database-reader-recipe/1",
        **expected,
        "database_resource_id": database,
        "image": image,
        "entrypoint": [journal.ENTRYPOINT],
        "arguments": [
            "-I",
            "-B",
            "-m",
            "aegis.lab_runner.persisted_probe",
            "--context-sha256",
            context_sha256,
        ],
        "user": "10001:10001",
        "working_directory": "/app",
        "host": copy.deepcopy(host),
    }


def create_arguments(store, role, image, context_sha256):
    spec = recipe(store, role, image, context_sha256)
    args = [
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        spec["name"],
        "--user",
        "10001:10001",
        "--workdir",
        "/app",
        "--entrypoint",
        journal.ENTRYPOINT,
        "--interactive",
        "--read-only",
        "--network",
        spec["host"]["NetworkMode"],
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--cpus",
        "0.5",
        "--pids-limit",
        "16",
        "--shm-size",
        "1m",
        "--restart",
        "no",
        "--stop-timeout",
        "5",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--tmpfs",
        "/tmp:" + TMPFS,
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "LANG=C.UTF-8",
    ]
    for key, value in sorted(spec["labels"].items()):
        args.extend(("--label", key + "=" + value))
    return (*args, image, *spec["arguments"])


def command(kind, store, role, image, context_sha256, known_id=None):
    recipe(store, role, image, context_sha256)
    if kind == "image" and known_id is None:
        return ("image", "inspect", "--format", IMAGE_FORMAT, image)
    if kind == "container" and known_id is not None:
        current = store.review()["resources"].get(role)
        if current is not None and current["resource_id"] == identifier(known_id):
            return ("container", "inspect", "--format", CONTAINER_FORMAT, known_id)
    # Recipe context comes exclusively from the locked operation, never a free DB ID.
    raise ActivationError("database_reader_query_not_allowed")


class DatabaseRuntimeDocker:
    def query(self, kind, store, role, image, context_sha256, known_id=None):
        try:
            return _execute(command(kind, store, role, image, context_sha256, known_id))
        except ActivationError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ActivationError("database_reader_query_failed") from None


def review_image(store, role, image, context_sha256, *, docker=None):
    spec = recipe(store, role, image, context_sha256)
    docker = docker or DatabaseRuntimeDocker()
    item = document(docker.query("image", store, role, image, context_sha256))
    if (
        not isinstance(item, dict)
        or set(item) != {"id", "user", "volumes", "environment", "exposed_ports"}
        or item["id"] != spec["image"]
        or item["user"] != "10001:10001"
        or item["volumes"] not in (None, {})
        or item["exposed_ports"] not in (None, {})
    ):
        raise ActivationError("database_reader_image_mismatch")
    journal._validate_environment(item["environment"], image=True)
    return {
        "image": image,
        "anonymous_volumes_excluded": True,
        "exposed_ports_excluded": True,
        "image_provenance_verified": False,
    }


def validate(spec, item, known_id, phase):
    journal._validate_process(
        spec, item, known_id, phase, additional_fields=("init", "exposed_ports")
    )
    journal._validate_host(item, spec["host"])
    if item["init"] is not None and item["init"] is not False:
        raise ActivationError("database_reader_init_mismatch")
    if item["exposed_ports"] not in (None, {}):
        raise ActivationError("database_reader_network_mismatch")
    optional_tmpfs = {
        "type": "tmpfs",
        "name": None,
        "target": "/tmp",
        "writable": True,
        "propagation": "",
    }
    if digest(item["mounts"]) not in {digest([]), digest([optional_tmpfs])} or item[
        "configured_mounts"
    ] not in (None, []):
        raise ActivationError("database_reader_mount_mismatch")
    if item["network_names"] != [None] or item["ports"] not in (None, {}):
        raise ActivationError("database_reader_network_mismatch")


def review(
    store, role, image, context_sha256, known_id, phase, *, docker=None, ownership_docker=None
):
    original = store.review()
    spec = recipe(store, role, image, context_sha256)
    operation, plan = store.summary()["id"], original["header"]["plan_sha256"]
    current = original["resources"].get(role)
    if (
        current is None
        or current["resource_id"] != identifier(known_id)
        or current["state"] not in {"OBSERVED", "START_REQUESTED"}
        or (phase == "exited" and current["state"] != "START_REQUESTED")
    ):
        raise ActivationError("database_reader_owned_resource_required")
    docker = docker or DatabaseRuntimeDocker()
    before = observe(operation, plan, role, known_id, docker=ownership_docker)
    database_before = observe(
        operation, plan, "db", spec["database_resource_id"], docker=ownership_docker
    )
    if (
        database_before["status"] != "present_owned_snapshot"
        or database_before["details"]["running"] is not True
    ):
        raise ActivationError("database_reader_database_not_running")
    item = document(docker.query("container", store, role, image, context_sha256, known_id))
    validate(spec, item, known_id, phase)
    database_after = observe(
        operation, plan, "db", spec["database_resource_id"], docker=ownership_docker
    )
    after = observe(operation, plan, role, known_id, docker=ownership_docker)
    if (
        before != after
        or before["status"] != "present_owned_snapshot"
        or before["details"]["image"] != image
        or before["details"]["running"] is not False
        or database_before != database_after
        or digest(store.review()) != digest(original)
    ):
        raise ActivationError("database_reader_ownership_changed")
    return {
        "format": "aegis-database-reader-runtime-review/1",
        "recipe_sha256": digest(spec),
        "resource_id": known_id,
        "database_resource_id": spec["database_resource_id"],
        "role": role,
        "phase": phase,
        "runtime_configuration_verified": True,
        "persistent_mounts_absent_verified": True,
        "owned_database_namespace_verified": True,
        "database_volume_binding_verified": False,
        "database_isolation_verified": False,
        "database_profile_verified": False,
        "image_provenance_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
