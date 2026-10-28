"""Compile only the fixed original-volume PostgreSQL server; no lifecycle or CLI."""

import copy

import runner_activation_database_policy as policy
import runner_activation_probe_runtime as probe
from runner_activation_intents import resource
from runner_activation_metadata import PROJECT, ActivationError, image_id

DATA = "/var/lib/postgresql/data"
VOLUME = PROJECT + "_postgres-data"
HBA = "/run/aegis/review-pg_hba.conf"
ENTRYPOINT = "/usr/local/bin/postgres"
TMPFS = "rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=70,gid=70"
MEMORY = 384 * 1024**2
SETTINGS = (
    ("data_directory", DATA),
    ("hba_file", HBA),
    ("listen_addresses", "127.0.0.1"),
    ("port", "5432"),
    ("unix_socket_directories", "/tmp"),
    ("default_transaction_read_only", "on"),
    ("statement_timeout", "15000"),
    ("idle_in_transaction_session_timeout", "15000"),
    ("shared_buffers", "32MB"),
    ("work_mem", "1MB"),
    ("maintenance_work_mem", "32MB"),
    ("max_connections", "8"),
    ("max_parallel_workers_per_gather", "0"),
)


def recipe(store, image, *, policy_root=policy.DEFAULT_ROOT):
    state = store.review()
    if state["closed"]:
        raise ActivationError("database_server_open_operation_required")
    image_id(image)
    authentication = policy.verify(store, root=policy_root)
    source = authentication["path"]
    # --mount has its own CSV grammar; never reinterpret a path as mount options.
    if any(char in source for char in (",", "\n", "\r", "\0")):
        raise ActivationError("database_server_policy_mount_path_invalid")
    expected = resource(store.summary()["id"], state["header"]["plan_sha256"], "db")
    host = {
        **probe.HOST_EXACT,
        **dict.fromkeys(probe.HOST_EMPTY, True),
        "Memory": MEMORY,
        "MemorySwap": MEMORY,
        "NanoCpus": 1_000_000_000,
        "PidsLimit": 64,
        "ShmSize": 64 * 1024**2,
        "Tmpfs": {"/tmp": TMPFS},
    }
    arguments = ["-D", DATA]
    for name, value in SETTINGS:
        arguments.extend(("-c", name + "=" + value))
    if store.review() != state:
        raise ActivationError("database_server_operation_changed")
    return {
        "format": "aegis-original-database-server-recipe/1",
        **expected,
        "image": image,
        "entrypoint": [ENTRYPOINT],
        "arguments": arguments,
        "user": "70:70",
        "working_directory": "/",
        "stdin_open": False,
        "policy_path": source,
        "policy_sha256": authentication["content_sha256"],
        "volume": VOLUME,
        "host": copy.deepcopy(host),
    }


def create_arguments(store, image, *, policy_root=policy.DEFAULT_ROOT):
    spec = recipe(store, image, policy_root=policy_root)
    current = store.review()["resources"].get("db")
    if current is None or current != {"state": "REQUESTED", "resource_id": None}:
        raise ActivationError("database_server_create_intent_required")
    args = [
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        spec["name"],
        "--user",
        "70:70",
        "--workdir",
        "/",
        "--entrypoint",
        ENTRYPOINT,
        "--read-only",
        "--network",
        "none",
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "384m",
        "--memory-swap",
        "384m",
        "--cpus",
        "1",
        "--pids-limit",
        "64",
        "--shm-size",
        "64m",
        "--restart",
        "no",
        "--stop-timeout",
        "5",
        "--stop-signal",
        "SIGTERM",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--tmpfs",
        "/tmp:" + TMPFS,
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "PGDATA=" + DATA,
        "--mount",
        "type=volume,source=" + VOLUME + ",target=" + DATA + ",volume-nocopy",
        "--mount",
        "type=bind,source="
        + spec["policy_path"]
        + ",target="
        + HBA
        + ",readonly,bind-propagation=rprivate",
    ]
    for key, value in sorted(spec["labels"].items()):
        args.extend(("--label", key + "=" + value))
    return (*args, image, *spec["arguments"])
