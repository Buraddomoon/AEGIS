"""Compile the fixed identity-only runner profile; no lifecycle or secret reads."""

import copy
from pathlib import Path

import runner_activation as plan
import runner_activation_isolated_network as network
import runner_activation_probe_runtime as probe
from aegis.lab_runner.protocol import RunnerIdentity
from runner_activation_intents import resource
from runner_activation_metadata import ActivationError, image_id
from runner_activation_ownership import identifier

IP = "172.30.88.2"
TMPFS = "rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=10001,gid=10001"
SECRETS = {
    "/run/secrets/runner_server_key": "runner-server.key",
    "/run/secrets/runner_server_cert": "runner-server.crt",
    "/run/secrets/runner_client_ca": "client-ca.crt",
}


def recipe(store, path, plan_sha256):
    artifact = plan.load_plan(path, plan_sha256)
    state = store.review()
    parent = state["resources"].get(network.ROLE)
    if (
        state["closed"]
        or state["header"]
        != {
            "plan_id": artifact["id"],
            "plan_sha256": plan_sha256,
            "scope_sha256": artifact["scope_sha256"],
        }
        or parent is None
        or parent["state"] != "OBSERVED"
        or parent["resource_id"] is None
    ):
        raise ActivationError("identity_runtime_pinned_plan_and_owned_network_required")
    known_network = identifier(parent["resource_id"])
    image = image_id(artifact["metadata"]["images"]["runner"]["id"])
    candidate = plan.pki.absolute(Path(artifact["candidate_path"]))
    # Compile only. Cryptographic validity, permissions and the current contents
    # must still be reviewed by the coordinator immediately before each effect.
    mounts = {target: str(candidate / name) for target, name in SECRETS.items()}
    if any(any(char in value for char in (",", "\r", "\n", "\0")) for value in mounts.values()):
        raise ActivationError("identity_runtime_mount_path_invalid")
    if any(artifact["expected_mount_sources"]["runner"].get(k) != v for k, v in mounts.items()):
        raise ActivationError("identity_runtime_secret_sources_mismatch")
    identity = RunnerIdentity.model_validate(artifact["pki"]["identities"])
    environment = {
        "LANG": "C.UTF-8",
        "TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "AEGIS_RUNNER_IDENTITY_ONLY": "true",
        **{"AEGIS_RUNNER_" + name.upper(): str(getattr(identity, name)) for name in plan.pki.IDS},
    }
    host = {
        **probe.HOST_EXACT,
        **dict.fromkeys(probe.HOST_EMPTY, True),
        "NetworkMode": known_network,
        "Tmpfs": {"/tmp": TMPFS},
    }
    if store.review() != state:
        raise ActivationError("identity_runtime_operation_changed")
    return {
        "format": "aegis-runner-identity-recipe/1",
        **resource(store.summary()["id"], plan_sha256, "runner"),
        "image": image,
        "identity": identity.model_copy(update={"tests": ()}).model_dump(mode="json"),
        "network_resource_id": known_network,
        "ipv4_address": IP,
        "entrypoint": [probe.ENTRYPOINT],
        "arguments": ["-I", "-B", "-m", "aegis.lab_runner.server"],
        "user": "10001:10001",
        "working_directory": "/app",
        "stdin_open": False,
        "mount_sources": mounts,
        "environment": environment,
        "host": copy.deepcopy(host),
    }


def create_arguments(store, path, plan_sha256):
    """Compiler only; no create/start RPC, approval or implicit volume creation."""
    state = store.review()
    spec = recipe(store, path, plan_sha256)
    if state["resources"].get("runner") != {"state": "REQUESTED", "resource_id": None}:
        raise ActivationError("identity_runtime_new_runner_intent_required")
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
        probe.ENTRYPOINT,
        "--read-only",
        "--network",
        spec["network_resource_id"],
        "--ip",
        IP,
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "192m",
        "--memory-swap",
        "192m",
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
        "--stop-signal",
        "SIGTERM",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--tmpfs",
        "/tmp:" + TMPFS,
    ]
    for target, source in sorted(spec["mount_sources"].items()):
        args.extend(
            (
                "--mount",
                "type=bind,source="
                + source
                + ",target="
                + target
                + ",readonly,bind-propagation=rprivate",
            )
        )
    for key, value in sorted(spec["environment"].items()):
        args.extend(("--env", key + "=" + value))
    for key, value in sorted(spec["labels"].items()):
        args.extend(("--label", key + "=" + value))
    if store.review() != state:
        raise ActivationError("identity_runtime_operation_changed")
    return (*args, spec["image"], *spec["arguments"])
