"""Compile only the fixed GET identity client; no RPC, payload file or secret read."""

import copy
from pathlib import Path

import runner_activation as plan
import runner_activation_identity_runtime as server
from aegis.domain.validation import digest
from runner_activation_intents import IDENTITY_CLIENT_ROLE as ROLE
from runner_activation_intents import _hash, _identity_parents, resource
from runner_activation_metadata import ActivationError, image_id
from runner_activation_ownership import identifier

IP = "172.30.88.3"
SECRETS = {
    "/run/secrets/controller_server_ca": "server-ca.crt",
    "/run/secrets/controller_client_cert": "runner-client.crt",
    "/run/secrets/controller_client_key": "runner-client.key",
}
PREVIOUS_CA = "/run/secrets/identity_previous_server_ca"


def recipe(store, path, plan_sha256, context_sha256):
    _hash(context_sha256)
    artifact = plan.load_plan(path, plan_sha256)
    state = store.review()
    if state["closed"] or state["header"] != {
        "plan_id": artifact["id"],
        "plan_sha256": plan_sha256,
        "scope_sha256": artifact["scope_sha256"],
    }:
        raise ActivationError("identity_client_pinned_plan_required")
    parent, network = _identity_parents(state["resources"])
    runner_id, network_id = identifier(parent["resource_id"]), identifier(network["resource_id"])
    parent_spec = server.recipe(store, path, plan_sha256)
    if (
        parent["start"].get("recipe_sha256") != digest(parent_spec)
        or parent["start"].get("pki_manifest_sha256") != artifact["pki"]["manifest_sha256"]
    ):
        raise ActivationError("identity_client_server_binding_mismatch")
    candidate, source = (
        plan.pki.absolute(Path(artifact[key])) for key in ("candidate_path", "source_path")
    )
    mounts = {target: str(candidate / name) for target, name in SECRETS.items()}
    mounts[PREVIOUS_CA] = str(source / "server-ca.crt")
    if any(any(char in value for char in (",", "\r", "\n", "\0")) for value in mounts.values()):
        raise ActivationError("identity_client_mount_path_invalid")
    if any(
        artifact["expected_mount_sources"]["api"].get(target) != value
        for target, value in mounts.items()
        if target != PREVIOUS_CA
    ):
        raise ActivationError("identity_client_secret_sources_mismatch")
    if store.review() != state:
        raise ActivationError("identity_client_operation_changed")
    return {
        "format": "aegis-identity-client-recipe/1",
        **resource(store.summary()["id"], plan_sha256, ROLE),
        "image": image_id(artifact["metadata"]["images"]["runner"]["id"]),
        "runner_resource_id": runner_id,
        "server_recipe_sha256": digest(parent_spec),
        "network_resource_id": network_id,
        "network_name": parent_spec["network_name"],
        "ipv4_address": IP,
        "request_context_sha256": context_sha256,
        "entrypoint": [server.probe.ENTRYPOINT],
        "arguments": [
            "-I",
            "-B",
            "-m",
            "aegis.lab_runner.identity_probe",
            "--context-sha256",
            context_sha256,
        ],
        "user": "10001:10001",
        "working_directory": "/app",
        "stdin_open": True,
        "mount_sources": mounts,
        "environment": {
            "LANG": "C.UTF-8",
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        },
        "host": copy.deepcopy(
            {
                **server.probe.HOST_EXACT,
                **dict.fromkeys(server.probe.HOST_EMPTY, True),
                "NetworkMode": network_id,
                "Tmpfs": {"/tmp": server.TMPFS},
            }
        ),
    }


def create_arguments(store, path, plan_sha256, context_sha256):
    state = store.review()
    spec = recipe(store, path, plan_sha256, context_sha256)
    if state["resources"].get(ROLE) != {"state": "REQUESTED", "resource_id": None}:
        raise ActivationError("identity_client_new_intent_required")
    args = server._create_arguments(spec)
    if store.review() != state:
        raise ActivationError("identity_client_operation_changed")
    return args
