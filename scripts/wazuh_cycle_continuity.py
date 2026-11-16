"""Fixed Wazuh journal-probe recipe and runtime validation, without lifecycle.

Reuse the existing read-only journal decoder and process restrictions while
keeping the Linux project's closed recipe unchanged. Original-volume access
still requires its own native preparation authorization and durable intent.
"""

import copy

import runner_activation_probe_result as result
import runner_activation_probe_runtime as process
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError

PROJECT = "aegis-wazuh-lab"
VOLUME = PROJECT + "_journal"


def recipe(review_id, package_sha256, role, image, proof_sha256):
    # The shared constructor validates role, image, IDs/hashes, entrypoint and
    # every process limit. Only project ownership and the fixed volume differ.
    spec = process.recipe(review_id, package_sha256, role, image, proof_sha256)
    return {
        **spec,
        "format": "aegis-wazuh-journal-probe-recipe/1",
        "name": PROJECT + "-review-" + review_id + "-" + role,
        "labels": {**spec["labels"], "com.docker.compose.project": PROJECT},
        "volume": VOLUME,
    }


def create_arguments(review_id, package_sha256, role, image, proof_sha256):
    spec = recipe(review_id, package_sha256, role, image, proof_sha256)
    arguments = list(process.create_arguments(review_id, package_sha256, role, image, proof_sha256))
    arguments[arguments.index("--name") + 1] = spec["name"]
    arguments[arguments.index("--mount") + 1] = (
        "type=volume,source=" + VOLUME + ",target=/state,readonly,volume-nocopy"
    )
    for index, value in enumerate(arguments):
        if value == "com.docker.compose.project=aegis-linux-lab":
            arguments[index] = "com.docker.compose.project=" + PROJECT
    return tuple(arguments)


def validate(spec, item, known_id, phase):
    # Do not accept an arbitrary caller-selected recipe/volume/process profile.
    labels = spec["labels"]
    expected = recipe(
        labels["io.aegis.activation-id"],
        labels["io.aegis.activation-plan-sha256"],
        spec["role"],
        spec["image"],
        spec["arguments"][-1],
    )
    if spec != expected:
        raise ActivationError("wazuh_journal_recipe_changed")
    process._validate_process(spec, item, known_id, phase)
    process._validate_host(item, copy.deepcopy(spec["host"]))
    mount = {
        "type": "volume",
        "name": VOLUME,
        "target": "/state",
        "writable": False,
        "propagation": "",
    }
    scratch = {"type": "tmpfs", "name": None, "target": "/tmp", "writable": True, "propagation": ""}
    if digest(item["mounts"]) not in {
        digest([mount]),
        digest([mount, scratch]),
        digest([scratch, mount]),
    }:
        raise ActivationError("wazuh_journal_original_ro_mount_required")
    if item["configured_mounts"] != [
        {
            "type": "volume",
            "source_name": VOLUME,
            "target": "/state",
            "readonly": True,
            "no_copy": True,
        }
    ]:
        raise ActivationError("wazuh_journal_nocopy_required")
    if item["ports"] not in (None, {}) or item["network_names"] not in (
        ["none", None],
        [None] if phase == "created" else ["none", None],
    ):
        raise ActivationError("wazuh_journal_network_forbidden")


def decode(raw, bundle, proof_sha256, expected_identity, old_descriptor_sha256):
    if (
        bundle["identity"] != expected_identity.model_dump(mode="json")
        or bundle["old_descriptor_sha256"] != old_descriptor_sha256
    ):
        raise ActivationError("wazuh_journal_original_identity_required")
    return result.decode(raw, bundle, proof_sha256)


def compare(before, after, bundle, proof_sha256, expected_identity, old_descriptor_sha256):
    decode(before, bundle, proof_sha256, expected_identity, old_descriptor_sha256)
    decode(after, bundle, proof_sha256, expected_identity, old_descriptor_sha256)
    return result.compare(before, after, bundle, proof_sha256)
