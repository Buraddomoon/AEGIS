"""Verify existing sealed build inputs against pinned main; never build/pull/run an image."""

import copy

import runner_activation_image_source as source
import runner_diagnostic_plan as inputs
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError, image_id


def review(build_inputs, image, tool_commit, *, repo=source.ROOT):
    """Local host/daemon trust, not a publisher signature or runtime-mode proof.

    Image ID and tool commit are fixed by the activation plan. Build references
    identify supporting proofs, not a different image or executable input.
    """
    image_id(image)
    if not isinstance(build_inputs, dict) or set(build_inputs) != {
        "build_id",
        "build_plan_sha256",
        "build_receipt_sha256",
    }:
        raise ActivationError("identity_image_closed_build_inputs_required")
    build_inputs = copy.deepcopy(build_inputs)
    if source._state(repo) != tool_commit:
        raise ActivationError("identity_image_tool_commit_drift")
    folder = inputs.image_build.ROOT / inputs._identifier(build_inputs["build_id"])
    inputs._hash(build_inputs["build_plan_sha256"])
    inputs._hash(build_inputs["build_receipt_sha256"])
    inputs.image_build.verify(folder, build_inputs["build_plan_sha256"])
    # Require the reviewed receipt to exist BEFORE reconciliation. Do not let
    # an image-only review publish a new receipt to satisfy this prerequisite.
    receipt = inputs.image_build._json(folder / "receipt.json")
    if (
        not isinstance(receipt, dict)
        or digest(receipt) != build_inputs["build_receipt_sha256"]
        or receipt.get("native_image_id") != image
        or receipt.get("build_client_exit_verified") is not True
    ):
        raise ActivationError("identity_image_completed_build_receipt_required")
    verified = inputs._runner(build_inputs, {"runner": image})
    if (
        inputs._current_source(repo, verified) != tool_commit
        or source._state(repo) != tool_commit
        or inputs.image_build._json(folder / "receipt.json") != receipt
    ):
        raise ActivationError("identity_image_inputs_changed")
    return {
        "format": "aegis-identity-image-input-review/1",
        "native_image_id": image,
        "tool_commit": tool_commit,
        **build_inputs,
        "sealed_source_sha256": verified["source_sha256"],
        "package_files_reviewed": len(verified["expected_check"]["package_files"]),
        "package_and_dependency_sources_current": True,
        "build_client_exit_verified": True,
        "local_build_inputs_verified": True,
        "publisher_signature_verified": False,
        "identity_mode_runtime_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
