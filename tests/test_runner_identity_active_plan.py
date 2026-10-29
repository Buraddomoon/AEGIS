"""Explicit identity-only ownership contexts; no native runner or container startup."""

import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_network import World
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_metadata import FakeDocker, images

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_active_metadata as active  # noqa: E402
import runner_activation_active_plan as active_plan  # noqa: E402


def setup(context, phase):
    world = World(context, phase)
    world.meta = FakeDocker()
    world.expected = active.metadata.inventory(images(), docker=world.meta)
    world.meta.calls.clear()
    if phase == "running":
        world.store.append(
            "identity_runtime_observed", {"role": "runner", "runtime_evidence_sha256": "9" * 64}
        )
    world.meta.responses["containers", None] = world.owners["runner"].named
    world.meta.responses["networks", None] = world.owners["network-isolated"].named
    world.meta.responses["network_name", "isolated"] = world.owners["network-isolated"].named
    return world


def review(world, phase):
    return active.review(
        world.store,
        images(),
        world.expected,
        "runner",
        "identity-" + phase,
        docker=world.meta,
        ownership_docker=world,
    )


@pytest.mark.parametrize("phase", ["create", "start", "running"])
def test_explicit_identity_context_reviews_global_membership_without_operational_claims(
    context, phase
):
    world = setup(context, phase)
    before = world.store.summary()
    result = review(world, phase)
    assert result["identity_only_ownership_context_verified"]
    assert result["project_membership_verified"] and result["journal_consumer_set_verified"]
    assert result["inventory"] == world.expected
    assert result["network_isolation_verified"] is result["authorization_verified"] is False
    assert world.store.summary() == before


@pytest.mark.parametrize("phase", ["create", "start", "running"])
def test_pinned_active_plan_rechecks_same_pki_and_source_in_identity_context(context, phase):
    world = setup(context, phase)
    result = active_plan.recheck(
        world.path,
        world.sha,
        world.store,
        "runner",
        "identity-" + phase,
        docker=world.meta,
        ownership_docker=world,
    )
    assert result["owned_metadata"]["identity_only_ownership_context_verified"]
    assert result["status"] == "active_plan_revalidated_not_activated"
    assert result["activation_performed"] is result["authorization_granted"] is False


@pytest.mark.parametrize("field", ["recipe_sha256", "pki_manifest_sha256"])
def test_start_fence_must_bind_actual_recipe_and_candidate_before_metadata_io(context, field):
    world = setup(context, "start")
    from runner_activation_identity_runtime import recipe

    spec = recipe(world.store, world.path, world.sha)
    artifact = active_plan.activation.load_plan(world.path, world.sha)
    data = {
        "role": "runner",
        "mode": "identity-only",
        "recipe_sha256": active_plan.digest(spec),
        "gates_sha256": "1" * 64,
        "pki_manifest_sha256": artifact["pki"]["manifest_sha256"],
        "network_resource_id": spec["network_resource_id"],
    }
    data[field] = "f" * 64
    world.store.append("identity_start_requested", data)
    before = {file: file.read_bytes() for file in world.store.folder.glob("*.json")}
    with pytest.raises(active.ActivationError, match="identity_start_binding_mismatch"):
        active_plan.recheck(
            world.path,
            world.sha,
            world.store,
            "runner",
            "identity-start",
            docker=world.meta,
            ownership_docker=world,
        )
    assert world.meta.calls == []
    assert before == {file: file.read_bytes() for file in world.store.folder.glob("*.json")}


@pytest.mark.parametrize(
    "scene",
    [
        "foreign_worker",
        "journal_consumer",
        "database_consumer",
        "other_network",
        "other_role",
        "extra_member",
        "not_running",
        "missing_runtime_fence",
    ],
)
def test_identity_context_does_not_allow_other_resources_or_infer_readiness(context, scene):
    world = setup(context, "start" if scene == "missing_runtime_fence" else "running")
    if scene == "other_role":
        world.store.request("redis")
    elif scene == "extra_member":
        world.owners["network-isolated"].details["member_count"] = 2
    elif scene == "not_running":
        world.owners["runner"].details["running"] = False
    elif scene != "missing_runtime_fence":
        key = {
            "foreign_worker": ("containers", None),
            "journal_consumer": ("consumers", "journal"),
            "database_consumer": ("consumers", "postgres-data"),
            "other_network": ("network_name", "backend"),
        }[scene]
        world.meta.responses[key] += ("f" * 64 + "\n").encode()
    with pytest.raises(active.ActivationError):
        review(world, "running")


@pytest.mark.parametrize(
    "role,phase",
    [
        ("runner", "create"),
        ("runner", "start"),
        ("runner", "running"),
        ("runner", "identity-created"),
        ("db", "identity-create"),
        ("journal-before", "identity-start"),
        ("worker", "identity-running"),
    ],
)
def test_identity_phase_names_never_enable_generic_execution_or_other_roles(role, phase):
    assert active.context_allowed(role, phase) is False
