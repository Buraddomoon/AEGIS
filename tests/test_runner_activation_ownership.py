"""Read-only Docker ownership fixtures; no runtime resource creation or deletion."""

import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_ownership as ownership  # noqa: E402
from runner_activation_intents import ROLES, resource  # noqa: E402

PLAN = "a" * 64
OBJECT = "b" * 64


class FakeDocker:
    def __init__(self, operation, role, present=True):
        self.calls = []
        self.named = self.labelled = self.known = (OBJECT + "\n").encode() if present else b""
        expected = resource(operation, PLAN, role)
        self.details = {
            "id": OBJECT,
            "name": ("/" if expected["kind"] == "container" else "") + expected["name"],
            **{key: expected["labels"][label] for key, label in ownership.LABELS.items()},
        }
        self.details.update(
            {"running": False, "image": "sha256:" + "c" * 64}
            if expected["kind"] == "container"
            else {"member_count": 0}
        )

    def query(self, kind, operation, plan, role, known_id=None):
        self.calls.append(ownership.command(kind, operation, plan, role, known_id))
        if kind == "inspect":
            return json.dumps(self.details).encode()
        return {"name": self.named, "labels": self.labelled, "known": self.known}[kind]


@pytest.mark.parametrize("role", sorted(ROLES))
def test_present_owned_snapshot_requires_exact_name_all_labels_and_recorded_id(role):
    operation = uuid4().hex
    docker = FakeDocker(operation, role)
    result = ownership.observe(operation, PLAN, role, OBJECT, docker=docker)
    assert result["status"] == "present_owned_snapshot" and result["resource_id"] == OBJECT
    assert result["stopped_or_empty_snapshot"] is True
    assert all(
        result[key] is False
        for key in (
            "effects_authorized",
            "runtime_mounts_verified",
            "network_isolation_verified",
            "normal_operation_permitted",
        )
    )
    assert len(docker.calls) == 7
    assert all(command[0] in {"ps", "container", "network"} for command in docker.calls)
    assert all(
        word not in command
        for command in docker.calls
        for word in ("start", "stop", "rm", "run", "exec", "create", "Config.Env")
    )
    assert all("Config.Env" not in " ".join(command) for command in docker.calls)


@pytest.mark.parametrize("role", sorted(ROLES))
def test_absence_requires_name_owner_label_and_historical_id_absent_twice(role):
    operation = uuid4().hex
    docker = FakeDocker(operation, role, present=False)
    result = ownership.observe(operation, PLAN, role, OBJECT, docker=docker)
    assert result["status"] == "absent_snapshot"
    assert result["details"] is None and result["resource_id"] is None
    assert result["stopped_or_empty_snapshot"] is False
    assert len(docker.calls) == 6
    assert all("inspect" not in command for command in docker.calls)


@pytest.mark.parametrize(
    "field", ["project", "operation", "plan", "role", "ownership", "name", "id"]
)
def test_single_label_name_or_id_mismatch_is_never_owned(field):
    operation = uuid4().hex
    docker = FakeDocker(operation, "runner")
    docker.details[field] = "foreign-value"
    with pytest.raises(ownership.ActivationError, match="inspection_mismatch"):
        ownership.observe(operation, PLAN, "runner", docker=docker)


@pytest.mark.parametrize(
    "scene", ["renamed", "lost_labels", "id_changed", "name_reused", "extra_name", "extra_owner"]
)
def test_collisions_renames_duplicates_and_missing_labels_cannot_be_absent_or_owned(scene):
    operation = uuid4().hex
    docker = FakeDocker(operation, "runner")
    if scene == "renamed":
        docker.named = b""
    elif scene == "lost_labels":
        docker.labelled = b""
    elif scene == "id_changed":
        docker.known = b""
    elif scene == "name_reused":
        docker.named = docker.labelled = ("d" * 64 + "\n").encode()
    elif scene == "extra_name":
        docker.named += ("d" * 64 + "\n").encode()
    else:
        docker.labelled += ("d" * 64 + "\n").encode()
    with pytest.raises(ownership.ActivationError):
        ownership.observe(operation, PLAN, "runner", OBJECT, docker=docker)


def test_unknown_id_after_ambiguous_create_can_be_discovered_by_name_and_composite_owner():
    operation = uuid4().hex
    docker = FakeDocker(operation, "runner")
    result = ownership.observe(operation, PLAN, "runner", docker=docker)
    assert result["resource_id"] == OBJECT and len(docker.calls) == 5
    labels = [item for item in docker.calls if any(word.startswith("label=") for word in item)]
    assert labels and all(item.count("--filter") == 1 for item in labels)
    assert all(
        "label=io.aegis.activation-resource=" + operation + ":runner" in item for item in labels
    )


@pytest.mark.parametrize("role", ["runner", "network-isolated"])
def test_running_container_or_network_with_members_is_not_stopped_or_empty(role):
    operation = uuid4().hex
    docker = FakeDocker(operation, role)
    docker.details.update({"running": True} if role == "runner" else {"member_count": 1})
    result = ownership.observe(operation, PLAN, role, docker=docker)
    assert result["status"] == "present_owned_snapshot"
    assert result["stopped_or_empty_snapshot"] is False and result["effects_authorized"] is False


@pytest.mark.parametrize(
    "role,field,value",
    [
        ("runner", "running", 0),
        ("runner", "image", "latest"),
        ("network-isolated", "member_count", False),
        ("network-isolated", "member_count", -1),
    ],
)
def test_malformed_projected_state_is_not_interpreted_as_stopped_or_empty(role, field, value):
    operation = uuid4().hex
    docker = FakeDocker(operation, role)
    docker.details[field] = value
    with pytest.raises(ownership.ActivationError, match="projection_invalid"):
        ownership.observe(operation, PLAN, role, docker=docker)


def test_resource_appearing_between_samples_is_not_reported_absent():
    operation = uuid4().hex
    docker = FakeDocker(operation, "runner", present=False)
    query = docker.query

    def changed(*args):
        result = query(*args)
        if len(docker.calls) == 2:
            docker.named = docker.labelled = (OBJECT + "\n").encode()
        return result

    docker.query = changed
    with pytest.raises(ownership.ActivationError, match="changed_during_review"):
        ownership.observe(operation, PLAN, "runner", docker=docker)


@pytest.mark.parametrize("raw", [b"short\n", b"\xff", b"\n", b"x" * 65537])
def test_bad_list_projection_cannot_silently_mean_absent(raw):
    operation = uuid4().hex
    docker = FakeDocker(operation, "runner", present=False)
    docker.named = raw
    with pytest.raises(ownership.ActivationError):
        ownership.observe(operation, PLAN, "runner", docker=docker)


@pytest.mark.parametrize("kind", ["create", "stop", "rm", "exec", "Config.Env", "volumes"])
def test_command_catalog_rejects_mutations_and_unprojected_inspection(kind):
    with pytest.raises(ownership.ActivationError, match="query_not_allowed"):
        ownership.command(kind, uuid4().hex, PLAN, "runner")


def test_no_free_target_id_or_non_allowlisted_role_and_safe_executor_failure(monkeypatch):
    with pytest.raises(ownership.ActivationError):
        ownership.command("inspect", uuid4().hex, PLAN, "runner", "d" * 64)
    with pytest.raises(ownership.ActivationError):
        ownership.command("inspect", uuid4().hex, PLAN, "worker")

    def fail(*args):
        raise OSError("private-sensitive-sentinel")

    monkeypatch.setattr(ownership, "_execute", fail)
    with pytest.raises(ownership.ActivationError, match="ownership_query_failed") as error:
        ownership.OwnershipDocker().query("name", uuid4().hex, PLAN, "runner")
    assert "private-sensitive-sentinel" not in str(error.value)
