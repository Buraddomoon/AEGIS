"""Original DB runtime against adversarial metadata fixtures; no Docker lifecycle."""

import copy
import json
import sys
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from test_runner_activation_database_server import IMAGE
from test_runner_activation_database_server import prepared as prepared
from test_runner_activation_ownership import FakeDocker as Owner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_database_inspection as inspection  # noqa: E402

OBJECT = "d" * 64


def projection(spec, phase):
    base = {"propagation": "", "no_copy": None, "policy_source_matches": False}
    volume = {
        **base,
        "type": "volume",
        "name": inspection.server.VOLUME,
        "target": inspection.server.DATA,
        "writable": True,
    }
    bind = {
        **base,
        "type": "bind",
        "name": None,
        "target": inspection.server.HBA,
        "writable": False,
        "policy_source_matches": True,
        "propagation": "rprivate",
    }
    return {
        "id": OBJECT,
        "name": "/" + spec["name"],
        "image": IMAGE,
        "image_reference": IMAGE,
        "user": "70:70",
        "entrypoint": spec["entrypoint"],
        "arguments": spec["arguments"],
        "working_directory": "/",
        "stdin_open": False,
        "tty": False,
        "healthcheck": ["NONE"],
        "stop_timeout": 5,
        "stop_signal": "SIGTERM",
        "init": None,
        "status": phase,
        "running": phase == "running",
        "restarting": False,
        "paused": False,
        "oom_killed": False,
        "exit_code": 0,
        "error_present": False,
        "ports": {"5432/tcp": None},
        "exposed_ports": {"5432/tcp": {}},
        "volumes": {inspection.server.DATA: {}},
        "label_count": 5,
        "labels": spec["labels"],
        "host": copy.deepcopy(spec["host"]),
        "network_names": ["none", None],
        "mounts": [volume, bind],
        "configured_mounts": [{**volume, "no_copy": True}, {**bind, "no_copy": False}],
        "environment": [{"key": key, "valid": True} for key in inspection.ENV_FIXED],
    }


class Docker:
    def __init__(self, spec, phase):
        self.calls = []
        self.item = projection(spec, phase)
        self.image = {
            "id": IMAGE,
            "user": "",
            "volumes": {inspection.server.DATA: {}},
            "exposed_ports": {"5432/tcp": {}},
            "label_count": 0,
            "onbuild": None,
            "environment": self.item["environment"],
        }

    def query(self, kind, image, **kwargs):
        self.calls.append(inspection.command(kind, image, **kwargs))
        return json.dumps(self.image if kind == "image" else self.item).encode()


def setup(prepared, phase="created"):
    store, root = prepared
    spec = inspection.server.recipe(store, IMAGE, policy_root=root)
    store.request("db")
    store.append("observed", {"role": "db", "resource_id": OBJECT})
    docker = Docker(spec, phase)
    owner = Owner(store.summary()["id"], "db")
    owner.details.update(id=OBJECT, image=IMAGE, running=phase == "running")
    owner.named = owner.labelled = owner.known = (OBJECT + "\n").encode()
    return store, root, spec, docker, owner


def review(store, root, docker, owner, phase="created"):
    return inspection.review(
        store, IMAGE, OBJECT, phase, policy_root=root, docker=docker, ownership_docker=owner
    )


@pytest.mark.parametrize("phase", ["created", "running"])
def test_runtime_verifies_exact_volume_policy_namespace_and_resource_without_proving_sql(
    prepared, phase
):
    store, root, spec, docker, owner = setup(prepared, phase)
    original = store.summary()
    result = review(store, root, docker, owner, phase)
    assert result["runtime_configuration_verified"] and result["network_none_verified"]
    assert (
        result["expected_database_volume_mount_verified"]
        and result["fixed_authentication_policy_mount_verified"]
    )
    assert result["published_ports_absent_verified"]
    assert all(
        result[key] is False
        for key in (
            "volume_contents_verified",
            "authentication_verified",
            "image_provenance_verified",
            "effects_authorized",
            "normal_operation_permitted",
        )
    )
    assert store.summary() == original and len(owner.calls) == 14
    assert result["recipe_sha256"] == digest(spec)
    assert "{{json .Config.Env}}" not in docker.calls[0][3]
    assert '"policy_source_matches"' in docker.calls[0][3]
    assert "{{json $m.Source}}" not in inspection._mounts(spec, effective=True)
    assert '{{if eq $m.Type "volume"}}{{json $m.Source}}{{else}}null{{end}}' in docker.calls[0][3]


@pytest.mark.parametrize(
    "field,value",
    [
        ("user", "0:0"),
        ("entrypoint", ["docker-entrypoint.sh"]),
        ("arguments", ["--single"]),
        ("stdin_open", True),
        ("init", True),
        ("init", 0),
        ("tty", True),
        ("working_directory", "/tmp"),
        ("stop_signal", "SIGKILL"),
        ("stop_timeout", 30),
        ("status", "exited"),
        ("running", True),
        ("exit_code", False),
        ("exit_code", 1),
        ("error_present", True),
        ("oom_killed", True),
        ("paused", True),
        ("ports", {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}),
        ("network_names", ["host", None]),
        ("network_names", ["none", "backend", None]),
        ("volumes", {}),
        ("exposed_ports", {"8080/tcp": {}}),
        ("label_count", 6),
        ("environment", [{"key": "LD_PRELOAD", "valid": False}]),
    ],
)
def test_unsafe_configuration_blocks_without_echo(prepared, field, value):
    store, root, _, docker, owner = setup(prepared)
    docker.item[field] = value
    with pytest.raises(inspection.ActivationError):
        review(store, root, docker, owner)


@pytest.mark.parametrize(
    "scene",
    [
        "wrong_volume",
        "readonly_data",
        "writable_policy",
        "foreign_policy",
        "policy_propagation",
        "extra_bind",
        "duplicate",
        "missing",
        "copy_volume",
        "configured_foreign_policy",
    ],
)
def test_mount_drift_cannot_hide_a_different_source_or_writable_authentication_file(
    prepared, scene
):
    store, root, _, docker, owner = setup(prepared)
    mounts = docker.item["mounts"]
    if scene == "wrong_volume":
        mounts[0]["name"] = "other-volume"
    elif scene == "readonly_data":
        mounts[0]["writable"] = False
    elif scene == "writable_policy":
        mounts[1]["writable"] = True
    elif scene == "foreign_policy":
        mounts[1]["policy_source_matches"] = False
    elif scene == "policy_propagation":
        mounts[1]["propagation"] = "rshared"
    elif scene == "extra_bind":
        mounts.append({"type": "bind", "target": "/host"})
    elif scene == "duplicate":
        mounts.append(copy.deepcopy(mounts[0]))
    elif scene == "missing":
        mounts.pop()
    elif scene == "copy_volume":
        docker.item["configured_mounts"][0]["no_copy"] = False
    else:
        docker.item["configured_mounts"][1]["policy_source_matches"] = False
    with pytest.raises(inspection.ActivationError, match="mount_mismatch"):
        review(store, root, docker, owner)


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkMode", "host"),
        ("ReadonlyRootfs", False),
        ("Privileged", True),
        ("Memory", 0),
        ("PidsLimit", -1),
        ("NanoCpus", 0),
        ("CapDrop", []),
        ("SecurityOpt", []),
        ("Binds", False),
        ("Devices", False),
        ("Tmpfs", {}),
    ],
)
def test_host_policy_is_exact(prepared, field, value):
    store, root, _, docker, owner = setup(prepared)
    docker.item["host"][field] = value
    with pytest.raises(inspection.ActivationError):
        review(store, root, docker, owner)


def test_mount_order_and_optional_effective_tmpfs_are_equivalent(prepared):
    store, root, _, docker, owner = setup(prepared)
    docker.item["mounts"].reverse()
    docker.item["configured_mounts"].reverse()
    docker.item["mounts"].append(
        {
            "type": "tmpfs",
            "name": None,
            "target": "/tmp",
            "writable": True,
            "propagation": "",
            "no_copy": None,
            "policy_source_matches": False,
        }
    )
    assert review(store, root, docker, owner)["runtime_configuration_verified"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("volumes", {"/other": {}}),
        ("volumes", None),
        ("user", "postgres"),
        ("onbuild", ["RUN unexpected"]),
        ("label_count", True),
        ("label_count", 1),
        ("exposed_ports", {"1234/tcp": {}}),
        ("environment", [{"key": "POSTGRES_PASSWORD", "valid": False}]),
    ],
)
def test_image_cannot_add_implicit_volumes_or_environment(prepared, field, value):
    _, _, _, docker, _ = setup(prepared)
    docker.image[field] = value
    with pytest.raises(inspection.ActivationError):
        inspection.review_image(IMAGE, docker=docker)


def test_image_projection_is_bounded_closed_and_never_proves_provenance(prepared):
    _, _, _, docker, _ = setup(prepared)
    result = inspection.review_image(IMAGE, docker=docker)
    assert result["unexpected_image_volumes_excluded"]
    assert result["image_provenance_verified"] is False
    assert docker.calls[0][:2] == ("image", "inspect")
    assert "{{json .Config.Env}}" not in inspection.IMAGE_FORMAT
    with pytest.raises(inspection.ActivationError, match="query_not_allowed"):
        inspection.command("start", IMAGE)


def test_policy_or_owner_mutation_during_inspect_blocks(prepared):
    store, root, _, docker, owner = setup(prepared)
    original = docker.query

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        owner.details["name"] = "/private-sensitive-sentinel"
        return result

    docker.query = changed
    with pytest.raises(inspection.ActivationError) as caught:
        review(store, root, docker, owner)
    assert "private-sensitive-sentinel" not in str(caught.value)


def test_official_build_metadata_and_omitted_root_user_are_allowed_without_loader_overrides(
    prepared,
):
    _, _, _, docker, _ = setup(prepared)
    docker.image["user"] = None
    docker.image["environment"] += [{"key": key, "valid": True} for key in inspection.ENV_METADATA]
    assert inspection.review_image(IMAGE, docker=docker)["unexpected_image_volumes_excluded"]
    assert '(index .Config "User")' in inspection.IMAGE_FORMAT
    assert '{{with (index .Config "Labels")}}' in inspection.IMAGE_FORMAT
    assert ".Config.User" not in inspection.IMAGE_FORMAT


@pytest.mark.parametrize(
    "scene", ["duplicate", "missing", "extra", "false", "integer", "wrong_keys"]
)
def test_environment_shape_cannot_hide_ambient_configuration(prepared, scene):
    _, _, _, docker, _ = setup(prepared)
    values = docker.image["environment"]
    if scene == "duplicate":
        values.append(copy.deepcopy(values[0]))
    elif scene == "missing":
        values.pop()
    elif scene == "extra":
        values.append({"key": "PGOPTIONS", "valid": True})
    elif scene == "false":
        values[0]["valid"] = False
    elif scene == "integer":
        values[0]["valid"] = 1
    else:
        values[0]["value"] = "private-sensitive-sentinel"
    with pytest.raises(inspection.ActivationError, match="environment_mismatch") as caught:
        inspection.review_image(IMAGE, docker=docker)
    assert "private-sensitive-sentinel" not in str(caught.value)


def test_templates_on_existing_demo_database_metadata_only_when_available():
    """No startup, SQL or original Lab volume; Demo is not an approved server."""
    if not Path("/usr/bin/docker").is_file() or not Path("/var/run/docker.sock").exists():
        pytest.skip("Optional existing Demo DB metadata; no resources created")
    try:
        raw = inspection._execute(
            (
                "ps",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                "label=com.docker.compose.project=aegis",
                "--filter",
                "label=com.docker.compose.service=db",
            )
        )
    except inspection.ActivationError:
        pytest.skip("Daemon unavailable; no resources created")
    ids = raw.decode("ascii").splitlines()
    if not ids:
        pytest.skip("Existing Demo DB absent; no resources created")
    assert len(ids) == 1
    item = inspection.document(
        inspection._execute(
            (
                "container",
                "inspect",
                "--format",
                inspection.container_format(
                    {"policy_path": "/not-mounted/aegis-fixed-pg_hba.conf"}
                ),
                inspection.identifier(ids[0]),
            )
        )
    )
    assert isinstance(item["environment"], list)
    assert all(
        set(entry) == {"key", "valid"} and type(entry["valid"]) is bool
        for entry in item["environment"]
    )
    assert all("source" not in mount for mount in item["mounts"])
    assert all("source" not in mount for mount in item["configured_mounts"])
    assert all(mount["policy_source_matches"] is False for mount in item["mounts"])
    assert inspection.review_image(item["image"])["image_provenance_verified"] is False


@pytest.mark.parametrize("phase", ["created", "running"])
def test_runtime_can_reconcile_a_durable_database_start_without_replaying_it(prepared, phase):
    store, root, spec, docker, owner = setup(prepared, phase)
    store.append(
        "database_start_requested",
        {
            "role": "db",
            "recipe_sha256": digest(spec),
            "gates_sha256": "e" * 64,
            "policy_sha256": inspection.server.policy.CONTENT_SHA256,
        },
    )
    result = review(store, root, docker, owner, phase)
    assert result["runtime_configuration_verified"]
    assert store.review()["resources"]["db"]["state"] == "START_REQUESTED"
    assert store.review()["resources"]["db"]["start"]["recipe_sha256"] == digest(spec)
