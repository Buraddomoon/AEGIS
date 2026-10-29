"""Adversarial metadata and real CLI against fake Unix daemon; no native containers."""

import copy
import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_ownership import OBJECT
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_mount_templates import render as render

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_inspection as inspection  # noqa: E402


@pytest.fixture
def spec():
    return {
        "name": "aegis-linux-lab-activation-" + uuid4().hex + "-runner",
        "image": "sha256:" + "a" * 64,
        "user": "10001:10001",
        "entrypoint": ["/usr/local/bin/python"],
        "arguments": ["-I", "-B", "-m", "aegis.lab_runner.server"],
        "labels": dict.fromkeys(inspection.probe.LABELS.values(), "fixture"),
        "host": {
            **inspection.probe.HOST_EXACT,
            **dict.fromkeys(inspection.probe.HOST_EMPTY, True),
            "NetworkMode": "c" * 64,
            "Tmpfs": {"/tmp": inspection.runtime.TMPFS},
        },
        "environment": {
            "AEGIS_RUNNER_IDENTITY_ONLY": "true",
            **{
                "AEGIS_RUNNER_" + key.upper(): str(uuid4())
                for key in inspection.runtime.plan.pki.IDS
            },
        },
        "mount_sources": {
            key: "/private/candidate/" + value for key, value in inspection.runtime.SECRETS.items()
        },
        "network_resource_id": "c" * 64,
        "network_name": "aegis-linux-lab_isolated",
    }


def projection(spec, phase="created"):
    return {
        "id": OBJECT,
        "name": "/" + spec["name"],
        "image": spec["image"],
        "image_reference": spec["image"],
        "user": "10001:10001",
        "entrypoint": spec["entrypoint"],
        "arguments": spec["arguments"],
        "working_directory": "/app",
        "stdin_open": False,
        "tty": False,
        "healthcheck": ["NONE"],
        "stop_timeout": 5,
        "stop_signal": "SIGTERM",
        "labels": spec["labels"],
        "label_count": 5,
        "running": phase == "running",
        "restarting": False,
        "paused": False,
        "oom_killed": False,
        "exit_code": 0,
        "error_present": False,
        "status": phase,
        "host": copy.deepcopy(spec["host"]),
        "init": None,
        "volumes": None,
        "ports": None,
        "exposed_ports": None,
        "environment": [
            {"key": key, "valid": True}
            for key in sorted(set(inspection.probe.ENV_FIXED) | set(spec["environment"]))
        ],
        "mounts": [
            {
                "type": "bind",
                "target": key,
                "source_matches": True,
                "writable": False,
                "propagation": "rprivate",
                "bind_options": None,
            }
            for key in spec["mount_sources"]
        ],
        "configured_mounts": [
            {
                "type": "bind",
                "target": key,
                "source_matches": True,
                "writable": False,
                "propagation": "rprivate",
                "bind_options": {"Propagation": "rprivate"},
            }
            for key in spec["mount_sources"]
        ],
        "network_names": [spec["network_name"], None],
        "endpoints": [
            {
                "name": spec["network_name"],
                "id": spec["network_resource_id"],
                "ip": inspection.runtime.IP,
                "prefix": 29,
                "ipv6": "",
                "ipv6_gateway": "",
                "configured_ip": inspection.runtime.IP,
                "configured_extra_addresses_absent": True,
                "links_absent": True,
                "driver_options_absent": True,
            },
            None,
        ],
    }


@pytest.mark.parametrize("phase", ["created", "running"])
def test_fixed_profile_accepts_only_expected_configuration_without_tls_claims(spec, phase):
    inspection.validate(spec, projection(spec, phase), OBJECT, phase)


@pytest.mark.parametrize(
    "field,value",
    [
        ("user", "0:0"),
        ("image_reference", "floating-tag"),
        ("stdin_open", True),
        ("tty", True),
        ("arguments", ["-c", "unreviewed"]),
        ("entrypoint", ["/bin/sh"]),
        ("init", True),
        ("init", 0),
        ("running", 0),
        ("exit_code", False),
        ("volumes", {"/state": {}}),
        ("ports", {"8443/tcp": [{}]}),
        ("exposed_ports", {"8443/tcp": {}}),
        ("label_count", 5.0),
        ("stop_signal", "SIGKILL"),
        ("healthcheck", ["CMD", "unreviewed"]),
        ("paused", True),
        ("restarting", True),
    ],
)
def test_alternate_process_ports_volumes_or_types_are_rejected(spec, field, value):
    item = projection(spec)
    item[field] = value
    with pytest.raises(inspection.ActivationError, match="configuration_mismatch"):
        inspection.validate(spec, item, OBJECT, "created")


@pytest.mark.parametrize(
    "scene",
    [
        "privileged",
        "network",
        "missing_mode",
        "false_mode",
        "duplicate",
        "unknown_env",
        "writable_key",
        "wrong_source",
        "extra_volume",
        "mount_option",
        "shared_mount",
        "network_id",
        "ip",
        "ipv6",
        "other_network",
        "integer_predicate",
    ],
)
def test_host_environment_secret_and_network_drift_fail_closed(spec, scene):
    item = projection(spec)
    if scene == "privileged":
        item["host"]["Privileged"] = True
    elif scene == "network":
        item["host"]["NetworkMode"] = "host"
    elif scene == "missing_mode":
        item["environment"] = [
            v for v in item["environment"] if v["key"] != "AEGIS_RUNNER_IDENTITY_ONLY"
        ]
    elif scene == "false_mode":
        next(v for v in item["environment"] if v["key"] == "AEGIS_RUNNER_IDENTITY_ONLY")[
            "valid"
        ] = False
    elif scene == "duplicate":
        item["environment"].append(item["environment"][0])
    elif scene == "unknown_env":
        item["environment"].append({"key": "LD_PRELOAD", "valid": True})
    elif scene == "writable_key":
        item["mounts"][0]["writable"] = True
    elif scene == "wrong_source":
        item["configured_mounts"][0]["source_matches"] = False
    elif scene == "extra_volume":
        item["mounts"].append({"type": "volume", "target": "/state"})
    elif scene == "mount_option":
        item["configured_mounts"][0]["bind_options"]["NonRecursive"] = True
    elif scene == "shared_mount":
        item["mounts"][0]["propagation"] = "rshared"
    elif scene == "network_id":
        item["endpoints"][0]["id"] = "f" * 64
    elif scene == "ip":
        item["endpoints"][0]["ip"] = "172.30.88.3"
    elif scene == "ipv6":
        item["endpoints"][0]["ipv6"] = "2001:db8::1"
    elif scene == "other_network":
        item["network_names"].insert(0, "other")
    else:
        item["environment"][0]["valid"] = 1
    with pytest.raises(inspection.ActivationError):
        inspection.validate(spec, item, OBJECT, "created")


def test_optional_tmpfs_predicates_are_strict_and_duplicates_are_not_ignored(spec):
    item = projection(spec)
    tmp = {
        "type": "tmpfs",
        "target": "/tmp",
        "source_matches": False,
        "writable": True,
        "propagation": "",
        "bind_options": None,
    }
    item["mounts"].append(tmp)
    inspection.validate(spec, item, OBJECT, "created")
    tmp["writable"] = 1
    with pytest.raises(inspection.ActivationError, match="mount_mismatch"):
        inspection.validate(spec, item, OBJECT, "created")
    tmp["writable"] = True
    item["mounts"].append(tmp.copy())
    with pytest.raises(inspection.ActivationError, match="mount_mismatch"):
        inspection.validate(spec, item, OBJECT, "created")


@pytest.mark.parametrize(
    "field", ["configured_extra_addresses_absent", "links_absent", "driver_options_absent"]
)
def test_configured_extra_addresses_and_endpoint_links_are_never_accepted(spec, field):
    item = projection(spec)
    item["endpoints"][0][field] = False
    with pytest.raises(inspection.ActivationError, match="network_mismatch"):
        inspection.validate(spec, item, OBJECT, "created")


def test_not_yet_allocated_endpoint_is_only_valid_before_start(spec):
    item = projection(spec)
    item["endpoints"][0].update(id="", ip="", prefix=0)
    inspection.validate(spec, item, OBJECT, "created")
    item.update(status="running", running=True)
    with pytest.raises(inspection.ActivationError, match="network_mismatch"):
        inspection.validate(spec, item, OBJECT, "running")


@pytest.mark.parametrize("scene", ["ok", "volume", "exposed", "onbuild", "root", "environment"])
def test_image_review_excludes_implicit_volumes_ports_and_environment_without_attesting_code(
    spec, scene
):
    item = {
        "id": spec["image"],
        "user": "10001:10001",
        "volumes": None,
        "ports": None,
        "onbuild": None,
        "environment": [
            {"key": k, "valid": True} for k in inspection.probe.ENV_FIXED if k != "TMPDIR"
        ],
    }
    if scene == "volume":
        item["volumes"] = {"/state": {}}
    elif scene == "exposed":
        item["ports"] = {"8443/tcp": {}}
    elif scene == "onbuild":
        item["onbuild"] = ["unreviewed"]
    elif scene == "root":
        item["user"] = "0:0"
    elif scene == "environment":
        item["environment"].append({"key": "LD_PRELOAD", "valid": True})

    class Docker:
        def query(self, kind, image):
            assert kind == "image" and image == spec["image"]
            return json.dumps(item).encode()

    if scene != "ok":
        with pytest.raises(inspection.ActivationError):
            inspection.review_image(spec["image"], docker=Docker())
    else:
        result = inspection.review_image(spec["image"], docker=Docker())
        assert result["anonymous_volumes_excluded"]
        assert result["identity_mode_implementation_verified"] is False
        assert result["image_provenance_verified"] is False


@pytest.mark.parametrize("phase", ["created", "running"])
def test_full_projection_runs_real_cli_on_fake_daemon_and_redacts_sources_and_environment(
    spec, render, phase
):
    expected = projection(spec, phase)
    fixed = {key: values[0] for key, values in inspection.probe.ENV_FIXED.items()}
    fixed.update(spec["environment"])
    raw = {
        "Id": OBJECT,
        "Name": expected["name"],
        "Image": spec["image"],
        "Config": {
            "Image": spec["image"],
            "User": "10001:10001",
            "Entrypoint": spec["entrypoint"],
            "Cmd": spec["arguments"],
            "WorkingDir": "/app",
            "OpenStdin": False,
            "Tty": False,
            "Healthcheck": {"Test": ["NONE"]},
            "StopTimeout": 5,
            "StopSignal": "SIGTERM",
            "Labels": spec["labels"],
            "Env": [k + "=" + v for k, v in fixed.items()],
        },
        "HostConfig": {
            **spec["host"],
            **dict.fromkeys(inspection.probe.HOST_EMPTY),
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": v,
                    "Target": k,
                    "ReadOnly": True,
                    "BindOptions": {"Propagation": "rprivate"},
                }
                for k, v in spec["mount_sources"].items()
            ],
        },
        "State": {
            "Status": phase,
            "Running": phase == "running",
            "Restarting": False,
            "Paused": False,
            "OOMKilled": False,
            "ExitCode": 0,
            "Error": "",
        },
        "Mounts": [
            {"Type": "bind", "Source": v, "Destination": k, "RW": False, "Propagation": "rprivate"}
            for k, v in spec["mount_sources"].items()
        ],
        "NetworkSettings": {
            "Ports": None,
            "Networks": {
                spec["network_name"]: {
                    "NetworkID": spec["network_resource_id"],
                    "IPAddress": inspection.runtime.IP,
                    "IPPrefixLen": 29,
                    "GlobalIPv6Address": "",
                    "IPv6Gateway": "",
                    "IPAMConfig": {"IPv4Address": inspection.runtime.IP},
                }
            },
        },
    }
    result = render(inspection.container_format(spec), document=raw)
    inspection.validate(spec, result, OBJECT, phase)
    assert "/private/candidate" not in json.dumps(result)
    raw["Config"]["Env"].append("UNREVIEWED=private-sensitive-sentinel")
    result = render(inspection.container_format(spec), document=raw)
    assert "private-sensitive-sentinel" not in json.dumps(result)
    with pytest.raises(inspection.ActivationError, match="environment_mismatch"):
        inspection.validate(spec, result, OBJECT, phase)


def test_review_requires_observed_exact_owned_runner_and_does_not_claim_tls(context):
    store, path, expected_sha = context
    store.request("runner")
    store.append("observed", {"role": "runner", "resource_id": OBJECT})
    spec = inspection.runtime.recipe(store, path, expected_sha)
    owner = Owner(store.summary()["id"], "runner")
    owner.details.update(plan=expected_sha, image=spec["image"])

    class Docker:
        def query(self, kind, image, *, spec=None, known_id=None):
            assert kind == "container" and known_id == OBJECT
            return json.dumps(projection(spec)).encode()

    result = inspection.review(
        store, path, expected_sha, OBJECT, "created", docker=Docker(), ownership_docker=owner
    )
    assert (
        result["original_volumes_not_mounted_verified"]
        and result["candidate_leaf_mount_paths_verified"]
    )
    assert all(
        result[k] is False
        for k in (
            "mutual_tls_verified",
            "identity_mode_implementation_verified",
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )


@pytest.mark.parametrize("scene", ["intent_change", "plan_expired", "owner_changed"])
def test_review_cannot_publish_after_final_inputs_or_ownership_change(context, monkeypatch, scene):
    store, path, expected_sha = context
    store.request("runner")
    store.append("observed", {"role": "runner", "resource_id": OBJECT})
    spec = inspection.runtime.recipe(store, path, expected_sha)
    owner = Owner(store.summary()["id"], "runner")
    owner.details.update(plan=expected_sha, image=spec["image"])
    expires = inspection.runtime.plan.datetime.fromisoformat(
        inspection.runtime.plan.load_plan(path, expected_sha)["expires_at"]
    )

    class Docker:
        def query(self, *_args, **_kwargs):
            if scene == "intent_change":
                store.request("redis")
            elif scene == "plan_expired":
                monkeypatch.setattr(inspection.runtime.plan.pki, "clock", lambda: expires)
            else:
                owner.details["image"] = "sha256:" + "f" * 64
            return json.dumps(projection(spec)).encode()

    with pytest.raises(inspection.ActivationError):
        inspection.review(
            store, path, expected_sha, OBJECT, "created", docker=Docker(), ownership_docker=owner
        )
