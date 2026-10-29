"""Read-only identity-container image/configuration checks; no lifecycle or TLS claims."""

import json
import subprocess

import runner_activation_identity_runtime as runtime
import runner_activation_probe_runtime as probe
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError, _execute, document, image_id
from runner_activation_ownership import identifier, observe

IMAGE_FORMAT = (
    probe.IMAGE_FORMAT[:-1]
    + ',"ports":{{json (index .Config "ExposedPorts")}},'
    + '"onbuild":{{json (index .Config "OnBuild")}}}'
)


def _environment_format(spec):
    fixed = {key: values[0] for key, values in probe.ENV_FIXED.items()}
    fixed.update(spec["environment"])
    predicates = [f"(eq $e {json.dumps(k + '=' + v)})" for k, v in fixed.items()]
    predicates += [f"(eq $key {json.dumps(k)})" for k in sorted(probe.ENV_METADATA)]
    return (
        "[{{range $i, $e := .Config.Env}}{{if $i}},{{end}}"
        '{{$key := index (split $e "=") 0}}'
        '{"key":{{json $key}},"valid":{{json (or ' + " ".join(predicates) + ")}}}{{end}}]"
    )


def _mounts(spec, *, effective):
    collection = ".Mounts" if effective else '(index .HostConfig "Mounts")'
    target = "$m.Destination" if effective else "$m.Target"
    matches = " ".join(
        "(and (eq " + target + " " + json.dumps(k) + ") (eq $m.Source " + json.dumps(v) + "))"
        for k, v in spec["mount_sources"].items()
    )
    options = (
        '"writable":{{json $m.RW}},"propagation":{{json $m.Propagation}},"bind_options":null'
        if effective
        else '"writable":{{json (not (index $m "ReadOnly"))}},'
        '"propagation":{{with (index $m "BindOptions")}}'
        '{{json (or (index . "Propagation") "")}}{{else}}""{{end}},'
        '"bind_options":{{json (index $m "BindOptions")}}'
    )
    return (
        "[{{range $i, $m := " + collection + "}}{{if $i}},{{end}}"
        '{"type":{{json $m.Type}},"target":{{json ' + target + "}},"
        '"source_matches":{{json (or ' + matches + ")}}," + options + "}{{end}}]"
    )


def container_format(spec):
    value = probe.CONTAINER_FORMAT.replace(probe.ENVIRONMENT_FORMAT, _environment_format(spec))
    value = value.replace(probe.EFFECTIVE_MOUNTS, _mounts(spec, effective=True))
    value = value.replace(probe.CONFIGURED_MOUNTS, _mounts(spec, effective=False))
    return (
        value[:-1]
        + ',"init":{{json (index .HostConfig "Init")}},'
        + '"stop_signal":{{json .Config.StopSignal}},'
        + '"volumes":{{json (index .Config "Volumes")}},'
        + '"exposed_ports":{{json (index .Config "ExposedPorts")}},'
        + '"endpoints":[{{range $name, $n := .NetworkSettings.Networks}}'
        + '{"name":{{json $name}},"id":{{json $n.NetworkID}},'
        + '"ip":{{json $n.IPAddress}},"prefix":{{json $n.IPPrefixLen}},'
        + '"ipv6":{{json $n.GlobalIPv6Address}},"ipv6_gateway":{{json $n.IPv6Gateway}},'
        + '"configured_ip":{{with (index $n "IPAMConfig")}}'
        + '{{json (index . "IPv4Address")}}{{else}}null{{end}},'
        + '"configured_extra_addresses_absent":{{with (index $n "IPAMConfig")}}'
        + '{{json (and (not (index . "IPv6Address")) (not (index . "LinkLocalIPs")))}}'
        + '{{else}}true{{end}},"links_absent":{{json (not (index $n "Links"))}},'
        + '"driver_options_absent":{{json (not (index $n "DriverOpts"))}}},{{end}}null]}'
    )


def command(kind, image, *, spec=None, known_id=None):
    image_id(image)
    if kind == "image" and spec is None and known_id is None:
        return ("image", "inspect", "--format", IMAGE_FORMAT, image)
    if kind == "container" and spec is not None and known_id is not None:
        return ("container", "inspect", "--format", container_format(spec), identifier(known_id))
    raise ActivationError("identity_runtime_query_not_allowed")


class IdentityInspectionDocker:
    def query(self, kind, image, *, spec=None, known_id=None):
        try:
            return _execute(command(kind, image, spec=spec, known_id=known_id))
        except ActivationError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ActivationError("identity_runtime_query_failed") from None


def review_image(image, *, docker=None):
    image_id(image)
    item = document((docker or IdentityInspectionDocker()).query("image", image))
    if (
        not isinstance(item, dict)
        or set(item) != {"id", "user", "volumes", "environment", "ports", "onbuild"}
        or item["id"] != image
        or item["user"] != "10001:10001"
        or item["volumes"] not in (None, {})
        or item["ports"] not in (None, {})
        or item["onbuild"] not in (None, [])
    ):
        raise ActivationError("identity_runtime_image_mismatch")
    probe._validate_environment(item["environment"], image=True)
    return {
        "image": image,
        "anonymous_volumes_excluded": True,
        "image_provenance_verified": False,
        "identity_mode_implementation_verified": False,
    }


def validate(spec, item, known_id, phase):
    if phase not in {"created", "running"}:
        raise ActivationError("identity_runtime_phase_invalid")
    config = {
        "id": identifier(known_id),
        "name": "/" + spec["name"],
        "image": spec["image"],
        "image_reference": spec["image"],
        "user": spec["user"],
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
    }
    if (
        not isinstance(item, dict)
        or set(item)
        != {
            *config,
            "host",
            "mounts",
            "configured_mounts",
            "network_names",
            "ports",
            "environment",
            "init",
            "volumes",
            "exposed_ports",
            "endpoints",
        }
        or any(digest(item[k]) != digest(v) for k, v in config.items())
        or (item["init"] is not None and item["init"] is not False)
        or any(item[k] not in (None, {}) for k in ("volumes", "ports", "exposed_ports"))
    ):
        raise ActivationError("identity_runtime_configuration_mismatch")
    probe._validate_host(item, spec["host"])
    base = set(probe.ENV_FIXED)
    expected_keys = base | set(spec["environment"])
    keys = set()
    if not isinstance(item["environment"], list):
        raise ActivationError("identity_runtime_environment_mismatch")
    for value in item["environment"]:
        if (
            not isinstance(value, dict)
            or set(value) != {"key", "valid"}
            or not isinstance(value["key"], str)
            or value["key"] not in expected_keys | probe.ENV_METADATA
            or value["key"] in keys
            or value["valid"] is not True
        ):
            raise ActivationError("identity_runtime_environment_mismatch")
        keys.add(value["key"])
    if not expected_keys <= keys:
        raise ActivationError("identity_runtime_environment_mismatch")
    for field, effective in (("mounts", True), ("configured_mounts", False)):
        expected = [
            {
                "type": "bind",
                "target": target,
                "source_matches": True,
                "writable": False,
                "propagation": "rprivate",
                "bind_options": None if effective else {"Propagation": "rprivate"},
            }
            for target in spec["mount_sources"]
        ]
        if not isinstance(item[field], list):
            raise ActivationError("identity_runtime_mount_mismatch")
        # Effective tmpfs may appear separately on supported daemon versions.
        tmp = {
            "type": "tmpfs",
            "target": "/tmp",
            "source_matches": False,
            "writable": True,
            "propagation": "",
            "bind_options": None,
        }
        actual = item[field]
        if effective:
            optional = [index for index, value in enumerate(actual) if digest(value) == digest(tmp)]
            if len(optional) == 1:
                actual = actual.copy()
                actual.pop(optional[0])
        if sorted(map(digest, actual)) != sorted(map(digest, expected)):
            raise ActivationError("identity_runtime_mount_mismatch")
    endpoint = {
        "name": spec["network_name"],
        "id": spec["network_resource_id"],
        "ip": runtime.IP,
        "prefix": 29,
        "ipv6": "",
        "ipv6_gateway": "",
        "configured_ip": runtime.IP,
        "configured_extra_addresses_absent": True,
        "links_absent": True,
        "driver_options_absent": True,
    }
    expected_endpoints = [[endpoint, None]]
    if phase == "created":
        expected_endpoints.append([{**endpoint, "ip": "", "prefix": 0, "id": ""}, None])
        expected_endpoints.append([{**endpoint, "ip": "", "prefix": 0}, None])
    if item["network_names"] != [endpoint["name"], None] or digest(item["endpoints"]) not in set(
        map(digest, expected_endpoints)
    ):
        raise ActivationError("identity_runtime_network_mismatch")


def review(store, path, plan_sha256, known_id, phase, *, docker=None, ownership_docker=None):
    original = store.review()
    current = original["resources"].get("runner", {})
    if current.get("resource_id") != identifier(known_id) or current.get("state") not in {
        "OBSERVED",
        "START_REQUESTED",
    }:
        raise ActivationError("identity_runtime_observed_runner_required")
    spec = runtime.recipe(store, path, plan_sha256)
    operation = store.summary()["id"]
    before = observe(operation, plan_sha256, "runner", known_id, docker=ownership_docker)
    item = document(
        (docker or IdentityInspectionDocker()).query(
            "container", spec["image"], spec=spec, known_id=known_id
        )
    )
    validate(spec, item, known_id, phase)
    after = observe(operation, plan_sha256, "runner", known_id, docker=ownership_docker)
    if (
        before != after
        or before["status"] != "present_owned_snapshot"
        or before["details"]["image"] != spec["image"]
        or before["details"]["running"] is not (phase == "running")
        or store.review() != original
        or digest(runtime.recipe(store, path, plan_sha256)) != digest(spec)
    ):
        raise ActivationError("identity_runtime_ownership_changed")
    return {
        "format": "aegis-identity-runtime-review/1",
        "resource_id": known_id,
        "phase": phase,
        "recipe_sha256": digest(spec),
        "configuration_sha256": digest(item),
        "runtime_configuration_verified": True,
        "original_volumes_not_mounted_verified": True,
        "published_ports_absent_verified": True,
        "candidate_leaf_mount_paths_verified": True,
        "mutual_tls_verified": False,
        "identity_mode_implementation_verified": False,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
