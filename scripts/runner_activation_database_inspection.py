"""Read-only projected metadata for the fixed original-volume PostgreSQL server."""

import json
import subprocess

import runner_activation_database_server as server
import runner_activation_probe_runtime as probe
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError, _execute, document, image_id
from runner_activation_ownership import LABELS, identifier, observe

ENV_FIXED = {
    "PATH": ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",),
    "LANG": ("C.UTF-8",),
    "PG_MAJOR": ("17",),
    "PGDATA": (server.DATA,),
}
# Official build metadata; not consumed by the direct postgres entrypoint.
# This does not attest the image's contents or make arbitrary PG* env acceptable.
ENV_METADATA = frozenset({"PG_VERSION", "PG_SHA256", "GOSU_VERSION", "DOCKER_PG_LLVM_DEPS"})


def _environment_format(*, image=False):
    fixed = {**ENV_FIXED, "LANG": ("C.UTF-8", "en_US.utf8")} if image else ENV_FIXED
    predicates = [
        f"(eq $e {json.dumps(key + '=' + value)})"
        for key, values in fixed.items()
        for value in values
    ]
    predicates += [f"(eq $key {json.dumps(key)})" for key in sorted(ENV_METADATA)]
    return (
        "[{{range $i, $e := .Config.Env}}{{if $i}},{{end}}"
        '{{$key := index (split $e "=") 0}}'
        '{"key":{{json $key}},"valid":{{json (or ' + " ".join(predicates) + ")}}}{{end}}]"
    )


IMAGE_FORMAT = (
    probe._projection(
        {
            "id": ".Id",
            "user": '(index .Config "User")',
            "volumes": '(index .Config "Volumes")',
            "exposed_ports": '(index .Config "ExposedPorts")',
            "onbuild": '(index .Config "OnBuild")',
        }
    )[:-1]
    + ',"label_count":{{with (index .Config "Labels")}}{{len .}}{{else}}0{{end}}'
    + ',"environment":'
    + _environment_format(image=True)
    + "}"
)


def container_format(spec):
    return (
        probe._projection(
            {
                "id": ".Id",
                "name": ".Name",
                "image": ".Image",
                "image_reference": ".Config.Image",
                "user": ".Config.User",
                "entrypoint": ".Config.Entrypoint",
                "arguments": ".Config.Cmd",
                "working_directory": ".Config.WorkingDir",
                "stdin_open": ".Config.OpenStdin",
                "tty": ".Config.Tty",
                "healthcheck": ".Config.Healthcheck.Test",
                "stop_timeout": '(index .Config "StopTimeout")',
                "stop_signal": ".Config.StopSignal",
                "init": '(index .HostConfig "Init")',
                "status": ".State.Status",
                "running": ".State.Running",
                "restarting": ".State.Restarting",
                "paused": ".State.Paused",
                "oom_killed": ".State.OOMKilled",
                "exit_code": ".State.ExitCode",
                "error_present": '(ne .State.Error "")',
                "ports": ".NetworkSettings.Ports",
                "exposed_ports": ".Config.ExposedPorts",
                "volumes": '(index .Config "Volumes")',
                "label_count": "(len .Config.Labels)",
            }
        )[:-1]
        + ',"network_names":[{{range $name, $_ := .NetworkSettings.Networks}}{{json $name}},{{end}}null]'
        + ',"labels":'
        + probe._projection(
            {label: '(index .Config.Labels "' + label + '")' for label in LABELS.values()}
        )
        + ',"host":'
        + probe._projection(
            {
                **{key: '(index .HostConfig "' + key + '")' for key in probe.HOST_EXACT},
                **{key: '(not (index .HostConfig "' + key + '"))' for key in probe.HOST_EMPTY},
            }
        )
        + ',"mounts":'
        + _mounts(spec, effective=True)
        + ',"configured_mounts":'
        + _mounts(spec, effective=False)
        + ',"environment":'
        + _environment_format()
        + "}"
    )


def _mounts(spec, *, effective):
    collection = ".Mounts" if effective else '(index .HostConfig "Mounts")'
    fields = {
        "type": "$m.Type",
        "name": '(index $m "Name")' if effective else "$m.Source",
        "target": "$m.Destination" if effective else "$m.Target",
        "writable": "$m.RW" if effective else "(not $m.ReadOnly)",
        "propagation": "$m.Propagation" if effective else '(index $m.BindOptions "Propagation")',
    }
    # Source is returned only for a named volume, never for a host bind path.
    source_match = "(eq $m.Source " + json.dumps(spec["policy_path"]) + ")"
    result = (
        "[{{range $i, $m := "
        + collection
        + "}}{{if $i}},{{end}}"
        + '{"type":{{json '
        + fields["type"]
        + '}},"name":'
        + '{{if eq $m.Type "volume"}}{{json '
        + fields["name"]
        + "}}{{else}}null{{end}},"
        + '"target":{{json '
        + fields["target"]
        + '}},"writable":{{json '
        + fields["writable"]
        + "}},"
        + '"policy_source_matches":{{if eq $m.Type "bind"}}{{json '
        + source_match
        + "}}{{else}}false{{end}},"
        + '"propagation":'
    )
    if effective:
        result += "{{json " + fields["propagation"] + "}}"
    else:
        result += '{{with $m.BindOptions}}{{json .Propagation}}{{else}}""{{end}}'
    result += ',"no_copy":'
    result += (
        "null" if effective else "{{with $m.VolumeOptions}}{{json .NoCopy}}{{else}}false{{end}}"
    )
    return result + "}{{end}}]"


def command(kind, image, *, spec=None, known_id=None):
    image_id(image)
    if kind == "image" and spec is None and known_id is None:
        return ("image", "inspect", "--format", IMAGE_FORMAT, image)
    if kind == "container" and spec is not None and known_id is not None:
        return ("container", "inspect", "--format", container_format(spec), identifier(known_id))
    raise ActivationError("database_server_query_not_allowed")


class DatabaseInspectionDocker:
    def query(self, kind, image, *, spec=None, known_id=None):
        try:
            return _execute(command(kind, image, spec=spec, known_id=known_id))
        except ActivationError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ActivationError("database_server_query_failed") from None


def _environment(items):
    if not isinstance(items, list) or not len(ENV_FIXED) <= len(items) <= len(ENV_FIXED) + len(
        ENV_METADATA
    ):
        raise ActivationError("database_server_environment_mismatch")
    keys = set()
    for item in items:
        if (
            not isinstance(item, dict)
            or set(item) != {"key", "valid"}
            or not isinstance(item["key"], str)
            or item["key"] not in {*ENV_FIXED, *ENV_METADATA}
            or item["valid"] is not True
            or item["key"] in keys
        ):
            raise ActivationError("database_server_environment_mismatch")
        keys.add(item["key"])
    if not set(ENV_FIXED) <= keys:
        raise ActivationError("database_server_environment_mismatch")


def review_image(image, *, docker=None):
    image_id(image)
    item = document((docker or DatabaseInspectionDocker()).query("image", image))
    if (
        not isinstance(item, dict)
        or set(item)
        != {"id", "user", "volumes", "exposed_ports", "label_count", "onbuild", "environment"}
        or item["id"] != image
        or item["user"] not in (None, "", "0", "0:0")
        or digest(item["volumes"]) != digest({server.DATA: {}})
        or digest(item["exposed_ports"]) != digest({"5432/tcp": {}})
        or type(item["label_count"]) is not int
        or item["label_count"] != 0
        or item["onbuild"] not in (None, [])
    ):
        raise ActivationError("database_server_image_mismatch")
    _environment(item["environment"])
    return {
        "image": image,
        "unexpected_image_volumes_excluded": True,
        "image_provenance_verified": False,
    }


def validate(spec, item, known_id, phase):
    if phase not in {"created", "running"}:
        raise ActivationError("database_server_phase_invalid")
    expected = {
        "id": identifier(known_id),
        "name": "/" + spec["name"],
        "image": spec["image"],
        "image_reference": spec["image"],
        "user": "70:70",
        "entrypoint": spec["entrypoint"],
        "arguments": spec["arguments"],
        "working_directory": "/",
        "stdin_open": False,
        "tty": False,
        "healthcheck": ["NONE"],
        "stop_timeout": 5,
        "stop_signal": "SIGTERM",
        "labels": spec["labels"],
        "label_count": 5,
        "exposed_ports": {"5432/tcp": {}},
        "volumes": {server.DATA: {}},
        "status": phase,
        "running": phase == "running",
        "restarting": False,
        "paused": False,
        "oom_killed": False,
        "exit_code": 0,
        "error_present": False,
    }
    fields = {
        *expected,
        "init",
        "ports",
        "network_names",
        "host",
        "mounts",
        "configured_mounts",
        "environment",
    }
    if (
        not isinstance(item, dict)
        or set(item) != fields
        or any(digest(item[key]) != digest(value) for key, value in expected.items())
        or (item["init"] is not None and item["init"] is not False)
    ):
        raise ActivationError("database_server_config_mismatch")
    _environment(item["environment"])
    probe._validate_host(item, spec["host"])
    networks = [["none", None], [None]] if phase == "created" else [["none", None]]
    if item["network_names"] not in networks or item["ports"] not in (None, {}, {"5432/tcp": None}):
        raise ActivationError("database_server_network_mismatch")
    _validate_mounts(item)


def _validate_mounts(item):
    base = {"propagation": "", "no_copy": None, "policy_source_matches": False}
    volume = {
        **base,
        "type": "volume",
        "name": server.VOLUME,
        "target": server.DATA,
        "writable": True,
    }
    bind = {
        **base,
        "type": "bind",
        "name": None,
        "target": server.HBA,
        "writable": False,
        "propagation": "rprivate",
        "policy_source_matches": True,
    }
    tmpfs = {**base, "type": "tmpfs", "name": None, "target": "/tmp", "writable": True}
    for field, expected in [
        ("mounts", [volume, bind]),
        (
            "configured_mounts",
            [
                {**volume, "no_copy": True},
                {**bind, "no_copy": False},
            ],
        ),
    ]:
        mounts = item[field]
        if not isinstance(mounts, list) or len(mounts) not in (
            {2, 3} if field == "mounts" else {2}
        ):
            raise ActivationError("database_server_mount_mismatch")
        observed = sorted(digest(mount) for mount in mounts)
        allowed = [sorted(digest(mount) for mount in expected)]
        if field == "mounts":
            allowed.append(sorted(digest(mount) for mount in [*expected, tmpfs]))
        if observed not in allowed:
            raise ActivationError("database_server_mount_mismatch")


def review(
    store,
    image,
    known_id,
    phase,
    *,
    policy_root=server.policy.DEFAULT_ROOT,
    docker=None,
    ownership_docker=None,
):
    original = store.review()
    current = original["resources"].get("db")
    if (
        current is None
        or current["resource_id"] != identifier(known_id)
        or current["state"] != "OBSERVED"
    ):
        raise ActivationError("database_server_owned_resource_required")
    spec = server.recipe(store, image, policy_root=policy_root)
    operation, plan = store.summary()["id"], original["header"]["plan_sha256"]
    before = observe(operation, plan, "db", known_id, docker=ownership_docker)
    item = document(
        (docker or DatabaseInspectionDocker()).query(
            "container", image, spec=spec, known_id=known_id
        )
    )
    validate(spec, item, known_id, phase)
    after = observe(operation, plan, "db", known_id, docker=ownership_docker)
    if (
        before != after
        or before["status"] != "present_owned_snapshot"
        or before["details"]["image"] != image
        or before["details"]["running"] is not (phase == "running")
        or digest(server.recipe(store, image, policy_root=policy_root)) != digest(spec)
        or digest(store.review()) != digest(original)
    ):
        raise ActivationError("database_server_runtime_changed")
    return {
        "format": "aegis-original-database-server-runtime-review/1",
        "resource_id": known_id,
        "recipe_sha256": digest(spec),
        "phase": phase,
        "runtime_configuration_verified": True,
        "expected_database_volume_mount_verified": True,
        "fixed_authentication_policy_mount_verified": True,
        "network_none_verified": True,
        "published_ports_absent_verified": True,
        "volume_contents_verified": False,
        "authentication_verified": False,
        "image_provenance_verified": False,
        "effects_authorized": False,
        "normal_operation_permitted": False,
    }
