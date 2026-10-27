"""Fixed journal-probe recipe and read-only runtime review; no lifecycle invocation."""

import copy
import json
import subprocess

from aegis.domain.validation import digest
from runner_activation_intents import _hash, resource
from runner_activation_metadata import PROJECT, ActivationError, _execute, document, image_id
from runner_activation_ownership import LABELS, identifier, observe

ROLES = frozenset({"journal-before", "journal-after"})
VOLUME = PROJECT + "_journal"
TMPFS = "rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=10001,gid=10001"
ENTRYPOINT = "/usr/local/bin/python"
MEMORY = 192 * 1024**2
HOST_EXACT = {
    "Privileged": False,
    "ReadonlyRootfs": True,
    "NetworkMode": "none",
    "IpcMode": "private",
    "CgroupnsMode": "private",
    "PidMode": "",
    "UTSMode": "",
    "UsernsMode": "",
    "Memory": MEMORY,
    "MemorySwap": MEMORY,
    "NanoCpus": 500_000_000,
    "PidsLimit": 16,
    "ShmSize": 1024**2,
    "CapDrop": ["ALL"],
    "SecurityOpt": ["no-new-privileges:true"],
    "PublishAllPorts": False,
    "AutoRemove": False,
    "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
    "LogConfig": {"Type": "none", "Config": {}},
    "Tmpfs": {"/tmp": TMPFS},
}
HOST_EMPTY = (
    "CapAdd",
    "Devices",
    "DeviceRequests",
    "DeviceCgroupRules",
    "VolumesFrom",
    "Binds",
    "Links",
    "GroupAdd",
    "PortBindings",
    "ExtraHosts",
    "Sysctls",
    "Dns",
    "DnsOptions",
    "DnsSearch",
)
ENV_FIXED = {
    "PATH": ("/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",),
    "LANG": ("C.UTF-8",),
    "PYTHONDONTWRITEBYTECODE": ("1",),
    "PYTHONUNBUFFERED": ("1",),
    "PIP_DISABLE_PIP_VERSION_CHECK": ("1",),
    "TMPDIR": ("/tmp",),
}
# Image build metadata only; -I and the fixed entrypoint do not consume these.
ENV_METADATA = frozenset({"GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"})


def _environment_projection():
    fixed = [
        f"(eq $e {json.dumps(key + '=' + value)})"
        for key, values in ENV_FIXED.items()
        for value in values
    ]
    metadata = [f"(eq $key {json.dumps(key)})" for key in sorted(ENV_METADATA)]
    return (
        "[{{range $i, $e := .Config.Env}}{{if $i}},{{end}}"
        '{{$key := index (split $e "=") 0}}'
        '{"key":{{json $key}},"valid":{{json (or ' + " ".join(fixed + metadata) + ")}}}{{end}}]"
    )


ENVIRONMENT_FORMAT = _environment_projection()


def recipe(operation_id, plan_sha256, role, image, proof_sha256):
    if role not in ROLES:
        raise ActivationError("journal_probe_role_required")
    expected = resource(operation_id, plan_sha256, role)
    image_id(image)
    _hash(proof_sha256)
    return {
        "format": "aegis-journal-probe-recipe/1",
        **expected,
        "image": image,
        "entrypoint": [ENTRYPOINT],
        "arguments": [
            "-I",
            "-B",
            "-m",
            "aegis.lab_runner.journal_probe",
            "--expected-sha256",
            proof_sha256,
        ],
        "volume": VOLUME,
        "user": "10001:10001",
        "working_directory": "/app",
        "host": copy.deepcopy({**HOST_EXACT, **{key: True for key in HOST_EMPTY}}),
    }


def create_arguments(operation_id, plan_sha256, role, image, proof_sha256):
    """Compile only. Caller must prove existing volume/image and authorization."""
    spec = recipe(operation_id, plan_sha256, role, image, proof_sha256)
    args = [
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        spec["name"],
        "--user",
        spec["user"],
        "--workdir",
        "/app",
        "--entrypoint",
        ENTRYPOINT,
        "--interactive",
        "--read-only",
        "--network",
        "none",
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
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--tmpfs",
        "/tmp:" + TMPFS,
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "LANG=C.UTF-8",
        "--mount",
        "type=volume,source=" + VOLUME + ",target=/state,readonly,volume-nocopy",
    ]
    for key, value in sorted(spec["labels"].items()):
        args.extend(("--label", key + "=" + value))
    return (*args, image, *spec["arguments"])


def _projection(fields):
    return (
        "{"
        + ",".join(
            json.dumps(key) + ":{{json " + expression + "}}" for key, expression in fields.items()
        )
        + "}"
    )


# Mount Sources from Docker's storage paths must never leave the daemon projection.
# Configured volume sources are names, and any bind source is redacted altogether.
EFFECTIVE_MOUNTS = (
    "[{{range $i, $m := .Mounts}}{{if $i}},{{end}}"
    '{"type":{{json $m.Type}},"name":{{json (index $m "Name")}},'
    '"target":{{json $m.Destination}},"writable":{{json $m.RW}},'
    '"propagation":{{json $m.Propagation}}}{{end}}]'
)
CONFIGURED_MOUNTS = (
    '[{{range $i, $m := (index .HostConfig "Mounts")}}{{if $i}},{{end}}'
    '{"type":{{json $m.Type}},"source_name":'
    '{{if eq $m.Type "volume"}}{{json $m.Source}}{{else}}null{{end}},'
    '"target":{{json $m.Target}},"readonly":{{json $m.ReadOnly}},'
    '"no_copy":{{with $m.VolumeOptions}}{{json .NoCopy}}{{else}}false{{end}}}{{end}}]'
)
CONTAINER_FORMAT = (
    _projection(
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
            "status": ".State.Status",
            "running": ".State.Running",
            "restarting": ".State.Restarting",
            "paused": ".State.Paused",
            "oom_killed": ".State.OOMKilled",
            "exit_code": ".State.ExitCode",
            "error_present": '(ne .State.Error "")',
            "ports": ".NetworkSettings.Ports",
            "label_count": "(len .Config.Labels)",
        }
    )[:-1]
    # The final null avoids a trailing-comma ambiguity without returning endpoints.
    + ',"network_names":[{{range $name, $_ := .NetworkSettings.Networks}}{{json $name}},{{end}}null]'
    + ',"labels":'
    + _projection({label: '(index .Config.Labels "' + label + '")' for label in LABELS.values()})
    + ',"host":'
    + _projection(
        {
            **{key: '(index .HostConfig "' + key + '")' for key in HOST_EXACT},
            **{key: '(not (index .HostConfig "' + key + '"))' for key in HOST_EMPTY},
        }
    )
    + ',"mounts":'
    + EFFECTIVE_MOUNTS
    + ',"configured_mounts":'
    + CONFIGURED_MOUNTS
    + ',"environment":'
    + ENVIRONMENT_FORMAT
    + "}"
)
IMAGE_FORMAT = (
    _projection(
        {
            "id": ".Id",
            "user": ".Config.User",
            "volumes": '(index .Config "Volumes")',
        }
    )[:-1]
    + ',"environment":'
    + ENVIRONMENT_FORMAT
    + "}"
)


def command(kind, operation_id, plan_sha256, role, image, proof_sha256, known_id=None):
    recipe(operation_id, plan_sha256, role, image, proof_sha256)
    if kind == "image" and known_id is None:
        return ("image", "inspect", "--format", IMAGE_FORMAT, image)
    if kind == "container" and known_id is not None:
        return ("container", "inspect", "--format", CONTAINER_FORMAT, identifier(known_id))
    raise ActivationError("journal_probe_query_not_allowed")


class ProbeRuntimeDocker:
    def query(self, kind, operation_id, plan_sha256, role, image, proof_sha256, known_id=None):
        try:
            return _execute(
                command(kind, operation_id, plan_sha256, role, image, proof_sha256, known_id)
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            if isinstance(error, ActivationError):
                raise
            raise ActivationError("journal_probe_query_failed") from None


def review_image(operation_id, plan_sha256, role, image, proof_sha256, *, docker=None):
    recipe(operation_id, plan_sha256, role, image, proof_sha256)
    docker = docker or ProbeRuntimeDocker()
    item = document(docker.query("image", operation_id, plan_sha256, role, image, proof_sha256))
    if (
        not isinstance(item, dict)
        or set(item) != {"id", "user", "volumes", "environment"}
        or item["id"] != image
        or item["user"] != "10001:10001"
        or item["volumes"] not in (None, {})
    ):
        raise ActivationError("journal_probe_image_mismatch")
    _validate_environment(item["environment"], image=True)
    return {"image": image, "anonymous_volumes_excluded": True, "image_provenance_verified": False}


def validate(spec, item, known_id, phase):
    """Validate a projection, never expose daemon values in errors or the receipt."""
    if phase not in {"created", "exited"}:
        raise ActivationError("journal_probe_phase_invalid")
    config = {
        "id": identifier(known_id),
        "name": "/" + spec["name"],
        "image": spec["image"],
        "image_reference": spec["image"],
        "user": spec["user"],
        "entrypoint": spec["entrypoint"],
        "arguments": spec["arguments"],
        "working_directory": "/app",
        "stdin_open": True,
        "tty": False,
        "healthcheck": ["NONE"],
        "stop_timeout": 5,
        "labels": spec["labels"],
        "label_count": len(spec["labels"]),
    }
    fields = {
        *config,
        "host",
        "mounts",
        "configured_mounts",
        "network_names",
        "ports",
        "status",
        "running",
        "restarting",
        "paused",
        "oom_killed",
        "exit_code",
        "error_present",
        "environment",
    }
    if (
        not isinstance(item, dict)
        or set(item) != fields
        or any(digest(item[key]) != digest(value) for key, value in config.items())
    ):
        raise ActivationError("journal_probe_config_mismatch")
    _validate_environment(item["environment"])
    host = item["host"]
    if (
        not isinstance(host, dict)
        or set(host) != {*HOST_EXACT, *HOST_EMPTY}
        or any(digest(host[key]) != digest(value) for key, value in HOST_EXACT.items())
        or any(host[key] is not True for key in HOST_EMPTY)
    ):
        raise ActivationError("journal_probe_host_mismatch")
    mounts = item["mounts"]
    expected_mount = {
        "type": "volume",
        "name": VOLUME,
        "target": "/state",
        "writable": False,
        "propagation": "",
    }
    optional_tmpfs = {
        "type": "tmpfs",
        "name": None,
        "target": "/tmp",
        "writable": True,
        "propagation": "",
    }
    if digest(mounts) not in {
        digest([expected_mount]),
        digest([expected_mount, optional_tmpfs]),
        digest([optional_tmpfs, expected_mount]),
    }:
        raise ActivationError("journal_probe_mount_mismatch")
    expected_configured = [
        {
            "type": "volume",
            "source_name": VOLUME,
            "target": "/state",
            "readonly": True,
            "no_copy": True,
        }
    ]
    if digest(item["configured_mounts"]) != digest(expected_configured):
        raise ActivationError("journal_probe_mount_options_mismatch")
    if item["network_names"] not in (
        ["none", None],
        [None] if phase == "created" else ["none", None],
    ) or item["ports"] not in (None, {}):
        raise ActivationError("journal_probe_network_mismatch")
    if (
        item["status"] != phase
        or type(item["exit_code"]) is not int
        or item["exit_code"] != 0
        or any(
            item[key] is not False
            for key in ("running", "restarting", "paused", "oom_killed", "error_present")
        )
    ):
        raise ActivationError("journal_probe_state_mismatch")


def _validate_environment(items, *, image=False):
    if not isinstance(items, list) or len(items) > len(ENV_FIXED) + len(ENV_METADATA):
        raise ActivationError("journal_probe_environment_mismatch")
    keys = set()
    for item in items:
        if (
            not isinstance(item, dict)
            or set(item) != {"key", "valid"}
            or not isinstance(item["key"], str)
            or item["valid"] is not True
            or item["key"] not in {*ENV_FIXED, *ENV_METADATA}
            or item["key"] in keys
        ):
            raise ActivationError("journal_probe_environment_mismatch")
        keys.add(item["key"])
    # Current official Python images may omit LANG. The recipe explicitly sets
    # it and TMPDIR; any inherited value for either must still satisfy policy.
    required = set(ENV_FIXED) - ({"TMPDIR", "LANG"} if image else set())
    if not required <= keys:
        raise ActivationError("journal_probe_environment_mismatch")


def review(
    operation_id,
    plan_sha256,
    role,
    image,
    proof_sha256,
    known_id,
    phase,
    *,
    docker=None,
    ownership_docker=None,
):
    spec = recipe(operation_id, plan_sha256, role, image, proof_sha256)
    identifier(known_id)
    docker = docker or ProbeRuntimeDocker()
    before = observe(operation_id, plan_sha256, role, known_id, docker=ownership_docker)
    item = document(
        docker.query("container", operation_id, plan_sha256, role, image, proof_sha256, known_id)
    )
    validate(spec, item, known_id, phase)
    after = observe(operation_id, plan_sha256, role, known_id, docker=ownership_docker)
    if (
        before != after
        or before["status"] != "present_owned_snapshot"
        or before["details"]["image"] != image
        or before["details"]["running"] is not False
    ):
        raise ActivationError("journal_probe_ownership_changed")
    return {
        "format": "aegis-journal-probe-runtime-review/1",
        "recipe_sha256": digest(spec),
        "resource_id": known_id,
        "role": role,
        "phase": phase,
        "runtime_configuration_verified": True,
        "journal_readonly_mount_verified": True,
        "network_none_verified": True,
        "volume_contents_verified": False,
        "image_provenance_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
