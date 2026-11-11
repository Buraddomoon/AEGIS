"""Closed native rotation recipes and projected physical validation; no effects on import."""

import copy

import runner_activation_database_inspection as database
import runner_activation_database_server as dbserver
import runner_activation_identity_inspection as identity
import runner_activation_probe_runtime as probe
from aegis.domain.validation import digest
from aegis.lab_runner.rotation_probe import MODES
from runner_activation_intents import ROTATION_HELPERS, ROTATION_RUNNERS, resource
from runner_activation_metadata import PROJECT, ActivationError
from runner_activation_ownership import identifier

ROLE_MODES = {"rotation-" + mode: mode for mode in MODES}
JOURNAL_ROLES = frozenset({"rotation-review-before", "rotation-binding", "rotation-review-after"})
ROLES = frozenset({"db", *ROTATION_HELPERS, *ROTATION_RUNNERS})
NETWORK_ROLE = "network-isolated"
STATE_VOLUME = PROJECT + "_journal"
WORK = "rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=10001,gid=10001"
SECRETS = {
    "/run/secrets/controller_server_ca": "server-ca.crt",
    "/run/secrets/controller_client_cert": "runner-client.crt",
    "/run/secrets/controller_client_key": "runner-client.key",
    "/run/secrets/controller_connection": "connection.json",
}
SERVER_SECRETS = {
    "/run/secrets/runner_server_key": "runner-server.key",
    "/run/secrets/runner_server_cert": "runner-server.crt",
    "/run/secrets/runner_client_ca": "client-ca.crt",
}


def recipe(c, role, context_sha256=None, *, policy_root):
    if role not in ROLES:
        raise ActivationError("rotation_runtime_role_invalid")
    state = c.store.review()
    if state["closed"]:
        raise ActivationError("rotation_runtime_operation_closed")
    net = state["resources"].get(NETWORK_ROLE, {})
    network_id = identifier(net.get("resource_id"))
    if net.get("state") != "OBSERVED":
        raise ActivationError("rotation_runtime_owned_network_required")
    images = {k: c.artifact["metadata"]["images"][k]["id"] for k in ("runner", "postgres")}
    if role == "db":
        spec = dbserver.recipe(c.store, images["postgres"], policy_root=policy_root)
        spec["host"]["NetworkMode"] = network_id
        spec["network_resource_id"] = network_id
        spec["network_name"] = resource(c.operation, c.plan_sha256, NETWORK_ROLE)["name"]
        spec["ipv4_address"] = "192.168.253.4"
        # The server exposes only loopback to administrative namespace sharers.
        # Original schema/grants must already be b7; this never runs a migration.
        args = spec["arguments"]
        args[args.index("default_transaction_read_only=on")] = "default_transaction_read_only=off"
        return spec
    runner = role in ROTATION_RUNNERS
    if runner:
        network_mode, ip = network_id, "192.168.253.2"
    else:
        database_id = state["resources"].get("db", {}).get("resource_id")
        network_mode, ip = "container:" + identifier(database_id), None
        if (
            type(context_sha256) is not str
            or len(context_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in context_sha256)
        ):
            raise ActivationError("rotation_runtime_context_hash_required")
    candidate = c.artifact["candidate_path"]
    selected = SERVER_SECRETS if runner else SECRETS
    mounts = {target: candidate + "/" + name for target, name in selected.items()}
    if any(any(ch in source for ch in (",", "\n", "\r", "\0")) for source in mounts.values()):
        raise ActivationError("rotation_runtime_secret_path_invalid")
    environment = {"LANG": "C.UTF-8", "TMPDIR": "/tmp"}
    if runner:
        environment |= {
            "AEGIS_RUNNER_" + k.upper(): v for k, v in c.artifact["pki"]["identities"].items()
        }
        environment["AEGIS_RUNNER_IDENTITY_ONLY"] = "false"
    host = copy.deepcopy(probe.HOST_EXACT | dict.fromkeys(probe.HOST_EMPTY, True))
    host["NetworkMode"] = network_mode
    if runner:
        host["Tmpfs"]["/work"] = WORK
        host["PidsLimit"] = 32
        host["Memory"] = host["MemorySwap"] = 256 * 1024**2
    volume = STATE_VOLUME if runner or role in JOURNAL_ROLES else None
    return {
        "format": "aegis-rotation-container-recipe/1",
        **resource(c.operation, c.plan_sha256, role),
        "image": images["runner"],
        "user": "10001:10001",
        "working_directory": "/app",
        "entrypoint": [probe.ENTRYPOINT],
        "stdin_open": not runner,
        "arguments": ["-I", "-B", "-m", "aegis.lab_runner.server"]
        if runner
        else [
            "-I",
            "-B",
            "-m",
            "aegis.lab_runner.rotation_probe",
            "--context-sha256",
            context_sha256,
        ],
        "environment": environment,
        "host": host,
        "mount_sources": mounts,
        "volume": volume,
        "volume_readonly": not runner,
        "network_resource_id": network_id,
        "network_mode": network_mode,
        "network_name": resource(c.operation, c.plan_sha256, NETWORK_ROLE)["name"],
        "ipv4_address": ip,
    }


def create_arguments(spec):
    role = spec["role"]
    if role not in ROLES:
        raise ActivationError("rotation_runtime_role_invalid")
    host = spec["host"]
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
        spec["working_directory"],
        "--entrypoint",
        spec["entrypoint"][0],
        "--read-only",
        "--network",
        host["NetworkMode"],
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        str(host["Memory"]),
        "--memory-swap",
        str(host["MemorySwap"]),
        "--cpus",
        str(host["NanoCpus"] / 1e9),
        "--pids-limit",
        str(host["PidsLimit"]),
        "--shm-size",
        str(host["ShmSize"]),
        "--restart",
        "no",
        "--stop-timeout",
        "5",
        "--stop-signal",
        "SIGTERM",
        "--no-healthcheck",
        "--log-driver",
        "none",
    ]
    if spec["stdin_open"]:
        args.append("--interactive")
    if spec["ipv4_address"]:
        args += ["--ip", spec["ipv4_address"]]
    for target, options in sorted(host["Tmpfs"].items()):
        args += ["--tmpfs", target + ":" + options]
    for k, v in sorted(
        spec.get("environment", {"LANG": "C.UTF-8", "PGDATA": dbserver.DATA}).items()
    ):
        args += ["--env", k + "=" + v]
    for k, v in sorted(spec["labels"].items()):
        args += ["--label", k + "=" + v]
    if role == "db":
        args += [
            "--mount",
            "type=volume,source=" + dbserver.VOLUME + ",target=" + dbserver.DATA + ",volume-nocopy",
            "--mount",
            "type=bind,source="
            + spec["policy_path"]
            + ",target="
            + dbserver.HBA
            + ",readonly,bind-propagation=rprivate",
        ]
    else:
        for target, source in sorted(spec["mount_sources"].items()):
            args += [
                "--mount",
                "type=bind,source="
                + source
                + ",target="
                + target
                + ",readonly,bind-propagation=rprivate",
            ]
        if spec["volume"]:
            args += [
                "--mount",
                "type=volume,source="
                + STATE_VOLUME
                + ",target=/state,volume-nocopy"
                + (",readonly" if spec["volume_readonly"] else ""),
            ]
    return (*args, spec["image"], *spec["arguments"])


def _volume_projection(effective):
    collection, target = (
        (".Mounts", "$m.Destination")
        if effective
        else ('(index .HostConfig "Mounts")', "$m.Target")
    )
    return (
        "[{{range $i,$m := "
        + collection
        + '}}{{if $i}},{{end}}{"type":{{json $m.Type}},"target":{{json '
        + target
        + '}},"name":{{if eq $m.Type "volume"}}{{json '
        + ('(index $m "Name")' if effective else "$m.Source")
        + '}}{{else}}null{{end}},"writable":{{json '
        + ("$m.RW" if effective else '(not (index $m "ReadOnly"))')
        + '}},"no_copy":'
        + (
            "null"
            if effective
            else '{{with (index $m "VolumeOptions")}}{{json (or (index . "NoCopy") false)}}{{else}}false{{end}}'
        )
        + "}{{end}}]"
    )


def container_format(spec):
    template = (
        database.container_format(spec) if spec["role"] == "db" else identity.container_format(spec)
    )
    return (
        template[:-1]
        + ',"native_volumes":'
        + _volume_projection(True)
        + ',"native_configured":'
        + _volume_projection(False)
        + "}"
    )


def validate(spec, value, known_id, phase):
    item = copy.deepcopy(value)
    volumes, configured = item.pop("native_volumes"), item.pop("native_configured")
    expected_volume = dbserver.VOLUME if spec["role"] == "db" else spec["volume"]
    target = dbserver.DATA if spec["role"] == "db" else "/state"
    writable = spec["role"] == "db" or spec["role"] in ROTATION_RUNNERS
    for actual, effective in ((volumes, True), (configured, False)):
        targets = {v["target"] for v in actual}
        if len(targets) != len(actual):
            raise ActivationError("rotation_runtime_duplicate_mount")
        allowed = {k: "bind" for k in spec.get("mount_sources", {})}
        if spec["role"] == "db":
            allowed[dbserver.HBA] = "bind"
        if expected_volume is not None:
            allowed[target] = "volume"
        if effective:
            allowed |= {k: "tmpfs" for k in spec["host"]["Tmpfs"]}
        if any(allowed.get(v["target"]) != v["type"] for v in actual):
            raise ActivationError("rotation_runtime_extra_or_wrong_mount")
        selected = [v for v in actual if v["type"] == "volume"]
        expected = (
            []
            if expected_volume is None
            else [
                {
                    "type": "volume",
                    "target": target,
                    "name": expected_volume,
                    "writable": writable,
                    "no_copy": None if effective else True,
                }
            ]
        )
        if digest(selected) != digest(expected):
            raise ActivationError("rotation_runtime_volume_mismatch")
    if spec["role"] == "db":
        if item["network_names"] not in (
            [spec["network_name"], None],
            [None] if phase == "created" else [],
        ):
            raise ActivationError("rotation_database_network_mismatch")
        item["network_names"] = ["none", None]
        database.validate(spec, item, known_id, phase)
    elif spec["role"] in ROTATION_RUNNERS:
        for field in ("mounts", "configured_mounts"):
            item[field] = [v for v in item[field] if v["target"] not in {"/state", "/work"}]
        identity._configuration(spec, item, known_id, phase, ip="192.168.253.2", stdin_open=False)
    else:
        if (
            item["network_names"] != [None]
            or item["endpoints"] != [None]
            or item["ports"] not in (None, {})
        ):
            raise ActivationError("rotation_admin_namespace_mismatch")
        # Reuse exact UID/argv/process/host/environment guards without inferring
        # journal mounts or connectivity from a Docker namespace name alone.
        probe._validate_process(
            spec,
            item,
            known_id,
            phase,
            additional_fields=("init", "stop_signal", "volumes", "exposed_ports", "endpoints"),
        )
        probe._validate_host(item, spec["host"])
        if (
            (item["init"] is not None and item["init"] is not False)
            or item["volumes"] not in (None, {})
            or item["exposed_ports"] not in (None, {})
            or item["stop_signal"] != "SIGTERM"
        ):
            raise ActivationError("rotation_admin_configuration_mismatch")
        for field, effective in (("mounts", True), ("configured_mounts", False)):
            actual = item[field]
            binds = [v for v in actual if v["type"] == "bind"]
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
            if sorted(map(digest, binds)) != sorted(map(digest, expected)):
                raise ActivationError("rotation_admin_secret_mount_mismatch")
            allowed = (
                set(spec["mount_sources"]) | ({"/state"} if expected_volume else set()) | {"/tmp"}
            )
            if any(
                v["target"] not in allowed or v["type"] not in {"bind", "volume", "tmpfs"}
                for v in actual
            ):
                raise ActivationError("rotation_admin_extra_mount")
    return {"recipe_sha256": digest(spec), "configuration_sha256": digest(value), "phase": phase}
