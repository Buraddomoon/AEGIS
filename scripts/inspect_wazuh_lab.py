"""Read-only Docker isolation checks for the exact authorized Wazuh project.

This does not start services, execute inside containers, query a SIEM or approve
a marker. A passing inspection is only one prerequisite of labs/wazuh/ASSAY.md.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path

from wazuh_lab import DOCKER, IMAGES, PRIVATE, PROJECT, ROOT, execute

MIB = 1024**2
NETWORKS = {
    "db": {"backend"},
    "redis": {"backend"},
    "migrate": {"backend"},
    "api": {"backend", "ingress", "isolated", "telemetry"},
    "worker": {"backend", "isolated", "telemetry"},
    "runner": {"isolated"},
    "observer": {"none"},
    "wazuh.indexer": {"telemetry"},
    "wazuh.manager": {"telemetry"},
    "wazuh.agent": {"telemetry"},
}
MEMORY = {
    "db": 384,
    "redis": 128,
    "migrate": 256,
    "api": 512,
    "worker": 256,
    "runner": 192,
    "observer": 96,
    "wazuh.indexer": 3072,
    "wazuh.manager": 2048,
    "wazuh.agent": 256,
}
LIMITS = {
    "runner": (64, 1_000_000_000),
    "observer": (16, 250_000_000),
    "wazuh.indexer": (512, 2_000_000_000),
    "wazuh.manager": (384, 1_500_000_000),
    "wazuh.agent": (128, 500_000_000),
}
HARDENED = {"runner", "observer", "api", "worker", "wazuh.indexer"}
ADDRESSES = {
    ("runner", "isolated"): "172.30.89.2",
    ("api", "isolated"): "172.30.89.4",
    ("worker", "isolated"): "172.30.89.5",
    ("wazuh.indexer", "telemetry"): "172.30.90.2",
    ("wazuh.manager", "telemetry"): "172.30.90.3",
    ("wazuh.agent", "telemetry"): "172.30.90.4",
    ("api", "telemetry"): "172.30.90.5",
    ("worker", "telemetry"): "172.30.90.6",
}


def expected_mounts(private: Path) -> dict[str, dict[str, tuple[str, str, bool]]]:
    """Explicit reviewed bind/volume allowlist, independent of rendered Compose."""

    def volume(name, writable=True):
        return "volume", PROJECT + "_" + name, writable

    def bind(path):
        return "bind", str(path), False

    def secret(name, filename):
        return "/run/secrets/" + name, bind(private / filename)

    controller = dict(
        secret(name, "runner/" + filename)
        for name, filename in (
            ("controller_server_ca", "server-ca.crt"),
            ("controller_client_cert", "runner-client.crt"),
            ("controller_client_key", "runner-client.key"),
            ("controller_connection", "connection.json"),
        )
    )
    application = {
        **controller,
        **dict(
            secret(name, filename)
            for name, filename in (
                ("wazuh_ca", "pki/root-ca.pem"),
                ("wazuh_collection", "collection.json"),
            )
        ),
    }
    indexer = {
        "/var/lib/wazuh-indexer": volume("indexer-data"),
        "/usr/share/wazuh-indexer/config/opensearch.yml": bind(
            ROOT / "labs/wazuh/config/indexer.yml"
        ),
    }
    for name, path in (
        ("roles.yml", ROOT / "labs/wazuh/config/roles.yml"),
        ("roles_mapping.yml", ROOT / "labs/wazuh/config/roles_mapping.yml"),
        ("internal_users.yml", private / "internal_users.yml"),
    ):
        indexer["/usr/share/wazuh-indexer/config/opensearch-security/" + name] = bind(path)
    for name in ("root-ca.pem", "indexer.pem", "indexer-key.pem"):
        indexer["/usr/share/wazuh-indexer/config/certs/" + name] = bind(private / "pki" / name)
    manager = {
        "/var/ossec/etc": volume("manager-etc"),
        "/var/ossec/logs": volume("manager-logs"),
        "/var/ossec/queue": volume("manager-queue"),
        "/wazuh-config-mount/etc/ossec.conf": bind(ROOT / "labs/wazuh/config/manager.xml"),
        "/wazuh-config-mount/api/configuration/api.yaml": bind(ROOT / "labs/wazuh/config/api.yml"),
        "/wazuh-config-mount/etc/rules/aegis_marker.xml": bind(
            ROOT / "labs/wazuh/rules.example.xml"
        ),
        "/wazuh-config-mount/etc/client.keys": bind(private / "client.keys"),
        **dict(
            secret(name, "pki/" + filename)
            for name, filename in (
                ("wazuh_ca", "root-ca.pem"),
                ("filebeat_cert", "filebeat.pem"),
                ("filebeat_key", "filebeat-key.pem"),
            )
        ),
    }
    return {
        "db": {"/var/lib/postgresql/data": volume("postgres-data")},
        "redis": {},
        "migrate": {},
        "api": application,
        "worker": application,
        "runner": {
            "/state": volume("journal"),
            "/work": volume("workspace"),
            **dict(
                secret(name, "runner/" + filename)
                for name, filename in (
                    ("runner_server_key", "runner-server.key"),
                    ("runner_server_cert", "runner-server.crt"),
                    ("runner_client_ca", "client-ca.crt"),
                )
            ),
        },
        "observer": {
            "/work": volume("workspace", False),
            "/observation-log": volume("observations"),
        },
        "wazuh.indexer": indexer,
        "wazuh.manager": manager,
        "wazuh.agent": {
            "/var/log/aegis": volume("observations", False),
            "/var/ossec/queue": volume("agent-queue"),
            "/wazuh-config-mount/etc/ossec.conf": bind(ROOT / "labs/wazuh/config/agent.xml"),
            "/wazuh-config-mount/etc/client.keys": bind(private / "client.keys"),
        },
    }


def validate(
    containers: list[dict], networks: list[dict], volumes: list[dict], *, private=PRIVATE
) -> dict[str, bool]:
    """Return only fixed check names and booleans; never echo daemon data/secrets."""
    checks = {}
    services = {}
    for item in containers:
        name = item.get("service")
        if (
            name not in NETWORKS
            or name in services
            or item.get("project") != PROJECT
            or item.get("oneoff", "").lower() != "false"
        ):
            return {"project_membership": False}
        services[name] = item
    checks["project_membership"] = set(services) == set(NETWORKS)
    checks["container_identities"] = len({item["id"] for item in containers}) == len(containers)
    mounts = expected_mounts(private)
    for name, item in services.items():
        host = item["host"]
        checks[name + ".state"] = (
            item["status"] == "exited" and item["exit_code"] == 0
            if name == "migrate"
            else item["status"] == "running" and not item["restarting"] and not item["oom_killed"]
        )
        checks[name + ".health"] = (
            name not in {"api", "db", "redis", "observer"} or item["health"] == "healthy"
        )
        checks[name + ".namespaces"] = (
            not host["Privileged"]
            and not host["CapAdd"]
            and not host["Devices"]
            and not host["DeviceRequests"]
            and not host["VolumesFrom"]
            and host["PidMode"] == ""
            and host["IpcMode"] in {"private", ""}
            and host["UTSMode"] == ""
            and host["CgroupnsMode"] != "host"
            and host["NetworkMode"]
            in {"none" if key == "none" else PROJECT + "_" + key for key in NETWORKS[name]}
        )
        checks[name + ".memory"] = host["Memory"] == MEMORY[name] * MIB
        if name in LIMITS:
            checks[name + ".process_cpu_limits"] = (host["PidsLimit"], host["NanoCpus"]) == LIMITS[
                name
            ]
        checks[name + ".security_options"] = (host["SecurityOpt"] or []) == (
            ["no-new-privileges:true"]
            if name in HARDENED | {"wazuh.manager", "wazuh.agent"}
            else []
        )
        if name in HARDENED:
            checks[name + ".capabilities"] = host["CapDrop"] == ["ALL"]
            checks[name + ".user"] = item["user"] == (
                "1000:0" if name == "wazuh.indexer" else "10001:10001"
            )
            if name != "wazuh.indexer":
                checks[name + ".readonly_root"] = host["ReadonlyRootfs"] is True
        expected_ports = (
            {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18786"}]} if name == "api" else {}
        )
        checks[name + ".ports"] = (
            (host["PortBindings"] or {}) == expected_ports
            and {key: value for key, value in (item["ports"] or {}).items() if value}
            == expected_ports
            and not host["PublishAllPorts"]
        )
        actual_networks = item["networks"]
        checks[name + ".networks"] = set(actual_networks) == {
            "none" if key == "none" else PROJECT + "_" + key for key in NETWORKS[name]
        }
        for (service, network), address in ADDRESSES.items():
            if service == name:
                checks[name + ".address." + network] = (
                    actual_networks.get(PROJECT + "_" + network, {}).get("IPAddress") == address
                )
        checks[name + ".observer_offline"] = name != "observer" or host["NetworkMode"] == "none"
        actual_mounts = item["mounts"]
        checks[name + ".mounts"] = (
            len(actual_mounts) == len(mounts[name])
            and {
                mount["Destination"]: (
                    mount["Type"],
                    mount.get("Name") if mount["Type"] == "volume" else mount["Source"],
                    mount["RW"],
                )
                for mount in actual_mounts
            }
            == mounts[name]
        )
        checks[name + ".tmpfs"] = set(host["Tmpfs"] or {}) == (
            {"/tmp"} if name in {"api", "worker"} else set()
        )
        expected_image = (
            IMAGES[name.removeprefix("wazuh.")]
            if name.startswith("wazuh.")
            else (
                "aegis-wazuh-runner:local"
                if name in {"runner", "observer"}
                else "aegis-wazuh-platform:local"
                if name in {"api", "worker", "migrate"}
                else {"db": "postgres:17-alpine", "redis": "redis:8-alpine"}[name]
            )
        )
        checks[name + ".image"] = item["image_reference"] == expected_image
    network_map = {item["Name"]: item for item in networks}
    checks["network_inventory"] = len(networks) == 4 and set(network_map) == {
        PROJECT + "_" + name for name in ("backend", "ingress", "isolated", "telemetry")
    }
    for name in ("backend", "ingress", "isolated", "telemetry"):
        item = network_map.get(PROJECT + "_" + name, {})
        checks["network." + name] = (
            item.get("Driver") == "bridge"
            and item.get("Internal") is (name != "ingress")
            and item.get("EnableIPv6") is False
            and (item.get("Labels") or {}).get("com.docker.compose.project") == PROJECT
        )
        allowed = {
            service["id"]
            for key, service in services.items()
            if name in NETWORKS[key] and service["status"] == "running"
        }
        checks["network." + name + ".members"] = set(item.get("Containers") or {}) == allowed
        if name in {"isolated", "telemetry"}:
            checks["network." + name + ".gateway"] = (item.get("Options") or {}).get(
                "com.docker.network.bridge.gateway_mode_ipv4"
            ) == "isolated"
            checks["network." + name + ".subnet"] = [
                entry.get("Subnet") for entry in (item.get("IPAM") or {}).get("Config", [])
            ] == ["172.30.89.0/29" if name == "isolated" else "172.30.90.0/29"]
    expected_volumes = {
        spec[1] for service in mounts.values() for spec in service.values() if spec[0] == "volume"
    }
    volume_map = {item["Name"]: item for item in volumes}
    checks["volume_inventory"] = (
        len(volume_map) == len(volumes) and set(volume_map) == expected_volumes
    )
    checks["volume_ownership"] = all(
        item.get("Driver") == "local"
        and (item.get("Labels") or {}).get("com.docker.compose.project") == PROJECT
        and item.get("Scope") == "local"
        for item in volumes
    )
    for name, item in volume_map.items():
        if name not in expected_volumes:
            continue
        if name == PROJECT + "_workspace":
            options = item.get("Options") or {}
            checks["workspace.tmpfs"] = (
                options.get("type") == "tmpfs"
                and options.get("device") == "tmpfs"
                and set(options.get("o", "").split(","))
                == {"size=1m", "uid=10001", "gid=10001", "mode=0700", "noexec", "nosuid", "nodev"}
                and set(options) == {"type", "device", "o"}
            )
        else:
            checks["volume." + name.removeprefix(PROJECT + "_") + ".local_storage"] = not item.get(
                "Options"
            )
    return checks


def projection(fields: dict[str, str]) -> str:
    """Go template with an explicit field allowlist, excluding Config.Env."""
    return (
        "{"
        + ",".join(json.dumps(key) + ":{{json " + value + "}}" for key, value in fields.items())
        + "}"
    )


HOST_FIELDS = (
    "Privileged",
    "CapAdd",
    "Devices",
    "DeviceRequests",
    "VolumesFrom",
    "PidMode",
    "IpcMode",
    "UTSMode",
    "CgroupnsMode",
    "NetworkMode",
    "Memory",
    "PidsLimit",
    "NanoCpus",
    "SecurityOpt",
    "CapDrop",
    "ReadonlyRootfs",
    "PortBindings",
    "PublishAllPorts",
    "Tmpfs",
)
CONTAINER_FORMAT = (
    projection(
        {
            "id": ".Id",
            "service": '(index .Config.Labels "com.docker.compose.service")',
            "project": '(index .Config.Labels "com.docker.compose.project")',
            "oneoff": '(index .Config.Labels "com.docker.compose.oneoff")',
            "status": ".State.Status",
            "exit_code": ".State.ExitCode",
            "restarting": ".State.Restarting",
            "oom_killed": ".State.OOMKilled",
            "user": ".Config.User",
            "image_reference": ".Config.Image",
            "ports": ".NetworkSettings.Ports",
            "networks": ".NetworkSettings.Networks",
            "mounts": ".Mounts",
        }
    )[:-1]
    + ',"host":'
    + projection({name: ".HostConfig." + name for name in HOST_FIELDS})
    + ',"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}}}'
)
PROJECT_LABEL = ',"Labels":{"com.docker.compose.project":{{json (index .Labels "com.docker.compose.project")}}}}'
NETWORK_FORMAT = (
    projection(
        {
            name: "." + name
            for name in (
                "Name",
                "Driver",
                "Internal",
                "EnableIPv6",
                "Options",
                "IPAM",
                "Containers",
            )
        }
    )[:-1]
    + PROJECT_LABEL
)
VOLUME_FORMAT = (
    projection(
        {
            name: "." + name
            for name in (
                "Name",
                "Driver",
                "Scope",
                "Options",
            )
        }
    )[:-1]
    + PROJECT_LABEL
)


def collect() -> tuple[list[dict], list[dict], list[dict]]:
    """Only ps/ls/inspect on the explicit local daemon; no exec/up/run/search."""
    snapshots = []
    for kind, listing, template, limit in (
        ("container", ["ps", "--all", "--quiet", "--no-trunc"], CONTAINER_FORMAT, 16),
        ("network", ["network", "ls", "--quiet", "--no-trunc"], NETWORK_FORMAT, 8),
        ("volume", ["volume", "ls", "--quiet"], VOLUME_FORMAT, 16),
    ):
        identifiers = execute(
            [*DOCKER, *listing, "--filter", "label=com.docker.compose.project=" + PROJECT],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()
        if (
            not identifiers
            or len(identifiers) > limit
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value) for value in identifiers)
        ):
            raise ValueError("Inventário local ausente ou incompatível; nenhum ensaio iniciado.")
        output = execute(
            [*DOCKER, "inspect", "--type", kind, "--format", template, *identifiers],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        items = [json.loads(line) for line in output.splitlines()]
        if len(items) != len(identifiers) or any(not isinstance(item, dict) for item in items):
            raise ValueError("Snapshot Docker incompleto; inspeção não aprovada.")
        snapshots.append(items)
    return tuple(snapshots)


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        checks = validate(*collect())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        # No raw Docker diagnostics, paths, env, daemon responses or secret values.
        print(
            json.dumps(
                {
                    "inspection_completed": False,
                    "isolation_verified": False,
                    "reason": "Laboratório ausente ou inspeção local indisponível/incompatível; não executar marcador.",
                },
                ensure_ascii=False,
            )
        )
        return 1
    passed = bool(checks) and all(checks.values())
    print(
        json.dumps(
            {
                "inspection_completed": True,
                "isolation_verified": passed,
                "checks": checks,
                "limitation": "Metadados Docker somente. Ainda exige conferir mounts/permissões dentro dos containers, mTLS, agente Active, regra, ingestão e permissões Indexer. Não autoriza início ou marcador.",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
