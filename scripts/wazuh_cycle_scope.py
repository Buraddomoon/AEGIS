"""Compile the bounded nine-service Wazuh renewal. Pure data, no lifecycle."""

import copy
import re
from dataclasses import dataclass
from pathlib import Path

from aegis.lab_runner.wazuh_network_profile import (
    ADDRESSES,
    GATEWAYS,
    INDEXER_IP,
    INDEXER_URL,
    SUBNETS,
)
from inspect_wazuh_lab import HARDENED, MEMORY, NETWORKS, expected_mounts

PROJECT = "aegis-wazuh-lab"
SERVICES = frozenset(NETWORKS) - {"migrate"}
IMAGE_ROLES = {"application", "runner", "postgres", "redis", "indexer", "manager", "agent"}
RUNNER_SECRETS = {
    "controller_server_ca": "server-ca.crt",
    "controller_client_cert": "runner-client.crt",
    "controller_client_key": "runner-client.key",
    "controller_connection": "connection.json",
    "runner_server_key": "runner-server.key",
    "runner_server_cert": "runner-server.crt",
    "runner_client_ca": "client-ca.crt",
}
SERVICE_SECRETS = {
    "wazuh_ca": "root-ca.pem",
    "indexer_cert": "indexer.pem",
    "indexer_key": "indexer-key.pem",
    "filebeat_cert": "filebeat.pem",
    "filebeat_key": "filebeat-key.pem",
}


@dataclass(frozen=True)
class CycleProfile:
    review_id: str
    source: Path
    runner_candidate: Path
    service_candidate: Path
    images: dict[str, str]

    def document(self):
        return {
            "review_id": self.review_id,
            "source": str(self.source),
            "runner_candidate": str(self.runner_candidate),
            "service_candidate": str(self.service_candidate),
            "images": dict(self.images),
        }

    def check(self):
        if not re.fullmatch(r"[a-f0-9]{32}", self.review_id):
            raise ValueError("cycle_review_identity_invalid")
        if set(self.images) != IMAGE_ROLES or any(
            not re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in self.images.values()
        ):
            raise ValueError("cycle_exact_image_ids_required")
        paths = (self.source, self.runner_candidate, self.service_candidate)
        if any(
            not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
            for path in paths
        ):
            raise ValueError("cycle_absolute_paths_required")
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("cycle_separate_candidates_required")

    def image_for(self, service):
        role = (
            "application"
            if service in {"api", "worker"}
            else "runner"
            if service in {"runner", "observer"}
            else "postgres"
            if service == "db"
            else service.removeprefix("wazuh.")
        )
        if service not in SERVICES:
            raise ValueError("cycle_service_not_allowed")
        return self.images[role]


def secret_files(profile):
    return {
        **{name: str(profile.runner_candidate / file) for name, file in RUNNER_SECRETS.items()},
        **{
            name: str(profile.service_candidate / "pki" / file)
            for name, file in SERVICE_SECRETS.items()
        },
        "wazuh_collection": str(profile.source / "collection.json"),
    }


def scoped_compose(rendered: dict, profile: CycleProfile) -> dict:
    """Select current images/PKI without migrate, seed, enrollment or new volumes.

    The caller must pin and recheck source/candidate hashes separately. This
    compiler does not read keys, attest runtime or authorize starting anything.
    """
    profile.check()
    if rendered.get("name") != PROJECT or set(rendered.get("services", {})) != set(NETWORKS):
        raise ValueError("cycle_exact_source_services_required")
    selected = {name: copy.deepcopy(rendered["services"][name]) for name in sorted(SERVICES)}
    volumes, secrets = set(), set()
    expected = expected_mounts(profile.source)
    for name, service in selected.items():
        if service.get("privileged") or service.get("network_mode") not in (None, "none"):
            raise ValueError("cycle_privilege_or_network_expansion")
        if service.get("network_mode") == "none":
            if name != "observer" or service.get("networks"):
                raise ValueError("cycle_observer_offline_required")
        elif set(service.get("networks", {})) != NETWORKS[name]:
            raise ValueError("cycle_exact_networks_required")
        for (member, network), address in ADDRESSES.items():
            if (
                member == name
                and service.get("networks", {}).get(network, {}).get("ipv4_address") != address
            ):
                raise ValueError("cycle_fixed_endpoint_required")
        if str(service.get("mem_limit")) != str(MEMORY[name] * 1024**2):
            raise ValueError("cycle_memory_limit_changed")
        environment = service.get("environment", {})
        if name in {"api", "worker"} and (
            environment.get("WAZUH_URL") != INDEXER_URL
            or environment.get("WAZUH_ALLOWED_IP") != INDEXER_IP
            or environment.get("WAZUH_USERNAME") != "aegis_reader"
        ):
            raise ValueError("cycle_fixed_reader_destination_required")
        if name == "wazuh.manager" and environment.get("FILEBEAT_SSL_VERIFICATION_MODE") != "full":
            raise ValueError("cycle_full_tls_verification_required")
        if name in HARDENED and service.get("cap_drop") != ["ALL"]:
            raise ValueError("cycle_capabilities_changed")
        if name in HARDENED - {"wazuh.indexer"} and service.get("read_only") is not True:
            raise ValueError("cycle_readonly_root_required")
        ports = service.get("ports", [])
        if name != "api" and ports:
            raise ValueError("cycle_published_service_port")
        if name == "api" and (
            len(ports) != 1
            or ports[0].get("host_ip") != "127.0.0.1"
            or str(ports[0].get("published")) != "18786"
            or ports[0].get("target") != 8080
        ):
            raise ValueError("cycle_loopback_api_required")
        mounts = {}
        for mount in service.get("volumes", []):
            target = mount["target"]
            if target in mounts:
                raise ValueError("cycle_duplicate_mount")
            kind, source = mount["type"], mount["source"]
            if kind == "volume":
                volumes.add(source)
                source = PROJECT + "_" + source
            elif kind != "bind" or mount.get("bind", {}).get("create_host_path") is not False:
                raise ValueError("cycle_explicit_file_mount_required")
            mounts[target] = kind, source, not mount.get("read_only", False)
        for secret in service.get("secrets", []):
            key = secret["source"]
            secrets.add(key)
            target = secret.get("target", key)
            target = target if target.startswith("/") else "/run/secrets/" + target
            if target in mounts:
                raise ValueError("cycle_duplicate_mount")
            mounts[target] = "bind", rendered["secrets"][key]["file"], False
        if mounts != expected[name]:
            raise ValueError("cycle_source_mounts_changed")
        service.pop("build", None)
        service["image"] = profile.image_for(name)
        service["pull_policy"] = "never"
        service["restart"] = "no"
        dependencies = service.get("depends_on", {})
        if not set(dependencies) <= SERVICES | {"migrate"}:
            raise ValueError("cycle_dependency_expansion")
        dependencies.pop("migrate", None)
        labels = service.setdefault("labels", {})
        if "aegis.cycle-review-id" in labels:
            raise ValueError("cycle_review_label_collision")
        labels["aegis.cycle-review-id"] = profile.review_id
    if secrets != set(secret_files(profile)):
        raise ValueError("cycle_secret_scope_changed")
    for name in ("isolated", "telemetry"):
        network = rendered["networks"][name]
        if (
            network.get("name") != PROJECT + "_" + name
            or network.get("internal") is not True
            or network.get("enable_ipv6", False) is not False
            or network.get("ipam", {}).get("config")
            != [{"subnet": SUBNETS[name], "gateway": GATEWAYS[name]}]
            or network.get("driver_opts", {}).get("com.docker.network.bridge.gateway_mode_ipv4")
            != "isolated"
        ):
            raise ValueError("cycle_fixed_subnets_required")
    result = {
        "name": PROJECT,
        "services": selected,
        "networks": copy.deepcopy(rendered["networks"]),
        "volumes": {
            name: {"name": PROJECT + "_" + name, "external": True} for name in sorted(volumes)
        },
        "secrets": {name: {"file": file} for name, file in secret_files(profile).items()},
    }
    if set(result["networks"]) != {"backend", "ingress", "isolated", "telemetry"}:
        raise ValueError("cycle_network_inventory_changed")
    return result
