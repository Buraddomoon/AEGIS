"""Derive the fixed TLS-only Compose scope. Pure data; never starts a container."""

import copy
import re

from aegis.lab_runner.wazuh_network_profile import ADDRESSES, GATEWAYS, SUBNETS

PROJECT = "aegis-wazuh-lab"
SERVICES = ("wazuh.indexer", "wazuh.manager", "wazuh.agent")
VOLUMES = {
    "indexer-data",
    "manager-etc",
    "manager-logs",
    "manager-queue",
    "agent-queue",
    "observations",
}
SECRETS = {"wazuh_ca", "indexer_cert", "indexer_key", "filebeat_cert", "filebeat_key"}


def scoped_compose(rendered: dict, review_id: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", review_id) or rendered.get("name") != PROJECT:
        raise ValueError("invalid_tls_scope_identity")
    selected = {name: copy.deepcopy(rendered["services"][name]) for name in SERVICES}
    volumes, secrets = set(), set()
    for name, service in selected.items():
        if service.get("ports") or service.get("network_mode") or service.get("privileged"):
            raise ValueError("tls_scope_network_or_privilege_expansion")
        if service.get("networks") != {"telemetry": {"ipv4_address": ADDRESSES[name, "telemetry"]}}:
            raise ValueError("tls_scope_fixed_endpoint_required")
        labels = service.setdefault("labels", {})
        if "aegis.tls-assay-id" in labels:
            raise ValueError("tls_scope_label_collision")
        labels["aegis.tls-assay-id"] = review_id
        service.pop("depends_on", None)  # Order is explicit; observer must never start.
        for mount in service.get("volumes", []):
            if "docker.sock" in str(mount.get("source", "")) or "docker.sock" in str(
                mount.get("target", "")
            ):
                raise ValueError("tls_scope_docker_socket_forbidden")
            if mount["type"] == "volume":
                volumes.add(mount["source"])
        secrets.update(item["source"] for item in service.get("secrets", []))
    if volumes != VOLUMES or secrets != SECRETS:
        raise ValueError("tls_scope_storage_or_secret_expansion")
    network = copy.deepcopy(rendered["networks"]["telemetry"])
    if (
        network.get("name") != PROJECT + "_telemetry"
        or network.get("internal") is not True
        or network.get("ipam", {}).get("config")
        != [{"subnet": SUBNETS["telemetry"], "gateway": GATEWAYS["telemetry"]}]
        or network.get("driver_opts", {}).get("com.docker.network.bridge.gateway_mode_ipv4")
        != "isolated"
    ):
        raise ValueError("tls_scope_fixed_network_required")
    network.setdefault("labels", {})["aegis.tls-assay-id"] = review_id
    return {
        "name": PROJECT,
        "services": selected,
        "networks": {"telemetry": network},
        # External volumes cannot be silently created/replaced if an original disappears.
        "volumes": {
            name: {"name": PROJECT + "_" + name, "external": True} for name in sorted(VOLUMES)
        },
        "secrets": {name: copy.deepcopy(rendered["secrets"][name]) for name in sorted(SECRETS)},
    }
