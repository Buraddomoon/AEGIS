"""Fixed rotation-network compiler and read-only inspection; no network lifecycle."""

import subprocess

import runner_activation_probe_runtime as projection
from aegis.domain.validation import digest
from runner_activation_intents import resource
from runner_activation_metadata import ActivationError, _execute, document
from runner_activation_ownership import LABELS, identifier, observe

ROLE = "network-isolated"
SUBNET = "172.30.88.0/29"
GATEWAY = "172.30.88.1"
OPTIONS = {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
FORMAT = (
    projection._projection(
        {
            "id": ".Id",
            "name": ".Name",
            "driver": ".Driver",
            "scope": ".Scope",
            "internal": ".Internal",
            "ipv4": '(index . "EnableIPv4")',
            "ipv6": ".EnableIPv6",
            "attachable": ".Attachable",
            "ingress": ".Ingress",
            "config_only": '(index . "ConfigOnly")',
            "config_from": '(index . "ConfigFrom")',
            "ipam": ".IPAM",
            "options": ".Options",
            "containers": ".Containers",
        }
    )[:-1]
    + ',"label_count":{{with (index . "Labels")}}{{len .}}{{else}}0{{end}},"labels":'
    + projection._projection(
        {label: '(index .Labels "' + label + '")' for label in LABELS.values()}
    )
    + "}"
)


def recipe(store):
    state = store.review()
    if state["closed"]:
        raise ActivationError("isolated_network_open_operation_required")
    return {
        "format": "aegis-isolated-rotation-network/1",
        **resource(store.summary()["id"], state["header"]["plan_sha256"], ROLE),
        "driver": "bridge",
        "scope": "local",
        "subnet": SUBNET,
        "gateway": GATEWAY,
        "options": dict(OPTIONS),
    }


def create_arguments(store):
    """Compile only: future caller must prove authorization, quiescence and IPAM availability."""
    state = store.review()
    spec = recipe(store)
    if state["resources"].get(ROLE) != {"state": "REQUESTED", "resource_id": None}:
        raise ActivationError("isolated_network_create_intent_required")
    args = [
        "network",
        "create",
        "--driver",
        "bridge",
        "--scope",
        "local",
        "--internal",
        "--attachable=false",
        "--ingress=false",
        "--config-only=false",
        "--ipv4=true",
        "--ipv6=false",
        "--ipam-driver",
        "default",
        "--subnet",
        SUBNET,
        "--gateway",
        GATEWAY,
        "--opt",
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
    ]
    for key, value in sorted(spec["labels"].items()):
        args.extend(("--label", key + "=" + value))
    if store.review() != state:
        raise ActivationError("isolated_network_operation_changed")
    return (*args, spec["name"])


def command(store, known_id):
    state = store.review()
    recipe(store)
    if state["resources"].get(ROLE) != {"state": "OBSERVED", "resource_id": identifier(known_id)}:
        raise ActivationError("isolated_network_observed_resource_required")
    return ("network", "inspect", "--format", FORMAT, known_id)


class NetworkDocker:
    def query(self, store, known_id):
        try:
            return _execute(command(store, known_id))
        except ActivationError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ActivationError("isolated_network_query_failed") from None


def _configuration(spec, item, known_id):
    """Validate non-membership fields; each caller must separately validate endpoints."""
    expected = {
        "id": identifier(known_id),
        "name": spec["name"],
        "driver": "bridge",
        "scope": "local",
        "internal": True,
        "ipv4": True,
        "ipv6": False,
        "attachable": False,
        "ingress": False,
        "config_only": False,
        "options": OPTIONS,
        "labels": spec["labels"],
        "label_count": 5,
    }
    if (
        not isinstance(item, dict)
        or set(item) != {*expected, "config_from", "ipam", "containers"}
        or any(digest(item[key]) != digest(value) for key, value in expected.items())
        or item["config_from"] not in (None, {}, {"Network": ""})
    ):
        raise ActivationError("isolated_network_configuration_mismatch")
    ipam = item["ipam"]
    if (
        not isinstance(ipam, dict)
        or not {"Driver", "Config"} <= set(ipam)
        or not set(ipam) <= {"Driver", "Options", "Config"}
        or ipam["Driver"] != "default"
        or ipam.get("Options") not in (None, {})
        or not isinstance(ipam["Config"], list)
        or len(ipam["Config"]) != 1
    ):
        raise ActivationError("isolated_network_ipam_mismatch")
    config = ipam["Config"][0]
    if (
        not isinstance(config, dict)
        or not {"Subnet", "Gateway"} <= set(config)
        or not set(config) <= {"Subnet", "Gateway", "IPRange", "AuxiliaryAddresses"}
        or config["Subnet"] != SUBNET
        or config["Gateway"] != GATEWAY
        or config.get("IPRange") not in (None, "")
        or config.get("AuxiliaryAddresses") not in (None, {})
    ):
        raise ActivationError("isolated_network_ipam_mismatch")


def validate(spec, item, known_id):
    _configuration(spec, item, known_id)
    if item["containers"] not in (None, {}):
        raise ActivationError("isolated_network_configuration_mismatch")


def review(store, known_id, *, docker=None, ownership_docker=None):
    """Verify only an empty owned network; no endpoints, traffic tests or activation implied."""
    original = store.review()
    spec = recipe(store)
    command(store, known_id)
    operation, plan = store.summary()["id"], original["header"]["plan_sha256"]
    before = observe(operation, plan, ROLE, known_id, docker=ownership_docker)
    if before["status"] != "present_owned_snapshot" or before["details"]["member_count"] != 0:
        raise ActivationError("isolated_network_empty_owned_resource_required")
    item = document((docker or NetworkDocker()).query(store, known_id))
    validate(spec, item, known_id)
    after = observe(operation, plan, ROLE, known_id, docker=ownership_docker)
    if before != after or store.review() != original:
        raise ActivationError("isolated_network_changed_during_review")
    return {
        "format": "aegis-isolated-network-configuration-review/1",
        "resource_id": known_id,
        "recipe_sha256": digest(spec),
        "configuration_sha256": digest(item),
        "status": "empty_owned_isolated_network_configuration_verified",
        "configured_internal_bridge_verified": True,
        "configured_gateway_mode_isolated_verified": True,
        "members_absent_verified": True,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
