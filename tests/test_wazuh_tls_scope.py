import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_tls_scope as scope  # noqa: E402
from test_wazuh_pki_rotation import prepared as prepared  # noqa: E402
from test_wazuh_pki_rotation import rendered as rendered  # noqa: E402


def test_scoped_real_compose_contains_only_three_services_one_network_and_original_volumes(
    rendered,
):
    _, candidate = rendered
    before = copy.deepcopy(candidate)
    result = scope.scoped_compose(candidate, "a" * 32)
    assert candidate == before
    assert set(result["services"]) == set(scope.SERVICES)
    assert set(result["networks"]) == {"telemetry"}
    assert set(result["volumes"]) == scope.VOLUMES
    assert set(result["secrets"]) == scope.SECRETS
    for name, service in result["services"].items():
        assert not service.get("depends_on") and not service.get("ports")
        assert service["labels"]["aegis.tls-assay-id"] == "a" * 32
        original = copy.deepcopy(candidate["services"][name])
        original.pop("depends_on", None)
        original.setdefault("labels", {})["aegis.tls-assay-id"] = "a" * 32
        assert service == original
    for name, volume in result["volumes"].items():
        assert volume == {"name": scope.PROJECT + "_" + name, "external": True}


@pytest.mark.parametrize(
    "change",
    [
        "project",
        "port",
        "hostnetwork",
        "privilege",
        "address",
        "extra-network",
        "extra-volume",
        "extra-secret",
        "ipam",
        "collision",
        "socket",
    ],
)
def test_scope_rejects_any_expansion_or_changed_endpoint(rendered, change):
    candidate = copy.deepcopy(rendered[1])
    service = candidate["services"]["wazuh.manager"]
    if change == "project":
        candidate["name"] = "other-project"
    elif change == "port":
        service["ports"] = [{"published": "55000"}]
    elif change == "hostnetwork":
        service["network_mode"] = "host"
    elif change == "privilege":
        service["privileged"] = True
    elif change == "address":
        service["networks"]["telemetry"]["ipv4_address"] = "172.30.90.3"
    elif change == "extra-network":
        service["networks"]["backend"] = {}
    elif change == "extra-volume":
        service["volumes"].append(
            {"type": "volume", "source": "postgres-data", "target": "/unreviewed"}
        )
    elif change == "extra-secret":
        service["secrets"].append({"source": "controller_client_key"})
    elif change == "ipam":
        candidate["networks"]["telemetry"]["ipam"]["config"][0]["subnet"] = "192.168.253.0/24"
    elif change == "collision":
        service["labels"] = {"aegis.tls-assay-id": "b" * 32}
    else:
        service["volumes"].append(
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
        )
    with pytest.raises(ValueError):
        scope.scoped_compose(candidate, "a" * 32)
