"""Fixed profiles and real Compose rendering, without daemon mutations or startup."""

import ipaddress
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from aegis.lab_runner.network_profile import LINUX_SUBNET
from aegis.lab_runner.wazuh_network_profile import ADDRESSES, GATEWAYS, SUBNETS

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_network_preflight as preflight  # noqa: E402
from prepare_wazuh_lab import prepare  # noqa: E402

OBJECT = "a" * 64


class Docker:
    def __init__(self, subnet="172.30.0.0/16"):
        self.subnet = subnet
        self.calls = []

    def query(self, known_id=None, *, timeout):
        assert 0 < timeout <= 5
        self.calls.append(known_id)
        if known_id is None:
            return (OBJECT + "\n").encode()
        return json.dumps(
            {
                "id": OBJECT,
                "driver": "bridge",
                "scope": "local",
                "ipam_driver": "default",
                "config": [{"Subnet": self.subnet}],
            }
        ).encode()


class Routes:
    def __init__(self, destinations=("default", "172.30.0.0/16", "192.168.253.0/29")):
        self.destinations = destinations
        self.calls = 0

    def query(self, *, timeout):
        self.calls += 1
        return json.dumps([{"dst": value} for value in self.destinations]).encode()


def test_both_profiles_do_not_overlap_linux_qasrc_or_each_other():
    networks = [
        ipaddress.ip_network(value) for value in (*SUBNETS.values(), LINUX_SUBNET, "172.30.0.0/16")
    ]
    assert not any(a.overlaps(b) for index, a in enumerate(networks) for b in networks[index + 1 :])
    for network, cidr in SUBNETS.items():
        addresses = [address for (_, name), address in ADDRESSES.items() if name == network]
        assert len(addresses) == len(set(addresses))
        assert GATEWAYS[network] not in addresses
        assert all(
            ipaddress.ip_address(address) in list(ipaddress.ip_network(cidr).hosts())
            for address in addresses
        )
    assert {network for (service, network) in ADDRESSES if service == "runner"} == {"isolated"}
    assert {network for (service, network) in ADDRESSES if service.startswith("wazuh.")} == {
        "telemetry"
    }


def test_read_only_preflight_has_two_fresh_snapshots_and_no_ownership_exemption():
    docker, routes = Docker(), Routes()
    result = preflight.review(docker=docker, routes=routes)
    assert result["subnets"] == list(SUBNETS.values())
    assert result["observed_ipv4_overlap_absent"]
    assert (
        result["effects_authorized"]
        is result["activation_verified"]
        is result["normal_operation_permitted"]
        is False
    )
    assert docker.calls == [None, OBJECT, None] * 2 and routes.calls == 2
    assert "172.30.0.0" not in json.dumps(result) and OBJECT not in json.dumps(result)


@pytest.mark.parametrize(
    "destination",
    [
        "192.168.253.8/29",
        "192.168.253.10/32",
        "192.168.253.16/29",
        "192.168.253.22/32",
        "192.168.253.0/24",
        "192.168.0.0/16",
    ],
)
def test_total_partial_and_host_route_collisions_fail_closed(destination):
    with pytest.raises(ValueError, match="docker_overlap"):
        preflight.review(docker=Docker(destination), routes=Routes())
    with pytest.raises(ValueError, match="host_route_overlap"):
        preflight.review(docker=Docker(), routes=Routes(("default", destination)))


def test_changed_snapshot_cannot_be_presented_as_available():
    class Changing(Routes):
        def query(self, **kwargs):
            self.destinations = ("192.0.2.0/24" if not self.calls else "192.0.2.0/25",)
            return super().query(**kwargs)

    with pytest.raises(ValueError, match="snapshot_changed"):
        preflight.review(docker=Docker(), routes=Changing())


def test_network_overlay_render_keeps_capability_boundaries_and_all_exact_addresses(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Compose CLI required, no daemon startup")
    source = prepare(tmp_path / "source")
    root = Path(__file__).resolve().parents[1]
    command = [
        "docker",
        "compose",
        "--env-file",
        str(source / "lab.env"),
        "--profile",
        "manual",
        "-p",
        "aegis-wazuh-lab",
    ]
    for file in (
        "docker-compose.yml",
        "labs/linux/compose.yml",
        "labs/linux/platform.yml",
        "labs/wazuh/compose.yml",
        "labs/wazuh/network.yml",
    ):
        command.extend(["-f", file])
    result = subprocess.run(
        [*command, "config", "--format", "json"],
        cwd=root,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(source)},
        timeout=15,
    )
    assert result.returncode == 0  # Config contains credentials: never echo output.
    config = json.loads(result.stdout)
    for (service, network), address in ADDRESSES.items():
        assert config["services"][service]["networks"][network]["ipv4_address"] == address
    for name, cidr in SUBNETS.items():
        network = config["networks"][name]
        assert network["ipam"]["config"] == [{"subnet": cidr, "gateway": GATEWAYS[name]}]
        assert network["internal"]
        assert network["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
    assert set(config["services"]["runner"]["networks"]) == {"isolated"}
    assert config["services"]["observer"]["network_mode"] == "none"
    for service, value in config["services"].items():
        if service != "api":
            assert not value.get("ports")
