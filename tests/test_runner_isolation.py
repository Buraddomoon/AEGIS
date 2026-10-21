import copy
import runpy
from pathlib import Path

import pytest
import yaml

validate = runpy.run_path("scripts/inspect_linux_lab.py")["validate"]


def test_opt_in_manifest_excludes_host_access_and_keeps_mount_options_atomic():
    config = yaml.safe_load(Path("labs/linux/compose.yml").read_text())
    assert config["name"] == "aegis-linux-lab"
    network = config["networks"]["isolated"]
    assert (
        network["internal"]
        and network["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
    )
    for service in config["services"].values():
        assert not service.get("ports") and not service.get("privileged")
        assert service.get("network_mode") != "host" and service["cap_drop"] == ["ALL"]
        assert service["read_only"] and "no-new-privileges:true" in service["security_opt"]
        assert len(service["tmpfs"]) == 1  # YAML commas must stay inside one mount string.
        assert ",noexec," in service["tmpfs"][0] and ",nosuid," in service["tmpfs"][0]
    assert config["services"]["runner"]["secrets"] == [
        "runner_server_key",
        "runner_server_cert",
        "runner_client_ca",
    ]
    assert not any("ca.key" in entry["file"] for entry in config["secrets"].values())


def runtime():
    container = {
        "Config": {"User": "10001:10001"},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PortBindings": {},
            "PidsLimit": 64,
            "Memory": 192 * 1024 * 1024,
            "NanoCpus": 1000000000,
            "Tmpfs": {"/work": "rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=10001,gid=10001"},
        },
        "NetworkSettings": {"Networks": {"aegis-linux-lab_isolated": {}}},
        "Mounts": [{"Type": "volume", "Destination": "/state", "RW": True}]
        + [
            {
                "Type": "bind",
                "Destination": "/run/secrets/" + key,
                "RW": False,
                "Source": "/local-config/" + name,
            }
            for key, name in [
                ("runner_server_key", "runner-server.key"),
                ("runner_server_cert", "runner-server.crt"),
                ("runner_client_ca", "client-ca.crt"),
            ]
        ],
    }
    network = {
        "Internal": True,
        "EnableIPv6": False,
        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
    }
    return container, network


@pytest.mark.parametrize(
    "threat",
    ["root", "writable", "ports", "host_network", "capabilities", "wrong_secret", "host_gateway"],
)
def test_runtime_inspection_refuses_weaker_isolation(threat):
    container, network = runtime()
    assert all(validate(container, network, Path("/local-config")).values())
    changed = copy.deepcopy(container)
    if threat == "root":
        changed["Config"]["User"] = "0"
    elif threat == "writable":
        changed["HostConfig"]["ReadonlyRootfs"] = False
    elif threat == "ports":
        changed["HostConfig"]["PortBindings"] = {"8443/tcp": [{"HostPort": "8443"}]}
    elif threat == "host_network":
        changed["NetworkSettings"]["Networks"] = {"host": {}}
    elif threat == "capabilities":
        changed["HostConfig"]["CapDrop"] = []
    elif threat == "wrong_secret":
        changed["Mounts"][1]["Source"] = "/other/private.key"
    elif threat == "host_gateway":
        network["Options"]["com.docker.network.bridge.gateway_mode_ipv4"] = "nat"
    with pytest.raises(ValueError):
        validate(changed, network, Path("/local-config"))


def test_platform_overlay_scopes_real_access_and_preserves_separate_demo_port():
    class ComposeLoader(yaml.SafeLoader):
        pass

    ComposeLoader.add_constructor("!override", lambda loader, node: loader.construct_sequence(node))
    config = yaml.load(Path("labs/linux/platform.yml").read_text(), Loader=ComposeLoader)
    assert config["name"] == "aegis-linux-lab"
    services = config["services"]
    assert services["api"]["ports"] == ["127.0.0.1:18785:8080"]
    assert set(services["worker"]["networks"]) == {"backend", "isolated"}
    for name in ("api", "worker"):
        environment = services[name]["environment"]
        assert environment["LINUX_RUNNER_CONFIG"] == "/run/secrets/controller_connection"
        assert environment["WAZUH_URL"] == environment["WAZUH_PASSWORD"] == ""
        assert services[name]["secrets"] == [
            "controller_server_ca",
            "controller_client_cert",
            "controller_client_key",
            "controller_connection",
        ]
        assert services[name]["restart"] == "no"
    # The default deployment never joins the lab network or receives its client key.
    default = yaml.safe_load(Path("docker-compose.yml").read_text())
    assert "isolated" not in default["networks"]
    assert "LINUX_RUNNER_CONFIG" not in default["services"]["api"]["environment"]
