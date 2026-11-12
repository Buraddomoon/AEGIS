"""Inspect rendered Compose on stdin, without starting or inspecting a Lab volume."""

import json
import re
import sys


def validate(config: dict) -> None:
    if config["name"] != "aegis-linux-lab":
        raise ValueError("Unexpected campaign project")
    services = config["services"]
    for service in services.values():
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", service.get("image", "")):
            raise ValueError("Every campaign image must use an immutable local image ID")
        if service.get("build") or service.get("privileged") or service.get("network_mode"):
            raise ValueError("Unreviewed build or host access")
        for mount in service.get("volumes", []):
            if mount["type"] != "volume":
                raise ValueError("Host data mounts are forbidden")
    if services["migrate"]["command"] != [
        "python",
        "-m",
        "aegis.operations.linux_campaign_readiness",
    ]:
        raise ValueError("Automatic migration/seed/grants are forbidden")
    if len(services["api"]["ports"]) != 1:
        raise ValueError("Unexpected API ports")
    port = services["api"]["ports"][0]
    if (port.get("host_ip"), str(port.get("published")), port.get("target")) != (
        "127.0.0.1",
        "18785",
        8080,
    ):
        raise ValueError("API must be bound to the reviewed loopback port")
    for name, service in services.items():
        if name != "api" and service.get("ports"):
            raise ValueError("Unexpected published service")
        if name in ("api", "worker"):
            if any(
                value for key, value in service["environment"].items() if key.startswith("WAZUH_")
            ):
                raise ValueError("No Wazuh integration is authorized by this package")
    network = config["networks"]["isolated"]
    if (
        not network["internal"]
        or network.get("enable_ipv6", False)
        or network["driver_opts"].get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated"
        or network["ipam"]["config"] != [{"subnet": "192.168.253.0/29", "gateway": "192.168.253.1"}]
    ):
        raise ValueError("Unexpected runner network")
    if config["volumes"]["postgres-data"]["name"] != "aegis-linux-lab_postgres-data":
        raise ValueError("Unexpected PostgreSQL volume")
    if config["volumes"]["journal"]["name"] != "aegis-linux-lab_journal":
        raise ValueError("Unexpected journal volume")


def main() -> None:
    try:
        validate(json.load(sys.stdin))
    except (KeyError, TypeError, ValueError):
        raise SystemExit(
            "BLOCKED: rendered Linux campaign configuration requires review."
        ) from None
    print(
        "PASS: immutable images, read-only schema gate, loopback API and isolated runner network."
    )


if __name__ == "__main__":
    main()
