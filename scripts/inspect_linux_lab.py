"""Read-only verification of this project's running Linux runner, never probe targets."""

import json
import os
import subprocess
from pathlib import Path

from dotenv import dotenv_values

IDS_ENV = os.environ.get("LINUX_IDS_ENV", ".local/linux-lab/ids.env")
COMPOSE = [
    "docker",
    "compose",
    "--env-file",
    IDS_ENV,
    "-f",
    "labs/linux/compose.yml",
]


def validate(container: dict, network: dict, configuration: Path):
    host = container["HostConfig"]
    checks = {
        "uid": container["Config"]["User"] == "10001:10001",
        "readonly": host["ReadonlyRootfs"] and not host["Privileged"],
        "capabilities": host["CapDrop"] == ["ALL"]
        and "no-new-privileges:true" in host["SecurityOpt"],
        "ports": not host["PortBindings"],
        "network": list(container["NetworkSettings"]["Networks"]) == ["aegis-linux-lab_isolated"],
        "gateway": network["Internal"]
        and not network["EnableIPv6"]
        and network["Options"].get("com.docker.network.bridge.gateway_mode_ipv4") == "isolated",
        "limits": host["PidsLimit"] == 64
        and host["Memory"] == 192 * 1024 * 1024
        and host["NanoCpus"] == 1000000000,
        "tmpfs": set(host["Tmpfs"]) == {"/work"}
        and set(("noexec", "nosuid", "nodev", "uid=10001", "gid=10001", "mode=0700", "size=1m"))
        <= set(host["Tmpfs"].get("/work", "").split(",")),
    }
    expected = {
        ("volume", "/state", True),
        ("bind", "/run/secrets/runner_server_key", False),
        ("bind", "/run/secrets/runner_server_cert", False),
        ("bind", "/run/secrets/runner_client_ca", False),
    }
    mounts = container["Mounts"]
    checks["mounts"] = {(m["Type"], m["Destination"], m["RW"]) for m in mounts} == expected
    checks["secret_scope"] = {
        Path(m["Source"]).resolve() for m in mounts if m["Type"] == "bind"
    } == {
        configuration.resolve() / name
        for name in ("runner-server.key", "runner-server.crt", "client-ca.crt")
    }
    if not all(checks.values()):
        raise ValueError(
            "Configuração de runtime diverge: "
            + ", ".join(k for k, valid in checks.items() if not valid)
        )
    return checks


def main():
    identifier = subprocess.check_output([*COMPOSE, "ps", "-q", "runner"], text=True).strip()
    if not identifier:
        raise SystemExit("Runner não iniciado. Nenhum ensaio foi executado.")
    container = json.loads(subprocess.check_output(["docker", "inspect", identifier]))[0]
    network = json.loads(
        subprocess.check_output(["docker", "network", "inspect", "aegis-linux-lab_isolated"])
    )[0]
    configuration = Path(dotenv_values(IDS_ENV)["AEGIS_LAB_CONFIG_DIR"])
    checks = validate(container, network, configuration)
    print(
        json.dumps(
            {
                "runtime_controls_verified": checks,
                "limitation": "Inspeção de configuração Docker; não substitui VM nem revisão independente.",
            }
        )
    )


if __name__ == "__main__":
    main()
