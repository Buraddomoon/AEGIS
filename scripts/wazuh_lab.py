"""Opt-in lifecycle of the separate local Wazuh lab. Never executes a marker."""

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
from pathlib import Path

import yaml
from wazuh_host_preflight import failures, inspect, local_environment

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".local/wazuh-lab"
PROJECT = "aegis-wazuh-lab"
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
COMPOSE = [*DOCKER, "compose", "--env-file", str(PRIVATE / "lab.env"), "-p", PROJECT]
for file in (
    "docker-compose.yml",
    "labs/linux/compose.yml",
    "labs/linux/platform.yml",
    "labs/wazuh/compose.yml",
):
    COMPOSE.extend(["-f", str(ROOT / file)])
IMAGES = json.loads((ROOT / "labs/wazuh/images.json").read_text())["images"]


def execute(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    # Compose gives shell variables precedence over --env-file. This assay must
    # use its private config, not an unrelated exported SIEM target/password.
    keys = (
        [line.split("=", 1)[0] for line in (PRIVATE / "lab.env").read_text().splitlines()]
        if (PRIVATE / "lab.env").is_file()
        else []
    )
    environment = local_environment(keys)
    return subprocess.run(command, cwd=ROOT, check=True, env=environment, **kwargs)


def resource_gate():
    if platform.machine() not in {"x86_64", "AMD64"}:
        raise ValueError("Este ensaio foi preparado somente para linux/amd64; não usar emulação.")
    issues = failures(inspect())
    if issues:
        raise ValueError("Preflight recusou início: " + " ".join(issues))


def network_gate():
    identifiers = execute(
        [*DOCKER, "network", "ls", "-q"], capture_output=True, text=True, timeout=10
    ).stdout.split()
    if identifiers:
        networks = json.loads(
            execute(
                [*DOCKER, "network", "inspect", *identifiers],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        )
        planned = [ipaddress.ip_network(item) for item in ("172.30.89.0/29", "172.30.90.0/29")]
        for network in networks:
            own = (network.get("Labels") or {}).get("com.docker.compose.project") == PROJECT
            for config in (network.get("IPAM") or {}).get("Config") or []:
                if not config.get("Subnet"):
                    continue
                subnet = ipaddress.ip_network(config["Subnet"])
                if not own and any(
                    subnet.version == item.version and subnet.overlaps(item) for item in planned
                ):
                    raise ValueError(
                        "Sub-rede do ensaio conflita com rede existente; não alterar redes."
                    )
    with socket.socket() as port:
        try:
            port.bind(("127.0.0.1", 18786))
        except OSError:
            raise ValueError(
                "Porta local 18786 ocupada; consultar status, sem substituir serviço."
            ) from None


def hash_users():
    target = PRIVATE / "internal_users.yml"
    if target.exists():
        raise ValueError(
            "Hashes já existem; não rotacionar identidade de um Indexer implicitamente."
        )
    credentials = json.loads((PRIVATE / "indexer-passwords.json").read_text())
    users = {"_meta": {"type": "internalusers", "config_version": 2}}
    for name in ("admin", "aegis_reader", "aegis_ingest"):
        # Fixed shell code. Secret only via stdin; never argv, Docker env or logs.
        result = execute(
            [
                *DOCKER,
                "run",
                "--rm",
                "-i",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "1000:0",
                "--memory",
                "256m",
                "--pids-limit",
                "64",
                "--cpus",
                "1",
                "--env",
                "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
                "--entrypoint",
                "/bin/bash",
                IMAGES["indexer"],
                "-c",
                "IFS= read -r AEGIS_HASH_PASSWORD; export AEGIS_HASH_PASSWORD; exec /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env AEGIS_HASH_PASSWORD",
            ],
            input=credentials[name] + "\n",
            capture_output=True,
            text=True,
            timeout=60,
        )
        hashes = re.findall(r"\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}", result.stdout)
        if len(hashes) != 1:
            raise ValueError("Ferramenta oficial não produziu um único hash BCrypt; não iniciar.")
        users[name] = {"hash": hashes[0], "reserved": name == "admin", "backend_roles": []}
    with target.open("x", encoding="utf-8") as file:
        file.write(yaml.safe_dump(users))
    target.chmod(0o444)  # Parent 0700; readable by the Indexer UID in a file-only bind mount.


def certificates_gate():
    for name in (
        "pki/indexer.pem",
        "pki/filebeat.pem",
        "runner/runner-server.crt",
        "runner/runner-client.crt",
    ):
        execute(
            ["openssl", "x509", "-checkend", "600", "-noout", "-in", str(PRIVATE / name)],
            capture_output=True,
            timeout=5,
        )
    if not (PRIVATE / "internal_users.yml").is_file():
        raise ValueError(
            "Preparação dos hashes ainda pendente; não iniciar com credenciais default."
        )


def check_rule():
    # This synthetic sandbox input is NOT written into the observer logfile or evidence DB.
    fixture = {
        "synthetic": True,
        "aegis": {
            "schema": "aegis-json/1",
            "observation": "marker_file_read",
            "behavior": "temporary-marker",
        },
    }
    execute(
        [
            *COMPOSE,
            "exec",
            "-T",
            "wazuh.manager",
            "/var/ossec/bin/wazuh-logtest",
            "-U",
            "100200:3:json",
        ],
        input=json.dumps(fixture) + "\n",
        text=True,
        timeout=30,
    )
    execute(
        [
            *COMPOSE,
            "exec",
            "-T",
            "wazuh.manager",
            "/var/ossec/bin/agent_control",
            "-i",
            "001",
            "-j",
        ],
        timeout=10,
    )
    print(
        "Regra testada em sandbox; conferir agent.id=001, nome aegis-marker e status Active. Isto não comprova ingestão/detecção real."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["config", "pull", "hash-users", "build", "up", "check-rule", "status", "down"],
    )
    parser.add_argument("--confirm-local-wazuh", action="store_true")
    args = parser.parse_args()
    if args.action not in {"config", "status"} and not args.confirm_local_wazuh:
        parser.error("Requer autorização específica prévia e --confirm-local-wazuh.")
    # Cleanup/status/config remain available when memory is low; never block shutdown.
    if args.action in {"pull", "hash-users", "build", "up"}:
        resource_gate()
    if args.action == "config":
        execute([*COMPOSE, "config", "--quiet"], timeout=10)
    elif args.action == "pull":
        for ref in IMAGES.values():
            execute([*DOCKER, "pull", "--platform", "linux/amd64", ref])
    elif args.action == "hash-users":
        hash_users()
    elif args.action == "build":
        execute([*COMPOSE, "build", "migrate", "runner"])
    elif args.action == "up":
        certificates_gate()
        network_gate()
        execute(
            [
                *COMPOSE,
                "up",
                "-d",
                "db",
                "redis",
                "migrate",
                "runner",
                "observer",
                "wazuh.indexer",
                "wazuh.manager",
                "wazuh.agent",
                "api",
                "worker",
            ]
        )
    elif args.action == "check-rule":
        check_rule()
    elif args.action == "status":
        execute([*COMPOSE, "ps"])
    elif args.action == "down":
        execute([*COMPOSE, "down"])  # Deliberately no -v or global prune.


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Never print captured Docker output/arguments, which may contain credentials.
        if isinstance(error, ValueError):
            print(str(error))
        else:
            print(
                "Operação não concluída. Preservar estado e inspecionar localmente sem publicar segredos."
            )
        raise SystemExit(1) from None
