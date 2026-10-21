"""Read-only host gate for a future authorized Wazuh assay. Never starts services."""

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

GIB = 1024**3


@dataclass(frozen=True)
class Resources:
    cpus: int
    available_bytes: int
    docker_free_bytes: int
    max_map_count: int


def local_environment(private_keys=()) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_DEFAULT_PLATFORM",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "COMPOSE_FILE",
        "COMPOSE_ENV_FILES",
        "BUILDX_BUILDER",
        *private_keys,
    ):
        environment.pop(name, None)
    return environment


def failures(resources: Resources) -> list[str]:
    issues = []
    if resources.cpus < 4:
        issues.append("Necessárias pelo menos 4 CPUs disponíveis ao processo.")
    if resources.available_bytes < 8 * GIB:
        issues.append("Necessários 8 GiB de MemAvailable; não contar swap como RAM disponível.")
    if resources.docker_free_bytes < 50 * GIB:
        issues.append("Necessários 50 GiB livres no filesystem do daemon Docker.")
    if resources.max_map_count < 262144:
        issues.append("vm.max_map_count abaixo de 262144; nenhuma alteração foi realizada.")
    return issues


def memory_available(content: str) -> int:
    for line in content.splitlines():
        parts = line.split()
        if parts and parts[0] == "MemAvailable:":
            if len(parts) != 3 or parts[2] != "kB" or int(parts[1]) < 0:
                break
            return int(parts[1]) * 1024
    raise ValueError("MemAvailable válido ausente; não estimar com MemFree ou swap.")


def docker_storage() -> Path:
    # Explicit local Unix socket: do not inspect a remote/context-selected daemon.
    command = ["docker", "--host", "unix:///var/run/docker.sock"]
    result = subprocess.run(
        [*command, "info", "--format", "{{json .DockerRootDir}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env=local_environment(),
    )
    root = Path(json.loads(result.stdout))
    if not root.is_absolute():
        raise ValueError("Daemon não informou diretório absoluto de armazenamento.")
    return root


def inspect() -> Resources:
    return Resources(
        cpus=len(os.sched_getaffinity(0)),
        available_bytes=memory_available(Path("/proc/meminfo").read_text()),
        docker_free_bytes=shutil.disk_usage(docker_storage()).free,
        max_map_count=int(Path("/proc/sys/vm/max_map_count").read_text()),
    )


def main() -> int:
    try:
        resources = inspect()
    except (OSError, ValueError, subprocess.SubprocessError):
        # Avoid leaking daemon diagnostics, paths, context credentials or environment.
        print(json.dumps({"ready": False, "reason": "Inspeção local indisponível; não iniciar."}))
        return 1
    issues = failures(resources)
    print(
        json.dumps(
            {
                "ready": not issues,
                "resources": asdict(resources),
                "issues": issues,
                "authorization": "Preflight não concede autorização de instalação/execução.",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return int(bool(issues))


if __name__ == "__main__":
    raise SystemExit(main())
