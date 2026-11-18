"""Code-owned Linux allowlist. Source changes require new profile identities."""

import hashlib
import os
import stat
from pathlib import Path

from aegis.domain.validation import digest

PROGRAM = Path(__file__).with_name("behavior_program.py")
PROGRAM_SHA256 = "4e239181a4c9827da18f386dbee1527747959ff973d584ad48dfae27d78c9c13"
PROFILES = {
    "process": {
        "definition_id": "linux-process-canary-v1",
        "behavior": "benign-process-creation",
        "technique_id": None,
        "argv": ["/bin/true", "<marker>"],
    },
    "shell": {
        "definition_id": "linux-shell-canary-v1",
        "behavior": "fixed-unix-shell",
        "technique_id": "T1059.004",
        "argv": ["/bin/sh", "-c", "printf '%s\\n' \"$0\"", "<marker>"],
    },
}
TEST_IDS = {
    "process": "linux-process-canary/v1@5d16dd8867b4f8f06163311cfbdd1d754a03784c7c53212cb1709d29738b52e3",
    "shell": "linux-shell-canary/v1@1baab18c75ad4a6ce8534962582fd61ae490eef1240ea8db9245af1c092438cb",
}


def review(kind: str) -> dict:
    return {
        "format": "aegis-linux-behavior-review/1",
        "version": 1,
        "kind": kind,
        **PROFILES[kind],
        "program_sha256": PROGRAM_SHA256,
        "cleanup_artifacts": ["proof.marker", "receipt.json"],
        "artifact_mode": 0o600,
        "max_effect_seconds": 5,
        "lease_seconds": 2,
        "address_space_bytes": 512 * 1024 * 1024,
        "free_inputs": False,
        "external_network": False,
    }


def kind_for(test_id: str) -> str:
    return next(kind for kind, identifier in TEST_IDS.items() if identifier == test_id)


def program_source(test_id: str) -> str:
    kind = kind_for(test_id)
    if test_id != f"linux-{kind}-canary/v1@" + digest(review(kind)):
        raise ValueError("Revisão Linux mudou sem uma nova identidade de teste.")
    fd = os.open(PROGRAM, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > 16384
        ):
            raise ValueError("Programa Linux fixo inválido.")
        raw = os.read(fd, 16385)
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != PROGRAM_SHA256:
        raise ValueError("Programa Linux difere da revisão fixada.")
    return raw.decode("utf-8") + f"\nmain({kind!r})\n"
