"""One code-reviewed mapping; metadata imports cannot change this allowlist."""

import hashlib
import os
import stat
from pathlib import Path

from aegis.domain.validation import digest

DEFINITION_ID = "atomic-file-permissions-v1"
TEST_ID = (
    "atomic-file-permissions/v1@9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673"
)
BEHAVIOR = "owned-file-permissions"
GUID = "34ca1464-de9d-40c6-8c77-690adf36a135"
SOURCE_COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
SOURCE_SHA256 = "f453e844306df372cf600ddd59d15626a83d3dd83cd5a4b3e5fe5175b4204f3b"
PROGRAM_SHA256 = "b645e702a86155857eea13e44866b4fb76c289eda670af07ca639936b9356838"
PROGRAM = Path(__file__).with_name("permissions_program.py")


def review() -> dict:
    return {
        "format": "aegis-atomic-review/1",
        "guid": GUID,
        "source_commit": SOURCE_COMMIT,
        "source_sha256": SOURCE_SHA256,
        "source_path": "atomics/T1222.002/T1222.002.yaml",
        "license_sha256": "65af6027045d23175366eab50e460ab3ee7790e591cb84cc32c78ac63a4c90e1",
        "technique_id": "T1222.002",
        "platform": "Linux",
        "adapter_version": 1,
        "program_sha256": PROGRAM_SHA256,
        "behavior": BEHAVIOR,
        "artifact": "proof.marker",
        "mode_before": 0o400,
        "mode_after": 0o600,
        "cleanup_artifacts": ["proof.marker", "receipt.json"],
        "shell": False,
        "free_inputs": False,
    }


def program_source() -> str:
    """Execute these verified bytes, closing the hash/path replacement race."""
    if TEST_ID != "atomic-file-permissions/v1@" + digest(review()):
        raise ValueError("Revisão Atomic mudou sem uma nova identidade de teste.")
    fd = os.open(PROGRAM, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > 16384
        ):
            raise ValueError("Programa Atomic fixo inválido.")
        raw = os.read(fd, 16385)
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != PROGRAM_SHA256:
        raise ValueError("Programa Atomic difere da revisão fixada.")
    return raw.decode("utf-8")


REVIEW_SHA256 = digest(review())
