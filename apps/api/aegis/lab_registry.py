"""Closed, host-owned deployment registry. Reading it never contacts a runner."""

import json
import os
import stat
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations.linux_runner import RunnerConnection


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    revision: int = Field(ge=1)
    owner: str = Field(min_length=3, max_length=120)
    isolation: str = Field(min_length=20, max_length=4000)
    connection: RunnerConnection


class Registry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    format: str = Field(pattern=r"^aegis-linux-registry/1$")
    entries: tuple[RegistryEntry, ...] = Field(max_length=100)

    @model_validator(mode="after")
    def distinct(self):
        # One reviewed runner/asset per laboratory; aliases cannot bypass claims.
        for values in (
            [e.id for e in self.entries],
            [e.connection.laboratory_id for e in self.entries],
            [e.connection.asset_id for e in self.entries],
            [e.connection.runner_id for e in self.entries],
            [e.connection.url for e in self.entries],
        ):
            if len(set(values)) != len(values):
                raise ValueError("Identidade ou endpoint duplicado no registro.")
        return self


def protected_read(path: Path, limit: int, *, private: bool = True) -> bytes:
    """Absolute regular files, no symlink components, bounded read on the checked fd."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Caminho deve ser absoluto e sem travessia.")
    parent = Path(path.anchor)
    for part in path.parts[1:-1]:
        parent /= part
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            # Sticky system temporary directories are allowed for isolated fixtures.
            if not (stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX):
                raise ValueError("Diretório de configuração sem proteção.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & (0o077 if private else 0o022)
            or info.st_size > limit
        ):
            raise ValueError("Arquivo de configuração sem proteção ou excedeu limite.")
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("Arquivo excedeu limite.")
        return content


def load() -> Registry:
    path = settings().linux_runner_registry
    if path is None:
        raise ValueError("Registro opt-in ausente.")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Chave JSON duplicada.")
            result[key] = value
        return result

    registry = Registry.model_validate(
        json.loads(protected_read(path, 262144), object_pairs_hook=unique_pairs)
    )
    for entry in registry.entries:
        config = entry.connection
        protected_read(config.server_ca, 65536, private=False)
        protected_read(config.client_cert, 65536, private=False)
        protected_read(config.client_key, 65536)
    return registry


def entry_for(*, entry_id: str | None = None, laboratory_id: str | None = None) -> RegistryEntry:
    matches = [
        entry
        for entry in load().entries
        if (entry_id is None or entry.id == entry_id)
        and (laboratory_id is None or str(entry.connection.laboratory_id) == laboratory_id)
    ]
    if len(matches) != 1:
        raise ValueError("Selecione uma conexão revisada inequívoca.")
    return matches[0]


def public(entry: RegistryEntry) -> dict:
    """No paths, endpoint, key material, or implied connectivity/authorization."""
    config = entry.connection
    return {
        "id": entry.id,
        "revision": entry.revision,
        "owner": entry.owner,
        "isolation": entry.isolation,
        "laboratory_id": str(config.laboratory_id),
        "asset_id": str(config.asset_id),
        "platform": "Linux",
        "test_id": config.test_id,
        "review_hash": digest(entry.model_dump(mode="json")),
    }
