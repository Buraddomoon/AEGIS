"""Opt-in host-owned Wazuh profiles; never accept destinations or secrets from HTTP."""

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations.wazuh_config import WazuhCollectionConfig
from aegis.lab_registry import protected_read


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    revision: int = Field(ge=1)
    url: str
    allowed_ip: str
    ca_file: Path
    username_file: Path
    password_file: Path
    policy: WazuhCollectionConfig


class Registry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    format: str = Field(pattern=r"^aegis-defensive-profiles/1$")
    entries: tuple[Profile, ...] = Field(max_length=100)

    @model_validator(mode="after")
    def distinct(self):
        if len({entry.id for entry in self.entries}) != len(self.entries):
            raise ValueError("IDs de perfil duplicados.")
        return self


class Resolved(BaseModel):
    model_config = ConfigDict(frozen=True)
    profile: Profile
    username: SecretStr
    password: SecretStr
    ca: str

    def descriptor(self) -> dict:
        profile = self.profile
        return {
            "provider": "wazuh-indexer",
            "profile": {"id": profile.id, "revision": profile.revision},
            "policy": profile.policy.model_dump(mode="json"),
            "destination": {
                "url": profile.url,
                "allowed_ip": profile.allowed_ip,
                "trust_sha256": hashlib.sha256(self.ca.encode()).hexdigest(),
                "principal_sha256": digest(self.username.get_secret_value()),
                "references_sha256": digest(profile.model_dump(mode="json")),
            },
        }


def load() -> Registry:
    path = settings().defensive_profiles
    if path is None:
        raise ValueError("Catálogo defensivo opt-in ausente.")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Chave duplicada.")
            value[key] = item
        return value

    return Registry.model_validate(
        json.loads(protected_read(path, 262144), object_pairs_hook=unique)
    )


def resolve(profile: Profile) -> Resolved:
    from aegis.integrations.wazuh import validate_destination

    validate_destination(
        profile.url, profile.allowed_ip, profile.policy.alerts_index, profile.policy.archives_index
    )
    username = protected_read(profile.username_file, 1024).decode().rstrip("\r\n")
    password = protected_read(profile.password_file, 4096).decode().rstrip("\r\n")
    ca = protected_read(profile.ca_file, 65536, private=False).decode()
    if not username or not password or any(c in username + password for c in "\r\n\x00"):
        raise ValueError("Referência de credencial inválida.")
    # Parse trust before advertising the profile as available. No network IO.
    import ssl

    ssl.create_default_context(cadata=ca)
    return Resolved(
        profile=profile, username=SecretStr(username), password=SecretStr(password), ca=ca
    )


def selected(profile_id: str) -> Resolved:
    entries = [entry for entry in load().entries if entry.id == profile_id]
    if len(entries) != 1:
        raise ValueError("Perfil conhecido indisponível.")
    return resolve(entries[0])


def candidates(lab_id: str) -> list[dict]:
    result = []
    for entry in load().entries:
        if str(entry.policy.laboratory_id) != lab_id:
            continue
        try:
            value = resolve(entry).descriptor()
        except (ValueError, OSError):
            result.append(
                {
                    "id": entry.id,
                    "revision": entry.revision,
                    "available": False,
                    "configuration_hash": None,
                    "policy": None,
                }
            )
        else:
            result.append(
                {
                    "id": entry.id,
                    "revision": entry.revision,
                    "available": True,
                    "configuration_hash": digest(value),
                    "policy": value["policy"],
                }
            )
    return result
