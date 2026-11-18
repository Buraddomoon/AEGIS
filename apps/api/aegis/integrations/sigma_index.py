"""Read-only physical gate for the fixed literal Sigma converter.

Expected hashes are operator-reviewed inputs, never learned from the response.
Only one concrete daily alert index is supported; aliases are refused.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis.domain.validation import digest
from aegis.integrations.sigma_converter_worker import FIELDS
from aegis.integrations.wazuh import WazuhIndexerProvider

SHA256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class IndexProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile_id: Literal["aegis-marker-keyword/1"] = "aegis-marker-keyword/1"
    index: str = Field(pattern=r"^wazuh-alerts-4\.x-[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
    server_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    mapping_sha256: SHA256
    settings_sha256: SHA256


class IndexMismatch(Exception):
    """Intentionally carries no upstream body, URL or credentials."""


def physical_field(mapping: dict, path: str) -> dict:
    node = mapping
    for part in path.split("."):
        if (
            node.get("enabled", True) is not True
            or node.get("type", "object") != "object"
            or not isinstance(node.get("properties"), dict)
        ):
            raise IndexMismatch()
        node = node["properties"][part]
        if not isinstance(node, dict):
            raise IndexMismatch()
    return node


def verify_index(provider: WazuhIndexerProvider, profile: IndexProfile, fields: set[str]) -> dict:
    """No search on a mismatch; callers must repeat this gate after searching."""
    try:
        if not fields or fields - set(FIELDS.values()):
            raise IndexMismatch()
        version = provider._request("GET", "/")["version"]["number"]
        if version != profile.server_version:
            raise IndexMismatch()
        mapping_response = provider._request("GET", f"/{profile.index}/_mapping")
        settings_response = provider._request("GET", f"/{profile.index}/_settings")
        aliases = provider._request("GET", f"/{profile.index}/_alias")
        if (
            set(mapping_response) != {profile.index}
            or set(settings_response) != {profile.index}
            or aliases != {profile.index: {"aliases": {}}}
            or digest(mapping_response) != profile.mapping_sha256
            or digest(settings_response) != profile.settings_sha256
        ):
            raise IndexMismatch()
        mapping = mapping_response[profile.index]["mappings"]
        source = mapping.get("_source", {})
        if (
            mapping.get("runtime")
            or source.get("enabled", True) is not True
            or source.get("includes")
            or source.get("excludes")
        ):
            raise IndexMismatch()
        for path in fields | {"agent.id", "timestamp"}:
            field = physical_field(mapping, path)
            if path == "timestamp":
                if field.get("type") != "date" or field.get("ignore_malformed", False) is not False:
                    raise IndexMismatch()
            elif (
                field.get("type") != "keyword"
                or field.get("normalizer") is not None
                or field.get("split_queries_on_whitespace", False) is not False
                or type(field.get("ignore_above", 512)) is not int
                or field.get("ignore_above", 512) < 512
                or "null_value" in field
            ):
                raise IndexMismatch()
            if field.get("index", True) is not True or field.get("script") is not None:
                raise IndexMismatch()
        return {
            "profile": profile.model_dump(),
            "profile_sha256": digest(profile.model_dump()),
            "fields": sorted(fields | {"agent.id", "timestamp"}),
            "aliases": [],
            "index_mapping_verified": True,
            "version_note": "Advertised API version; not proof of the Wazuh distribution version.",
        }
    except (KeyError, TypeError, ValueError, AttributeError):
        raise IndexMismatch() from None
