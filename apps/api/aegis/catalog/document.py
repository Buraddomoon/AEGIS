"""Bounded Enterprise catalog profile, not a general STIX validator."""

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.domain.validation import digest

FORMAT = "aegis-enterprise-catalog/1"
VERSION = r"(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})"
HEX64 = r"[a-f0-9]{64}"
COMMIT = r"[a-f0-9]{40}"
TECHNIQUE = r"T[0-9]{4}(?:\.[0-9]{3})?"
MAX_BUNDLE = 80_000_000
MAX_LICENSE = 64_000
MAX_NORMALIZED = 12_000_000
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"


def source_url(version, commit):
    if not re.fullmatch(VERSION, version) or not re.fullmatch(COMMIT, commit):
        raise ValueError("ATT&CK version/commit must be explicit and canonical")
    return BASE + f"{commit}/enterprise-attack/enterprise-attack-{version}.json"


def stix_id(value, kind):
    prefix = kind + "--"
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or str(uuid.UUID(value[len(prefix) :])) != value[len(prefix) :]
    ):
        raise ValueError("Invalid STIX identity")
    return value


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        raise ValueError("Expected source UTC timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError("Expected source UTC timestamp")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, revalidate_instances="always"
    )


class Technique(StrictModel):
    id: str = Field(pattern="^" + TECHNIQUE + "$")
    stix_id: str
    name: str = Field(min_length=1, max_length=240)
    description: str = Field(max_length=100_000)
    tactics: list[str] = Field(max_length=32)
    platforms: list[str] = Field(max_length=40)
    parent_id: str | None = Field(default=None, pattern=r"^T[0-9]{4}$")
    reference: str = Field(max_length=160)
    dataset_version: str = Field(pattern="^" + VERSION + "$")
    revoked: bool = False
    deprecated: bool = False
    source_modified: str | None = None

    @field_validator("stix_id")
    @classmethod
    def validate_stix(cls, value):
        return stix_id(value, "attack-pattern")

    @field_validator("source_modified")
    @classmethod
    def validate_modified(cls, value):
        return timestamp(value) if value is not None else None

    @field_validator("tactics", "platforms")
    @classmethod
    def validate_list(cls, values):
        if len(values) != len(set(values)) or any(
            not value.strip() or len(value) > 80 for value in values
        ):
            raise ValueError("Invalid or duplicate catalog values")
        return values

    @model_validator(mode="after")
    def reference_matches(self):
        expected = "https://attack.mitre.org/techniques/" + self.id.replace(".", "/")
        if self.reference not in (expected, expected + "/"):
            raise ValueError("Official reference does not match technique identity")
        if not self.name.strip():
            raise ValueError("Technique name is empty")
        if self.parent_id and ("." not in self.id or self.parent_id != self.id.split(".")[0]):
            raise ValueError("Invalid subtechnique parent")
        return self


class Document(StrictModel):
    format: Literal["aegis-enterprise-catalog/1"] = FORMAT
    provenance: Literal["bundled", "official_commit"]
    version: str = Field(pattern="^" + VERSION + "$")
    source_url: str
    source_commit: str | None = Field(default=None, pattern="^" + COMMIT + "$")
    source_sha256: str = Field(pattern="^" + HEX64 + "$")
    license_sha256: str = Field(pattern="^" + HEX64 + "$")
    collection_id: str | None = None
    collection_modified: str | None = None
    techniques: list[Technique] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def identities(self):
        if self.provenance == "official_commit":
            if (
                self.source_commit is None
                or self.collection_id is None
                or self.collection_modified is None
                or self.source_url != source_url(self.version, self.source_commit)
            ):
                raise ValueError("Missing pinned official provenance")
            stix_id(self.collection_id, "x-mitre-collection")
            timestamp(self.collection_modified)
            if any(t.source_modified is None for t in self.techniques):
                raise ValueError("Missing source modification timestamp")
        elif (
            self.source_commit is not None
            or self.collection_id is not None
            or self.collection_modified is not None
            or self.source_url
            != BASE + f"master/enterprise-attack/enterprise-attack-{self.version}.json"
        ):
            raise ValueError("Bundled legacy provenance must remain explicit")
        ids = [t.id for t in self.techniques]
        if ids != sorted(set(ids)) or len({t.stix_id for t in self.techniques}) != len(ids):
            raise ValueError("Duplicate or unordered technique identity")
        lookup = {t.id: t for t in self.techniques}
        for t in self.techniques:
            if t.dataset_version != self.version:
                raise ValueError("Mixed catalog versions")
            if not t.revoked and not t.deprecated and "." in t.id:
                parent = lookup.get(t.parent_id)
                if parent is None or parent.revoked or parent.deprecated or parent.parent_id:
                    raise ValueError("Active subtechnique has no active parent")
            elif t.parent_id is not None and t.parent_id not in lookup:
                raise ValueError("Missing historical parent")
        return self

    @property
    def identity(self):
        return digest(self.model_dump(mode="json"))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw, limit):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError("Catalog file exceeds size limit")

    def invalid(value):
        raise ValueError("Non-JSON numeric constant")

    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid)


def boolean(item, key):
    value = item.get(key, False)
    if type(value) is not bool:
        raise ValueError("Invalid STIX boolean")
    return value


def normalize(raw, version, commit, license_raw):
    url = source_url(version, commit)
    if not isinstance(license_raw, bytes) or not 0 < len(license_raw) <= MAX_LICENSE:
        raise ValueError("Invalid license file")
    bundle = parse_json(raw, MAX_BUNDLE)
    if (
        not isinstance(bundle, dict)
        or bundle.get("type") != "bundle"
        or not isinstance(bundle.get("objects"), list)
        or not 1 <= len(bundle["objects"]) <= 100_000
    ):
        raise ValueError("Invalid Enterprise bundle")
    objects = bundle["objects"]
    if any(not isinstance(o, dict) or not isinstance(o.get("id"), str) for o in objects):
        raise ValueError("Invalid STIX object")
    by_id = {o["id"]: o for o in objects}
    if len(by_id) != len(objects):
        raise ValueError("Ambiguous STIX object versions")
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise ValueError("Exactly one Enterprise collection required")
    collection = collections[0]
    if (
        collection.get("name") != "Enterprise ATT&CK"
        or collection.get("x_mitre_version") != version
        or collection.get("spec_version") != "2.1"
    ):
        raise ValueError("Collection domain/version mismatch")
    contents = collection.get("x_mitre_contents")
    if not isinstance(contents, list) or not 1 <= len(contents) <= 100_000:
        raise ValueError("Collection membership missing")
    members = {}
    for entry in contents:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"object_ref", "object_modified"}
            or entry["object_ref"] in members
        ):
            raise ValueError("Invalid collection membership")
        member = by_id.get(entry["object_ref"])
        if member is None or member.get("modified") != entry["object_modified"]:
            raise ValueError("Missing or changed collection member")
        timestamp(entry["object_modified"])
        members[entry["object_ref"]] = entry["object_modified"]
    if any(
        o["id"] not in members and o.get("type") not in ("x-mitre-collection", "marking-definition")
        for o in objects
    ):
        raise ValueError("Unlisted collection object")
    patterns = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    allowed_tactics = {
        o.get("x_mitre_shortname") for o in objects if o.get("type") == "x-mitre-tactic"
    }
    if any(
        not isinstance(t, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", t)
        for t in allowed_tactics
    ):
        raise ValueError("Invalid official tactic identity")
    edges = {}
    live = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "subtechnique-of":
            source, target = o.get("source_ref"), o.get("target_ref")
            if (
                source not in patterns
                or target not in patterns
                or (source in edges and edges[source] != target)
            ):
                raise ValueError("Invalid or ambiguous subtechnique relationship")
            edges[source] = target
            if not boolean(o, "revoked") and not boolean(o, "x_mitre_deprecated"):
                if source in live:
                    raise ValueError("Ambiguous active subtechnique relationship")
                live[source] = target
    external = {}
    for o in patterns.values():
        refs = [
            r
            for r in o.get("external_references", [])
            if isinstance(r, dict) and r.get("source_name") == "mitre-attack"
        ]
        if (
            len(refs) != 1
            or "enterprise-attack" not in o.get("x_mitre_domains", [])
            or o.get("spec_version") != "2.1"
        ):
            raise ValueError("Technique domain/reference mismatch")
        external[o["id"]] = refs[0]
    techniques = []
    for key, o in patterns.items():
        retired = boolean(o, "revoked") or boolean(o, "x_mitre_deprecated")
        is_sub = boolean(o, "x_mitre_is_subtechnique")
        ref = external[key]
        if (
            is_sub != ("." in ref.get("external_id", ""))
            or (is_sub and not retired and key not in live)
            or (not is_sub and key in edges)
        ):
            raise ValueError("Technique/relationship mismatch")
        parent = edges.get(key)
        phases = o.get("kill_chain_phases", [])
        if not isinstance(phases, list) or any(not isinstance(p, dict) for p in phases):
            raise ValueError("Invalid tactic references")
        tactics = [
            p.get("phase_name") for p in phases if p.get("kill_chain_name") == "mitre-attack"
        ]
        if any(t not in allowed_tactics for t in tactics):
            raise ValueError("Unknown tactic reference")
        techniques.append(
            Technique(
                id=ref.get("external_id"),
                stix_id=key,
                name=o.get("name"),
                description=o.get("description", ""),
                tactics=tactics,
                platforms=o.get("x_mitre_platforms", []),
                parent_id=external[parent].get("external_id") if parent else None,
                reference=ref.get("url"),
                dataset_version=version,
                revoked=boolean(o, "revoked"),
                deprecated=boolean(o, "x_mitre_deprecated"),
                source_modified=o.get("modified"),
            )
        )
    return Document(
        provenance="official_commit",
        version=version,
        source_url=url,
        source_commit=commit,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        license_sha256=hashlib.sha256(license_raw).hexdigest(),
        collection_id=collection["id"],
        collection_modified=collection["modified"],
        techniques=sorted(techniques, key=lambda t: t.id),
    )


def bundled_document(raw, license_raw):
    if not isinstance(license_raw, bytes) or not 0 < len(license_raw) <= MAX_LICENSE:
        raise ValueError("Invalid bundled license file")
    legacy = parse_json(raw, MAX_NORMALIZED)
    if not isinstance(legacy, dict) or set(legacy) != {
        "version",
        "source_url",
        "source_sha256",
        "techniques",
    }:
        raise ValueError("Invalid bundled legacy snapshot")
    return Document(
        provenance="bundled",
        version=legacy["version"],
        source_url=legacy["source_url"],
        source_sha256=legacy["source_sha256"],
        license_sha256=hashlib.sha256(license_raw).hexdigest(),
        techniques=[Technique.model_validate(t) for t in legacy["techniques"]],
    )
