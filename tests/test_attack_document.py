"""Catalog profile tests use a clearly labelled reduced STIX fixture, not a release."""

import copy
import json
from pathlib import Path

import pytest
from aegis.catalog.document import (
    BASE,
    Document,
    Technique,
    bundled_document,
    normalize,
    parse_json,
    source_url,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/attack/synthetic-enterprise-test.json"
LICENSE = (ROOT / "fixtures/attack/LICENSE.txt").read_bytes()
COMMIT = "a" * 40  # Transport fixture identity, never asserted to be a real Git commit.


def bundle():
    return json.loads(FIXTURE.read_bytes())


def encoded(value):
    return json.dumps(value).encode()


def test_reduced_fixture_preserves_explicit_lifecycle_and_parent():
    result = normalize(FIXTURE.read_bytes(), "20.0", COMMIT, LICENSE)
    assert len(result.techniques) == 5
    lookup = {t.id: t for t in result.techniques}
    assert lookup["T1059.001"].parent_id == "T1059"
    assert sum(t.revoked for t in result.techniques) == 1
    assert sum(t.deprecated for t in result.techniques) == 1
    assert result.source_commit == COMMIT and result.provenance == "official_commit"
    assert Document.model_validate_json(result.model_dump_json()).identity == result.identity


def test_distributed_legacy_remains_explicit_without_invented_provenance():
    result = bundled_document((ROOT / "fixtures/attack/enterprise.json").read_bytes(), LICENSE)
    assert result.provenance == "bundled" and result.source_commit is None
    assert result.collection_id is None and len(result.techniques) == 706
    assert all(
        not t.revoked and not t.deprecated and t.source_modified is None for t in result.techniques
    )


@pytest.mark.parametrize(
    "version,commit",
    [
        ("latest", COMMIT),
        ("20.0", "master"),
        ("20.00", COMMIT),
        ("20.0", "A" * 40),
        ("../20.0", COMMIT),
    ],
)
def test_no_arbitrary_url_branch_or_ambiguous_version(version, commit):
    with pytest.raises(ValueError):
        source_url(version, commit)


@pytest.mark.parametrize(
    "change",
    [
        "duplicate-object",
        "duplicate-external-id",
        "missing-member",
        "unlisted-object",
        "member-modified",
        "wrong-version",
        "wrong-domain",
        "duplicate-member",
        "unknown-tactic",
        "missing-parent",
        "ambiguous-parent",
        "string-boolean",
        "wrong-reference",
        "duplicate-platform",
        "invalid-timestamp",
    ],
)
def test_malformed_or_partial_source_is_rejected(change):
    data = bundle()
    objects = data["objects"]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    pattern = next(o for o in objects if o["type"] == "attack-pattern")
    child = next(
        o for o in objects if o["type"] == "attack-pattern" and o.get("x_mitre_is_subtechnique")
    )
    parent = next(
        o
        for o in objects
        if o["type"] == "attack-pattern"
        and not o.get("x_mitre_is_subtechnique")
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    )
    if change == "duplicate-object":
        objects.append(copy.deepcopy(pattern))
    elif change == "duplicate-external-id":
        next(r for r in child["external_references"] if r["source_name"] == "mitre-attack")[
            "external_id"
        ] = next(r for r in parent["external_references"] if r["source_name"] == "mitre-attack")[
            "external_id"
        ]
    elif change == "missing-member":
        objects.remove(pattern)
    elif change == "unlisted-object":
        collection["x_mitre_contents"] = [
            r for r in collection["x_mitre_contents"] if r["object_ref"] != pattern["id"]
        ]
    elif change == "member-modified":
        collection["x_mitre_contents"][0]["object_modified"] = "2026-01-01T00:00:00Z"
    elif change == "wrong-version":
        collection["x_mitre_version"] = "19.2"
    elif change == "wrong-domain":
        pattern["x_mitre_domains"] = ["mobile-attack"]
    elif change == "duplicate-member":
        collection["x_mitre_contents"].append(copy.deepcopy(collection["x_mitre_contents"][0]))
    elif change == "unknown-tactic":
        pattern["kill_chain_phases"][0]["phase_name"] = "not-a-real-tactic"
    elif change == "missing-parent":
        for o in list(objects):
            if o["type"] == "relationship" and o.get("relationship_type") == "subtechnique-of":
                objects.remove(o)
                collection["x_mitre_contents"] = [
                    r for r in collection["x_mitre_contents"] if r["object_ref"] != o["id"]
                ]
    elif change == "ambiguous-parent":
        edge = copy.deepcopy(next(o for o in objects if o["type"] == "relationship"))
        edge["id"] = "relationship--11111111-1111-4111-8111-111111111111"
        edge["target_ref"] = parent["id"]
        objects.append(edge)
        collection["x_mitre_contents"].append(
            {"object_ref": edge["id"], "object_modified": edge["modified"]}
        )
    elif change == "string-boolean":
        pattern["revoked"] = "false"
    elif change == "wrong-reference":
        next(r for r in pattern["external_references"] if r["source_name"] == "mitre-attack")[
            "url"
        ] = "https://untrusted.invalid/technique"
    elif change == "duplicate-platform":
        pattern["x_mitre_platforms"] = ["Linux", "Linux"]
    elif change == "invalid-timestamp":
        pattern["modified"] = "not-time"
        next(r for r in collection["x_mitre_contents"] if r["object_ref"] == pattern["id"])[
            "object_modified"
        ] = "not-time"
    with pytest.raises((ValueError, TypeError)):
        normalize(encoded(data), "20.0", COMMIT, LICENSE)


def test_json_duplicate_keys_nonfinite_values_and_limits():
    for raw in (b'{"type":"bundle","type":"bundle"}', b'{"value":NaN}'):
        with pytest.raises(ValueError):
            parse_json(raw, 1024)
    with pytest.raises(ValueError, match="size"):
        parse_json(b"{}", 1)


def test_document_rejects_mixed_versions_or_identity_rewrites():
    document = normalize(FIXTURE.read_bytes(), "20.0", COMMIT, LICENSE).model_dump()
    document["techniques"][0]["dataset_version"] = "19.2"
    with pytest.raises(ValueError, match="Mixed"):
        Document.model_validate(document)
    with pytest.raises(ValueError, match="reference"):
        Technique.model_validate(
            {
                **normalize(FIXTURE.read_bytes(), "20.0", COMMIT, LICENSE)
                .techniques[0]
                .model_dump(),
                "reference": BASE + "unrelated",
            }
        )
