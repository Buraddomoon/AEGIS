"""Official graph semantics with reduced synthetic STIX, never native collection."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from aegis.catalog import artifacts, store
from aegis.catalog.context import detail
from aegis.catalog.document import CONTEXT_FORMAT, FORMAT, Document, normalize
from aegis.models import AttackCatalogRelease, User
from conftest import create_queued
from sqlalchemy.orm import Session
from test_attack_api import catalog_client as _catalog_client
from test_attack_api import finish
from test_attack_publication import catalog_db as _catalog_db
from test_attack_publication import publish

catalog_db = _catalog_db
catalog_client = _catalog_client
ROOT = Path(__file__).resolve().parents[1]
LICENSE = (ROOT / "fixtures/attack/LICENSE.txt").read_bytes()
COMMIT = "a" * 40


def context_bundle():
    data = json.loads((ROOT / "fixtures/attack/synthetic-enterprise-test.json").read_bytes())
    objects = data["objects"]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    child = next(
        o for o in objects if o["type"] == "attack-pattern" and o.get("x_mitre_is_subtechnique")
    )
    modified = child["modified"]
    nodes = []
    for i, (kind, external, path) in enumerate(
        [
            ("x-mitre-data-source", "DS0001", "datasources/DS0001"),
            ("x-mitre-data-component", "DC0001", "datacomponents/DC0001"),
            ("x-mitre-analytic", "AN0001", "detectionstrategies/DET0001#AN0001"),
            ("x-mitre-detection-strategy", "DET0001", "detectionstrategies/DET0001"),
        ],
        1,
    ):
        nodes.append(
            {
                "id": f"{kind}--00000000-0000-4000-8000-{i:012d}",
                "type": kind,
                "spec_version": "2.1",
                "modified": modified,
                "name": f"Synthetic reference {external}",
                "x_mitre_domains": ["enterprise-attack"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": external,
                        "url": "https://attack.mitre.org/" + path,
                    }
                ],
            }
        )
    source, component, analytic, strategy = nodes
    source["x_mitre_deprecated"] = True
    component["x_mitre_data_source_ref"] = source["id"]
    analytic["x_mitre_log_source_references"] = [
        {
            "x_mitre_data_component_ref": component["id"],
            "name": "Synthetic:Process",
            "channel": "Synthetic event channel",
        }
    ]
    strategy["x_mitre_analytic_refs"] = [analytic["id"]]
    nodes.append(
        {
            "id": "relationship--00000000-0000-4000-8000-000000000005",
            "type": "relationship",
            "spec_version": "2.1",
            "modified": modified,
            "relationship_type": "detects",
            "source_ref": strategy["id"],
            "target_ref": child["id"],
        }
    )
    objects.extend(nodes)
    collection["x_mitre_contents"].extend(
        {"object_ref": o["id"], "object_modified": o["modified"]} for o in nodes
    )
    return data


def document(data=None, profile=CONTEXT_FORMAT):
    return normalize(
        json.dumps(data or context_bundle()).encode(), "20.0", COMMIT, LICENSE, profile=profile
    )


def test_graph_preserves_ids_edges_release_flags_and_log_reference():
    doc = document()
    result = detail(doc, "T1059.001")
    assert result["status"] == "available"
    assert result["parent"]["technique"]["id"] == "T1059"
    assert result["parent"]["relationship"]["stix_id"].startswith("relationship--")
    assert result["parent"]["technique"]["dataset_version"] == doc.version
    (row,) = result["telemetry"]
    assert [row[k]["id"] for k in ("strategy", "analytic", "component", "data_source")] == [
        "DET0001",
        "AN0001",
        "DC0001",
        "DS0001",
    ]
    assert row["data_source"]["deprecated"] is True
    assert row["log_source"]["name"] == "Synthetic:Process"
    assert detail(doc, "T1059")["children"][0]["technique"]["id"] == "T1059.001"
    assert detail(doc, "T1059")["telemetry"] == []  # No upward inheritance.
    assert detail(doc, "T1059")["status"] == "not_provided"
    assert detail(doc, "T9999")["status"] == "technique_absent"
    assert Document.model_validate_json(doc.model_dump_json()).identity == doc.identity


def test_legacy_hash_and_parent_navigation_are_preserved_without_invented_sources():
    old = document(profile=FORMAT)
    raw = old.model_dump(mode="json")
    assert "context" not in raw
    from aegis.domain.validation import digest

    assert old.identity == digest(raw)
    assert detail(old, "T1059.001")["status"] == "legacy_unavailable"
    assert detail(old, "T1059.001")["parent"]["relationship"] is None
    new = document()
    assert new.identity != old.identity
    assert store.context_upgrade(old, new)
    assert not store.context_upgrade(new, old)
    changed = context_bundle()
    changed["objects"][0]["name"] += " changed source"
    assert not store.context_upgrade(old, document(changed))


@pytest.mark.parametrize(
    "change",
    [
        "missing-analytic",
        "missing-component",
        "wrong-component-kind",
        "duplicate-analytic",
        "wrong-reference",
        "wrong-domain",
        "duplicate-external",
        "invalid-edge",
        "bad-stix",
        "wrong-type",
        "duplicate-log-key",
        "invalid-timestamp",
    ],
)
def test_malformed_graph_fails_closed(change):
    data = context_bundle()
    nodes = data["objects"]
    source = next(o for o in nodes if o["type"] == "x-mitre-data-source")
    component = next(o for o in nodes if o["type"] == "x-mitre-data-component")
    analytic = next(o for o in nodes if o["type"] == "x-mitre-analytic")
    strategy = next(o for o in nodes if o["type"] == "x-mitre-detection-strategy")
    if change == "missing-analytic":
        strategy["x_mitre_analytic_refs"] = [
            "x-mitre-analytic--00000000-0000-4000-8000-000000000099"
        ]
    elif change == "missing-component":
        analytic["x_mitre_log_source_references"][0]["x_mitre_data_component_ref"] = "missing"
    elif change == "wrong-component-kind":
        analytic["x_mitre_log_source_references"][0]["x_mitre_data_component_ref"] = source["id"]
    elif change == "duplicate-analytic":
        strategy["x_mitre_analytic_refs"] *= 2
    elif change == "wrong-reference":
        component["external_references"][0]["url"] = (
            "https://attackXmitre.org/datacomponents/DC0001"
        )
    elif change == "wrong-domain":
        analytic["x_mitre_domains"] = ["mobile-attack"]
    elif change == "duplicate-external":
        component["external_references"] *= 2
    elif change == "invalid-edge":
        next(o for o in nodes if o.get("relationship_type") == "detects")["target_ref"] = "missing"
    elif change == "bad-stix":
        component["id"] = "x-mitre-data-component--wrong"
    elif change == "wrong-type":
        strategy["x_mitre_analytic_refs"] = "not-a-list"
    elif change == "duplicate-log-key":
        analytic["x_mitre_log_source_references"][0]["name"] = ""
    elif change == "invalid-timestamp":
        analytic["modified"] = "invalid"
    with pytest.raises((ValueError, TypeError)):
        document(data)


def test_no_analytic_or_no_log_sources_stays_explicit():
    data = context_bundle()
    analytic = next(o for o in data["objects"] if o["type"] == "x-mitre-analytic")
    analytic.pop("x_mitre_log_source_references")
    (row,) = detail(document(data), "T1059.001")["telemetry"]
    assert row["analytic"]["id"] == "AN0001" and "component" not in row
    strategy = next(o for o in data["objects"] if o["type"] == "x-mitre-detection-strategy")
    strategy["x_mitre_analytic_refs"] = []
    (row,) = detail(document(data), "T1059.001")["telemetry"]
    assert "analytic" not in row and "component" not in row


def test_direct_component_relationship_and_retired_reference():
    data = context_bundle()
    edge = next(o for o in data["objects"] if o.get("relationship_type") == "detects")
    edge["source_ref"] = next(
        o["id"] for o in data["objects"] if o["type"] == "x-mitre-data-component"
    )
    edge["revoked"] = True
    (row,) = detail(document(data), "T1059.001")["telemetry"]
    assert row["component"]["id"] == "DC0001" and row["relationship"]["revoked"]
    assert row["data_source"]["id"] == "DS0001" and "strategy" not in row


def test_same_source_profile_upgrade_publishes_new_release_without_rewriting(catalog_client):
    client, engine, actor = catalog_client
    old, new = document(profile=FORMAT), document()
    publish(engine, actor, old)
    before = client.get("/api/v1/coverage").json()
    publish(engine, actor, new)
    with Session(engine) as db:
        assert db.get(AttackCatalogRelease, old.identity).document == old.model_dump(mode="json")
        assert db.get(AttackCatalogRelease, new.identity).document == new.model_dump(mode="json")
        assert "immutable_version_conflict" in store.plan(db, old, old.license_sha256)["blockers"]
    payload = client.get("/api/v1/techniques/T1059.001").json()
    assert payload["catalog_context"]["catalog"]["release_id"] == new.identity
    assert payload["catalog_context"]["telemetry"][0]["component"]["id"] == "DC0001"
    assert payload["observed_telemetry"] == [] and payload["telemetry_sources"] == []
    after = client.get("/api/v1/coverage").json()
    assert before["evaluated_techniques"] == after["evaluated_techniques"] == 0
    assert before["catalogued_techniques"] == after["catalogued_techniques"] == 3
    assert (
        client.get("/api/v1/techniques/T1059.001?catalog_release_id=" + old.identity).status_code
        == 409
    )
    absent = client.get("/api/v1/techniques/T1059.004").json()
    assert absent["catalog_context"]["status"] == "technique_absent"
    assert absent["catalog_context"]["parent"] is None
    with Session(engine) as db:
        db.get(User, actor).role = "viewer"
        db.commit()
    assert client.get("/api/v1/techniques/T1059.001").status_code == 200


def test_observations_require_events_and_keep_mode_and_historical_release(catalog_client):
    client, engine, actor = catalog_client
    empty = client.get("/api/v1/techniques/T1059.001").json()
    assert empty["tests"] and empty["telemetry_sources"] == []
    run = create_queued(client, ["demo-powershell"])
    finish(run["id"])
    reports = {
        kind: client.get(f"/api/v1/reports/{run['id']}?format={kind}").content
        for kind in ["json", "html", "pdf"]
    }
    prior = client.get("/api/v1/techniques/T1059.001").json()
    (observed,) = prior["observed_telemetry"]
    assert observed["synthetic"] is True and observed["sources"]
    assert all(source["synthetic"] and source["event_count"] > 0 for source in observed["sources"])
    publish(engine, actor, document())
    current = client.get("/api/v1/techniques/T1059.001").json()
    assert current["coverage"] == "NOT_TESTED"
    assert current["observed_telemetry"] == prior["observed_telemetry"]
    assert observed["catalog_release_id"] != current["catalog_context"]["catalog"]["release_id"]
    real = client.get("/api/v1/techniques/T1059.001?mode=linux").json()
    assert real["telemetry_sources"] == [] and real["observed_telemetry"] == []
    for kind, raw in reports.items():
        assert client.get(f"/api/v1/reports/{run['id']}?format={kind}").content == raw


def test_offline_enrichment_preserves_old_candidate_and_never_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(
        artifacts, "fetch", lambda *a, **k: pytest.fail("offline enrichment downloaded")
    )
    cache = tmp_path / "private" / "cache"
    artifacts.private(cache.parent, True)
    artifacts.private(cache, True)
    raw = json.dumps(context_bundle()).encode()
    old = normalize(raw, "20.0", COMMIT, LICENSE, profile=FORMAT)
    artifacts.save_candidate(cache, old, raw, LICENSE)
    before = {p.name: p.read_bytes() for p in (cache / old.identity).iterdir()}
    new_id = artifacts.enrich(cache, old.identity)
    new = artifacts.load(cache, new_id)
    assert new.format == CONTEXT_FORMAT and new.source_sha256 == hashlib.sha256(raw).hexdigest()
    assert new_id != old.identity and artifacts.enrich(cache, new_id) == new_id
    assert before == {p.name: p.read_bytes() for p in (cache / old.identity).iterdir()}
    changed = copy.deepcopy(new.model_dump())
    changed["context"]["objects"][0]["name"] += " changed"
    assert Document.model_validate(changed).identity != new.identity


def test_context_migration_preserves_documents_and_refuses_history_loss(catalog_db):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text

    engine, actor = catalog_db
    old = document(profile=FORMAT)
    publish(engine, actor, old)
    config = Config("alembic.ini")
    command.downgrade(config, "c8e4a6d21f90")
    with engine.connect() as connection:
        before = list(
            connection.execute(text("SELECT id, document FROM attack_catalog_releases ORDER BY id"))
        )
    command.upgrade(config, "head")
    command.check(config)
    with engine.connect() as connection:
        assert (
            list(
                connection.execute(
                    text("SELECT id, document FROM attack_catalog_releases ORDER BY id")
                )
            )
            == before
        )
    publish(engine, actor, document())
    with pytest.raises(RuntimeError, match="history exists"):
        command.downgrade(config, "c8e4a6d21f90")
    with Session(engine) as db:
        assert store.checked(db.get(AttackCatalogRelease, old.identity)) == old
        assert store.checked(db.get(AttackCatalogRelease, document().identity)) == document()
