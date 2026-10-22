import uuid

from aegis.db import session_factory
from aegis.models import CampaignRun
from aegis.models import TestDefinition as Definition
from aegis.queries import scope_changes
from aegis.worker import claim_next, process_run
from conftest import create_queued
from test_rule_links import import_rule, review_body


def test_comparison_uses_historical_rule_links_versions_and_environment(admin):
    rule, version = import_rule(admin)
    first = create_queued(admin, ["demo-shell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    import_rule(admin, version["content"].replace("level: informational", "level: low"))
    latest = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    assert (
        admin.post(f"/api/v1/rules/{rule['id']}/test-links", json=review_body(latest)).status_code
        == 201
    )
    later = admin.post(
        f"/api/v1/campaigns/{first['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    assert (
        admin.post(
            f"/api/v1/executions/{later['id']}/approve",
            json={"confirm_scope_hash": later["scope_hash"]},
        ).status_code
        == 200
    )
    assert (
        admin.post(f"/api/v1/executions/{later['id']}/start", json={"confirm": True}).status_code
        == 200
    )
    assert claim_next() == later["id"]
    process_run(later["id"])
    url = f"/api/v1/coverage/compare?before={first['id']}&after={later['id']}"
    compared = admin.get(url).json()
    assert not compared["same_scope"] and not compared["comparable"]
    assert compared["tests"][0]["before"] == compared["tests"][0]["after"] == "DETECTED"
    changes = compared["scope_changes"]
    assert changes["rule_versions"] == [{"key": rule["id"], "before": 1, "after": 2}]
    assert changes["rule_test_links"][0]["before"] is None
    assert changes["rule_test_links"][0]["after"]["rule_version"] == 2
    assert changes["environment"] == changes["test_definitions"] == []
    # Further live edits must not change comparison of two completed historical snapshots.
    import_rule(admin, version["content"].replace("level: informational", "level: medium"))
    with session_factory()() as db:
        db.get(Definition, "demo-shell").version = 2
        db.commit()
    assert admin.get(url).json() == compared


def test_legacy_scope_has_unknown_link_context_and_removed_test_is_visible(admin):
    first = create_queued(admin, ["demo-shell", "demo-file-marker"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    with session_factory()() as db:
        run = db.get(CampaignRun, first["id"])
        run.scope = {k: v for k, v in run.scope.items() if k != "rule_test_links"}
        db.commit()
    later = admin.post(
        f"/api/v1/campaigns/{first['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    compared = admin.get(
        f"/api/v1/coverage/compare?before={first['id']}&after={later['id']}"
    ).json()
    assert not compared["scope_changes"]["link_context_recorded"]
    assert compared["scope_changes"]["rule_test_links"] is None


def test_scope_diff_reports_test_and_environment_changes_without_inference():
    before = {
        "test_definitions": [{"id": "shell", "version": 1}],
        "environment_version": 1,
        "rule_test_links": [],
        "rule_versions": {},
    }
    after = {
        **before,
        "environment_version": 2,
        "test_definitions": [{"id": "other", "version": 2}],
    }
    changes = scope_changes(before, after)
    assert [x["key"] for x in changes["test_definitions"]] == ["other", "shell"]
    assert changes["environment"] == [{"key": "environment_version", "before": 1, "after": 2}]
    assert changes["rule_test_links"] == []
