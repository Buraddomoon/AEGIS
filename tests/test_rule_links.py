import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from aegis import rule_links
from aegis.db import session_factory
from aegis.models import AuditEvent, RuleTestLink, User
from aegis.models import TestDefinition as Definition
from aegis.schemas import RuleTestReview
from aegis.worker import claim_next, process_run
from conftest import create_queued
from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from test_integrations import SIGMA


def import_rule(client, content=SIGMA):
    response = client.post("/api/v1/rules", json={"content": content})
    assert response.status_code == 201, response.text
    rule = response.json()
    version = client.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    return rule, version


def review_body(version, **updates):
    return {
        "rule_version_id": version["id"],
        "test_id": "demo-shell",
        "confirm_rule_sha256": version["sha256"],
        "confirm_test_version": 1,
        "rationale": "Avaliar processo benigno de shell e a fonte de criação de processos.",
        **updates,
    }


def links(client, rule, **params):
    return client.get("/api/v1/rule-test-links", params={"rule_id": rule["id"], **params}).json()


def test_review_replace_retire_keeps_history_and_audit(admin):
    rule, version = import_rule(admin)
    url = f"/api/v1/rules/{rule['id']}/test-links"
    first = admin.post(url, json=review_body(version))
    assert first.status_code == 201, first.text
    first = first.json()
    listed = links(admin, rule)["items"][0]
    assert listed["rule_sha256"] == version["sha256"]
    assert listed["purpose"] == "planning_only_not_deployed" and not listed["review_required"]
    assert admin.post(url, json=review_body(version)).status_code == 409
    second = admin.post(url, json=review_body(version, replaces_id=first["id"])).json()
    assert second["id"] != first["id"]
    assert links(admin, rule)["total"] == 1
    history = links(admin, rule, include_retired=True, limit=1)
    assert history["total"] == 2 and len(history["items"]) == 1
    assert admin.delete(url + "/" + first["id"]).status_code == 200
    assert links(admin, rule)["items"][0]["id"] == second["id"]
    assert admin.delete(url + "/" + second["id"]).status_code == 200
    assert admin.delete(url + "/" + second["id"]).status_code == 200
    assert links(admin, rule)["total"] == 0
    history = links(admin, rule, include_retired=True)["items"]
    assert all(x["retired_at"] and x["retired_by"] for x in history)
    with session_factory()() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "sigma.test_link.retire")
            )
            == 1
        )


@pytest.mark.parametrize(
    "change, status",
    [
        ({"confirm_rule_sha256": "0" * 64}, 409),
        ({"confirm_test_version": 2}, 409),
        ({"rule_version_id": str(uuid.uuid4())}, 404),
        ({"test_id": "unknown-test"}, 404),
        ({"rationale": " " * 30}, 422),
        ({"command": "anything"}, 422),
    ],
)
def test_review_rejects_stale_or_invalid_input(admin, change, status):
    rule, version = import_rule(admin)
    assert (
        admin.post(
            f"/api/v1/rules/{rule['id']}/test-links", json=review_body(version, **change)
        ).status_code
        == status
    )
    assert links(admin, rule)["total"] == 0


def test_new_versions_require_explicit_review_and_wrong_rule_is_rejected(admin):
    rule, version = import_rule(admin)
    url = f"/api/v1/rules/{rule['id']}/test-links"
    first = admin.post(url, json=review_body(version)).json()
    other, other_version = import_rule(
        admin, SIGMA.replace("6d2e4d91-0ff3-4569-a2e7-0bbb163f4421", str(uuid.uuid4()))
    )
    assert admin.post(url, json=review_body(other_version)).status_code == 404
    assert admin.delete(f"/api/v1/rules/{other['id']}/test-links/{first['id']}").status_code == 404
    _, newest = import_rule(admin, SIGMA.replace("level: informational", "level: low"))
    current = links(admin, rule)["items"][0]
    assert current["review_required"] and current["rule_version"] == 1
    assert current["latest_rule_version"] == 2
    assert admin.post(url, json=review_body(version, replaces_id=first["id"])).status_code == 409
    assert admin.post(url, json=review_body(newest, replaces_id=first["id"])).status_code == 201
    assert not links(admin, rule)["items"][0]["review_required"]
    with session_factory()() as db:
        db.get(Definition, "demo-shell").version = 2
        db.commit()
    assert links(admin, rule)["items"][0]["review_required"]


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_review_authorization_and_csrf(admin, role):
    rule, version = import_rule(admin)
    url = f"/api/v1/rules/{rule['id']}/test-links"
    response = admin.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": role, "password": "Test-only-randomized-scope-23!"},
    )
    admin.headers["x-csrf-token"] = response.json()["csrf_token"]
    assert admin.get("/api/v1/rule-test-links").status_code == 200
    result = admin.post(url, json=review_body(version))
    assert result.status_code == (201 if role == "operator" else 403)
    if role == "operator":
        admin.headers.pop("x-csrf-token")
        assert admin.delete(url + "/" + result.json()["id"]).status_code == 403
    else:
        assert admin.delete(url + "/" + str(uuid.uuid4())).status_code == 403


def test_concurrent_review_does_not_overwrite_another_operator(admin):
    rule, version = import_rule(admin)

    def create(_):
        with session_factory()() as db:
            actor = db.scalar(select(User).where(User.role == "operator"))
            try:
                return rule_links.review(
                    db, rule["id"], RuleTestReview(**review_body(version)), actor
                ).id
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, range(2)))
    assert results.count(409) == 1
    assert links(admin, rule)["total"] == 1


def test_database_rejects_duplicate_active_links_and_mismatched_version(admin):
    rule, version = import_rule(admin)
    other, _ = import_rule(
        admin, SIGMA.replace("6d2e4d91-0ff3-4569-a2e7-0bbb163f4421", str(uuid.uuid4()))
    )
    first = admin.post(f"/api/v1/rules/{rule['id']}/test-links", json=review_body(version)).json()
    for target_rule in [rule["id"], other["id"]]:
        with session_factory()() as db:
            db.add(
                RuleTestLink(
                    rule_id=target_rule,
                    rule_version_id=version["id"],
                    test_id="demo-shell",
                    test_version=1,
                    rationale="duplicate",
                    created_by=first["created_by"],
                )
            )
            with pytest.raises(IntegrityError):
                db.commit()


def test_database_history_cannot_be_rewritten_or_deleted(admin):
    rule, version = import_rule(admin)
    url = f"/api/v1/rules/{rule['id']}/test-links"
    link = admin.post(url, json=review_body(version)).json()
    assert admin.delete(url + "/" + link["id"]).status_code == 200
    for statement in [
        update(RuleTestLink)
        .where(RuleTestLink.id == link["id"])
        .values(retired_at=None, retired_by=None),
        update(RuleTestLink).where(RuleTestLink.id == link["id"]).values(rationale="rewritten"),
        delete(RuleTestLink).where(RuleTestLink.id == link["id"]),
    ]:
        with session_factory()() as db, pytest.raises(IntegrityError):
            db.execute(statement)
    assert links(admin, rule, include_retired=True)["items"][0]["rationale"] == link["rationale"]


def test_scope_and_report_preserved_after_rule_review(admin):
    rule, version = import_rule(admin)
    first = create_queued(admin, ["demo-shell"])
    assert claim_next() == first["id"]
    process_run(first["id"])
    original = admin.get(f"/api/v1/reports/{first['id']}").json()
    first_coverage = admin.get("/api/v1/coverage").json()
    response = admin.post(f"/api/v1/rules/{rule['id']}/test-links", json=review_body(version))
    assert response.status_code == 201, response.text
    assert original == admin.get(f"/api/v1/reports/{first['id']}").json()
    assert first_coverage == admin.get("/api/v1/coverage").json()
    technique = admin.get("/api/v1/techniques/T1059.004").json()
    assert technique["operational_rules"] == []
    assert len(technique["planned_rule_links"]) == 1
    later = admin.post(
        f"/api/v1/campaigns/{first['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    assert later["scope"]["rule_test_links"][0]["id"] == response.json()["id"]
    assert later["scope_hash"] != first["scope_hash"]
    admin.delete(f"/api/v1/rules/{rule['id']}/test-links/{response.json()['id']}")
    assert (
        admin.post(
            f"/api/v1/executions/{later['id']}/approve",
            json={"confirm_scope_hash": later["scope_hash"]},
        ).status_code
        == 409
    )
