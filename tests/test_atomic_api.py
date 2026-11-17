import hashlib
import uuid

import pytest
from aegis.db import session_factory
from aegis.models import AtomicEntry, AtomicReview, AuditEvent
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from test_atomic_catalog import COMMIT, RAW, SHA

BASE = "/api/v1/catalog/atomic"


def payload(content=RAW, commit=COMMIT):
    return {
        "content": content,
        "source_commit": commit,
        "source_sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


def imported(admin):
    result = admin.post(BASE + "/imports", json=payload())
    assert result.status_code == 201, result.text
    return admin.get(BASE).json()["items"][0]


def test_import_query_review_and_campaign_separation(admin):
    before = admin.get("/api/v1/tests").json()
    entry = imported(admin)
    repeated = admin.post(BASE + "/imports", json=payload())
    assert repeated.status_code == 200 and repeated.json()["unchanged"]
    assert repeated.json()["source"]["source_sha256"] == SHA
    page = admin.get(BASE, params={"q": "T1059.004", "platform": "linux", "limit": 2}).json()
    assert page["total"] >= 2 and len(page["items"]) == 2
    assert not page["items"][0]["approved"] and not page["items"][0]["available_for_new_scope"]
    assert admin.get(BASE, params={"q": "%"}).json()["total"] == 0
    assert admin.get(BASE, params={"platform": "invalid-platform"}).json()["total"] == 0
    assert admin.get(BASE, params={"q": entry["guid"]}).json()["total"] == 1
    detail = admin.get(BASE + f"/entries/{entry['id']}").json()
    assert detail["attack_mapping_status"] == "active"
    assert detail["source"]["source_commit"] == COMMIT
    assert detail["guid"] == entry["guid"]
    assert "command" not in detail
    assert "metadata_projection" not in detail
    review_url = BASE + f"/entries/{entry['id']}/reviews"
    review = {
        "decision": "reviewed",
        "expected_sequence": 0,
        "note": "Revisado somente como metadado; risco de execução não avaliado.",
    }
    result = admin.post(review_url, json=review)
    assert result.status_code == 201, result.text
    assert not result.json()["executable"] and not result.json()["approved"]
    assert admin.post(review_url, json=review).status_code == 409
    result = admin.post(review_url, json={**review, "decision": "rejected", "expected_sequence": 1})
    assert result.status_code == 201
    history = admin.get(review_url, params={"limit": 1}).json()
    assert history["total"] == 2 and history["items"][0]["decision"] == "rejected"
    assert admin.get(BASE, params={"review_status": "rejected"}).json()["total"] == 1
    assert admin.get(BASE, params={"review_status": "pending"}).json()["total"] == 16
    assert admin.get("/api/v1/tests").json() == before
    lab = admin.get("/api/v1/labs").json()["items"][0]
    denied = admin.post(
        "/api/v1/campaigns",
        json={
            "name": "Atomic unavailable",
            "objective": "Only a metadata fixture",
            "laboratory_id": lab["id"],
            "test_ids": [entry["id"]],
        },
    )
    assert denied.status_code == 404
    with session_factory()() as db:
        actions = list(
            db.scalars(select(AuditEvent.action).where(AuditEvent.action.like("atomic.%")))
        )
        assert actions.count("atomic.import") == 1
        assert actions.count("atomic.import_unchanged") == 1
        assert actions.count("atomic.metadata_review") == 2
        for operation in ("UPDATE atomic_reviews SET note='rewrite'", "DELETE FROM atomic_reviews"):
            with pytest.raises(DBAPIError, match="history is immutable"):
                db.execute(text(operation))
            db.rollback()


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_only_admin_imports_or_reviews(client, role):
    login = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": role, "password": "Test-only-randomized-scope-23!"},
    )
    client.headers["x-csrf-token"] = login.json()["csrf_token"]
    assert client.get(BASE).status_code == 200
    assert client.get(BASE + "/documents").status_code == 200
    assert client.post(BASE + "/imports", json=payload()).status_code == 403
    assert (
        client.post(
            BASE + f"/entries/{uuid.uuid4()}/reviews",
            json={"decision": "reviewed", "note": "only metadata", "expected_sequence": 0},
        ).status_code
        == 403
    )


def test_authentication_csrf_origin_and_bounds(client, admin):
    client.cookies.clear()
    assert client.get(BASE).status_code == 401
    assert client.post(BASE + "/imports", json=payload()).status_code == 401
    login = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "administrator", "password": "Test-only-randomized-scope-23!"},
    )
    csrf = login.json()["csrf_token"]
    client.headers["x-csrf-token"] = "wrong"
    assert client.post(BASE + "/imports", json=payload()).status_code == 403
    client.headers["x-csrf-token"] = csrf
    assert (
        client.post(
            BASE + "/imports", json=payload(), headers={"origin": "https://untrusted.invalid"}
        ).status_code
        == 403
    )
    for params in (
        {"limit": 101},
        {"offset": -1},
        {"q": "x" * 101},
        {"review_status": "approved"},
        {"document_id": "invalid"},
    ):
        assert client.get(BASE, params=params).status_code == 422
    assert client.get(BASE + f"/entries/{uuid.uuid4()}").status_code == 404
    assert client.get(BASE + "/entries/not-uuid").status_code == 422
    assert (
        client.post(BASE + "/imports", json={**payload(), "content": "é" * 40000}).status_code
        == 422
    )
    assert client.post(BASE + "/imports", json={**payload(), "approved": True}).status_code == 422
    result = client.post(BASE + "/imports", content=b"x" * 262145)
    assert result.status_code == 413


@pytest.mark.parametrize(
    "content",
    [
        "!!python/object/apply:os.system [NEVER-ECHO-UNTRUSTED]",
        "attack_technique: null",
        "x: &a [1]\ny: *a",
    ],
)
def test_parse_errors_are_consistent_redacted_and_audited(admin, content):
    result = admin.post(BASE + "/imports", json=payload(content))
    assert result.status_code == 422
    assert "error" in result.json() and "NEVER-ECHO-UNTRUSTED" not in result.text
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AtomicEntry)) == 0
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "atomic.import_rejected"))
        assert event and "NEVER-ECHO" not in str(event.details)


def test_import_version_is_independent_and_review_not_inherited(admin):
    entry = imported(admin)
    url = BASE + f"/entries/{entry['id']}/reviews"
    assert (
        admin.post(
            url,
            json={"decision": "reviewed", "note": "Fixture metadata only", "expected_sequence": 0},
        ).status_code
        == 201
    )
    assert (
        admin.post(BASE + "/imports", json=payload(RAW + "\n# fixture change\n")).status_code == 422
    )
    assert admin.post(BASE + "/imports", json=payload(commit="a" * 40)).status_code == 201
    docs = admin.get(BASE + "/documents").json()
    assert docs["total"] == 2
    document = next(x for x in docs["items"] if x["source_commit"] == "a" * 40)
    page = admin.get(
        BASE, params={"document_id": document["document_id"], "review_status": "pending"}
    ).json()
    assert page["total"] == 17
    assert admin.get(url).json()["total"] == 1
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AtomicReview)) == 1


def test_import_rate_limit(admin):
    for _ in range(10):
        assert admin.post(BASE + "/imports", json=payload("invalid scalar")).status_code == 422
    assert admin.post(BASE + "/imports", json=payload()).status_code == 429


def test_runtime_grants_are_insert_only_and_support_previous_schema(db_ready, pg_engine):
    from aegis.operations.runtime_grants import RUNTIME_PERMISSIONS

    role = "aegis_atomic_test_" + uuid.uuid4().hex
    with pg_engine.begin() as conn:
        namespace = conn.scalar(text("SELECT current_schema()"))
        conn.exec_driver_sql(f'CREATE ROLE "{role}" NOLOGIN')
    try:
        with pg_engine.begin() as conn:
            for statement in RUNTIME_PERMISSIONS:
                conn.exec_driver_sql(
                    statement.replace("SCHEMA public", f'SCHEMA "{namespace}"').replace(
                        "aegis_app", f'"{role}"'
                    )
                )
            for table in ("atomic_documents", "atomic_entries", "atomic_reviews"):
                for privilege, allowed in (
                    ("SELECT", True),
                    ("INSERT", True),
                    ("UPDATE", False),
                    ("DELETE", False),
                ):
                    assert (
                        conn.scalar(
                            text("SELECT has_table_privilege(:role,:table,:privilege)"),
                            {"role": role, "table": f"{namespace}.{table}", "privilege": privilege},
                        )
                        is allowed
                    )
    finally:
        with pg_engine.begin() as conn:
            conn.exec_driver_sql(f'DROP OWNED BY "{role}"')
            conn.exec_driver_sql(f'DROP ROLE "{role}"')


def test_concurrent_reviews_preserve_first_decision(admin):
    from concurrent.futures import ThreadPoolExecutor
    from uuid import UUID

    from aegis.atomic_api import Review, review
    from aegis.models import User
    from fastapi import HTTPException

    entry = imported(admin)

    def decide(decision):
        with session_factory()() as db:
            user = db.scalar(select(User).where(User.username == "administrator"))
            try:
                review(
                    UUID(entry["id"]),
                    Review(
                        decision=decision, note="Concurrent fixture review", expected_sequence=0
                    ),
                    user,
                    db,
                )
                return 201
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(decide, ["reviewed", "rejected"])) == [201, 409]
    assert admin.get(BASE + f"/entries/{entry['id']}/reviews").json()["total"] == 1


def test_redis_unavailable_denies_import_without_writes(admin, monkeypatch):
    import aegis.security as security
    from redis.exceptions import RedisError

    def unavailable():
        raise RedisError("unavailable")

    monkeypatch.setattr(security, "redis_client", unavailable)
    assert admin.post(BASE + "/imports", json=payload()).status_code == 503
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AtomicEntry)) == 0
