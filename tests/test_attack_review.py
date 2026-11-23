"""Read-only administrative review against disposable PG and synthetic STIX only."""

import json
import os

import pytest
from aegis.catalog import artifacts, review, store
from aegis.config import settings
from sqlalchemy import text
from sqlalchemy.orm import Session
from test_attack_api import catalog_client as _catalog_client
from test_attack_artifacts import source_transport
from test_attack_document import COMMIT
from test_attack_publication import LICENSE_HASH, fingerprint, publish
from test_attack_publication import catalog_db as _catalog_db

catalog_db = _catalog_db
catalog_client = _catalog_client
BASE = "/api/v1/catalog/attack/reviews"


@pytest.fixture
def prepared(catalog_client, tmp_path, monkeypatch):
    client, engine, actor = catalog_client
    cache = tmp_path / ".local/attack-catalog"
    with source_transport() as transport:
        identity = artifacts.prepare(cache, "20.0", COMMIT, transport=transport)
    with Session(engine) as db:
        plan = store.plan(db, artifacts.load(cache, identity), LICENSE_HASH)
    artifacts.save_plan(cache, plan)
    monkeypatch.setattr(settings(), "attack_review_cache", cache)
    # Neither a list, detail nor instruction is allowed to touch the network.
    monkeypatch.setattr(artifacts, "fetch", lambda *a, **kw: pytest.fail("Network reached"))
    return client, engine, actor, cache, plan


def test_review_is_opt_in_and_anonymous_cannot_read(catalog_client, monkeypatch):
    client, _, _ = catalog_client
    monkeypatch.setattr(settings(), "attack_review_cache", None)
    assert client.get(BASE).json()["status"] == "disabled"
    assert client.get(BASE + "/" + "a" * 64).status_code == 409
    client.cookies.clear()
    assert client.get(BASE).status_code == 401


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_only_active_admin_reads_plans(prepared, role):
    client, engine, actor, _, plan = prepared
    with engine.begin() as db:
        db.execute(text("UPDATE users SET role=:role WHERE id=:id"), {"role": role, "id": actor})
    for path in (
        BASE,
        BASE + "/" + plan["plan_sha256"],
        BASE + "/" + plan["plan_sha256"] + "/instruction",
    ):
        assert client.get(path).status_code == 403


def test_review_paginates_exact_diff_and_instructions_without_writes(prepared):
    client, engine, actor, cache, plan = prepared
    before = fingerprint(engine)
    files = {str(p.relative_to(cache)): p.read_bytes() for p in cache.rglob("*") if p.is_file()}
    listing = client.get(BASE + "?limit=1")
    assert listing.headers["cache-control"] == "no-store"
    assert listing.json()["items"][0]["plan_sha256"] == plan["plan_sha256"]
    path = BASE + "/" + plan["plan_sha256"]
    detail = client.get(path + "?limit=2").json()
    assert detail["publication_status"] == "not_applied"
    assert len(detail["changes"]["items"]) == 2
    assert detail["tests_requiring_review"]["total"] == 3
    assert len(detail["tests_requiring_review"]["items"]) == 2
    second = client.get(path + "?offset=2&test_offset=2&limit=2").json()
    assert second["changes"]["items"][0]["id"] == plan["changes"][2]["id"]
    assert len(second["tests_requiring_review"]["items"]) == 1
    absent = next(c for c in detail["changes"]["items"] if c["kind"] == "absent")
    assert absent["before"] == {"present_in_current": True}
    assert absent["after"] == {"present_in_current": False}
    instruction = client.get(path + "/instruction").json()
    assert instruction["status"] == "host_only_not_applied"
    assert instruction["command"].endswith("--actor " + actor)
    assert plan["candidate_id"] in instruction["command"]
    assert "--confirm-plan " + plan["plan_sha256"] in instruction["command"]
    assert fingerprint(engine) == before
    assert files == {
        str(p.relative_to(cache)): p.read_bytes() for p in cache.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize(
    "drift", ["candidate", "plan", "symlink", "mode", "fifo", "test", "published"]
)
def test_drift_refuses_detail_and_confirmation(prepared, drift):
    client, engine, actor, cache, plan = prepared
    saved = cache / "plans" / (plan["plan_sha256"] + ".json")
    if drift == "candidate":
        (cache / plan["candidate_id"] / "bundle.json").write_text("{}")
    elif drift == "plan":
        saved.write_text(json.dumps({**plan, "action": "already_applied"}))
    elif drift == "symlink":
        saved.unlink()
        saved.symlink_to(cache / plan["candidate_id"] / "document.json")
    elif drift == "mode":
        saved.chmod(0o644)
    elif drift == "fifo":
        saved.unlink()
        os.mkfifo(saved, 0o600)
    elif drift == "test":
        with engine.begin() as db:
            db.execute(text("UPDATE test_definitions SET version=version+1 WHERE id='demo-shell'"))
    else:
        publish(engine, actor)
    before = fingerprint(engine)
    for suffix in ("", "/instruction"):
        response = client.get(BASE + "/" + plan["plan_sha256"] + suffix)
        assert response.status_code == 409
        assert str(cache) not in response.text and "postgresql" not in response.text
    assert fingerprint(engine) == before


def test_blockers_and_real_already_applied_status(prepared):
    client, engine, actor, cache, plan = prepared
    publish(engine, actor)
    with Session(engine) as db:
        fresh = store.plan(db, artifacts.load(cache, plan["candidate_id"]), LICENSE_HASH)
    artifacts.save_plan(cache, fresh)
    path = BASE + "/" + fresh["plan_sha256"]
    assert client.get(path).json()["publication_status"] == "already_applied"
    assert client.get(path + "/instruction").status_code == 409


def test_stored_blockers_prevent_instructions(prepared, tmp_path, monkeypatch):
    client, engine, _, cache, plan = prepared
    fixture_root = tmp_path / "reviewed-fixtures"
    (fixture_root / "attack").mkdir(parents=True)
    license_raw = b"Different reviewed license fixture"
    (fixture_root / "attack/LICENSE.txt").write_bytes(license_raw)
    import hashlib

    with Session(engine) as db:
        blocked = store.plan(
            db, artifacts.load(cache, plan["candidate_id"]), hashlib.sha256(license_raw).hexdigest()
        )
    artifacts.save_plan(cache, blocked)
    monkeypatch.setattr(settings(), "fixtures_path", fixture_root)
    path = BASE + "/" + blocked["plan_sha256"]
    assert "license_review_required" in client.get(path).json()["blockers"]
    assert client.get(path + "/instruction").status_code == 409


@pytest.mark.parametrize("query", ["limit=51", "limit=0", "offset=-1", "offset=101"])
def test_inventory_bounds(prepared, query):
    assert prepared[0].get(BASE + "?" + query).status_code == 422


def test_no_web_preparation_upload_or_publication(prepared):
    client, engine, _, _, plan = prepared
    before = fingerprint(engine)
    for path in (BASE, BASE + "/prepare", BASE + "/" + plan["plan_sha256"] + "/apply"):
        assert client.post(path, json={"url": "https://example.invalid/source"}).status_code in {
            404,
            405,
        }
    assert client.get(BASE + "/not-a-hash").status_code == 422
    assert fingerprint(engine) == before


def test_inventory_overflow_fails_closed(prepared):
    client, _, _, cache, _ = prepared
    for index in range(review.MAX_PLANS):
        (cache / "plans" / str(index)).touch(mode=0o600)
    assert client.get(BASE).status_code == 409


def test_review_database_transaction_refuses_writes(prepared, monkeypatch):
    client, engine, _, _, plan = prepared
    before = fingerprint(engine)

    def attempted_write(db, *args):
        assert db.scalar(text("SHOW transaction_read_only")) == "on"
        db.execute(text("UPDATE test_definitions SET version=version+1"))
        pytest.fail("Read-only transaction allowed a write")

    monkeypatch.setattr(store, "plan", attempted_write)
    assert client.get(BASE + "/" + plan["plan_sha256"]).status_code == 409
    assert fingerprint(engine) == before
