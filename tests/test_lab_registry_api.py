# ruff: noqa: F811
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aegis import linux_labs, services
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import Asset, Campaign, CampaignRun, Laboratory, User
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from test_lab_registry import registry  # noqa: F401
from test_linux_campaigns import login


def register(admin, entry):
    result = admin.post(
        "/api/v1/labs/linux/register",
        json={
            "name": entry["id"],
            "owner": entry["owner"],
            "isolation_review": "Offline review fixture, no external access.",
            "confirm_isolation_review": True,
            "registry_id": entry["id"],
            "confirm_registry_hash": entry["review_hash"],
        },
    )
    assert result.status_code == 201, result.text
    return result.json()


@pytest.fixture
def labs(admin, registry, monkeypatch):
    path, document = registry
    entries = admin.get("/api/v1/labs/linux/connections?limit=100").json()["items"]
    labs = [register(admin, entry) for entry in entries]
    called = []

    class Remote:
        def __init__(self, lab_id):
            self.lab_id = lab_id

        def preflight(self):
            called.append(self.lab_id)
            return SimpleNamespace(laboratory_id=self.lab_id)

        def close(self):
            pass

    monkeypatch.setattr(linux_labs, "deployment_client", lambda lab_id: Remote(lab_id))
    for lab in labs:
        check = admin.post(f"/api/v1/labs/{lab['id']}/preflight", json={"confirm": True})
        assert check.status_code == 200 and check.json()["success"], check.text
        assert (
            admin.patch(
                f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": True}
            ).status_code
            == 200
        )
    assert called == [lab["id"] for lab in labs]
    return admin, path, document, labs


def campaign(client, lab, asset_id=None):
    result = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Exact registry campaign",
            "objective": "Fixture only; no transport or effect.",
            "laboratory_id": lab["id"],
            "test_ids": ["linux-file-marker-v1"],
            **({"asset_id": asset_id} if asset_id else {}),
        },
    )
    return result


def test_multiple_labs_exact_scopes_and_no_external_agent_fallback(labs):
    client, _, document, registered = labs
    login(client, "operator")
    snapshots = []
    for lab, raw in zip(registered, document["entries"], strict=True):
        asset_id = raw["connection"]["asset_id"]
        response = campaign(client, lab, asset_id)
        assert response.status_code == 201, response.text
        run = client.post(
            f"/api/v1/campaigns/{response.json()['id']}/runs", json={"idempotency_key": uuid4().hex}
        )
        assert run.status_code == 201, run.text
        scope = run.json()["scope"]
        assert scope["laboratory_id"] == lab["id"] == scope["runner"]["laboratory_id"]
        assert scope["asset_id"] == asset_id == scope["runner"]["asset_id"]
        assert scope["telemetry"] == {"provider": "unavailable"}
        assert scope["runner"]["registry"]["id"] == raw["id"]
        snapshots.append(run.json())
    assert snapshots[0]["scope_hash"] != snapshots[1]["scope_hash"]
    assert (
        campaign(
            client, registered[0], document["entries"][1]["connection"]["asset_id"]
        ).status_code
        == 409
    )
    for lab in registered:
        assets = client.get(
            "/api/v1/assets", params={"laboratory_id": lab["id"], "limit": 1}
        ).json()
        assert assets["total"] == 1 and assets["items"][0]["available_test_ids"] == [
            "linux-file-marker-v1"
        ]
    assert client.get("/api/v1/labs?limit=1&offset=1").json()["total"] == 3


@pytest.mark.parametrize(
    "field", ["owner", "isolation", "revision", "url", "test_id", "server_ca", "removed"]
)
def test_drift_invalidates_only_affected_lab_and_preserves_original_scope(labs, field):
    client, path, document, registered = labs
    login(client, "operator")
    response = campaign(client, registered[0])
    run = client.post(
        f"/api/v1/campaigns/{response.json()['id']}/runs", json={"idempotency_key": uuid4().hex}
    ).json()
    before = copy.deepcopy(run["scope"])
    changed = document["entries"][0]
    if field == "removed":
        document["entries"].pop(0)
    elif field in {"owner", "isolation"}:
        changed[field] += " changed"
    elif field == "revision":
        changed[field] += 1
    elif field == "server_ca":
        # Certificates are shared by this fixture; give only this entry a different path/content.
        replacement = path.parent / "replacement-ca"
        replacement.write_text("changed public fixture certificate")
        changed["connection"][field] = str(replacement)
    elif field == "test_id":
        from aegis.lab_runner.atomic_policy import TEST_ID

        changed["connection"][field] = TEST_ID
    else:
        changed["connection"][field] = "https://192.168.253.6:8443"
    path.write_text(json.dumps(document))
    with session_factory()() as db:
        assert not linux_labs.binding_valid(db, db.get(Laboratory, registered[0]["id"]))
        assert linux_labs.binding_valid(db, db.get(Laboratory, registered[1]["id"]))
        stored = db.get(CampaignRun, run["id"])
        assert stored.scope == before and stored.scope_hash == digest(before)
    login(client, "administrator")
    assert (
        client.post(
            f"/api/v1/executions/{run['id']}/approve",
            json={"confirm_scope_hash": run["scope_hash"], "confirm_real_execution": True},
        ).status_code
        == 409
    )
    assert campaign(client, registered[1]).status_code == 201


def test_invalid_registry_never_falls_back_and_selection_is_reviewed(admin, registry):
    path, _ = registry
    entry = admin.get("/api/v1/labs/linux/connections").json()["items"][0]
    bad = {**entry, "review_hash": "0" * 64}
    with pytest.raises(AssertionError):
        register(admin, bad)
    body = {
        "name": "Missing selection",
        "owner": entry["owner"],
        "isolation_review": "Fixture with no selection or effect.",
        "confirm_isolation_review": True,
    }
    assert admin.post("/api/v1/labs/linux/register", json=body).status_code == 409
    path.write_text("{}")
    response = admin.get("/api/v1/labs/linux/connections")
    assert response.status_code == 409
    assert str(path) not in response.text
    assert admin.post("/api/v1/labs/linux/register", json=body).status_code == 409


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_registry_is_admin_only(labs, role):
    client, _, _, _ = labs
    login(client, role)
    assert client.get("/api/v1/labs/linux/connections").status_code == 403
    assert client.post("/api/v1/labs/linux/register", json={"name": "irrelevant"}).status_code in (
        403,
        422,
    )


def test_constraints_and_migration_preserve_existing_history(labs):
    client, _, document, registered = labs
    response = campaign(client, registered[0])
    identifier = response.json()["id"]
    with session_factory()() as db:
        original = db.get(Campaign, identifier)
        assert original.asset_id is None
        original.asset_id = document["entries"][1]["connection"]["asset_id"]
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        assert db.get(Campaign, identifier).asset_id is None
    command.check(Config("alembic.ini"))
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(Config("alembic.ini"), "e2a71c9d064b")
    with session_factory()() as db:
        assert db.get(Campaign, identifier).laboratory_id == registered[0]["id"]


def test_preflight_drift_during_io_cannot_publish_success(labs, monkeypatch):
    client, path, document, registered = labs
    lab = registered[0]

    class Remote:
        def preflight(self):
            document["entries"][0]["revision"] += 1
            path.write_text(json.dumps(document))
            return SimpleNamespace(laboratory_id=lab["id"])

        def close(self):
            pass

    monkeypatch.setattr(linux_labs, "deployment_client", lambda _: Remote())
    result = client.post(f"/api/v1/labs/{lab['id']}/preflight", json={"confirm": True})
    assert result.status_code == 200 and result.json()["success"] is False


def test_other_lab_lock_does_not_block_scope_request(labs):
    client, _, _, registered = labs
    response = campaign(client, registered[1])
    with session_factory()() as db:
        actor_id = db.scalar(select(User.id).where(User.username == "operator"))

    def request():
        with session_factory()() as db:
            db.execute(text("SET LOCAL lock_timeout='1500ms'"))
            return services.request_run(
                db, response.json()["id"], db.get(User, actor_id), uuid4().hex
            ).laboratory_id

    with session_factory()() as holder, ThreadPoolExecutor(max_workers=1) as pool:
        holder.scalar(
            select(Laboratory).where(Laboratory.id == registered[0]["id"]).with_for_update()
        )
        assert pool.submit(request).result(timeout=5) == registered[1]["id"]


def test_windows_asset_never_gains_linux_capacity_or_scope(labs):
    client, _, document, registered = labs
    asset_id = document["entries"][0]["connection"]["asset_id"]
    with session_factory()() as db:
        db.get(Asset, asset_id).platform = "Windows"
        db.commit()
    assert (
        client.get("/api/v1/assets", params={"laboratory_id": registered[0]["id"]}).json()["items"][
            0
        ]["available_test_ids"]
        == []
    )
    assert campaign(client, registered[0], asset_id).status_code == 409


def test_registry_mutations_require_csrf_and_viewer_reads_are_paginated(labs):
    client, _, _, registered = labs
    client.headers.pop("x-csrf-token")
    assert client.post("/api/v1/labs/linux/register", json={}).status_code == 403
    login(client, "viewer")
    response = client.get(
        "/api/v1/assets", params={"laboratory_id": registered[0]["id"], "offset": 1, "limit": 1}
    )
    assert (
        response.status_code == 200
        and response.json()["items"] == []
        and response.json()["total"] == 1
    )
    asset_id = client.get("/api/v1/assets", params={"laboratory_id": registered[0]["id"]}).json()[
        "items"
    ][0]["id"]
    assert client.get(f"/api/v1/assets/{asset_id}/history").json()["total"] == 0
    client.cookies.clear()
    assert client.get("/api/v1/labs/linux/connections").status_code == 401
