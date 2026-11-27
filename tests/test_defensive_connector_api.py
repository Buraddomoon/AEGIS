# ruff: noqa: F811
"""Disposable PostgreSQL/API fixtures; no native lab or corporate network."""

import json
from types import SimpleNamespace

import pytest
from aegis import telemetry
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.models import Asset, AuditEvent, Laboratory
from sqlalchemy import select
from test_defensive_profiles import profile_registry, save  # noqa: F401
from test_linux_campaigns import login


@pytest.fixture
def connector(admin, profile_registry):
    path, entry = profile_registry
    with session_factory()() as db:
        lab = Laboratory(
            id=entry["policy"]["laboratory_id"],
            name="Offline connector fixture",
            description="Offline fixture",
            kind="linux",
            authorized=False,
            owner="Fixture",
            isolation="Offline; no runtime or original volumes.",
        )
        db.add(lab)
        db.flush()
        db.add(
            Asset(
                id=entry["policy"]["asset_id"],
                laboratory_id=lab.id,
                name="Offline asset",
                platform="Linux",
                synthetic=False,
                external_id="007",
            )
        )
        db.commit()
    base = f"/api/v1/labs/{entry['policy']['laboratory_id']}/wazuh-binding"
    value = admin.get(base).json()["profiles"][0]
    payload = {
        "profile_id": entry["id"],
        "confirm_configuration_hash": value["configuration_hash"],
        "review": "Reviewed offline profile, bounded transport only; no native operation.",
        "confirm_read_only_scope": True,
    }
    return admin, base, payload, path, entry


def test_review_drift_and_disable_preserve_scope(connector):
    client, base, payload, path, entry = connector
    assert client.put(base, json=payload).status_code == 200
    with session_factory()() as db:
        lab = db.get(Laboratory, entry["policy"]["laboratory_id"])
        scope = telemetry.scope_for(db, lab, db.get(Asset, entry["policy"]["asset_id"]))
        assert scope["profile"]["id"] == entry["id"]
        run = SimpleNamespace(
            laboratory_id=lab.id,
            scope={"telemetry": scope, "asset_id": entry["policy"]["asset_id"]},
        )
        assert telemetry.scope_valid(db, run)
        entry["revision"] += 1
        save(path, entry)
        assert not telemetry.scope_valid(db, run)
    assert client.get(base).json()["status"] == "configuration_changed"
    assert client.put(base, json=payload).status_code == 409
    assert digest(scope) == digest(run.scope["telemetry"])
    assert (
        client.post(
            base + "/remove",
            json={
                "confirm": True,
                "confirm_configuration_hash": payload["confirm_configuration_hash"],
            },
        ).status_code
        == 200
    )
    assert client.get(base).json()["status"] == "unbound"


@pytest.mark.parametrize("fault", ["success", "transport", "drift"])
def test_sanitized_bounded_diagnostic_and_audit(connector, monkeypatch, fault):
    client, base, payload, path, entry = connector
    client.put(base, json=payload).raise_for_status()
    calls = []

    def test_connection():
        calls.append("GET /")
        if fault == "transport":
            raise OSError("private-fixture-password upstream-body")
        if fault == "drift":
            entry["revision"] += 1
            save(path, entry)
        return "private-fixture-password arbitrary-upstream-version"

    monkeypatch.setattr(
        telemetry,
        "configured_provider",
        lambda *a, **kw: SimpleNamespace(test_connection=test_connection),
    )
    response = client.post(
        base + "/test",
        json={"confirm": True, "confirm_configuration_hash": payload["confirm_configuration_hash"]},
    )
    assert response.status_code == 200, response.text
    assert (
        response.json()["status"]
        == {"success": "reachable", "transport": "unavailable", "drift": "stale"}[fault]
    )
    assert response.json()["events_queried"] is False
    assert calls == ["GET /"]
    with session_factory()() as db:
        events = [
            e.details
            for e in db.scalars(
                select(AuditEvent).where(AuditEvent.action == "wazuh.profile_diagnostic")
            )
        ]
    assert len(events) == 1
    assert "private-fixture" not in response.text + json.dumps(events)


def test_rbac_csrf_hash_and_no_url_input(connector):
    client, base, payload, _, _ = connector
    for role in ("viewer", "operator"):
        login(client, role)
        assert client.get(base).status_code == 200
        assert client.put(base, json=payload).status_code == 403
        assert (
            client.post(
                base + "/test",
                json={
                    "confirm": True,
                    "confirm_configuration_hash": payload["confirm_configuration_hash"],
                },
            ).status_code
            == 403
        )
        assert client.post(base + "/remove", json={"confirm": True}).status_code == 403
    login(client, "administrator")
    assert client.put(base, json={**payload, "url": "https://untrusted"}).status_code == 422
    assert client.put(base, json={**payload, "profile_id": "unknown"}).status_code == 409
    assert (
        client.put(base, json={**payload, "confirm_configuration_hash": "a" * 64}).status_code
        == 409
    )
    token = client.headers.pop("x-csrf-token")
    assert client.put(base, json=payload).status_code == 403
    client.headers["x-csrf-token"] = token


def test_missing_profile_and_rate_limit_never_connect(connector, monkeypatch):
    client, base, payload, path, _ = connector
    client.put(base, json=payload).raise_for_status()
    path.unlink()
    monkeypatch.setattr(
        telemetry, "configured_provider", lambda *a, **kw: pytest.fail("Network forbidden")
    )
    body = {"confirm": True, "confirm_configuration_hash": payload["confirm_configuration_hash"]}
    for _ in range(5):
        assert client.post(base + "/test", json=body).status_code == 409
    assert client.post(base + "/test", json=body).status_code == 429
    assert client.get(base).json()["configuration_available"] is False
    assert client.post("/api/v1/connectors/wazuh/test").status_code in (409, 429)
