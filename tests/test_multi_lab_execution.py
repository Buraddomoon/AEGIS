# ruff: noqa: F811
"""Two in-memory HTTP runner fixtures, temporary artifacts; no native lab traffic."""

import json
from uuid import uuid4

import httpx
import pytest
from aegis import linux_labs
from aegis.config import settings
from aegis.db import session_factory
from aegis.integrations.linux_runner import LinuxRunnerClient
from aegis.lab_runner.engine import Runner
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.lab_runner.server import create_app
from aegis.models import CampaignRun, Laboratory, RunnerCleanup, RunnerDispatch
from aegis.worker import claim_next, process_run
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_lab_registry_api import register
from test_linux_campaigns import linux, login, queued  # noqa: F401


@pytest.fixture
def multi(linux, tmp_path, monkeypatch):
    client, lab, first = linux
    assert (
        client.patch(
            f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": False}
        ).status_code
        == 200
    )
    original = linux_labs.connection()
    original.client_key.chmod(0o600)
    second_work, second_state = tmp_path / "second-work", tmp_path / "second-state"
    second_work.mkdir(mode=0o700)
    second_state.mkdir(mode=0o700)
    second = Runner(
        RunnerIdentity(runner_id=uuid4(), laboratory_id=uuid4(), asset_id=uuid4()),
        second_work,
        second_state,
    )
    configs = [
        original,
        original.model_copy(
            update={
                "runner_id": second.identity.runner_id,
                "laboratory_id": second.identity.laboratory_id,
                "asset_id": second.identity.asset_id,
                "url": "https://192.168.253.3:8443",
            }
        ),
    ]
    entries = [
        {
            "id": f"closed-{i}",
            "revision": 1,
            "owner": "Fixture only",
            "isolation": "Temporary fixture with in-memory HTTP; no native laboratory.",
            "connection": config.model_dump(mode="json"),
        }
        for i, config in enumerate(configs)
    ]
    path = tmp_path / "multi.json"
    path.write_text(json.dumps({"format": "aegis-linux-registry/1", "entries": entries}))
    path.chmod(0o600)
    monkeypatch.setattr(settings(), "linux_runner_registry", path)
    servers = [
        TestClient(create_app(instance), base_url="https://testserver")
        for instance in (first, second)
    ]
    calls = []

    def factory(lab_id):
        config = next(c for c in configs if str(c.laboratory_id) == lab_id)
        server = servers[configs.index(config)]

        def dispatch(request):
            calls.append((lab_id, request.method, request.url.path))
            result = server.request(
                request.method,
                request.url.path,
                content=request.content,
                headers=dict(request.headers),
            )
            return httpx.Response(result.status_code, content=result.content)

        return LinuxRunnerClient(config, transport=httpx.MockTransport(dispatch))

    monkeypatch.setattr(linux_labs, "deployment_client", factory)
    records = []
    try:
        listing = client.get("/api/v1/labs/linux/connections")
        assert listing.status_code == 200, listing.text
        for entry in listing.json()["items"]:
            record = register(client, entry)
            result = client.post(f"/api/v1/labs/{record['id']}/preflight", json={"confirm": True})
            assert result.json()["success"], result.text
            assert (
                client.patch(
                    f"/api/v1/labs/{record['id']}/authorization", json={"authorized": True}
                ).status_code
                == 200
            )
            records.append(record)
        yield client, records, (first, second), path, entries, calls
    finally:
        for server in servers:
            server.close()
        second.close()


def test_two_claims_dispatch_and_cleanup_stay_with_their_original_lab(multi):
    client, labs, runners, _, _, calls = multi
    runs = [queued((client, lab, runner)) for lab, runner in zip(labs, runners, strict=True)]
    # Both laboratories have independent durable reservations, even before processing.
    assert {claim_next(), claim_next()} == {r["id"] for r in runs}
    for run in runs:
        process_run(run["id"])
    with session_factory()() as db:
        for run, lab, runner in zip(runs, labs, runners, strict=True):
            stored = db.get(CampaignRun, run["id"])
            assert stored.state == "COMPLETED"
            assert db.get(Laboratory, lab["id"]).active_run_id is None
            dispatch = db.scalar(
                select(RunnerDispatch).where(
                    RunnerDispatch.spec["laboratory_id"].astext == lab["id"]
                )
            )
            assert dispatch.spec["asset_id"] == str(runner.identity.asset_id)
            assert dispatch.spec["runner_id"] == str(runner.identity.runner_id)
            cleanup = db.scalar(
                select(RunnerCleanup).where(RunnerCleanup.execution_id == dispatch.execution_id)
            )
            assert cleanup.content["cleanup_state"] == "CLEANED"
            assert cleanup.content["spec"] == dispatch.spec
    for lab in labs:
        own = [path for lab_id, method, path in calls if lab_id == lab["id"] and method == "POST"]
        assert sum(path.endswith("/start") for path in own) == 1
        assert sum(path.endswith("/cleanup") for path in own) == 1


def test_drift_rejects_one_queued_lab_without_dispatching_or_blocking_other(multi):
    client, labs, runners, path, entries, calls = multi
    runs = [queued((client, lab, runner)) for lab, runner in zip(labs, runners, strict=True)]
    entries[0]["revision"] += 1
    path.write_text(json.dumps({"format": "aegis-linux-registry/1", "entries": entries}))
    assert claim_next() is None
    assert claim_next() == runs[1]["id"]
    process_run(runs[1]["id"])
    with session_factory()() as db:
        assert db.get(CampaignRun, runs[0]["id"]).state == "REJECTED"
        assert db.get(CampaignRun, runs[1]["id"]).state == "COMPLETED"
        assert db.get(Laboratory, labs[0]["id"]).active_run_id is None
    assert not any(lab_id == labs[0]["id"] and method == "POST" for lab_id, method, _ in calls)
