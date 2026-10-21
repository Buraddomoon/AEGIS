import runpy
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import httpx
import pytest
from aegis import linux_labs
from aegis.config import settings
from aegis.db import session_factory
from aegis.integrations.linux_runner import LinuxRunnerClient, RunnerConnection
from aegis.lab_runner.server import create_app
from aegis.models import (
    CampaignRun,
    Laboratory,
    LabVerification,
    RunnerCleanup,
    RunnerDispatch,
    RunnerReceipt,
    User,
    now,
)
from aegis.models import (
    TestDefinition as Definition,
)
from aegis.models import (
    TestExecution as Execution,
)
from aegis.worker import claim_next, process_run, recover_abandoned
from fastapi.testclient import TestClient
from sqlalchemy import func, select

initialize = runpy.run_path("scripts/init_linux_lab.py")["initialize"]


def login(client, role):
    result = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": role, "password": "Test-only-randomized-scope-23!"},
    )
    assert result.status_code == 200, result.text
    client.headers["x-csrf-token"] = result.json()["csrf_token"]


@pytest.fixture
def linux(admin, runner, tmp_path, monkeypatch):
    pki = initialize(tmp_path / "pki")
    configuration = RunnerConnection(
        url="https://172.30.88.2:8443",
        runner_id=runner.identity.runner_id,
        laboratory_id=runner.identity.laboratory_id,
        asset_id=runner.identity.asset_id,
        server_ca=pki / "server-ca.crt",
        client_cert=pki / "runner-client.crt",
        client_key=pki / "runner-client.key",
    )
    config_file = tmp_path / "connection.json"
    config_file.write_text(configuration.model_dump_json())
    monkeypatch.setattr(settings(), "linux_runner_config", config_file)
    remote = TestClient(create_app(runner), base_url="https://testserver")

    def dispatch(request):
        result = remote.request(
            request.method, request.url.path, content=request.content, headers=dict(request.headers)
        )
        return httpx.Response(result.status_code, content=result.content)

    monkeypatch.setattr(
        linux_labs,
        "client",
        lambda: LinuxRunnerClient(configuration, transport=httpx.MockTransport(dispatch)),
    )
    result = admin.post(
        "/api/v1/labs/linux/register",
        json={
            "name": "Linux Lab autorizado",
            "owner": "Responsável de testes",
            "isolation_review": "Container isolado, sem portas host, UID sem privilégios e tmpfs revisados.",
            "confirm_isolation_review": True,
        },
    )
    assert result.status_code == 201, result.text
    lab = result.json()
    check = admin.post(f"/api/v1/labs/{lab['id']}/preflight", json={"confirm": True})
    assert check.status_code == 200 and check.json()["success"], check.text
    assert (
        admin.patch(
            f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": True}
        ).status_code
        == 200
    )
    return admin, lab, runner


def requested(linux):
    client, lab, runner = linux
    login(client, "operator")
    campaign = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Campanha Linux real",
            "objective": "Validar marcador benigno e comprovante, sem consulta SIEM.",
            "laboratory_id": lab["id"],
            "test_ids": ["linux-file-marker-v1"],
        },
    )
    assert campaign.status_code == 201, campaign.text
    run = client.post(
        f"/api/v1/campaigns/{campaign.json()['id']}/runs",
        json={"idempotency_key": uuid.uuid4().hex},
    )
    assert run.status_code == 201, run.text
    return run.json()


def queued(linux):
    client = linux[0]
    run = requested(linux)
    login(client, "administrator")
    approved = client.post(
        f"/api/v1/executions/{run['id']}/approve",
        json={"confirm_scope_hash": run["scope_hash"], "confirm_real_execution": True},
    )
    assert approved.status_code == 200, approved.text
    start = client.post(f"/api/v1/executions/{run['id']}/start", json={"confirm": True})
    assert start.status_code == 200, start.text
    return run


def test_linux_campaign_uses_same_worker_and_persists_distinct_receipts(linux):
    client, lab, runner = linux
    run = queued(linux)
    assert run["synthetic"] is False and run["scope"]["mode"] == "linux"
    assert claim_next() == run["id"]
    process_run(run["id"])
    detail = client.get("/api/v1/executions/" + run["id"]).json()
    assert detail["state"] == "COMPLETED", detail
    execution = detail["executions"][0]
    assert not execution["synthetic"] and execution["executed"]
    assert execution["result"]["outcome"] == "INCONCLUSIVE"
    assert (
        not execution["result"]["synthetic"]
        and not execution["events"]
        and not execution["evidence"]
    )
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(RunnerDispatch)) == 1
        receipt = db.scalar(select(RunnerReceipt))
        assert receipt.content["kind"] == "execution_receipt" and not receipt.content["synthetic"]
        assert db.scalar(select(RunnerCleanup)).content["cleanup_state"] == "CLEANED"
        assert db.get(Laboratory, lab["id"]).active_run_id is None
    assert list(runner.workspace.root.iterdir()) == []


def test_linux_self_approval_and_missing_real_confirmation_are_rejected(linux):
    client = linux[0]
    run = requested(linux)
    assert (
        client.post(
            f"/api/v1/executions/{run['id']}/approve",
            json={"confirm_scope_hash": run["scope_hash"], "confirm_real_execution": True},
        ).status_code
        == 403
    )
    login(client, "administrator")
    assert (
        client.post(
            f"/api/v1/executions/{run['id']}/approve",
            json={"confirm_scope_hash": run["scope_hash"]},
        ).status_code
        == 409
    )
    # An administrator requesting a new run cannot approve it themselves.
    another = client.post(
        f"/api/v1/campaigns/{run['campaign_id']}/runs", json={"idempotency_key": uuid.uuid4().hex}
    ).json()
    assert (
        client.post(
            f"/api/v1/executions/{another['id']}/approve",
            json={"confirm_scope_hash": another["scope_hash"], "confirm_real_execution": True},
        ).status_code
        == 409
    )


def test_withdrawn_test_is_rejected_before_effect(linux):
    run = queued(linux)
    with session_factory()() as db:
        db.get(Definition, "linux-file-marker-v1").approved = False
        db.commit()
    assert claim_next() is None
    assert linux[0].get("/api/v1/executions/" + run["id"]).json()["state"] == "REJECTED"
    assert not list(linux[2].workspace.root.iterdir())


def test_preflight_expiry_and_revocation_invalidate_scope(linux):
    client, lab, _ = linux
    with session_factory()() as db:
        db.scalar(
            select(LabVerification).where(LabVerification.laboratory_id == lab["id"])
        ).expires_at = now() - timedelta(seconds=1)
        db.commit()
    login(client, "operator")
    response = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Expired Linux scope",
            "objective": "Expired preflight must prevent preparation",
            "laboratory_id": lab["id"],
            "test_ids": ["linux-file-marker-v1"],
        },
    )
    assert response.status_code == 409
    login(client, "administrator")
    assert client.get("/api/v1/labs").json()["items"][-1]["connection_status"] == "disconnected"


def test_linux_scheduling_is_never_implicitly_authorized(linux):
    client = linux[0]
    run = requested(linux)
    start = now() + timedelta(minutes=1)
    result = client.post(
        "/api/v1/schedules",
        json={
            "campaign_id": run["campaign_id"],
            "interval_seconds": 60,
            "max_occurrences": 1,
            "max_duration_seconds": 30,
            "starts_at": start.isoformat(),
            "ends_at": (start + timedelta(hours=1)).isoformat(),
        },
    )
    assert result.status_code == 409


@pytest.mark.parametrize("concurrent", [False, True])
def test_crashed_linux_worker_is_quarantined_and_recovery_never_starts_job(linux, concurrent):
    client, lab, _ = linux
    run = queued(linux)
    assert claim_next() == run["id"]
    with session_factory()() as db:
        current = db.get(CampaignRun, run["id"])
        item = db.scalar(select(Execution).where(Execution.run_id == run["id"]))
        dispatch = linux_labs.ensure_dispatch(db, current, item)
        remote = linux_labs.client()
        from aegis.lab_runner.protocol import JobSpec

        view = remote.prepare(JobSpec.model_validate(dispatch.spec))
        linux_labs.persist_view(db, item.id, view)  # Persist generation before any start.
        remote.close()
        current.deadline_at = now() - timedelta(seconds=60)
        current.heartbeat_at = now() - timedelta(seconds=60)
        db.commit()
    assert recover_abandoned() == 1
    detail = client.get("/api/v1/executions/" + run["id"]).json()
    assert detail["state"] == "CLEANUP_FAILED"
    with session_factory()() as db:
        assert db.get(Laboratory, lab["id"]).active_run_id == run["id"]

    def recover():
        return client.post(f"/api/v1/labs/{lab['id']}/recover", json={"confirm": True})

    if concurrent:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: recover(), range(2)))
        assert sorted(result.status_code for result in responses) == [200, 409]
        recovered = next(result for result in responses if result.status_code == 200)
    else:
        recovered = recover()
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["active_run_id"] is None
    with session_factory()() as db:
        assert db.scalar(select(RunnerReceipt)) is None
        assert db.scalar(select(RunnerCleanup)).content["state"] == "CANCELLED"


@pytest.mark.parametrize("change", ["requester", "approver", "binding", "lab"])
def test_changed_linux_authorization_is_rejected_before_prepare(linux, change, monkeypatch):
    run = queued(linux)
    with session_factory()() as db:
        if change in ("requester", "approver"):
            user = db.scalar(
                select(User).where(
                    User.username == ("operator" if change == "requester" else "administrator")
                )
            )
            user.active = False
        elif change == "lab":
            db.get(Laboratory, run["laboratory_id"]).authorized = False
        else:
            monkeypatch.setattr(settings(), "linux_runner_config", None)
        db.commit()
    assert claim_next() is None
    with session_factory()() as db:
        assert db.get(CampaignRun, run["id"]).state == "REJECTED"
        assert db.scalar(select(RunnerDispatch)) is None


def test_missing_remote_job_does_not_release_quarantine(linux):
    run = queued(linux)
    assert claim_next() == run["id"]
    with session_factory()() as db:
        current = db.get(CampaignRun, run["id"])
        execution = db.scalar(select(Execution).where(Execution.run_id == run["id"]))
        linux_labs.ensure_dispatch(db, current, execution)
        current.deadline_at = current.heartbeat_at = now() - timedelta(seconds=60)
        db.commit()
    assert recover_abandoned() == 1
    response = linux[0].post(f"/api/v1/labs/{run['laboratory_id']}/recover", json={"confirm": True})
    assert response.status_code == 409
    with session_factory()() as db:
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id == run["id"]
        assert db.scalar(select(RunnerCleanup)) is None


def test_real_reports_receipts_and_mode_metrics_stay_separate(linux):
    client = linux[0]
    run = queued(linux)
    assert claim_next() == run["id"]
    process_run(run["id"])
    detail = client.get("/api/v1/executions/" + run["id"]).json()
    assert detail["executions"][0]["runner_receipt"]["content"]["kind"] == "execution_receipt"
    assert detail["executions"][0]["runner_cleanup"]["content"]["cleanup_state"] == "CLEANED"
    report = client.get(f"/api/v1/reports/{run['id']}?format=json")
    assert report.status_code == 200, report.text
    assert report.json()["synthetic"] is False
    html = client.get(f"/api/v1/reports/{run['id']}?format=html").text
    assert "COMPROVANTES DO EXECUTOR" in html and "EVIDÊNCIAS SINTÉTICAS" not in html
    demo = client.get("/api/v1/coverage?mode=demo").json()
    real = client.get("/api/v1/coverage?mode=linux").json()
    assert demo["total_runs"] == demo["completed_tests"] == 0
    assert real["total_runs"] == real["completed_tests"] == 1 and not real["synthetic"]
    assert real["detected_percentage"] is None and real["valid_tests"] == 0
    assert client.get("/api/v1/executions?mode=demo").json()["total"] == 0
    assert client.get("/api/v1/executions?mode=linux").json()["total"] == 1


@pytest.mark.parametrize("lost", ["prepare", "start", "cleanup", "cleanup_commit"])
def test_ambiguous_linux_responses_never_replay_start(linux, monkeypatch, lost):
    from aegis.integrations.linux_runner import RunnerUnavailable

    run = queued(linux)
    assert claim_next() == run["id"]
    original_client, original_persist = linux_labs.client, linux_labs.persist_view
    calls, dropped = [], []

    def unreliable_client():
        remote = original_client()
        original = remote.request

        def request(method, path, data=None):
            calls.append((method, path))
            response = original(method, path, data)
            target = path == "/v1/jobs" if lost == "prepare" else path.endswith("/" + lost)
            if method == "POST" and target and not dropped:
                dropped.append(True)
                raise RunnerUnavailable("Response lost after server accepted request")
            return response

        remote.request = request
        return remote

    def unreliable_commit(db, identifier, view):
        original_persist(db, identifier, view)
        if lost == "cleanup_commit" and view.cleanup_state == "CLEANED" and not dropped:
            dropped.append(True)
            raise RuntimeError("Simulated transaction failure after remote cleanup")

    monkeypatch.setattr(linux_labs, "client", unreliable_client)
    monkeypatch.setattr(linux_labs, "persist_view", unreliable_commit)
    process_run(run["id"])
    assert dropped
    with session_factory()() as db:
        current = db.get(CampaignRun, run["id"])
        if lost in ("cleanup", "cleanup_commit"):
            assert current.state == "CLEANUP_FAILED"
            assert db.get(Laboratory, current.laboratory_id).active_run_id == current.id
        else:
            assert current.state in ("FAILED", "CLEANUP_FAILED")
        needs_recovery = current.state == "CLEANUP_FAILED"
    if needs_recovery:
        result = linux[0].post(
            f"/api/v1/labs/{run['laboratory_id']}/recover", json={"confirm": True}
        )
        assert result.status_code == 200, result.text
    starts = [path for method, path in calls if method == "POST" and path.endswith("/start")]
    assert len(starts) == (0 if lost == "prepare" else 1)
    assert not list(linux[2].workspace.root.iterdir())
    with session_factory()() as db:
        assert db.get(Laboratory, run["laboratory_id"]).active_run_id is None
        assert db.scalar(select(RunnerCleanup)).content["cleanup_state"] == "CLEANED"
