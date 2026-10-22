import importlib
import json
import stat
import sys
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def assay(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    module = importlib.import_module("smoke_wazuh_platform")
    monkeypatch.setattr(module, "PRIVATE", tmp_path)
    return module


def test_missing_confirmation_never_inspects_or_mutates(assay, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["smoke_wazuh_platform.py"])
    monkeypatch.setattr(assay, "assay", lambda: pytest.fail("Must not start"))
    with pytest.raises(SystemExit):
        assay.main()


def test_existing_intent_preserves_original_run_and_never_creates_accounts(assay, monkeypatch):
    path = assay.PRIVATE / "assay-intent.jsonl"
    intent = assay.Intent(path)
    intent.append("START_INTENT", run_id="original-run")
    intent.close()
    original = path.read_bytes()
    monkeypatch.setattr(assay, "collect", lambda: ([], [], []))
    monkeypatch.setattr(assay, "validate", lambda *args: {"isolation": True})
    monkeypatch.setattr(assay, "accounts_local", lambda *args, **kwargs: pytest.fail("No retry"))
    with pytest.raises(FileExistsError):
        assay.assay()
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(original)["run_id"] == "original-run"


def test_failed_runtime_never_claims_intent_or_creates_accounts(assay, monkeypatch):
    monkeypatch.setattr(assay, "collect", lambda: ([], [], []))
    monkeypatch.setattr(assay, "validate", lambda *args: {"isolation": False})
    with pytest.raises(ValueError, match="isolation"):
        assay.assay()
    assert not (assay.PRIVATE / "assay-intent.jsonl").exists()


def test_accounts_use_only_owner_migration_container_and_stdin(assay, monkeypatch):
    calls = []
    monkeypatch.setattr(assay, "execute", lambda command, **kwargs: calls.append((command, kwargs)))
    values = [{"username": "fixture-user", "password": "fixture-secret", "role": "operator"}]
    assay.accounts_local(values)
    command, options = calls[0]
    assert command[: len(assay.COMPOSE)] == assay.COMPOSE
    assert "migrate" in command and "api" not in command and "worker" not in command
    assert "fixture-secret" not in " ".join(command)
    assert json.loads(options["input"])[0]["password"] == "fixture-secret"
    assert options["capture_output"]


def test_artifacts_are_private_and_cannot_be_overwritten(assay):
    assay.save("execution.json", {"run_id": "original-run"})
    path = assay.PRIVATE / "execution.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        assay.save("execution.json", {"run_id": "another-run"})
    assert json.loads(path.read_text())["run_id"] == "original-run"


@pytest.mark.parametrize("scenario", ["complete", "ambiguous-start", "previous-execution"])
def test_one_start_is_durable_and_ambiguous_response_keeps_recovery_access(
    assay, monkeypatch, scenario
):
    # HTTP contract only: no Docker, runner, real marker or external Wazuh.
    calls, account_actions = [], []
    monkeypatch.setattr(assay, "collect", lambda: ([], [], []))
    monkeypatch.setattr(assay, "validate", lambda *args: {"isolation": True})
    monkeypatch.setattr(
        assay, "accounts_local", lambda accounts, disable=False: account_actions.append(disable)
    )
    real_client = httpx.Client

    def handle(request):
        path = request.url.path.removeprefix("/api/v1")
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, path, body))
        value = {}
        if path == "/auth/login":
            value = {"csrf_token": "fixture"}
        elif path == "/executions":
            value = {"total": int(scenario == "previous-execution")}
        elif path == "/connectors/wazuh/test":
            value = {"status": "connected"}
        elif path == "/labs/linux/register":
            value = {"id": "fixture-lab"}
        elif path.endswith("/preflight"):
            value = {"success": True}
        elif path == "/campaigns":
            value = {"id": "fixture-campaign"}
        elif path.endswith("/runs"):
            value = {"id": "fixture-run", "scope_hash": "fixture-hash"}
        elif path.endswith("/approve"):
            assert body["max_duration_seconds"] == 120 and body["confirm_real_execution"]
        elif path.endswith("/start"):
            lines = [
                json.loads(line)
                for line in (assay.PRIVATE / "assay-intent.jsonl").read_text().splitlines()
            ]
            assert lines[-1]["stage"] == "START_INTENT" and lines[-1]["run_id"] == "fixture-run"
            if scenario == "ambiguous-start":
                raise httpx.ReadTimeout("Fixture lost response; never retry", request=request)
        elif path == "/executions/fixture-run":
            value = {
                "state": "COMPLETED",
                "synthetic": False,
                "executions": [
                    {
                        "executed": True,
                        "synthetic": False,
                        "runner_cleanup": {"content": {"cleanup_state": "CLEANED"}},
                        "result": {"outcome": "DETECTED"},
                        "evidence": ["fixture-only"],
                        "events": ["fixture-only"],
                    }
                ],
            }
        elif path.startswith("/reports/") and request.url.params.get("format") == "html":
            return httpx.Response(200, text="<p>Fixture only</p>")
        return httpx.Response(200, json=value)

    monkeypatch.setattr(
        assay.httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    if scenario == "complete":
        assay.assay()
        assert account_actions == [False, True]
        assert (assay.PRIVATE / "execution.json").exists()
        assert not (assay.PRIVATE / "assay-accounts.json").exists()
    else:
        with pytest.raises(httpx.ReadTimeout if scenario == "ambiguous-start" else ValueError):
            assay.assay()
        assert account_actions == ([False] if scenario == "ambiguous-start" else [False, True])
        assert (assay.PRIVATE / "assay-accounts.json").exists() == (scenario == "ambiguous-start")
    starts = [call for call in calls if call[1].endswith("/start")]
    assert len(starts) == (0 if scenario == "previous-execution" else 1)
    if scenario != "previous-execution":
        assert ("PATCH", "/labs/fixture-lab/authorization", {"authorized": False}) in calls
    if scenario == "ambiguous-start":
        assert '"stage": "RECOVERY_REQUIRED"' in (assay.PRIVATE / "assay-intent.jsonl").read_text()
    before = list(calls)
    with pytest.raises(FileExistsError):
        assay.assay()
    assert calls == before
