"""Real API/PG and temporary fixture runner; no native Wazuh or original volumes."""

import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from aegis.domain.validation import digest
from aegis.integrations import wazuh as wazuh_provider
from aegis.main import app
from aegis.worker import claim_next, process_run
from fastapi.testclient import TestClient
from test_linux_campaigns import linux as linux  # noqa: F401
from test_linux_campaigns import login, queued
from test_wazuh_campaigns import wazuh as wazuh  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_cycle_assay as cycle  # noqa: E402
from wazuh_cycle_scope import IMAGE_ROLES, CycleProfile  # noqa: E402


@pytest.fixture
def reviewed(wazuh, tmp_path):
    linux, _, scenario = wazuh
    client, lab, runner = linux
    old = queued(linux)
    assert claim_next() == old["id"]
    process_run(old["id"])
    login(client, "administrator")
    historical = client.get("/api/v1/executions/" + old["id"]).json()
    assert historical["state"] == "COMPLETED"
    client.patch(
        f"/api/v1/labs/{lab['id']}/authorization", json={"authorized": False}
    ).raise_for_status()
    actual = next(
        item for item in client.get("/api/v1/labs").json()["items"] if item["id"] == lab["id"]
    )
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    intent = source / "assay-intent.jsonl"
    intent.write_bytes(b'{"historical_fixture":true}\n')
    intent.chmod(0o600)
    profile = CycleProfile(
        "a" * 32,
        source,
        tmp_path / "runner-pki",
        tmp_path / "service-pki",
        {name: "sha256:" + "b" * 64 for name in IMAGE_ROLES},
    )
    baseline = {
        "format": cycle.FORMAT,
        "review_id": profile.review_id,
        "profile_sha256": digest(profile.document()),
        "identity": runner.identity.model_dump(mode="json"),
        "runs": {old["id"]: digest(historical)},
        "environment_version": actual["environment_version"],
        "runner_descriptor_sha256": digest(old["scope"]["runner"]),
        "telemetry_scope_sha256": digest(old["scope"]["telemetry"]),
        "historical_intent_sha256": hashlib.sha256(intent.read_bytes()).hexdigest(),
    }
    return profile, baseline, historical, scenario


@pytest.mark.parametrize(
    "scenario",
    [
        "detected",
        "inconclusive",
        "lost-start",
        "stale-history",
        "stale-gate",
        "same-user",
        "stale-scope",
    ],
)
def test_current_attempt_preserves_history_and_one_use_intent(
    reviewed, tmp_path, monkeypatch, scenario
):
    profile, baseline, historical, telemetry = reviewed
    original_intent = (profile.source / "assay-intent.jsonl").read_bytes()
    root = tmp_path / "attempts"
    calls, gates = [], []
    original_request = cycle.request
    monkeypatch.setattr(
        wazuh_provider,
        "configured_provider",
        lambda: wazuh_provider.WazuhIndexerProvider(
            "https://indexer.fixture:9200",
            "fixture-reader",
            "fixture-password",
            "192.0.2.10",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"version": {"number": "fixture-only"}})
            ),
        ),
    )

    def recheck(**context):
        gates.append(context)
        if scenario == "stale-gate" and context["stage"] == "before_start":
            raise ValueError("fixture_gate_stale")

    def traced(client, method, path, body=None):
        calls.append((method, path, body))
        if path.endswith("/start"):
            events = [
                json.loads(line)
                for line in (root / profile.review_id / "attempt.jsonl").read_text().splitlines()
            ]
            assert events[-1]["stage"] == "START_INTENT"
            result = original_request(client, method, path, body)
            if scenario == "lost-start":
                raise httpx.ReadTimeout("fixture lost response")
            assert claim_next() == result["id"]
            process_run(result["id"])
            return result
        if path.endswith("/approve"):
            assert body["validity_minutes"] == 2 and body["max_duration_seconds"] == 120
        return original_request(client, method, path, body)

    monkeypatch.setattr(cycle, "request", traced)
    # This bypasses no native gate: the entire test uses disposable infrastructure
    # and explicit contract fixtures; it cannot produce a real Wazuh result.
    with (
        TestClient(app, base_url=cycle.API) as admin,
        TestClient(app, base_url=cycle.API) as operator,
    ):
        for client, role in (
            (admin, "administrator"),
            (operator, "administrator" if scenario == "same-user" else "operator"),
        ):
            response = client.post(
                "/auth/login",
                headers={"x-aegis-request": "browser"},
                json={"username": role, "password": "Test-only-randomized-scope-23!"},
            )
            response.raise_for_status()
            client.headers["x-csrf-token"] = response.json()["csrf_token"]
        if scenario == "stale-history":
            baseline["runs"][historical["id"]] = "0" * 64
        elif scenario == "stale-scope":
            baseline["telemetry_scope_sha256"] = "0" * 64
        elif scenario == "inconclusive":
            telemetry["outcome"] = "INCONCLUSIVE"
        if scenario in {"detected", "inconclusive"}:
            result = cycle.run_once(
                admin, operator, profile, baseline, digest(baseline), root, recheck=recheck
            )
            detail = json.loads(Path(result["execution_path"]).read_text())
            assert result["cleanup_confirmed"] and not result["ui_exports_verified"]
            assert detail["executions"][0]["result"]["outcome"] == (
                "DETECTED" if scenario == "detected" else "INCONCLUSIVE"
            )
            assert not detail["synthetic"]
        else:
            with pytest.raises(httpx.ReadTimeout if scenario == "lost-start" else ValueError):
                cycle.run_once(
                    admin, operator, profile, baseline, digest(baseline), root, recheck=recheck
                )
        current = original_request(admin, "GET", "/executions/" + historical["id"])
        assert current == historical
        before = list(calls)
        with pytest.raises(FileExistsError):
            cycle.run_once(
                admin, operator, profile, baseline, digest(baseline), root, recheck=recheck
            )
        assert calls == before
        lab = next(
            item
            for item in original_request(admin, "GET", "/labs")["items"]
            if item["id"] == baseline["identity"]["laboratory_id"]
        )
        assert lab["authorized"] is False
    starts = [call for call in calls if call[1].endswith("/start")]
    assert len(starts) == int(scenario in {"detected", "inconclusive", "lost-start"})
    events = (root / profile.review_id / "attempt.jsonl").read_text()
    assert ("RECOVERY_REQUIRED" in events) == (scenario == "lost-start")
    assert (profile.source / "assay-intent.jsonl").read_bytes() == original_intent


def test_modified_profile_or_historical_intent_never_reaches_clients(reviewed, tmp_path):
    profile, baseline, _, _ = reviewed
    expected = digest(baseline)
    profile.images["runner"] = "sha256:" + "c" * 64
    with pytest.raises(ValueError):
        cycle.check_baseline(baseline, expected, profile)
    profile.images["runner"] = "sha256:" + "b" * 64
    (profile.source / "assay-intent.jsonl").write_bytes(b"changed fixture\n")
    with pytest.raises(ValueError, match="intent_changed"):
        cycle.check_baseline(baseline, expected, profile)
