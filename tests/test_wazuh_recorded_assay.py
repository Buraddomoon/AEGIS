"""Offline checks of recorded local evidence, not new live Wazuh validation."""

import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest
from aegis.domain.contracts import Collection, ExecutionContext
from aegis.domain.validation import digest, validate
from aegis.integrations.wazuh import WazuhIndexerProvider
from aegis.integrations.wazuh_config import WazuhCollectionConfig

DIRECTORY = Path(__file__).resolve().parents[1] / "docs/evidence/wazuh-2026-10-22"


def recorded():
    summary = json.loads((DIRECTORY / "result.json").read_text())
    raw = json.loads((DIRECTORY / "alert.json").read_text())
    item = summary["execution"]
    policy = WazuhCollectionConfig(
        laboratory_id=summary["laboratory_id"],
        asset_id=item["asset_id"],
        agent_id=summary["scope"]["agent_id"],
        expected_rule=summary["scope"]["expected_rule"],
        ingestion_window_seconds=60,
        ingestion_wait_seconds=60,
        poll_interval_seconds=2,
    )
    ctx = ExecutionContext(
        item["id"],
        summary["laboratory_id"],
        item["asset_id"],
        item["marker"],
        "temporary-marker",
        datetime.fromisoformat(item["started_at"]),
        datetime.fromisoformat(item["ended_at"]),
        False,
        policy.expected_rule,
    )
    return summary, raw, policy, ctx


def test_recorded_artifacts_preserve_byte_and_canonical_integrity():
    manifest = json.loads((DIRECTORY / "sha256.json").read_text())
    assert set(manifest) == {"alert.json", "observer.jsonl", "result.json"}
    for filename, expected in manifest.items():
        assert hashlib.sha256((DIRECTORY / filename).read_bytes()).hexdigest() == expected
    summary, raw, _, _ = recorded()
    assert digest(raw) == summary["alert_sha256"]
    for name in ("runner_receipt", "runner_cleanup"):
        assert digest(summary[name]["content"]) == summary[name]["sha256"]
    observed = json.loads((DIRECTORY / "observer.jsonl").read_text())
    assert json.loads(raw["_source"]["full_log"]) == observed
    fields = raw["_source"]["data"]["aegis"]
    assert int(fields["artifact_bytes"]) == observed["aegis"]["artifact_bytes"] == 43
    assert fields["artifact_sha256"] == summary["runner_receipt"]["content"]["artifact_sha256"]
    assert (
        summary["closure"]["executions"] == 1 and summary["coverage"]["evaluated_techniques"] == 0
    )


def test_recorded_real_schema_normalizes_external_agent_and_correlates_original_alert():
    summary, raw, policy, ctx = recorded()
    event = WazuhIndexerProvider.normalize(raw, "alert", policy)
    assert event.asset_id == ctx.asset_id and raw["_source"]["agent"]["id"] == "001"
    assert not event.synthetic and not summary["synthetic"]
    assert event.raw == raw and event.source_id == raw["_id"]
    verdict = validate(ctx, Collection((event,), False, True, True), True, 5, 60)
    assert verdict.outcome == "DETECTED" and verdict.evidence == (event,)


@pytest.mark.parametrize("agent", ["1", 1, "002"])
def test_changed_recording_agent_does_not_inherit_the_reviewed_asset_mapping(agent):
    _, original, policy, _ = recorded()
    changed = copy.deepcopy(original)
    changed["_source"]["agent"]["id"] = agent
    with pytest.raises(ValueError, match="Agente"):
        WazuhIndexerProvider.normalize(changed, "alert", policy)


def test_changed_recording_rule_never_reproduces_expected_detection():
    _, original, policy, ctx = recorded()
    changed = copy.deepcopy(original)
    changed["_source"]["rule"]["id"] = "100201"
    event = WazuhIndexerProvider.normalize(changed, "alert", policy)
    assert (
        validate(ctx, Collection((event,), False, True, True), True, 5, 60).outcome
        == "OBSERVED_NOT_ALERTED"
    )
