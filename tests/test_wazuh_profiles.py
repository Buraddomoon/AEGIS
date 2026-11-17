"""Manually anonymized contract fixtures, not captures from a native SIEM."""

import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from aegis.domain.validation import validate
from aegis.integrations.wazuh import WazuhIndexerProvider
from test_wazuh_collection import context, hit, policy, provider, response

PROFILES = [
    ("wazuh-4.14.9/1", "timestamp"),
    ("wazuh-4.14.9-at-timestamp/1", "@timestamp"),
]


@pytest.mark.parametrize("schema,timestamp", PROFILES)
@pytest.mark.parametrize("kind", ["alert", "archive"])
def test_profile_query_and_normalization_preserve_source(schema, timestamp, kind):
    document = json.loads(Path(f"fixtures/wazuh-4.14.9-{kind}.json").read_text())
    instant = datetime.fromisoformat(document["_source"][timestamp].replace("Z", "+00:00"))
    ctx = replace(context(), started_at=instant, ended_at=instant)
    cfg = policy(schema_id=schema, timestamp_field=timestamp, archives_index="wazuh-archives-4.x-*")
    calls = []

    def handle(request):
        calls.append(request)
        selected = ("archives" if kind == "archive" else "alerts") in request.url.path
        return httpx.Response(200, json=response([document] if selected else []))

    result = provider(handle, cfg).collect(ctx)
    assert result.complete and result.alerts_available and result.telemetry_available
    (event,) = result.events
    assert event.source_id == document["_id"]
    assert event.source == "wazuh-indexer:" + document["_index"]
    assert event.raw == document
    assert event.timestamp.utcoffset() == (
        timedelta(hours=-3) if timestamp == "timestamp" else timedelta()
    )
    for request in calls:
        filters = json.loads(request.content)["query"]["bool"]["filter"]
        assert list(filters[1]["range"]) == [timestamp]
    expected = "DETECTED" if kind == "alert" else "OBSERVED_NOT_ALERTED"
    assert validate(ctx, result, True).outcome == expected


@pytest.mark.parametrize("schema,timestamp", PROFILES)
@pytest.mark.parametrize(
    "change",
    [
        {"alerts_index": "custom-alerts-*"},
        {"archives_index": "custom-archives-*"},
        {"identity_prefix": "data.other"},
    ],
)
def test_explicit_profiles_refuse_field_drift(schema, timestamp, change):
    with pytest.raises(ValueError, match="perfil Wazuh"):
        policy(schema_id=schema, timestamp_field=timestamp, **change)


@pytest.mark.parametrize("schema,timestamp", PROFILES)
def test_profile_timestamp_has_no_fallback(schema, timestamp):
    wrong = "@timestamp" if timestamp == "timestamp" else "timestamp"
    with pytest.raises(ValueError, match="perfil Wazuh"):
        policy(schema_id=schema, timestamp_field=wrong)
    document = json.loads(Path("fixtures/wazuh-4.14.9-alert.json").read_text())
    cfg = policy(schema_id=schema, timestamp_field=timestamp)
    del document["_source"][timestamp]
    with pytest.raises(KeyError):
        WazuhIndexerProvider.normalize(document, "alert", cfg)
    document["_source"][timestamp] = "2026-11-17T09:00:00"
    with pytest.raises(ValueError, match="timezone"):
        WazuhIndexerProvider.normalize(document, "alert", cfg)


def test_unknown_version_is_not_implicitly_supported():
    with pytest.raises(ValueError):
        policy(schema_id="wazuh-5.0/1")
    assert policy(timestamp_field="@timestamp").schema_id == "aegis-json/1"


@pytest.mark.parametrize("fault", ["total_bool", "shard_bool", "total_drift", "conflict"])
def test_scroll_cannot_claim_complete_with_invalid_metadata_or_changed_document(fault):
    ctx, calls = context(), []

    def handle(request):
        calls.append(request)
        if request.method == "DELETE":
            assert json.loads(request.content) == {"scroll_id": ["latest-cursor"]}
            return httpx.Response(200, json={"succeeded": True})
        first = request.url.path != "/_search/scroll"
        document = hit(ctx)
        if fault == "conflict" and not first:
            document["_source"]["rule"]["id"] = "100201"
        page = response([document] if first or (fault == "conflict" and len(calls) == 2) else [])
        page["_scroll_id"] = "first-cursor" if first else "latest-cursor"
        page["hits"]["total"]["value"] = 1
        if fault == "total_bool":
            page["hits"]["total"]["value"] = True
        elif fault == "shard_bool":
            page["_shards"]["successful"] = True
        elif fault == "total_drift" and not first:
            page["hits"]["total"]["value"] = 0
        return httpx.Response(200, json=page)

    result = provider(handle).collect(ctx)
    assert not result.complete and calls[-1].method == "DELETE"
    if fault == "conflict":
        assert not result.events
        assert validate(ctx, result, True).outcome == "INCONCLUSIVE"
