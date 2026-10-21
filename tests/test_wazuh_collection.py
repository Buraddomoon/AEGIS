"""Contract-only Indexer fixtures; no external Wazuh or endpoint is contacted."""

import asyncio
import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx
import pytest
from aegis.domain.contracts import ExecutionContext
from aegis.domain.validation import validate
from aegis.integrations.wazuh import WazuhIndexerProvider
from aegis.integrations.wazuh_config import WazuhCollectionConfig
from aegis.integrations.wazuh_polling import WazuhPollingProvider

LAB = UUID("deef2f0d-142e-4bc3-9762-2527b4dc0001")
ASSET = UUID("deef2f0d-142e-4bc3-9762-2527b4dc0002")


def policy(**changes):
    return WazuhCollectionConfig(
        laboratory_id=LAB, asset_id=ASSET, agent_id="007", expected_rule="100200", **changes
    )


def context():
    instant = datetime.now(UTC)
    return ExecutionContext(
        "fixture-execution",
        str(LAB),
        str(ASSET),
        "aegis-fixture-marker",
        "temporary-marker",
        instant,
        instant,
        False,
        "100200",
    )


def hit(ctx, kind="alert"):
    document = {
        "_id": "fixture-" + kind,
        "_index": "wazuh-alerts-4.x-fixture" if kind == "alert" else "wazuh-archives-4.x-fixture",
        "_source": {
            "timestamp": ctx.started_at.isoformat(),
            "agent": {"id": "007", "name": "anonymized-lab-fixture"},
            "manager": {"name": "fixture-manager"},
            "data": {
                "aegis": {
                    "laboratory_id": ctx.laboratory_id,
                    "execution_id": ctx.execution_id,
                    "marker": ctx.marker,
                    "behavior": ctx.behavior,
                    "observation": "marker_file_read",
                }
            },
        },
    }
    if kind == "alert":
        document["_source"]["rule"] = {
            "id": "100200",
            "level": 3,
            "description": "Fixture: laboratory marker observed",
        }
    return document


def response(hits=()):
    return {
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": list(hits)},
    }


def provider(handler, cfg=None, **kwargs):
    return WazuhIndexerProvider(
        "https://indexer.fixture:9200",
        "fixture-readonly",
        "fixture-not-a-real-secret",
        "192.0.2.10",
        policy=cfg or policy(),
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"agent_id": "000"},
        {"alerts_index": "_all"},
        {"alerts_index": "a/b"},
        {"archives_index": "wazuh-alerts-4.x-*"},
        {"archives_index": "wazuh-*"},
        {"identity_prefix": "data.aegis;anything"},
        {"timestamp_field": "untrusted"},
        {"ingestion_wait_seconds": 120, "poll_interval_seconds": 0.1},
        {"request_timeout_seconds": 60},
        {"command": "arbitrary"},
        {"schema_id": "unreviewed"},
    ],
)
def test_policy_rejects_ambiguous_or_unbounded_configuration(change):
    values = policy().model_dump()
    with pytest.raises(ValueError):
        WazuhCollectionConfig.model_validate({**values, **change})


def test_agent_translation_and_original_identity_are_both_preserved():
    ctx = context()
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json=response([hit(ctx)]))

    result = provider(handle).collect(ctx)
    assert result.complete and validate(ctx, result, True).outcome == "DETECTED"
    event = result.events[0]
    assert event.asset_id == str(ASSET) and event.raw["_source"]["agent"]["id"] == "007"
    assert b'"agent.id":"007"' in requests[0].content
    assert str(ASSET).encode() not in requests[0].content
    assert b"fixture-execution" in requests[0].content


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent", str(ASSET)),
        ("agent", "008"),
        ("marker", "different"),
        ("laboratory_id", "different"),
        ("execution_id", "different"),
        ("behavior", "different"),
    ],
)
def test_foreign_identity_never_becomes_a_detection(field, value):
    ctx, document = context(), None
    document = hit(ctx)
    if field == "agent":
        document["_source"]["agent"]["id"] = value
    else:
        document["_source"]["data"]["aegis"][field] = value
    result = provider(lambda _: httpx.Response(200, json=response([document]))).collect(ctx)
    assert not result.events and not result.complete
    assert validate(ctx, result, True).outcome == "INCONCLUSIVE"


@pytest.mark.parametrize(
    "fault",
    [
        "zero_shards",
        "failed_shards",
        "missing_total",
        "timed_out",
        "terminated",
        "no_indices",
        "forbidden",
        "redirect",
        "compressed",
        "malformed",
    ],
)
def test_empty_or_partial_responses_do_not_establish_clean_negative(fault):
    document = response()
    code, headers = 200, {}
    if fault == "zero_shards":
        document["_shards"] = {"total": 0, "successful": 0, "failed": 0}
    elif fault == "failed_shards":
        document["_shards"]["failed"] = 1
    elif fault == "missing_total":
        del document["hits"]["total"]
    elif fault == "timed_out":
        document["timed_out"] = True
    elif fault == "terminated":
        document["terminated_early"] = True
    elif fault in ("no_indices", "forbidden", "redirect"):
        code = {"no_indices": 404, "forbidden": 403, "redirect": 302}[fault]
    elif fault == "compressed":
        headers["content-encoding"] = "gzip"
    else:
        document["hits"]["hits"] = "wrong-schema"
    result = provider(
        lambda _: httpx.Response(
            code,
            content=b"{}" if fault == "compressed" else json.dumps(document).encode(),
            headers=headers,
        )
    ).collect(context())
    assert not result.complete and validate(context(), result, True).outcome == "INCONCLUSIVE"


class Clock:
    def __init__(self):
        self.value = time.monotonic()

    def now(self):
        return self.value

    def sleep(self, value):
        self.value += value


def test_polling_waits_for_late_alert_and_deduplicates_repeated_archive_hits():
    ctx, clock, calls = context(), Clock(), []
    cfg = policy(
        ingestion_window_seconds=1,
        ingestion_wait_seconds=1,
        poll_interval_seconds=0.5,
        archives_index="wazuh-archives-4.x-*",
    )

    def handle(request):
        calls.append(request)
        documents = (
            [hit(ctx, "telemetry")]
            if "archives" in request.url.path
            else ([hit(ctx)] if clock.value >= start + 0.5 else [])
        )
        return httpx.Response(200, json=response(documents))

    start = clock.value
    poll = WazuhPollingProvider(
        provider(handle, cfg),
        datetime.now(UTC) + timedelta(seconds=30),
        lambda: None,
        clock=clock.now,
        sleep=clock.sleep,
    )
    result = poll.collect(ctx)
    assert validate(ctx, result, True).outcome == "DETECTED"
    assert len(result.events) == 2 and poll.summary["attempts"] == 2
    assert not poll.summary["window_satisfied"]


def test_negative_waits_until_window_and_requires_final_complete_snapshot():
    ctx, clock = context(), Clock()
    cfg = policy(
        ingestion_window_seconds=1,
        ingestion_wait_seconds=1,
        poll_interval_seconds=0.5,
        archives_index="wazuh-archives-4.x-*",
    )

    def handle(request):
        return httpx.Response(
            200, json=response([hit(ctx, "telemetry")] if "archives" in request.url.path else [])
        )

    poll = WazuhPollingProvider(
        provider(handle, cfg),
        datetime.now(UTC) + timedelta(seconds=30),
        lambda: None,
        clock=clock.now,
        sleep=clock.sleep,
    )
    result = poll.collect(ctx)
    assert poll.summary["attempts"] == 3 and poll.summary["window_satisfied"]
    assert len(result.events) == 1 and result.complete
    assert validate(ctx, result, True).outcome == "OBSERVED_NOT_ALERTED"


def test_run_budget_reserves_cleanup_and_cannot_prove_a_negative():
    ctx, clock = context(), Clock()
    poll = WazuhPollingProvider(
        provider(lambda _: httpx.Response(200, json=response())),
        datetime.now(UTC) + timedelta(seconds=5),
        lambda: None,
        clock=clock.now,
        sleep=clock.sleep,
    )
    result = poll.collect(ctx)
    assert poll.summary["attempts"] == 0 and not result.complete
    assert validate(ctx, result, True).outcome == "INCONCLUSIVE"


def test_changed_source_document_is_not_reused_as_evidence():
    ctx, clock = context(), Clock()
    cfg = policy(
        ingestion_window_seconds=1,
        ingestion_wait_seconds=1,
        poll_interval_seconds=0.5,
        archives_index="wazuh-archives-4.x-*",
    )
    start = clock.value

    def handle(request):
        document = hit(ctx, "telemetry")
        document["_source"]["revision"] = int(clock.value > start)
        return httpx.Response(
            200, json=response([document] if "archives" in request.url.path else [])
        )

    result = WazuhPollingProvider(
        provider(handle, cfg),
        datetime.now(UTC) + timedelta(seconds=30),
        lambda: None,
        clock=clock.now,
        sleep=clock.sleep,
    ).collect(ctx)
    assert (
        not result.events
        and not result.complete
        and validate(ctx, result, True).outcome == "INCONCLUSIVE"
    )


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_total_request_timeout_covers_slow_headers_and_fragmented_body(phase):
    closed = []

    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(100):
                await asyncio.sleep(0.02)
                yield b" "

        async def aclose(self):
            closed.append(True)

    async def handle(request):
        if phase == "headers":
            await asyncio.sleep(2)
        return httpx.Response(200, stream=SlowBody())

    remote = provider(handle, policy(request_timeout_seconds=0.1))
    started = time.monotonic()
    result = remote.collect(context())
    assert time.monotonic() - started < 1
    assert not result.complete and remote.closed
    if phase == "body":
        assert closed


def test_guard_cancels_in_the_middle_of_a_fragmented_body():
    calls, closed = [], []

    class Fragmented(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10):
                yield b" "

        async def aclose(self):
            closed.append(True)

    class Cancelled(Exception):
        pass

    def guard():
        calls.append(True)
        if len(calls) == 3:
            raise Cancelled()

    remote = provider(lambda _: httpx.Response(200, stream=Fragmented()), guard=guard)
    with pytest.raises(Cancelled):
        remote.collect(context())
    assert closed and remote.closed


def test_unexpected_correlated_rule_is_observation_not_expected_detection():
    ctx = context()
    document = hit(ctx)
    document["_source"]["rule"]["id"] = "100201"
    result = provider(lambda _: httpx.Response(200, json=response([document]))).collect(ctx)
    assert validate(ctx, result, True).outcome == "OBSERVED_NOT_ALERTED"
    assert validate(replace(ctx, expected_rule=""), result, True).outcome == "INCONCLUSIVE"
