"""Availability and time-window contracts; no native SIEM or lab effects."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from aegis.domain.validation import validate
from aegis.integrations.wazuh_polling import WazuhPollingProvider
from test_wazuh_collection import Clock, context, hit, policy, provider, response


@pytest.mark.parametrize(
    "status,phrase",
    [
        (401, "autenticação recusada"),
        (403, "permissão negada"),
        (404, "índice ou cursor ausente"),
        (503, "erro HTTP do Indexer"),
    ],
)
@pytest.mark.parametrize("source", ["alerts", "archives"])
def test_source_failures_remain_distinct_and_never_echo_server_data(status, phrase, source):
    ctx = context()

    def handle(request):
        if source in request.url.path:
            return httpx.Response(status, json={"error": "sensitive-upstream-body"})
        return httpx.Response(200, json=response())

    result = provider(handle, policy(archives_index="wazuh-archives-4.x-*")).collect(ctx)
    assert not result.complete
    assert result.alerts_available == (source != "alerts")
    assert result.telemetry_available == (source != "archives")
    assert phrase in result.error
    assert "sensitive" not in result.error
    assert validate(ctx, result, True).outcome == "INCONCLUSIVE"


@pytest.mark.parametrize("archives", [None, "wazuh-archives-4.x-*"])
def test_no_telemetry_means_no_correlated_evidence_and_records_archive_availability(archives):
    result = provider(
        lambda _: httpx.Response(200, json=response()), policy(archives_index=archives)
    ).collect(context())
    assert result.complete and result.error is None
    assert result.telemetry_available == bool(archives)
    phrase = "Archives: consulta completa (0" if archives else "Archives: consulta não configurada"
    assert phrase in " ".join(result.diagnostics)
    verdict = validate(context(), result, True)
    assert verdict.outcome == "NO_TELEMETRY"
    assert "não comprova falha de detecção" in verdict.reason


@pytest.mark.parametrize(
    "fault", ["permission", "index", "timeout", "transport", "schema", "partial"]
)
def test_final_poll_keeps_specific_failure_after_ingestion_window(fault):
    ctx, clock = context(), Clock()

    def handle(request):
        if "archives" in request.url.path:
            return httpx.Response(200, json=response([hit(ctx, "telemetry")]))
        if fault == "timeout":
            raise httpx.ReadTimeout("sensitive-upstream-message", request=request)
        if fault == "transport":
            raise httpx.ConnectError("sensitive-upstream-message", request=request)
        if fault in ("permission", "index"):
            return httpx.Response(403 if fault == "permission" else 404, json={})
        page = response()
        if fault == "schema":
            page["hits"] = None
        if fault == "partial":
            page["_shards"]["failed"] = 1
        return httpx.Response(200, json=page)

    poll = WazuhPollingProvider(
        provider(
            handle,
            policy(
                archives_index="wazuh-archives-4.x-*",
                ingestion_window_seconds=1,
                ingestion_wait_seconds=1,
                poll_interval_seconds=0.5,
            ),
        ),
        datetime.now(UTC) + timedelta(seconds=30),
        lambda: None,
        clock=clock.now,
        sleep=clock.sleep,
    )
    result = poll.collect(ctx)
    assert poll.summary["window_satisfied"] and not result.complete
    phrases = {
        "permission": "permissão negada",
        "index": "índice ou cursor ausente",
        "timeout": "tempo de consulta esgotado",
        "transport": "transporte indisponível",
        "schema": "resposta inválida",
        "partial": "consulta incompleta",
    }
    assert phrases[fault] in result.error and "sensitive" not in result.error
    assert len(result.events) == 1
    assert validate(ctx, result, True).outcome == "INCONCLUSIVE"


@pytest.mark.parametrize("seconds", [-31, 121])
def test_out_of_window_observation_is_not_a_clean_negative(seconds):
    ctx = context()
    document = hit(ctx, "telemetry")
    document["_source"]["timestamp"] = (ctx.started_at + timedelta(seconds=seconds)).isoformat()
    result = provider(
        lambda request: httpx.Response(
            200, json=response([document] if "archives" in request.url.path else [])
        ),
        policy(archives_index="wazuh-archives-4.x-*"),
    ).collect(ctx)
    assert not result.complete and not result.events
    assert validate(ctx, result, True).outcome == "INCONCLUSIVE"


def test_early_observation_does_not_prove_missing_alert_before_window():
    ctx, clock = context(), Clock()
    remote = provider(
        lambda request: httpx.Response(
            200, json=response([hit(ctx, "telemetry")] if "archives" in request.url.path else [])
        ),
        policy(archives_index="wazuh-archives-4.x-*"),
    )
    poll = WazuhPollingProvider(
        remote,
        datetime.now(UTC) + timedelta(seconds=5.5),
        lambda: None,
        clock=clock.now,
        sleep=clock.sleep,
    )
    result = poll.collect(ctx)
    assert result.events and not result.complete and not poll.summary["window_satisfied"]
    assert "Janela de ingestão incompleta" in result.error
    assert validate(ctx, result, True).outcome == "INCONCLUSIVE"
