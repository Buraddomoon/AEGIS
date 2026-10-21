import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any

from aegis.domain.contracts import Collection, Event, ExecutionContext

LOGIC_VERSION = "aegis-correlation/1.1"


class Outcome(StrEnum):
    DETECTED = "DETECTED"
    OBSERVED_NOT_ALERTED = "OBSERVED_NOT_ALERTED"
    NO_TELEMETRY = "NO_TELEMETRY"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    NOT_TESTED = "NOT_TESTED"


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome
    reason: str
    evidence: tuple[Event, ...]


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        ).encode()
    ).hexdigest()


def correlates(
    ctx: ExecutionContext, event: Event, skew_seconds: int = 5, ingestion_seconds: int = 120
) -> bool:
    return (
        event.laboratory_id == ctx.laboratory_id
        and event.asset_id == ctx.asset_id
        and event.execution_id == ctx.execution_id
        and event.marker == ctx.marker
        and event.behavior == ctx.behavior
        and event.synthetic == ctx.synthetic
        and ctx.started_at - timedelta(seconds=skew_seconds)
        <= event.timestamp
        <= ctx.ended_at + timedelta(seconds=ingestion_seconds)
    )


def validate(
    ctx: ExecutionContext,
    collection: Collection,
    executed: bool,
    skew_seconds: int = 5,
    ingestion_seconds: int = 120,
) -> Verdict:
    if not executed:
        return Verdict(Outcome.EXECUTION_FAILED, "Adaptador não confirmou a execução.", ())
    matching = tuple(
        e for e in collection.events if correlates(ctx, e, skew_seconds, ingestion_seconds)
    )
    alerts = tuple(
        e
        for e in matching
        if e.kind == "alert" and ctx.expected_rule and e.rule_id == ctx.expected_rule
    )
    if alerts:
        return Verdict(
            Outcome.DETECTED,
            "Execução confirmada; alerta com regra esperada, marcador, ativo, laboratório, comportamento e janela compatíveis.",
            alerts,
        )
    observed = tuple(e for e in matching if e.kind in ("telemetry", "alert"))
    if not ctx.expected_rule:
        return Verdict(
            Outcome.INCONCLUSIVE, "Regra esperada não definida no escopo aprovado.", observed
        )
    if not collection.complete or collection.error or not collection.alerts_available:
        return Verdict(
            Outcome.INCONCLUSIVE,
            "Coleta incompleta ou consulta de alertas indisponível; ausência de alerta não é conclusiva.",
            observed,
        )
    if observed:
        return Verdict(
            Outcome.OBSERVED_NOT_ALERTED,
            "Observação correlacionada; consulta completa sem alerta da regra esperada.",
            observed,
        )
    return Verdict(
        Outcome.NO_TELEMETRY,
        "Execução confirmada, sem evidência suficiente de telemetria correlacionada; não comprova falha de detecção.",
        (),
    )
