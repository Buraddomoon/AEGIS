from aegis.domain.contracts import Collection, Event, ExecutionContext
from aegis.domain.validation import Outcome


class DemoExecutionAdapter:
    def prepare(self, context: ExecutionContext) -> None:
        if not context.synthetic:
            raise ValueError("DemoAdapter aceita apenas escopo sintético.")

    def execute(self, context: ExecutionContext) -> bool:
        # In-memory simulation only. Never touches endpoint, subprocess or host network.
        return context.synthetic

    def cleanup(self, context: ExecutionContext) -> None:
        # Synthetic artifact is scoped to this context; no external side effect exists.
        if not context.synthetic:
            raise ValueError("Escopo inválido para cleanup demonstrativo.")


class DemoTelemetryProvider:
    def __init__(self, scenario: str):
        self.scenario = scenario

    def collect(self, context: ExecutionContext) -> Collection:
        if self.scenario == Outcome.INCONCLUSIVE:
            return Collection((), False, False, False, "Indisponibilidade sintética da coleta.")
        if self.scenario == Outcome.NO_TELEMETRY:
            return Collection((), False, True)
        kinds = ["telemetry", "alert"] if self.scenario == Outcome.DETECTED else ["telemetry"]
        events = []
        for kind in kinds:
            raw = {
                "synthetic": True,
                "execution_id": context.execution_id,
                "laboratory_id": context.laboratory_id,
                "asset_id": context.asset_id,
                "marker": context.marker,
                "behavior": context.behavior,
                "timestamp": context.started_at.isoformat(),
                "kind": kind,
                "rule_id": context.expected_rule if kind == "alert" else None,
                "message": "Evidência demonstrativa gerada pelo adaptador; não é evento real.",
            }
            events.append(
                Event(
                    source_id=f"{context.execution_id}:{kind}",
                    source="aegis-demo",
                    timestamp=context.started_at,
                    laboratory_id=context.laboratory_id,
                    asset_id=context.asset_id,
                    execution_id=context.execution_id,
                    marker=context.marker,
                    behavior=context.behavior,
                    kind=kind,
                    rule_id=raw["rule_id"],
                    synthetic=True,
                    raw=raw,
                )
            )
        return Collection(tuple(events), True, True)

    def alerts(self, context: ExecutionContext) -> Collection:
        result = self.collect(context)
        return Collection(
            tuple(e for e in result.events if e.kind == "alert"),
            result.telemetry_available,
            result.alerts_available,
            result.complete,
            result.error,
        )
