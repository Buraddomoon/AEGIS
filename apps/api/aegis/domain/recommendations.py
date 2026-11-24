"""Offline advice over recorded facts. Never executes or changes a verdict."""

from copy import deepcopy
from typing import Any

from aegis.domain.validation import digest

POLICY_VERSION = "aegis-recommendations/1"
LIMITATIONS = [
    "Análise nova e separada sobre registros históricos; não altera regra, aprovação ou veredicto.",
    "Prioridade é ordem técnica de investigação, não severidade ou risco de negócio.",
    "Ausência de alerta não comprova vulnerabilidade, comprometimento ou proteção empresarial.",
    "Recibo e cleanup do executor são fatos operacionais, não evidências defensivas.",
    "Nenhuma ação é executada. Repetição, coleta externa e mudanças exigem escopo e autorização próprios.",
]
# The complete policy is embedded in the analysis, so advice remains attributable
# after the application policy changes. Change the version when logic changes.
RULES = {
    "cleanup_failed": (
        10,
        "Estado CLEANUP_FAILED no pai ou filho.",
        "Falha de cleanup registrada.",
        "Priorizar recuperação segura pelo procedimento do laboratório; preservar recibos, journals e fences e confirmar a limpeza sob autorização específica antes de nova execução.",
    ),
    "execution_failed": (
        20,
        "Outcome EXECUTION_FAILED ou estado FAILED/TIMED_OUT.",
        "Execução falhou ou excedeu o prazo registrado.",
        "Inspecionar a falha do adaptador e seus comprovantes operacionais; confirmar o efeito e cleanup antes de solicitar nova execução aprovada. Não avaliar detecção a partir dessa falha.",
    ),
    "collection_unavailable": (
        30,
        "Resultado registra alerts_available=false ou telemetry_available=false.",
        "Uma capacidade de coleta está indisponível no resultado registrado.",
        "Verificar a capacidade indisponível, configuração, acesso e disponibilidade da fonte prevista no escopo; não interpretar consulta indisponível como ausência de eventos.",
    ),
    "window_incomplete": (
        40,
        "Coleta registra window_satisfied=false.",
        "A janela de coleta registrada não foi cumprida.",
        "Inspecionar início/fim, janela de ingestão e tentativas da coleta; planejar nova observação apenas no escopo autorizado, sem concluir ausência de alerta nessa janela incompleta.",
    ),
    "collection_incomplete": (
        45,
        "Resultado collection_complete=false ou coleta complete=false.",
        "A coleta registrada está incompleta.",
        "Inspecionar motivo e tentativas de coleta e limites da fonte; resolver a incompletude antes de comparar ausência de alertas.",
    ),
    "inconclusive": (
        50,
        "Outcome INCONCLUSIVE.",
        "O veredicto registrado é inconclusivo.",
        "Revisar a justificativa, regra esperada e contexto aprovado; identificar quais evidências faltam, sem reclassificar o resultado histórico.",
    ),
    "observed_not_alerted": (
        60,
        "Outcome OBSERVED_NOT_ALERTED.",
        "Observação sem alerta da regra esperada registrada no veredicto.",
        "Inspecionar os eventos vinculados, regra esperada, versão e vínculo registrados; revisar condições da regra e planejar validação do mesmo escopo após mudanças aprovadas, sem implantação automática.",
    ),
    "no_telemetry": (
        70,
        "Outcome NO_TELEMETRY.",
        "O resultado registra evidência insuficiente de telemetria correlacionada.",
        "Verificar instrumentação, capacidade da fonte e filtros de correlação por ativo, marcador e janela. Não concluir falha de detecção ou ausência física de telemetria.",
    ),
    "not_tested": (
        80,
        "Resultado ausente ou outcome NOT_TESTED.",
        "Não há avaliação defensiva registrada para este teste.",
        "Conferir estado e escopo da solicitação; aguardar conclusão ou solicitar revisão e aprovação próprias antes de testar. Não reutilizar autorizações consumidas.",
    ),
    "detected": (
        90,
        "Outcome DETECTED.",
        "O veredicto registra detecção limitada ao teste.",
        "Inspecionar o alerta e os vínculos de evidência registrados, regra e janela; conservar a prova desse escopo sem extrapolar eficácia geral do SIEM ou cobertura ATT&CK.",
    ),
    "unknown": (
        85,
        "Outcome não reconhecido pela política.",
        "A política não reconhece o resultado registrado.",
        "Inspecionar o contrato e versão originais; manter o estado desconhecido sem preencher contexto retroativamente.",
    ),
}


def analyze_recommendations(detail: dict[str, Any]) -> dict[str, Any]:
    """Same snapshot => same analysis; source order is retained and hashed."""
    policy: dict[str, Any] = {
        "version": POLICY_VERSION,
        "rules": {
            code: {"priority": r[0], "condition": r[1], "reason": r[2], "action": r[3]}
            for code, r in RULES.items()
        },
        "limitations": LIMITATIONS,
    }
    items = []
    for index, execution in enumerate(detail.get("executions", [])):
        result = execution.get("result") or {}
        collection = execution.get("collection") or {}
        outcome = result.get("outcome", "NOT_TESTED")
        codes = []
        if "CLEANUP_FAILED" in (detail.get("state"), execution.get("state")):
            codes.append("cleanup_failed")
        if outcome == "EXECUTION_FAILED" or execution.get("state") in ("FAILED", "TIMED_OUT"):
            codes.append("execution_failed")
        if any(result.get(key) is False for key in ("alerts_available", "telemetry_available")):
            codes.append("collection_unavailable")
        if collection.get("window_satisfied") is False:
            codes.append("window_incomplete")
        if result.get("collection_complete") is False or collection.get("complete") is False:
            codes.append("collection_incomplete")
        outcome_code = outcome.lower()
        if outcome_code in RULES and outcome_code != "execution_failed":
            codes.append(outcome_code)
        elif outcome_code not in RULES:
            codes.append("unknown")
        facts = {
            "run_state": detail.get("state"),
            "execution_state": execution.get("state"),
            "executed": execution.get("executed"),
            "outcome": outcome,
            "result": deepcopy(result) or None,
            "collection": deepcopy(collection) or None,
        }
        # Only links already recorded for this result are defensively associated.
        # An orphan link remains visible with missing metadata, never fabricated.
        events = {event.get("id"): event for event in execution.get("events", [])}
        evidence = []
        for link in execution.get("evidence", []):
            event = events.get(link.get("event_id")) or {}
            evidence.append(
                {
                    "link_id": link.get("id"),
                    "event_id": link.get("event_id"),
                    "reason": link.get("reason"),
                    "source": event.get("source"),
                    "kind": event.get("kind"),
                    "sha256": event.get("sha256"),
                    "synthetic": event.get("synthetic"),
                    "event_present": bool(event),
                }
            )
        for code in sorted(set(codes), key=lambda c: (RULES[c][0], c)):
            items.append(
                {
                    "execution_id": execution.get("id"),
                    "execution_index": index,
                    "test_id": execution.get("test_id"),
                    "synthetic": execution.get("synthetic"),
                    "code": code,
                    **deepcopy(policy["rules"][code]),
                    "facts": deepcopy(facts),
                    "evidence": deepcopy(evidence),
                }
            )
    items.sort(key=lambda item: (item["priority"], item["execution_index"], item["code"]))
    analysis = {
        "kind": "new_analysis",
        "policy": deepcopy(policy),
        "policy_sha256": digest(policy),
        "input_sha256": digest(detail),
        "run_id": detail.get("id"),
        "synthetic": detail.get("synthetic"),
        "items": items,
        "limitations": list(LIMITATIONS),
    }
    return {**analysis, "integrity_sha256": digest(analysis)}
