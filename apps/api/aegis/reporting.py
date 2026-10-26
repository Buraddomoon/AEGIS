import html
import json

from fastapi.encoders import jsonable_encoder

from aegis.domain.validation import digest

LIMITATION = "Dados sintéticos. Ausência de alerta não comprova comprometimento, vulnerabilidade explorável ou risco de negócio. Este relatório não valida proteção de ambiente real."

REAL_LIMITATION = "Laboratório Linux autorizado. Comprovantes do executor confirmam somente o efeito e cleanup do teste benigno. SIEM não consultado: não há confirmação de observação ou detecção defensiva. Ausência de alerta não comprova comprometimento ou risco de negócio."


def build_report(detail: dict) -> dict:
    # Hash exactly the JSON representation delivered to clients, including UTC dates.
    detail = jsonable_encoder(detail)
    queried = any(
        (item.get("collection") or {}).get("provider") == "wazuh-indexer"
        and (item.get("collection") or {}).get("attempts", 0) > 0
        for item in detail["executions"]
    )
    real_limitation = (
        "Coleta Wazuh registrada neste escopo; disponibilidade, janela e evidências devem ser inspecionadas. Recibo do executor não é alerta. Uma regra de instrumentação do marcador benigno valida somente esse pipeline, sem comprovar proteção empresarial ou técnica ATT&CK."
        if queried
        else REAL_LIMITATION
    )
    return {
        "product": "ÆGIS",
        "report_version": "1.1",
        "synthetic": detail["synthetic"],
        "run": detail,
        "limitations": [LIMITATION if detail["synthetic"] else real_limitation],
        "recommendations": [
            "Verificar instrumentação e disponibilidade da coleta nas simulações sem telemetria.",
            "Revisar regras e repetir o mesmo escopo após mudanças aprovadas.",
            "Confirmar resultados em laboratório autorizado antes de extrapolar conclusões.",
        ],
        "integrity_sha256": digest(detail),
    }


class HTMLReportExporter:
    def export(self, report: dict) -> str:
        def escape(value):
            return html.escape(str(value), quote=True)

        run = report["run"]
        rows = "".join(
            f"<tr><td>{escape(e['test_id'])}</td><td>{escape((e['result'] or {}).get('outcome', 'NOT_TESTED'))}</td><td>{escape((e['result'] or {}).get('reason', 'Sem conclusão'))}</td></tr>"
            for e in run["executions"]
        )
        notice = (
            "DEMONSTRAÇÃO · EVIDÊNCIAS SINTÉTICAS"
            if report["synthetic"]
            else "LABORATÓRIO REAL · COMPROVANTES DO EXECUTOR"
        )
        limitation = " ".join(report["limitations"])
        catalog = run["scope"].get("attack_catalog")
        catalog_text = (
            f"Enterprise v{catalog['version']} · release {catalog['release_id']}"
            if catalog
            else "Versão ATT&CK não registrada no escopo histórico."
        )
        raw = escape(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>ÆGIS — relatório</title>
<style>body{{font:15px system-ui;max-width:1100px;margin:48px auto;padding:20px;color:#132235}}h1{{color:#176658}}td,th{{padding:14px;text-align:left;border-bottom:1px solid #ccd6dd}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.notice{{padding:20px;background:#eef7f3}}</style>
<h1>ÆGIS · Validação de detecção</h1><div class="notice"><strong>{escape(notice)}</strong><p>{escape(limitation)}</p></div>
<h2>{escape(run["campaign_name"])}</h2><p>{escape(run["objective"])}</p>
<p>Execução: {escape(run["id"])} · Estado: {escape(run["state"])}</p><p>Data UTC: {escape(run["created_at"])} · Ambiente v{escape(run["scope"]["environment_version"])}</p>
<p>Catálogo ATT&CK: {escape(catalog_text)}</p>
<h2>Resumo executivo</h2><p>Foram avaliadas {len(run["executions"])} simulações neste escopo. As classificações abaixo distinguem detecção, observação sem alerta e insuficiência de evidências. Os resultados não demonstram proteção de uma organização.</p>
<h2>Resultados técnicos</h2><table><tr><th>Simulação</th><th>Resultado</th><th>Justificativa</th></tr>{rows}</table>
<h2>Recomendações</h2><ul>{"".join("<li>" + escape(r) + "</li>" for r in report["recommendations"])}</ul>
<h2>Integridade</h2><p>SHA-256 do conteúdo da execução: {escape(report["integrity_sha256"])}. Hash permite verificar alterações; não é assinatura digital.</p>
<h2>Escopo, aprovação, evidências e trilha completa</h2><pre>{raw}</pre></html>"""


def seal_analysis(content: dict) -> dict:
    content = jsonable_encoder(content)
    return {**content, "integrity_sha256": digest(content)}


def build_coverage_report(metrics: dict) -> dict:
    return seal_analysis(
        {
            "product": "ÆGIS",
            "report_version": "aegis-coverage-report/1",
            "kind": "coverage",
            "synthetic": metrics["synthetic"],
            "contains_synthetic": metrics["synthetic"],
            "metrics": metrics,
            "limitations": [
                metrics["limitation"],
                "Recorte pela data de solicitação, início inclusivo/fim exclusivo. Snapshot na exportação; pode incluir novos dados do mesmo recorte.",
                "Runs não concluídas/falhas são contabilizadas por estado, sem participar da taxa de detecção. Legado sem versão permanece desconhecido.",
            ],
        }
    )


def build_comparison_report(comparison: dict, before: dict, after: dict) -> dict:
    def summary(report):
        from collections import Counter

        outcomes = Counter(
            (e.get("result") or {}).get("outcome", "NOT_TESTED")
            for e in report["run"]["executions"]
        )
        completed = (
            Counter(
                (e.get("result") or {}).get("outcome", "NOT_TESTED")
                for e in report["run"]["executions"]
                if e["state"] == "COMPLETED"
            )
            if report["run"]["state"] == "COMPLETED"
            else Counter()
        )
        valid = sum(completed[k] for k in ("DETECTED", "OBSERVED_NOT_ALERTED", "NO_TELEMETRY"))
        return {
            "outcomes": dict(outcomes),
            "valid_tests": valid,
            "detected_tests": completed["DETECTED"],
            "detected_percentage": round(completed["DETECTED"] / valid * 100, 1) if valid else None,
        }

    old, new = summary(before), summary(after)
    delta = None
    if comparison["comparable"] and all(s["detected_percentage"] is not None for s in (old, new)):
        delta = round(
            100
            * (
                new["detected_tests"] / new["valid_tests"]
                - old["detected_tests"] / old["valid_tests"]
            ),
            1,
        )
    return seal_analysis(
        {
            "product": "ÆGIS",
            "report_version": "aegis-comparison-report/1",
            "kind": "comparison",
            "synthetic": before["synthetic"] and after["synthetic"],
            "contains_synthetic": before["synthetic"] or after["synthetic"],
            "comparison": comparison,
            "before": before,
            "after": after,
            "summary": {
                "before": old,
                "after": new,
                "changed_results": sum(t["changed"] for t in comparison["tests"]),
                "detected_rate_delta_percentage_points": delta,
                "denominator": "DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY, por lado concluído; demais classificações excluídas.",
            },
            "limitations": [
                comparison["limitation"],
                "Diferença de resultado/taxa não demonstra causalidade, comprometimento ou proteção empresarial. Contexto desconhecido não comprova equivalência.",
                *before["limitations"],
                *after["limitations"],
            ],
        }
    )


def export_analysis_html(report: dict) -> str:
    def escape(value):
        return html.escape(str(value), quote=True)

    synthetic = report["synthetic"]
    notice = (
        "DEMONSTRAÇÃO · RESULTADOS SINTÉTICOS"
        if synthetic
        else "ESCOPO MISTO · CONTÉM DADOS SINTÉTICOS"
        if report["contains_synthetic"]
        else "LABORATÓRIO REAL · LIMITAÇÕES DAS FONTES REGISTRADAS"
    )
    if report["kind"] == "coverage":
        c = report["metrics"]
        title = "Cobertura no recorte selecionado"
        summary = f"{c['total_runs']} runs no recorte; {c['completed_tests']} testes concluídos; {c['outcomes'].get('DETECTED', 0)} detectados em {c['valid_tests']} testes válidos."
        rows = "".join(
            f"<tr><td>{escape(k)}</td><td>{escape(v)}</td></tr>" for k, v in c["outcomes"].items()
        )
        details = f"<p>Snapshot UTC: {escape(c['snapshot_at'])}</p><p>{escape(c['denominator'])}</p><table><tr><th>Resultado</th><th>Quantidade</th></tr>{rows}</table>"
    else:
        title = "Comparação entre execuções"
        c, s = report["comparison"], report["summary"]
        summary = (
            "Mesmo escopo concluído e contexto registrado."
            if c["comparable"]
            else "Comparabilidade não confirmada; revisar diferenças e contextos desconhecidos."
        )
        rows = "".join(
            f"<tr><td>{escape(t['test_id'])}</td><td>{escape(t['before'])}</td><td>{escape(t['after'])}</td></tr>"
            for t in c["tests"]
        )
        details = f"<p>{escape(c['before_id'])} → {escape(c['after_id'])}</p><p>Válidos: {s['before']['valid_tests']} antes / {s['after']['valid_tests']} depois. Delta em pontos percentuais: {escape(s['detected_rate_delta_percentage_points'] if s['detected_rate_delta_percentage_points'] is not None else 'não calculado')}.</p><table><tr><th>Teste</th><th>Anterior</th><th>Atual</th></tr>{rows}</table>"
    limitations = "".join(f"<li>{escape(item)}</li>" for item in report["limitations"])
    raw = escape(json.dumps(report, ensure_ascii=False, indent=2))
    return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>ÆGIS — {escape(title)}</title>
<style>body{{font:15px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#132235}}td,th{{padding:12px;border-bottom:1px solid #ccd6dd;text-align:left}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.notice{{padding:20px;background:#eef7f3}}</style>
<h1>ÆGIS · {escape(title)}</h1><div class="notice"><strong>{escape(notice)}</strong></div>
<h2>Resumo executivo</h2><p>{escape(summary)}</p>{details}<h2>Limitações e recomendações de análise</h2><ul>{limitations}</ul>
<h2>Integridade</h2><p>SHA256 do documento sem integrity_sha256: {escape(report["integrity_sha256"])}. Não é assinatura digital.</p>
<h2>Escopo, membros, evidências e diferenças técnicas</h2><pre>{raw}</pre></html>"""
