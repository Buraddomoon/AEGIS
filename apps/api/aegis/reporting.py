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
        raw = escape(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>ÆGIS — relatório</title>
<style>body{{font:15px system-ui;max-width:1100px;margin:48px auto;padding:20px;color:#132235}}h1{{color:#176658}}td,th{{padding:14px;text-align:left;border-bottom:1px solid #ccd6dd}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.notice{{padding:20px;background:#eef7f3}}</style>
<h1>ÆGIS · Validação de detecção</h1><div class="notice"><strong>{escape(notice)}</strong><p>{escape(limitation)}</p></div>
<h2>{escape(run["campaign_name"])}</h2><p>{escape(run["objective"])}</p>
<p>Execução: {escape(run["id"])} · Estado: {escape(run["state"])}</p><p>Data UTC: {escape(run["created_at"])} · Ambiente v{escape(run["scope"]["environment_version"])}</p>
<h2>Resumo executivo</h2><p>Foram avaliadas {len(run["executions"])} simulações neste escopo. As classificações abaixo distinguem detecção, observação sem alerta e insuficiência de evidências. Os resultados não demonstram proteção de uma organização.</p>
<h2>Resultados técnicos</h2><table><tr><th>Simulação</th><th>Resultado</th><th>Justificativa</th></tr>{rows}</table>
<h2>Recomendações</h2><ul>{"".join("<li>" + escape(r) + "</li>" for r in report["recommendations"])}</ul>
<h2>Integridade</h2><p>SHA-256 do conteúdo da execução: {escape(report["integrity_sha256"])}. Hash permite verificar alterações; não é assinatura digital.</p>
<h2>Escopo, aprovação, evidências e trilha completa</h2><pre>{raw}</pre></html>"""
