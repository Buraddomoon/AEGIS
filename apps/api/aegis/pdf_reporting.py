"""Bounded, text-only PDF adapter over existing report snapshots; no resource fetching."""

import html
import json
import textwrap
import threading
import time
import unicodedata
from io import BytesIO
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer
from reportlab.platypus.doctemplate import LayoutError

from aegis.domain.validation import digest
from aegis.reporting import execution_summary_lines, summarize_execution

MAX_SOURCE_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PAGES = 120
MAX_SECONDS = 20
_RENDER_LOCK = threading.Lock()
_FONT_DIR = Path(reportlab.__file__).resolve().parent / "fonts"
for name, file in (("AegisReport", "Vera.ttf"), ("AegisReportBold", "VeraBd.ttf")):
    pdfmetrics.registerFont(TTFont(name, str(_FONT_DIR / file)))
_GLYPHS = set(pdfmetrics.getFont("AegisReport").face.charToGlyph)


class PDFExportError(ValueError):
    """Static limit/integrity error; never emit report contents or driver messages."""


class PDFBusyError(PDFExportError):
    pass


def _text(value) -> str:
    """Keep unsupported/control characters visible instead of silent missing glyphs."""
    result = []
    for char in str(value):
        if char == "\n":
            result.append("<br/>")
        elif char == "\t":
            result.append("    ")
        elif ord(char) not in _GLYPHS or unicodedata.category(char).startswith("C"):
            result.append(f"\\u{ord(char):04x}" if ord(char) <= 65535 else f"\\U{ord(char):08x}")
        else:
            result.append(html.escape(char, quote=True))
    return "".join(result)


def _notice(report):
    if report["synthetic"]:
        return "DEMONSTRAÇÃO · DADOS SINTÉTICOS · EVIDÊNCIAS SIMULADAS"
    if report.get("contains_synthetic"):
        return "ESCOPO MISTO · CONTÉM DADOS SINTÉTICOS"
    return "LABORATÓRIO REAL · LIMITAÇÕES DAS FONTES REGISTRADAS"


class PDFReportExporter:
    def export(self, report: dict) -> bytes:
        # Snapshot encoding bounds document work and detaches mutable caller data.
        raw = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise PDFExportError("pdf_source_limit")
        report = json.loads(raw)
        expected = digest(
            report["run"]
            if "run" in report
            else {key: value for key, value in report.items() if key != "integrity_sha256"}
        )
        if report["integrity_sha256"] != expected:
            raise PDFExportError("pdf_report_integrity_mismatch")
        if "run" in report and "summary" in report:
            if digest(report["summary"]) != digest(summarize_execution(report["run"])):
                raise PDFExportError("pdf_report_integrity_mismatch")
        if not _RENDER_LOCK.acquire(blocking=False):
            raise PDFBusyError("pdf_renderer_busy")
        try:
            return self._render(report, raw)
        except LayoutError:
            raise PDFExportError("pdf_layout_limit") from None
        finally:
            _RENDER_LOCK.release()

    def _render(self, report, raw):
        started = time.monotonic()
        ink, accent = colors.HexColor("#18283d"), colors.HexColor("#176658")
        body = ParagraphStyle(
            "body",
            fontName="AegisReport",
            fontSize=9,
            leading=14,
            textColor=ink,
            spaceAfter=7,
            splitLongWords=True,
        )
        heading = ParagraphStyle(
            "heading",
            parent=body,
            fontName="AegisReportBold",
            fontSize=13,
            leading=18,
            textColor=accent,
            spaceBefore=13,
            keepWithNext=True,
        )
        title = ParagraphStyle(
            "title",
            parent=heading,
            fontSize=23,
            leading=29,
            spaceBefore=15,
        )
        code = ParagraphStyle("code", fontName="Courier", fontSize=7, leading=10)
        story = []

        def add(text, style=body):
            # Only our fixed <br/> nodes survive escaping. No user markup/links/images.
            story.append(Paragraph(_text(text), style))

        notice, source_hash = _notice(report), digest(report)

        def page(canvas, doc):
            if doc.page > MAX_PAGES or time.monotonic() - started > MAX_SECONDS:
                raise PDFExportError("pdf_page_or_time_limit")
            canvas.saveState()
            canvas.setFont("AegisReportBold", 8)
            canvas.setFillColor(accent)
            canvas.drawString(42, A4[1] - 30, notice)
            canvas.setStrokeColor(colors.HexColor("#cbd5df"))
            canvas.line(42, A4[1] - 38, A4[0] - 42, A4[1] - 38)
            canvas.setFont("AegisReport", 7)
            canvas.setFillColor(ink)
            canvas.drawString(42, 28, "ÆGIS · Fonte JSON SHA256: " + source_hash[:24] + "…")
            canvas.drawRightString(A4[0] - 42, 28, f"Página {doc.page}")
            canvas.restoreState()

        add("ÆGIS", title)
        add("Validação de detecção · Relatório técnico e executivo", heading)
        add(notice)
        for limitation in report["limitations"]:
            add(limitation)
        add("Resumo executivo", heading)
        if "run" in report:
            run = report["run"]
            add(run["campaign_name"], heading)
            add(run["objective"])
            add(f"Execução: {run['id']} · Estado: {run['state']}")
            add(f"Solicitação UTC: {run['created_at']}")
            add(f"Versão do ambiente: {run['scope']['environment_version']}")
            catalog = run["scope"].get("attack_catalog")
            add(
                f"ATT&CK Enterprise v{catalog['version']} · Release: {catalog['release_id']}"
                if catalog
                else "Versão ATT&CK não registrada no escopo histórico."
            )
            for line in execution_summary_lines(run):
                add(line)
            add("Resultados técnicos", heading)
            for execution in run["executions"]:
                result = execution.get("result") or {}
                add(f"{execution['test_id']} · {result.get('outcome', 'NOT_TESTED')}", heading)
                add(f"Estado do teste: {execution['state']}")
                add(result.get("reason", "Sem conclusão registrada."))
                add(f"Evidências correlacionadas: {len(execution.get('evidence', []))}.")
            add("Recomendações", heading)
            for recommendation in report["recommendations"]:
                add(recommendation)
        elif report["kind"] == "coverage":
            metrics = report["metrics"]
            add("Cobertura no recorte selecionado", heading)
            add(
                f"{metrics['total_runs']} execuções; {metrics['completed_tests']} testes concluídos; "
                f"{metrics['outcomes'].get('DETECTED', 0)} detectados em "
                f"{metrics['valid_tests']} testes válidos."
            )
            add(f"Snapshot UTC: {metrics['snapshot_at']}")
            add(metrics["denominator"])
            for outcome, count in sorted(metrics["outcomes"].items()):
                add(f"{outcome}: {count}")
        else:
            comparison, summary = report["comparison"], report["summary"]
            add("Comparação entre execuções", heading)
            add(
                "Mesmo escopo concluído e contexto registrado."
                if comparison["comparable"]
                else "Comparabilidade não confirmada; revisar diferenças e contextos desconhecidos."
            )
            add(f"Anterior: {comparison['before_id']} · Atual: {comparison['after_id']}")
            add(
                f"Testes válidos: {summary['before']['valid_tests']} antes / "
                f"{summary['after']['valid_tests']} depois."
            )
            delta = summary["detected_rate_delta_percentage_points"]
            add(f"Delta em pontos percentuais: {delta if delta is not None else 'não calculado'}.")
            add(summary["denominator"])
            for test in comparison["tests"]:
                add(f"{test['test_id']}: {test['before']} → {test['after']}")
        add("Integridade e interpretação", heading)
        add("SHA256 do relatório JSON completo: " + source_hash)
        add(
            (
                "SHA256 do conteúdo da execução: "
                if "run" in report
                else "SHA256 do documento sem integrity_sha256: "
            )
            + report["integrity_sha256"]
        )
        add(
            "Esses hashes identificam conteúdo JSON, não os bytes deste PDF; não são assinaturas "
            "digitais. O apêndice preserva o relatório completo. Caracteres sem glifo e controles "
            "são exibidos como escapes Unicode. JSON é a referência para processamento automático."
        )
        story.extend([PageBreak()])
        add("Apêndice técnico · Escopo e evidências completos", heading)
        add(
            "Conteúdo JSON completo, sem truncamento; quebras de linha podem ser acrescentadas pelo layout."
        )
        # Preformatted is plain text, with no Paragraph parser or evaluation.
        lines = []
        for line in raw.splitlines():
            lines.extend(
                textwrap.wrap(
                    line,
                    width=98,
                    expand_tabs=False,
                    replace_whitespace=False,
                    drop_whitespace=False,
                    break_on_hyphens=False,
                )
                or [""]
            )
        story.append(Preformatted("\n".join(lines), code))
        story.append(Spacer(1, 8))
        output = BytesIO()
        document = SimpleDocTemplate(
            output,
            pagesize=A4,
            leftMargin=42,
            rightMargin=42,
            topMargin=53,
            bottomMargin=45,
            title="ÆGIS · Validação de detecção",
            author="ÆGIS",
            subject="Relatório com escopo, evidências e limitações",
            creator="AEGIS PDF exporter/1",
            invariant=1,
            pageCompression=1,
        )
        document.build(story, onFirstPage=page, onLaterPages=page)
        result = output.getvalue()
        if len(result) > MAX_OUTPUT_BYTES or time.monotonic() - started > MAX_SECONDS:
            raise PDFExportError("pdf_output_or_time_limit")
        return result
