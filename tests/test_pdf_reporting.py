"""Parse actual generated PDFs, including hostile text and bounded failure paths."""

from copy import deepcopy
from io import BytesIO

import pytest
from aegis import pdf_reporting as pdf
from aegis.domain.validation import digest
from aegis.reporting import build_comparison_report, build_coverage_report, build_report
from pypdf import PdfReader


@pytest.fixture
def report():
    return build_report(
        {
            "id": "fixture-run",
            "synthetic": True,
            "state": "COMPLETED",
            "campaign_name": "Validação de detecção ÆGIS",
            "objective": "Conferir evidências e limitações sem inferir proteção empresarial.",
            "created_at": "2026-11-05T12:00:00+00:00",
            "scope": {"environment_version": 1},
            "executions": [
                {
                    "test_id": "demo-shell",
                    "state": "COMPLETED",
                    "result": {"outcome": "DETECTED", "reason": "Alerta sintético correlacionado."},
                    "evidence": [{"event_id": "original-event-42", "sha256": "e" * 64}],
                    "events": [{"raw": {"marker": "aegis-run-marker"}}],
                }
            ],
        }
    )


def parsed(report):
    data = pdf.PDFReportExporter().export(report)
    assert data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")
    reader = PdfReader(BytesIO(data), strict=True)
    return data, reader, "\n".join(page.extract_text() for page in reader.pages)


def test_pdf_contains_full_evidence_hashes_accents_and_synthetic_notice_on_every_page(report):
    before = deepcopy(report)
    data, reader, text = parsed(report)
    assert len(reader.pages) >= 2
    assert "Validação de detecção ÆGIS" in text
    assert "original-event-42" in text and "aegis-run-marker" in text and "e" * 64 in text
    assert digest(report) in text and report["integrity_sha256"] in text
    assert "não são assinaturas" in text
    assert all("DADOS SINTÉTICOS" in page.extract_text() for page in reader.pages)
    assert "não valida proteção de ambiente real" in text
    assert report == before
    # Stable PDF metadata/font subsets for a fixed source; no new generation timestamp.
    assert pdf.PDFReportExporter().export(report) == data
    assert "/OpenAction" not in reader.trailer["/Root"]
    assert all("/Annots" not in page for page in reader.pages)


def test_user_markup_urls_expressions_and_unsupported_unicode_are_only_visible_text(
    report, monkeypatch
):
    import reportlab.lib.rl_safe_eval as evaluator
    import reportlab.lib.utils as utils

    def denied(*args, **kwargs):
        pytest.fail("No user-resource fetching or expression evaluation")

    monkeypatch.setattr(utils, "open_for_read", denied)
    monkeypatch.setattr(evaluator, "rl_safe_eval", denied)
    report["run"]["campaign_name"] = (
        '<img src="file:///sensitive-sentinel"><font color="[[danger]]">& conteúdo ✅ \u202e'
    )
    report["run"]["executions"][0]["events"][0]["raw"]["url"] = "https://invalid.example/pixel"
    report = build_report(report["run"])
    _, reader, text = parsed(report)
    assert '<img src="file:///sensitive-sentinel">' in text
    assert '<font color="[[danger]]">' in text
    assert "\\u2705" in text and "\\u202e" in text
    assert "invalid.example/pixel" in text
    assert all("/Annots" not in page for page in reader.pages)


@pytest.mark.parametrize("kind", ["coverage", "comparison", "mixed", "real"])
def test_other_report_types_preserve_unknown_comparability_and_source_notices(report, kind):
    if kind in {"comparison", "mixed"}:
        second = deepcopy(report)
        second["synthetic"] = kind != "mixed"
        second["run"]["state"] = "CREATED"
        comparison = {
            "comparable": False,
            "before_id": "before",
            "after_id": "after",
            "tests": [
                {
                    "test_id": "demo-shell",
                    "before": "DETECTED",
                    "after": "NOT_TESTED",
                    "changed": True,
                }
            ],
            "limitation": "Sem equivalência confirmada.",
        }
        selected = build_comparison_report(comparison, report, second)
    elif kind == "coverage":
        selected = build_coverage_report(
            {
                "synthetic": True,
                "limitation": "Recorte sintético.",
                "total_runs": 0,
                "completed_tests": 0,
                "valid_tests": 0,
                "outcomes": {},
                "denominator": "DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY",
                "snapshot_at": "2026-11-05T12:00:00Z",
                "selection": {"mode": "demo"},
            }
        )
    else:
        source = deepcopy(report["run"])
        source["synthetic"] = False
        selected = build_report(source)
    _, reader, text = parsed(selected)
    assert selected["integrity_sha256"] in text and digest(selected) in text
    if kind in {"comparison", "mixed"}:
        assert "Comparabilidade não confirmada" in text and "não calculado" in text
    if kind == "mixed":
        assert all("ESCOPO MISTO" in page.extract_text() for page in reader.pages)
    if kind == "real":
        assert all("LABORATÓRIO REAL" in page.extract_text() for page in reader.pages)
        assert "SIEM não consultado" in text


def test_source_integrity_and_size_are_checked_before_rendering(report, monkeypatch):
    changed = deepcopy(report)
    changed["run"]["objective"] = "adulterado"
    with pytest.raises(pdf.PDFExportError, match="integrity"):
        pdf.PDFReportExporter().export(changed)
    monkeypatch.setattr(pdf, "MAX_SOURCE_BYTES", 10)
    with pytest.raises(pdf.PDFExportError, match="source_limit"):
        pdf.PDFReportExporter().export(report)


@pytest.mark.parametrize("limit", ["MAX_PAGES", "MAX_OUTPUT_BYTES", "MAX_SECONDS"])
def test_limits_refuse_partial_documents_and_release_renderer(report, monkeypatch, limit):
    with monkeypatch.context() as patch:
        patch.setattr(pdf, limit, 0)
        with pytest.raises(pdf.PDFExportError, match="limit"):
            pdf.PDFReportExporter().export(report)
    parsed(report)


def test_busy_renderer_is_explicit_and_never_queues_another_pdf(report):
    with pdf._RENDER_LOCK:
        with pytest.raises(pdf.PDFBusyError):
            pdf.PDFReportExporter().export(report)
    parsed(report)
