"""Actual HTML/PDF parsers and HTTP fixtures; no native collector or database."""

from contextlib import contextmanager
from copy import deepcopy
from html.parser import HTMLParser
from io import BytesIO
from types import SimpleNamespace

import pytest
from aegis import analytics_api, api, report_downloads
from aegis.db import get_db
from aegis.domain.recommendations import analyze_recommendations
from aegis.domain.validation import digest
from aegis.main import create_app
from aegis.pdf_reporting import PDFReportExporter
from aegis.reporting import (
    HTMLReportExporter,
    build_recommendation_report,
    build_report,
    export_analysis_html,
)
from aegis.security import current_user
from fastapi.testclient import TestClient
from pypdf import PdfReader
from test_recommendations import source


@pytest.fixture
def detail():
    detail = source("OBSERVED_NOT_ALERTED")
    detail.update(
        campaign_name="Fixture offline",
        objective="Inspecionar fatos.",
        created_at="2026-11-23T12:00:00+00:00",
    )
    return detail


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.appendix = False
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "pre":
            self.appendix = True

    def handle_endtag(self, tag):
        if tag == "pre":
            self.appendix = False

    def handle_data(self, data):
        if not self.appendix:
            self.parts.append(data)


def test_separate_document_preserves_historical_bytes_and_source(detail):
    old = build_report(detail)
    original = deepcopy(detail)
    html_before = HTMLReportExporter().export(old)
    pdf_before = PDFReportExporter().export(old)
    report = build_recommendation_report(detail)
    assert report["source_snapshot"] == detail == original
    assert report["analysis"] == analyze_recommendations(detail)
    assert report["analysis"]["input_sha256"] == digest(report["source_snapshot"])
    assert report["integrity_sha256"] == digest(
        {k: v for k, v in report.items() if k != "integrity_sha256"}
    )
    assert build_report(detail) == old
    assert HTMLReportExporter().export(old) == html_before
    assert PDFReportExporter().export(old) == pdf_before


def test_html_and_pdf_present_same_actions_and_provenance_outside_appendix(detail):
    report = build_recommendation_report(detail)
    parser = Text()
    parser.feed(export_analysis_html(report))
    visible = " ".join(parser.parts)
    pdf = PDFReportExporter().export(report)
    reader = PdfReader(BytesIO(pdf), strict=True)
    pdf_text = "\n".join(page.extract_text() for page in reader.pages)
    for value in [
        report["analysis"]["policy"]["version"],
        report["analysis"]["policy_sha256"],
        report["analysis"]["input_sha256"],
        report["analysis"]["items"][0]["reason"],
        report["analysis"]["items"][0]["action"],
    ]:
        assert value in visible
        assert value in pdf_text.replace("\n", " ")
    assert "linked" in pdf_text and "a" * 64 in pdf_text
    assert all("DADOS SINTÉTICOS" in page.extract_text() for page in reader.pages)
    assert PDFReportExporter().export(report) == pdf
    assert not {"script", "img", "iframe"}.intersection(parser.tags)


def test_hostile_facts_are_text_only_and_real_origin_is_preserved(detail):
    detail["synthetic"] = False
    detail["executions"][0]["result"]["reason"] = '<script>alert("fixture")</script>'
    report = build_recommendation_report(detail)
    parser = Text()
    parser.feed(export_analysis_html(report))
    assert "script" not in parser.tags
    assert report["synthetic"] is False
    assert "LIMITAÇÕES DAS FONTES REGISTRADAS" in " ".join(parser.parts)


@pytest.fixture
def http_fixture(monkeypatch, detail):
    """Exercise routing/auth/validation with explicitly substituted storage only."""
    db = SimpleNamespace(commit=lambda: None)

    @contextmanager
    def read_snapshot(_db):
        assert _db is db
        yield db

    monkeypatch.setattr(api.analytics, "read_snapshot", read_snapshot)
    monkeypatch.setattr(api.queries, "execution_detail", lambda snapshot, run_id: deepcopy(detail))
    monkeypatch.setattr(api, "rate_limit", lambda *args: None)
    monkeypatch.setattr(analytics_api, "audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(report_downloads, "rate_limit", lambda *args: None)
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id="fixture-viewer", role="viewer"
    )
    with TestClient(app) as client:
        yield client, detail, app


@pytest.mark.parametrize("format", ["json", "html", "pdf"])
def test_http_export_matches_preview_and_preserves_source(http_fixture, format):
    client, detail, _ = http_fixture
    original = deepcopy(detail)
    preview = client.get("/api/v1/executions/fixture-run")
    assert preview.status_code == 200
    analysis = preview.json()["recommendation_analysis"]
    response = client.get(
        "/api/v1/reports/fixture-run/recommendations",
        params={"format": format, "expected_analysis_sha256": analysis["integrity_sha256"]},
    )
    assert response.status_code == 200, response.text[:200] if format != "pdf" else "PDF failed"
    if format == "json":
        assert response.json()["analysis"] == analysis
    elif format == "html":
        assert analysis["integrity_sha256"] in response.text
    else:
        text = " ".join(p.extract_text() for p in PdfReader(BytesIO(response.content)).pages)
        assert analysis["integrity_sha256"] in text
    assert detail == original


@pytest.mark.parametrize("change", ["result", "policy", "hash", "missing", "format"])
def test_http_rejects_stale_or_invalid_export(http_fixture, monkeypatch, change):
    client, detail, _ = http_fixture
    hash = client.get("/api/v1/executions/fixture-run").json()["recommendation_analysis"][
        "integrity_sha256"
    ]
    params = {"expected_analysis_sha256": hash}
    if change == "result":
        detail["executions"][0]["result"]["reason"] = "Drift"
    elif change == "policy":
        from aegis.domain import recommendations

        monkeypatch.setattr(recommendations, "POLICY_VERSION", "aegis-recommendations/next")
    elif change == "hash":
        params["expected_analysis_sha256"] = "bad"
    elif change == "missing":
        params = {}
    else:
        params["format"] = "executable"
    assert client.get("/api/v1/reports/fixture-run/recommendations", params=params).status_code == (
        409 if change in ("result", "policy") else 422
    )


def test_http_requires_authentication(http_fixture):
    client, _, app = http_fixture
    del app.dependency_overrides[current_user]
    assert (
        client.get(
            "/api/v1/reports/fixture-run/recommendations",
            params={"expected_analysis_sha256": "a" * 64},
        ).status_code
        == 401
    )
