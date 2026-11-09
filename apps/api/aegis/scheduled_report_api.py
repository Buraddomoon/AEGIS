"""Authenticated downloads of frozen automatic snapshots; never generate a job here."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis import analytics, services
from aegis.db import get_db
from aegis.domain.validation import digest
from aegis.models import Schedule, ScheduledReport, User
from aegis.report_downloads import pdf_download
from aegis.reporting import HTMLReportExporter, export_analysis_html
from aegis.security import audit, current_user, rate_limit

router = APIRouter(prefix="/schedules", tags=["Reports"])
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[User, Depends(current_user)]


def metadata(item: ScheduledReport) -> dict:
    return {
        key: getattr(item, key)
        for key in (
            "id",
            "created_at",
            "schedule_id",
            "authorization_id",
            "occurrence_id",
            "run_id",
            "previous_run_id",
            "kind",
            "state",
            "attempts",
            "next_attempt_at",
            "error_code",
            "document_sha256",
            "generated_at",
        )
    } | {"synthetic": True}


@router.get("/{schedule_id}/reports")
def list_reports(
    schedule_id: str,
    user: Viewer,
    db: DB,
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
):
    with analytics.read_snapshot(db) as snapshot:
        services.get_or_404(snapshot, Schedule, schedule_id)
        query = select(ScheduledReport).where(ScheduledReport.schedule_id == schedule_id)
        total = snapshot.scalar(select(func.count()).select_from(query.subquery()))
        rows = snapshot.scalars(
            query.order_by(ScheduledReport.created_at.desc(), ScheduledReport.id.desc())
            .offset(offset)
            .limit(limit)
        )
        return {
            "items": [metadata(item) for item in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
            "schedule_id": schedule_id,
        }


def checked_document(item: ScheduledReport) -> dict:
    document = item.document
    if (
        not isinstance(document, dict)
        or document.get("synthetic") is not True
        or digest(document) != item.document_sha256
    ):
        raise HTTPException(409, "Integridade do relatório automático não confirmada.")
    expected = {
        "report_id": item.id,
        "kind": item.kind,
        "schedule_id": item.schedule_id,
        "authorization_id": item.authorization_id,
        "occurrence_id": item.occurrence_id,
        "run_id": item.run_id,
        "previous_run_id": item.previous_run_id,
    }
    automation = document.get("automation")
    if not isinstance(automation, dict) or any(
        key not in automation or automation[key] != value for key, value in expected.items()
    ):
        raise HTTPException(409, "Contexto do relatório automático não confirmado.")
    if item.kind == "BASELINE":
        source = document.get("run")
        valid = (
            isinstance(source, dict)
            and source.get("id") == item.run_id
            and digest(source) == document.get("integrity_sha256")
        )
    else:
        comparison = document.get("comparison")
        valid = (
            isinstance(comparison, dict)
            and comparison.get("before_id") == item.previous_run_id
            and comparison.get("after_id") == item.run_id
            and digest({key: value for key, value in document.items() if key != "integrity_sha256"})
            == document.get("integrity_sha256")
        )
    if not valid:
        raise HTTPException(409, "Integridade do conteúdo do relatório automático não confirmada.")
    return document


@router.get(
    "/{schedule_id}/reports/{report_id}", responses={200: {"content": {"application/pdf": {}}}}
)
def download_report(
    schedule_id: str,
    report_id: str,
    user: Viewer,
    db: DB,
    format: Literal["json", "html", "pdf"] = "json",
    expected_sha256: str | None = Query(None, pattern=r"^[a-f0-9]{64}$"),
):
    rate_limit("analysis-report:" + user.id, 30, 60)
    with analytics.read_snapshot(db) as snapshot:
        item = services.get_or_404(snapshot, ScheduledReport, report_id)
        if item.schedule_id != schedule_id:
            raise HTTPException(404, "Relatório não encontrado neste agendamento.")
        if item.state != "READY":
            raise HTTPException(
                409, "Relatório automático ainda não está pronto; consulte o estado da solicitação."
            )
        if expected_sha256 is not None and item.document_sha256 != expected_sha256:
            raise HTTPException(409, "Referência do relatório mudou; recarregue a lista.")
        document = checked_document(item)
        filename = f"aegis-auto-{item.document_sha256[:16]}.{format}"
        identifier, kind = item.id, item.kind
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-AEGIS-Report-SHA256": digest(document),
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    if format == "pdf":
        response = pdf_download(document, filename, user.id)
    elif format == "html":
        content = (
            HTMLReportExporter().export(document)
            if kind == "BASELINE"
            else export_analysis_html(document)
        )
        response = HTMLResponse(content, headers=headers)
    else:
        response = JSONResponse(document, headers=headers)
    audit(
        db,
        user.id,
        "report.scheduled.export",
        identifier,
        format=format,
        kind=kind,
        document_sha256=digest(document),
    )
    db.commit()
    return response
