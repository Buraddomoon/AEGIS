"""Authenticated analytical snapshots; exports preserve their exact scope."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from aegis import analytics, queries
from aegis.db import get_db
from aegis.models import CampaignRun, User
from aegis.reporting import (
    build_comparison_report,
    build_coverage_report,
    build_report,
    export_analysis_html,
)
from aegis.security import audit, current_user, rate_limit

router = APIRouter(prefix="/coverage", tags=["Coverage"])
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[User, Depends(current_user)]


def selection(
    mode: Literal["demo", "linux"] = "demo",
    catalog_release: str = Query("all", pattern=analytics.RELEASE_PATTERN),
    requested_from: str | None = Query(None, max_length=40),
    requested_before: str | None = Query(None, max_length=40),
):
    try:
        return analytics.Selection(
            mode=mode,
            catalog_release=catalog_release,
            requested_from=requested_from,
            requested_before=requested_before,
        )
    except ValidationError as error:
        raise RequestValidationError(
            [{**e, "loc": ("query", *e["loc"])} for e in error.errors()]
        ) from None


Scope = Annotated[analytics.Selection, Depends(selection)]
ExpectedHash = Annotated[str | None, Query(pattern=r"^[a-f0-9]{64}$")]


@router.get("")
def coverage(user: Viewer, db: DB, scope: Scope):
    with analytics.read_snapshot(db) as snapshot:
        return queries.coverage(snapshot, selection=scope)


@router.get("/runs")
def runs(
    user: Viewer,
    db: DB,
    scope: Scope,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
):
    with analytics.read_snapshot(db) as snapshot:
        resolved, scope_hash, _, _ = analytics.resolve(snapshot, scope)
        query = analytics.run_query(resolved)
        analytics.run_count(snapshot, query)
        query = query.where(CampaignRun.state == "COMPLETED")
        total = analytics.run_count(snapshot, query)
        rows = (
            snapshot.execute(
                query.with_only_columns(
                    CampaignRun.id,
                    CampaignRun.campaign_id,
                    CampaignRun.created_at,
                    CampaignRun.synthetic,
                    CampaignRun.state,
                )
                .offset(offset)
                .limit(limit)
            )
            .mappings()
            .all()
        )
        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
            "scope_sha256": scope_hash,
            "selection": resolved,
        }


def deliver(db, user, report, format):
    audit(
        db,
        user.id,
        "report.analysis.export",
        report["integrity_sha256"],
        kind=report["kind"],
        format=format,
    )
    db.commit()
    if format == "html":
        return HTMLResponse(
            export_analysis_html(report),
            headers={
                "Content-Disposition": f'attachment; filename="aegis-{report["kind"]}-{report["integrity_sha256"][:16]}.html"'
            },
        )
    return report


@router.get("/report")
def coverage_report(
    user: Viewer,
    db: DB,
    scope: Scope,
    format: Literal["json", "html"] = "json",
    expected_scope_sha256: ExpectedHash = None,
):
    rate_limit("analysis-report:" + user.id, 30, 60)
    with analytics.read_snapshot(db) as snapshot:
        metrics = queries.coverage(snapshot, selection=scope, include_members=True)
        if expected_scope_sha256 and expected_scope_sha256 != metrics["scope_sha256"]:
            raise HTTPException(
                409, "Referência do recorte mudou; recarregue os indicadores antes de exportar."
            )
        report = build_coverage_report(metrics)
    return deliver(db, user, report, format)


@router.get("/compare")
def compare(before: str, after: str, user: Viewer, db: DB):
    with analytics.read_snapshot(db) as snapshot:
        return queries.compare(snapshot, before, after)


@router.get("/compare/report")
def comparison_report(
    before: str, after: str, user: Viewer, db: DB, format: Literal["json", "html"] = "json"
):
    rate_limit("analysis-report:" + user.id, 30, 60)
    with analytics.read_snapshot(db) as snapshot:
        comparison = queries.compare(snapshot, before, after)
        report = build_comparison_report(
            comparison,
            build_report(queries.execution_detail(snapshot, before)),
            build_report(queries.execution_detail(snapshot, after)),
        )
    return deliver(db, user, report, format)
