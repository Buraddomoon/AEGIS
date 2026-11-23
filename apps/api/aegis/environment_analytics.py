"""Bounded two-laboratory projection, materialized in one analytical transaction."""

import json
from datetime import datetime
from typing import Literal

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select

from aegis import analytics
from aegis import environment_comparison as domain
from aegis.domain.validation import digest
from aegis.models import (
    CampaignRun,
    DetectionEvidence,
    Laboratory,
    TelemetryEvent,
    ValidationResult,
)
from aegis.models import TestExecution as Execution
from aegis.queries import record
from aegis.reporting import seal_analysis

MAX_RUNS = 100
MAX_EXECUTIONS = 1000
MAX_EVENTS = 5000
MAX_BYTES = 2 * 1024 * 1024
LAB_PATTERN = r"^[a-f0-9-]{36}$"


class PairQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    before_laboratory_id: str = Field(pattern=LAB_PATTERN)
    after_laboratory_id: str = Field(pattern=LAB_PATTERN)
    before_mode: Literal["demo", "linux"]
    after_mode: Literal["demo", "linux"]
    before_catalog_release: str = Field(default="all", pattern=analytics.RELEASE_PATTERN)
    after_catalog_release: str = Field(default="all", pattern=analytics.RELEASE_PATTERN)
    before_requested_from: str | None = Field(default=None, max_length=40)
    before_requested_before: str | None = Field(default=None, max_length=40)
    after_requested_from: str | None = Field(default=None, max_length=40)
    after_requested_before: str | None = Field(default=None, max_length=40)
    format: Literal["json", "html", "pdf"] = "json"
    expected_snapshot_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    snapshot_at: AwareDatetime | None = None

    def selection(self, side):
        try:
            return analytics.Selection(
                **{
                    k: getattr(self, side + "_" + k)
                    for k in ("mode", "catalog_release", "requested_from", "requested_before")
                }
            )
        except ValidationError as error:
            raise RequestValidationError(
                [{**e, "loc": ("query", side, *e["loc"])} for e in error.errors()]
            ) from None


def limited(db, statement, maximum, noun):
    rows = list(db.scalars(statement.limit(maximum + 1)))
    if len(rows) > maximum:
        raise HTTPException(422, f"Comparação excede {maximum} {noun} por lado; reduza o recorte.")
    return rows


def project(db, pair, side):
    selection = pair.selection(side)
    lab_id = getattr(pair, side + "_laboratory_id")
    lab = db.get(Laboratory, lab_id)
    if lab is None:
        raise HTTPException(404, "Laboratório não encontrado.")
    # Historical reads remain possible for revoked labs; no activation check here.
    scope, scope_hash, _, _ = analytics.resolve(db, selection)
    scope = {**scope, "laboratory_id": lab_id}
    query = analytics.run_query(scope).where(CampaignRun.laboratory_id == lab_id)
    runs = limited(db, query, MAX_RUNS, "execuções")
    executions = limited(
        db,
        select(Execution)
        .where(Execution.run_id.in_([r.id for r in runs]))
        .order_by(Execution.run_id, Execution.test_id, Execution.id),
        MAX_EXECUTIONS,
        "testes",
    )
    ids = [e.id for e in executions]
    results = {
        r.execution_id: r
        for r in db.scalars(select(ValidationResult).where(ValidationResult.execution_id.in_(ids)))
    }
    events = limited(
        db,
        select(TelemetryEvent)
        .where(TelemetryEvent.execution_id.in_(ids))
        .order_by(TelemetryEvent.timestamp, TelemetryEvent.id),
        MAX_EVENTS,
        "eventos",
    )
    evidence = limited(
        db,
        select(DetectionEvidence)
        .where(DetectionEvidence.result_id.in_([r.id for r in results.values()]))
        .order_by(DetectionEvidence.id),
        MAX_EVENTS,
        "vínculos de evidência",
    )
    event_map, evidence_map, execution_map = {}, {}, {}
    for event in events:
        event_map.setdefault(event.execution_id, []).append(
            {
                "event_id": event.id,
                "source_id": event.source_id,
                "source": event.source,
                "timestamp": event.timestamp,
                "kind": event.kind,
                "rule_id": event.rule_id,
                "synthetic": event.synthetic,
                "sha256": event.sha256,
                "record_sha256": digest(jsonable_encoder(record(event))),
            }
        )
    for link in evidence:
        evidence_map.setdefault(link.result_id, []).append(record(link))
    for execution in executions:
        result = results.get(execution.id)
        execution_map.setdefault(execution.run_id, []).append(
            {
                "id": execution.id,
                "test_id": execution.test_id,
                "asset_id": execution.asset_id,
                "synthetic": execution.synthetic,
                "state": execution.state,
                "execution_sha256": digest(jsonable_encoder(record(execution))),
                "result": record(result) if result else None,
                "result_sha256": digest(jsonable_encoder(record(result))) if result else None,
                "events": event_map.get(execution.id, []),
                "evidence": evidence_map.get(result.id, []) if result else [],
            }
        )
    members = [
        {
            "id": r.id,
            "campaign_id": r.campaign_id,
            "laboratory_id": r.laboratory_id,
            "created_at": r.created_at,
            "synthetic": r.synthetic,
            "state": r.state,
            "scope_hash": r.scope_hash,
            "scope": r.scope,
            "executions": execution_map.get(r.id, []),
        }
        for r in runs
    ]
    return {
        **domain.cohort(members, selection.mode == "demo"),
        "laboratory_id": lab_id,
        "selection": scope,
        "selection_sha256": digest({"scope_sha256": scope_hash, "laboratory_id": lab_id}),
    }


def build(db, pair: PairQuery):
    if pair.before_laboratory_id == pair.after_laboratory_id:
        raise HTTPException(409, "Selecione dois laboratórios distintos.")
    now = db.scalar(select(func.transaction_timestamp()))
    stamp: datetime = pair.snapshot_at or now
    if stamp > now:
        raise HTTPException(422, "Snapshot não pode estar no futuro.")
    before, after = project(db, pair, "before"), project(db, pair, "after")
    report = seal_analysis(
        {
            "product": "ÆGIS",
            "report_version": "aegis-environment-comparison/1",
            "kind": "environment-comparison",
            "snapshot_at": stamp,
            "synthetic": before["synthetic"] and after["synthetic"],
            "contains_synthetic": before["synthetic"] or after["synthetic"],
            "before": before,
            "after": after,
            "comparison": domain.compare_cohorts(before, after),
            "limitations": [
                domain.LIMITATION,
                domain.DENOMINATOR,
                "Snapshot histórico materializado; exportação revalida o conteúdo inteiro e recusa drift. Hash não é assinatura.",
                "Eventos identificados por origem e hashes, sem payload bruto; somente fatos já persistidos, sem nova coleta.",
            ],
        }
    )
    if len(json.dumps(report, ensure_ascii=False).encode()) > MAX_BYTES:
        raise HTTPException(
            422, "Comparação excede 2MiB; reduza o recorte. Nenhum membro truncado."
        )
    if (
        pair.expected_snapshot_sha256
        and pair.expected_snapshot_sha256 != report["integrity_sha256"]
    ):
        raise HTTPException(
            409, "Snapshot mudou; consulte novamente os dois recortes antes de exportar."
        )
    return report
