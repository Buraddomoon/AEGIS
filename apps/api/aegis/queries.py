from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import Session

from aegis.domain.validation import Outcome
from aegis.models import (
    Approval,
    AttackTechnique,
    Campaign,
    CampaignRun,
    CampaignTest,
    DetectionEvidence,
    ExecutionStep,
    TelemetryEvent,
    TestExecution,
    ValidationResult,
)
from aegis.services import get_or_404


def record(entity) -> dict:
    # Never use on User or LoginSession: explicit DTOs omit credential material.
    return {
        column.key: getattr(entity, column.key) for column in inspect(entity).mapper.column_attrs
    }


def page(db: Session, query, offset: int, limit: int) -> dict:
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    return {
        "items": [record(x) for x in db.scalars(query.offset(offset).limit(limit))],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


def campaign_detail(db: Session, campaign: Campaign) -> dict:
    return {
        **record(campaign),
        "test_ids": list(
            db.scalars(select(CampaignTest.test_id).where(CampaignTest.campaign_id == campaign.id))
        ),
    }


def execution_detail(db: Session, run_id: str) -> dict:
    run = get_or_404(db, CampaignRun, run_id)
    approval = db.scalar(select(Approval).where(Approval.run_id == run_id))
    items = []
    for execution in db.scalars(
        select(TestExecution).where(TestExecution.run_id == run_id).order_by(TestExecution.test_id)
    ):
        result = db.scalar(
            select(ValidationResult).where(ValidationResult.execution_id == execution.id)
        )
        events = db.scalars(
            select(TelemetryEvent)
            .where(TelemetryEvent.execution_id == execution.id)
            .order_by(TelemetryEvent.timestamp)
        ).all()
        evidence = (
            db.scalars(
                select(DetectionEvidence).where(DetectionEvidence.result_id == result.id)
            ).all()
            if result
            else []
        )
        items.append(
            {
                **record(execution),
                "result": record(result) if result else None,
                "events": [record(e) for e in events],
                "evidence": [record(e) for e in evidence],
            }
        )
    steps = db.scalars(
        select(ExecutionStep)
        .where(ExecutionStep.run_id == run_id)
        .order_by(ExecutionStep.created_at, ExecutionStep.id)
    ).all()
    campaign = get_or_404(db, Campaign, run.campaign_id)
    return {
        **record(run),
        "campaign_name": campaign.name,
        "objective": campaign.objective,
        "approval": record(approval) if approval else None,
        "executions": items,
        "steps": [record(s) for s in steps],
    }


def completed_results(db: Session):
    return db.execute(
        select(ValidationResult, TestExecution, CampaignRun)
        .join(TestExecution, ValidationResult.execution_id == TestExecution.id)
        .join(CampaignRun, CampaignRun.id == TestExecution.run_id)
        .where(CampaignRun.state == "COMPLETED", TestExecution.state == "COMPLETED")
        .order_by(CampaignRun.created_at)
    ).all()


def coverage(db: Session) -> dict:
    rows = completed_results(db)
    counts = Counter(row[0].outcome for row in rows)
    valid = sum(
        counts[k] for k in [Outcome.DETECTED, Outcome.OBSERVED_NOT_ALERTED, Outcome.NO_TELEMETRY]
    )
    tested = {
        t["technique_id"]
        for _, execution, run in rows
        for t in run.scope["test_definitions"]
        if t["id"] == execution.test_id and t["technique_id"]
    }
    trend = {}
    for result, _execution, run in rows:
        bucket = trend.setdefault(
            run.id, {"run_id": run.id, "date": run.created_at, "detected": 0, "evaluated": 0}
        )
        bucket["detected"] += int(result.outcome == Outcome.DETECTED)
        bucket["evaluated"] += 1
    return {
        "synthetic": True,
        "scope": "Demo Lab • execuções concluídas • todas as datas",
        "catalogued_techniques": db.scalar(select(func.count()).select_from(AttackTechnique)),
        "evaluated_techniques": len(tested),
        "total_runs": db.scalar(select(func.count()).select_from(CampaignRun)),
        "completed_tests": len(rows),
        "valid_tests": valid,
        "outcomes": dict(counts),
        "detected_percentage": round(counts[Outcome.DETECTED] / valid * 100, 1) if valid else None,
        "denominator": "DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY, somente testes com execução concluída; INCONCLUSIVE e EXECUTION_FAILED excluídos",
        "limitation": "Percentual deste escopo de testes sintéticos; não representa proteção da organização.",
        "trend": list(trend.values())[-30:],
    }


def technique_outcomes(db: Session) -> dict[str, str]:
    result = {}
    for verdict, execution, run in completed_results(db):
        test = next(t for t in run.scope["test_definitions"] if t["id"] == execution.test_id)
        if test["technique_id"]:
            result[test["technique_id"]] = verdict.outcome
    return result


def compare(db: Session, before_id: str, after_id: str) -> dict:
    before, after = execution_detail(db, before_id), execution_detail(db, after_id)
    if before["campaign_id"] != after["campaign_id"]:
        from fastapi import HTTPException

        raise HTTPException(409, "Selecione execuções da mesma campanha.")
    previous = {item["test_id"]: item for item in before["executions"]}
    rows = []
    for item in after["executions"]:
        old = previous.get(item["test_id"], {}).get("result")
        new = item.get("result")
        rows.append(
            {
                "test_id": item["test_id"],
                "before": old["outcome"] if old else "NOT_TESTED",
                "after": new["outcome"] if new else "NOT_TESTED",
                "changed": (old or {}).get("outcome") != (new or {}).get("outcome"),
            }
        )
    comparable = (
        before["scope"] == after["scope"] and before["state"] == after["state"] == "COMPLETED"
    )
    return {
        "before_id": before_id,
        "after_id": after_id,
        "synthetic": True,
        "comparable": comparable,
        "same_scope": before["scope_hash"] == after["scope_hash"],
        "before_scope": before["scope"],
        "after_scope": after["scope"],
        "tests": rows,
        "limitation": "Resultados demonstrativos. Mudanças de ambiente, versões de regras ou testes exigem revisão da comparabilidade.",
    }
