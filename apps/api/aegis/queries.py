from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import Session

from aegis.catalog import store as catalog
from aegis.domain.validation import Outcome
from aegis.models import (
    Approval,
    AttackTechnique,
    Campaign,
    CampaignRun,
    CampaignTest,
    DetectionEvidence,
    ExecutionStep,
    RunnerCleanup,
    RunnerDispatch,
    RunnerReceipt,
    Schedule,
    ScheduleAuthorization,
    ScheduleOccurrence,
    TelemetryCollection,
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
                **{
                    name: (record(value) if value else None)
                    for name, model in [
                        ("collection", TelemetryCollection),
                        ("runner_dispatch", RunnerDispatch),
                        ("runner_receipt", RunnerReceipt),
                        ("runner_cleanup", RunnerCleanup),
                    ]
                    for value in [
                        db.scalar(select(model).where(model.execution_id == execution.id))
                    ]
                },
            }
        )
    steps = db.scalars(
        select(ExecutionStep)
        .where(ExecutionStep.run_id == run_id)
        .order_by(ExecutionStep.created_at, ExecutionStep.id)
    ).all()
    campaign = get_or_404(db, Campaign, run.campaign_id)
    occurrence = db.scalar(select(ScheduleOccurrence).where(ScheduleOccurrence.run_id == run.id))
    scheduled_plan, grant = None, None
    if run.schedule_id and approval and approval.schedule_authorization_id:
        from aegis.scheduling import plan

        schedule = get_or_404(db, Schedule, run.schedule_id)
        scheduled_plan = {**plan(schedule), "plan_hash": schedule.plan_hash}
        grant = db.get(ScheduleAuthorization, approval.schedule_authorization_id)
    return {
        **record(run),
        "campaign_name": campaign.name,
        "objective": campaign.objective,
        "approval": record(approval) if approval else None,
        "schedule_occurrence": record(occurrence) if occurrence else None,
        "schedule_plan": scheduled_plan,
        "schedule_authorization": record(grant) if grant else None,
        "executions": items,
        "steps": [record(s) for s in steps],
    }


def completed_results(db: Session, mode: str | None = None):
    query = (
        select(ValidationResult, TestExecution, CampaignRun)
        .join(TestExecution, ValidationResult.execution_id == TestExecution.id)
        .join(CampaignRun, CampaignRun.id == TestExecution.run_id)
        .where(CampaignRun.state == "COMPLETED", TestExecution.state == "COMPLETED")
        .order_by(CampaignRun.created_at)
    )
    if mode is not None:
        query = query.where(CampaignRun.synthetic.is_(mode == "demo"))
    return db.execute(query).all()


def coverage(db: Session, mode: str = "demo") -> dict:
    current = catalog.reference(db)
    rows = completed_results(db, mode)
    counts = Counter(row[0].outcome for row in rows)
    valid = sum(
        counts[k] for k in [Outcome.DETECTED, Outcome.OBSERVED_NOT_ALERTED, Outcome.NO_TELEMETRY]
    )
    historical_tested = {
        t["technique_id"]
        for _, execution, run in rows
        for t in run.scope["test_definitions"]
        if t["id"] == execution.test_id and t["technique_id"]
    }
    active_ids = set(
        db.scalars(
            select(AttackTechnique.id).where(
                AttackTechnique.present_in_current,
                ~AttackTechnique.revoked,
                ~AttackTechnique.deprecated,
            )
        )
    )
    tested = {
        t["technique_id"]
        for _, execution, run in rows
        if run.scope.get("attack_catalog", {}).get("release_id") == current["release_id"]
        for t in run.scope["test_definitions"]
        if t["id"] == execution.test_id and t["technique_id"] in active_ids
    }
    trend = {}
    for result, _execution, run in rows:
        bucket = trend.setdefault(
            run.id, {"run_id": run.id, "date": run.created_at, "detected": 0, "evaluated": 0}
        )
        bucket["detected"] += int(result.outcome == Outcome.DETECTED)
        bucket["evaluated"] += 1
    return {
        "synthetic": mode == "demo",
        "mode": mode,
        "scope": ("Demo Lab" if mode == "demo" else "Laboratórios Linux reais")
        + " • execuções concluídas • todas as datas e releases",
        "catalogued_techniques": len(active_ids),
        "evaluated_techniques": len(tested),
        "historical_evaluated_techniques": len(historical_tested),
        "attack_catalog": current,
        "technique_coverage_scope": "Somente técnicas ativas avaliadas na mesma release atual; histórico legado não é reclassificado.",
        "total_runs": db.scalar(
            select(func.count())
            .select_from(CampaignRun)
            .where(CampaignRun.synthetic.is_(mode == "demo"))
        ),
        "completed_tests": len(rows),
        "valid_tests": valid,
        "outcomes": dict(counts),
        "detected_percentage": round(counts[Outcome.DETECTED] / valid * 100, 1) if valid else None,
        "denominator": "DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY, testes concluídos no modo selecionado em todas as releases; INCONCLUSIVE e EXECUTION_FAILED excluídos",
        "limitation": "Percentual somente deste modo e escopo de testes; não representa proteção da organização. Comprovantes de execução não são detecções.",
        "trend": list(trend.values())[-30:],
    }


def technique_outcomes(db: Session, mode: str = "demo") -> dict[str, str]:
    current = catalog.reference(db)
    result = {}
    for verdict, execution, run in completed_results(db, mode):
        if run.scope.get("attack_catalog", {}).get("release_id") != current["release_id"]:
            continue
        test = next(t for t in run.scope["test_definitions"] if t["id"] == execution.test_id)
        if test["technique_id"]:
            result[test["technique_id"]] = verdict.outcome
    return result


def scope_changes(before: dict, after: dict) -> dict:
    def differences(old: dict, new: dict) -> list[dict]:
        return [
            {"key": key, "before": old.get(key), "after": new.get(key)}
            for key in sorted(old.keys() | new.keys())
            if old.get(key) != new.get(key)
        ]

    recorded = "rule_test_links" in before and "rule_test_links" in after
    environment_keys = (
        "laboratory_id",
        "environment_version",
        "asset_id",
        "mode",
        "synthetic",
        "runner",
        "telemetry",
        "logic_version",
        "clock_skew_seconds",
        "ingestion_window_seconds",
        "attack_catalog",
        "attack_techniques",
    )
    return {
        "rule_versions": differences(
            before.get("rule_versions", {}), after.get("rule_versions", {})
        ),
        "test_definitions": differences(
            {t["id"]: t for t in before["test_definitions"]},
            {t["id"]: t for t in after["test_definitions"]},
        ),
        "environment": differences(
            {k: before.get(k) for k in environment_keys},
            {k: after.get(k) for k in environment_keys},
        ),
        "link_context_recorded": recorded,
        "catalog_context_recorded": "attack_catalog" in before and "attack_catalog" in after,
        "rule_test_links": differences(
            {f"{x['rule_id']}:{x['test_id']}": x for x in before["rule_test_links"]},
            {f"{x['rule_id']}:{x['test_id']}": x for x in after["rule_test_links"]},
        )
        if recorded
        else None,
    }


def compare(db: Session, before_id: str, after_id: str) -> dict:
    before, after = execution_detail(db, before_id), execution_detail(db, after_id)
    if before["campaign_id"] != after["campaign_id"]:
        from fastapi import HTTPException

        raise HTTPException(409, "Selecione execuções da mesma campanha.")
    previous = {item["test_id"]: item for item in before["executions"]}
    current = {item["test_id"]: item for item in after["executions"]}
    rows = []
    for test_id in sorted(previous.keys() | current.keys()):
        old = previous.get(test_id, {}).get("result")
        new = current.get(test_id, {}).get("result")
        rows.append(
            {
                "test_id": test_id,
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
        "synthetic": before["synthetic"] and after["synthetic"],
        "mode": before["scope"]["mode"],
        "comparable": comparable,
        "same_scope": before["scope_hash"] == after["scope_hash"],
        "before_scope": before["scope"],
        "after_scope": after["scope"],
        "scope_changes": scope_changes(before["scope"], after["scope"]),
        "tests": rows,
        "limitation": "Mudanças de ambiente, versões de regras ou testes exigem revisão da comparabilidade. Recibos do executor não comprovam detecção defensiva.",
    }
