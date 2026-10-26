from collections import Counter

from fastapi.encoders import jsonable_encoder
from sqlalchemy import func, select
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import Session

from aegis import analytics
from aegis.catalog import store as catalog
from aegis.domain.validation import Outcome, digest
from aegis.models import (
    Approval,
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


def completed_results(db: Session, mode: str | None = None, run_ids=None):
    query = (
        select(ValidationResult, TestExecution, CampaignRun)
        .join(TestExecution, ValidationResult.execution_id == TestExecution.id)
        .join(CampaignRun, CampaignRun.id == TestExecution.run_id)
        .where(CampaignRun.state == "COMPLETED", TestExecution.state == "COMPLETED")
        .order_by(CampaignRun.created_at, CampaignRun.id, TestExecution.id)
    )
    if mode is not None:
        query = query.where(CampaignRun.synthetic.is_(mode == "demo"))
    if run_ids is not None:
        query = query.where(CampaignRun.id.in_(run_ids))
    return db.execute(query).all()


def coverage(db: Session, mode: str = "demo", selection=None, include_members=False) -> dict:
    selection = selection or analytics.Selection(mode=mode)
    scope, scope_hash, current, active_ids = analytics.resolve(db, selection)
    runs = analytics.bounded_runs(db, scope)
    rows = completed_results(db, selection.mode, [r.id for r in runs])
    counts = Counter(row[0].outcome for row in rows)
    valid_outcomes = {Outcome.DETECTED, Outcome.OBSERVED_NOT_ALERTED, Outcome.NO_TELEMETRY}
    valid = sum(counts[k] for k in valid_outcomes)
    historical_tested = {
        t["technique_id"]
        for _, execution, run in rows
        for t in run.scope["test_definitions"]
        if t["id"] == execution.test_id and t["technique_id"]
    }
    evaluated_catalog = scope["evaluation_catalog"]
    tested = {
        t["technique_id"]
        for _, execution, run in rows
        if evaluated_catalog
        and run.scope.get("attack_catalog", {}).get("release_id") == evaluated_catalog["release_id"]
        for t in run.scope["test_definitions"]
        if t["id"] == execution.test_id and t["technique_id"] in active_ids
    }
    trend = {}
    for result, _execution, run in rows:
        bucket = trend.setdefault(
            run.id,
            {"run_id": run.id, "date": run.created_at, "detected": 0, "evaluated": 0, "valid": 0},
        )
        bucket["detected"] += int(result.outcome == Outcome.DETECTED)
        bucket["evaluated"] += 1
        bucket["valid"] += int(result.outcome in valid_outcomes)
    data = {
        "synthetic": selection.mode == "demo",
        "mode": selection.mode,
        "scope": ("Demo Lab" if selection.mode == "demo" else "Laboratórios Linux reais")
        + " • período pela data da solicitação • releases: "
        + selection.catalog_release,
        "selection": scope,
        "scope_sha256": scope_hash,
        "snapshot_at": db.scalar(select(func.transaction_timestamp())),
        "catalogued_techniques": len(active_ids) if active_ids is not None else None,
        "evaluated_techniques": len(tested) if active_ids is not None else None,
        "historical_evaluated_techniques": len(historical_tested),
        "attack_catalog": current,
        "technique_coverage_scope": "Técnicas ativas do catálogo de referência, avaliadas nessa mesma release dentro do recorte. Legado não recebe contexto retroativo.",
        "total_runs": len(runs),
        "run_states": dict(Counter(r.state for r in runs)),
        "unversioned_runs": sum(
            not r.scope.get("attack_catalog", {}).get("release_id") for r in runs
        ),
        "completed_tests": len(rows),
        "valid_tests": valid,
        "outcomes": dict(counts),
        "detected_percentage": round(counts[Outcome.DETECTED] / valid * 100, 1) if valid else None,
        "denominator": "DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY; somente runs e filhos COMPLETED dentro deste modo/período/release. INCONCLUSIVE e EXECUTION_FAILED excluídos; estados das runs informados separadamente",
        "limitation": "Percentual somente deste recorte de testes; não representa proteção da organização. Comprovantes de execução não são detecções.",
        "trend": list(trend.values())[-30:],
    }
    if include_members:
        results = {}
        for result, execution, run in rows:
            results.setdefault(run.id, []).append(
                {
                    "execution_id": execution.id,
                    "test_id": execution.test_id,
                    "result_id": result.id,
                    "outcome": result.outcome,
                    "result_sha256": digest(jsonable_encoder(record(result))),
                }
            )
        data["members"] = [
            {
                "run_id": r.id,
                "campaign_id": r.campaign_id,
                "state": r.state,
                "created_at": r.created_at,
                "scope_sha256": r.scope_hash,
                "catalog_release_id": r.scope.get("attack_catalog", {}).get("release_id"),
                "results": results.get(r.id, []),
            }
            for r in runs
        ]
    return data


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
    if before_id == after_id:
        from fastapi import HTTPException

        raise HTTPException(409, "Selecione duas execuções diferentes.")
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
    changes = scope_changes(before["scope"], after["scope"])
    reasons = []
    if before["scope"] != after["scope"]:
        reasons.append("scope_changed")
    if before["state"] != "COMPLETED" or after["state"] != "COMPLETED":
        reasons.append("incomplete_runs")
    if not changes["catalog_context_recorded"]:
        reasons.append("unknown_catalog_context")
    if not changes["link_context_recorded"]:
        reasons.append("unknown_rule_link_context")
    comparable = not reasons
    return {
        "before_id": before_id,
        "after_id": after_id,
        "synthetic": before["synthetic"] and after["synthetic"],
        "mode": before["scope"]["mode"],
        "comparable": comparable,
        "same_scope": before["scope_hash"] == after["scope_hash"],
        "before_scope": before["scope"],
        "after_scope": after["scope"],
        "scope_changes": changes,
        "comparability_reasons": reasons,
        "tests": rows,
        "limitation": "Mudanças de ambiente, versões de regras ou testes exigem revisão da comparabilidade. Recibos do executor não comprovam detecção defensiva.",
    }
