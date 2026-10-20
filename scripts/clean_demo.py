"""Delete ONLY synthetic campaign data; preserve identities, catalog and audit."""

from aegis.db import session_factory
from aegis.models import (
    Approval,
    Campaign,
    CampaignRun,
    CampaignTest,
    DetectionEvidence,
    ExecutionStep,
    Laboratory,
    TelemetryEvent,
    TestExecution,
    ValidationResult,
)
from aegis.security import audit
from sqlalchemy import delete, select

if input("Excluir campanhas e resultados do Demo Lab? Digite LIMPAR DEMO: ") != "LIMPAR DEMO":
    raise SystemExit("Nenhum dado alterado.")
with session_factory()() as db:
    labs = db.scalars(select(Laboratory).where(Laboratory.kind == "demo").with_for_update()).all()
    if any(lab.active_run_id for lab in labs):
        raise SystemExit("Há laboratório reservado; cancele/finalize as execuções primeiro.")
    lab_ids = [lab.id for lab in labs]
    campaigns = list(db.scalars(select(Campaign.id).where(Campaign.laboratory_id.in_(lab_ids))))
    runs = list(
        db.scalars(
            select(CampaignRun.id).where(
                CampaignRun.campaign_id.in_(campaigns), CampaignRun.synthetic.is_(True)
            )
        )
    )
    executions = list(db.scalars(select(TestExecution.id).where(TestExecution.run_id.in_(runs))))
    results = list(
        db.scalars(select(ValidationResult.id).where(ValidationResult.execution_id.in_(executions)))
    )
    for model, condition in [
        (DetectionEvidence, DetectionEvidence.result_id.in_(results)),
        (ValidationResult, ValidationResult.id.in_(results)),
        (TelemetryEvent, TelemetryEvent.execution_id.in_(executions)),
        (ExecutionStep, ExecutionStep.run_id.in_(runs)),
        (TestExecution, TestExecution.id.in_(executions)),
        (Approval, Approval.run_id.in_(runs)),
        (CampaignRun, CampaignRun.id.in_(runs)),
        (CampaignTest, CampaignTest.campaign_id.in_(campaigns)),
        (Campaign, Campaign.id.in_(campaigns)),
    ]:
        db.execute(delete(model).where(condition))
    audit(db, None, "demo.cleanup", "demo", campaigns=len(campaigns), runs=len(runs))
    db.commit()
    print(
        f"{len(campaigns)} campanha(s) e {len(runs)} execução(ões) sintéticas excluídas; auditoria preservada."
    )
