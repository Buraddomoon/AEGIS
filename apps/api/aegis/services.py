from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import linux_labs, rule_links, telemetry
from aegis.catalog import store as catalog
from aegis.domain.states import TERMINAL, State, check_transition
from aegis.domain.validation import LOGIC_VERSION, digest
from aegis.models import (
    Approval,
    Asset,
    Campaign,
    CampaignRun,
    CampaignTest,
    DetectionRule,
    ExecutionStep,
    Laboratory,
    TestDefinition,
    TestExecution,
    User,
    now,
    uid,
)
from aegis.security import audit


def get_or_404(db: Session, model, identifier: str):
    item = db.get(model, identifier)
    if item is None:
        raise HTTPException(404, "Recurso não encontrado.")
    return item


def move(
    db: Session, run: CampaignRun, new: str, message: str, execution: TestExecution | None = None
) -> None:
    entity = execution or run
    check_transition(entity.state, new)
    entity.state = new
    db.add(
        ExecutionStep(
            run_id=run.id,
            execution_id=execution.id if execution else None,
            state=new,
            message=message,
        )
    )
    audit(db, None, "execution.transition", entity.id, state=new, message=message)


def snapshot_scope(db: Session, campaign: Campaign) -> dict:
    try:
        catalog_reference = catalog.reference(db)
    except catalog.CatalogError as error:
        raise HTTPException(409, str(error)) from None
    lab = get_or_404(db, Laboratory, campaign.laboratory_id)
    if not lab.authorized or lab.kind not in ("demo", "linux"):
        raise HTTPException(409, "Laboratório não autorizado ou modo de execução indisponível.")
    tests = db.scalars(
        select(TestDefinition)
        .join(CampaignTest, TestDefinition.id == CampaignTest.test_id)
        .where(CampaignTest.campaign_id == campaign.id)
        .order_by(TestDefinition.id)
    ).all()
    if not tests or any(not t.approved for t in tests):
        raise HTTPException(409, "Campanha vazia ou teste fora da allowlist.")
    synthetic = lab.kind == "demo"
    if any(t.execution_kind != ("demo" if synthetic else "linux_marker") for t in tests):
        raise HTTPException(409, "Teste incompatível com o modo do laboratório.")
    try:
        techniques = catalog.scope_techniques(
            db, catalog_reference, [t.technique_id for t in tests if t.technique_id]
        )
    except catalog.CatalogError as error:
        raise HTTPException(409, str(error)) from None
    if not synthetic and (
        len(tests) != 1
        or tests[0].id != linux_labs.TEST_DEFINITION_ID
        or not linux_labs.verified(db, lab)
    ):
        raise HTTPException(409, "Linux exige teste fixo revisado e preflight vigente do binding.")
    asset = db.scalar(
        select(Asset).where(Asset.laboratory_id == lab.id, Asset.synthetic.is_(synthetic))
    )
    if not asset:
        raise HTTPException(409, "Ativo autorizado do laboratório não está cadastrado.")
    if not synthetic and asset.id != linux_labs.descriptor()["asset_id"]:
        raise HTTPException(409, "Ativo não corresponde ao runner revisado.")
    scope = {
        "campaign_id": campaign.id,
        "laboratory_id": lab.id,
        "environment_version": lab.environment_version,
        "asset_id": asset.id,
        "mode": lab.kind,
        "synthetic": synthetic,
        "logic_version": LOGIC_VERSION,
        "attack_catalog": catalog_reference,
        "attack_techniques": techniques,
        "clock_skew_seconds": 5,
        "ingestion_window_seconds": 120,
        "test_definitions": [
            {
                "id": t.id,
                "name": t.name,
                "version": t.version,
                "technique_id": t.technique_id,
                "behavior": t.behavior,
                "expected_rule": t.expected_rule,
                "demo_outcome": t.demo_outcome,
                "cleanup": t.cleanup,
                "execution_kind": t.execution_kind,
            }
            for t in tests
        ],
        "rule_versions": {r.id: r.latest_version for r in db.scalars(select(DetectionRule))},
        "rule_test_links": rule_links.snapshot_links(db, [t.id for t in tests]),
    }
    if not synthetic:
        scope["runner"] = linux_labs.descriptor()
        scope["telemetry"] = telemetry.scope_for(db, lab, asset)
        if scope["telemetry"]["provider"] == "wazuh-indexer":
            policy = scope["telemetry"]["policy"]
            scope["clock_skew_seconds"] = policy["clock_skew_seconds"]
            scope["ingestion_window_seconds"] = policy["ingestion_window_seconds"]
            scope["test_definitions"][0]["expected_rule"] = policy["expected_rule"]
    return scope


def request_run(
    db: Session, campaign_id: str, actor: User, key: str, *, commit: bool = True
) -> CampaignRun:
    existing = db.scalar(
        select(CampaignRun).where(
            CampaignRun.requested_by == actor.id, CampaignRun.idempotency_key == key
        )
    )
    if existing:
        if existing.campaign_id != campaign_id:
            raise HTTPException(409, "Chave de idempotência já usada em outra campanha.")
        return existing
    campaign = get_or_404(db, Campaign, campaign_id)
    if get_or_404(db, Laboratory, campaign.laboratory_id).kind == "linux":
        # Serialize creation with revocation/rebinding. Refresh the identity map:
        # a scope read before the administrator's lock must not survive it.
        db.scalar(
            select(Laboratory)
            .where(Laboratory.id == campaign.laboratory_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    scope = snapshot_scope(db, campaign)
    run = CampaignRun(
        id=uid(),
        campaign_id=campaign.id,
        laboratory_id=campaign.laboratory_id,
        requested_by=actor.id,
        idempotency_key=key,
        scope=scope,
        scope_hash=digest(scope),
        state=State.CREATED,
        synthetic=scope["synthetic"],
    )
    db.add(run)
    db.flush()
    move(db, run, State.PENDING_APPROVAL, "Solicitação criada; aguardando aprovação explícita.")
    for test in scope["test_definitions"]:
        execution = TestExecution(
            id=uid(),
            run_id=run.id,
            test_id=test["id"],
            asset_id=scope["asset_id"],
            marker="aegis-" + uid(),
            state=State.CREATED,
            synthetic=scope["synthetic"],
        )
        db.add(execution)
        db.flush()
        move(db, run, State.PENDING_APPROVAL, "Incluído no escopo solicitado.", execution)
    audit(db, actor.id, "run.request", run.id, scope_hash=run.scope_hash, synthetic=run.synthetic)
    db.commit() if commit else db.flush()
    return run


def locked_run(db: Session, run_id: str) -> CampaignRun:
    run = db.scalar(select(CampaignRun).where(CampaignRun.id == run_id).with_for_update())
    if not run:
        raise HTTPException(404, "Execução não encontrada.")
    return run


def approve_run(
    db: Session,
    run_id: str,
    actor: User,
    minutes: int,
    duration: int,
    *,
    confirm_real: bool = False,
) -> Approval:
    run = locked_run(db, run_id)
    if run.state != State.PENDING_APPROVAL:
        raise HTTPException(409, "Execução não aguarda aprovação.")
    if db.scalar(select(Approval).where(Approval.run_id == run.id)):
        raise HTTPException(409, "Já existe uma aprovação; crie nova solicitação se expirou.")
    if not run.synthetic and (not confirm_real or actor.id == run.requested_by):
        raise HTTPException(
            409, "Linux exige confirmação real e administrador diferente do solicitante."
        )
    fresh = snapshot_scope(db, get_or_404(db, Campaign, run.campaign_id))
    if digest(fresh) != run.scope_hash:
        raise HTTPException(409, "Escopo mudou; crie uma nova solicitação.")
    approval = Approval(
        run_id=run.id,
        approved_by=actor.id,
        scope_hash=run.scope_hash,
        expires_at=now() + timedelta(minutes=minutes),
        max_duration_seconds=duration,
    )
    db.add(approval)
    audit(
        db,
        actor.id,
        "run.approve",
        run.id,
        scope_hash=run.scope_hash,
        minutes=minutes,
        max_duration_seconds=duration,
        max_uses=1,
    )
    db.commit()
    return approval


def start_run(
    db: Session, run_id: str, actor: User, *, commit: bool = True, at: datetime | None = None
) -> CampaignRun:
    instant = at or now()
    run = locked_run(db, run_id)
    # Repeated starts do not consume a new approval or create duplicate jobs.
    if run.state in {
        State.QUEUED,
        State.PREPARING,
        State.RUNNING,
        State.COLLECTING,
        State.VALIDATING,
        State.CLEANING_UP,
        State.COMPLETED,
    }:
        return run
    if run.state != State.PENDING_APPROVAL:
        raise HTTPException(409, "Estado não permite início.")
    approval = db.scalar(select(Approval).where(Approval.run_id == run.id).with_for_update())
    if not approval or approval.used_at or approval.expires_at <= instant:
        raise HTTPException(409, "Aprovação ausente, consumida ou expirada.")
    lab = db.scalar(select(Laboratory).where(Laboratory.id == run.laboratory_id).with_for_update())
    if lab.active_run_id:
        raise HTTPException(409, "Laboratório já possui execução em andamento.")
    fresh = snapshot_scope(db, get_or_404(db, Campaign, run.campaign_id))
    if digest(fresh) != run.scope_hash or approval.scope_hash != run.scope_hash:
        raise HTTPException(409, "Configuração mudou após revisão; solicite nova execução.")
    if not linux_labs.approval_valid(db, run, approval):
        raise HTTPException(409, "Autorização Linux ou identidades deixaram de ser válidas.")
    approval.used_at = instant
    lab.active_run_id = run.id
    # Absolute queue+execution deadline prevents indefinitely reserved laboratories.
    run.deadline_at = min(
        instant + timedelta(seconds=approval.max_duration_seconds), approval.expires_at
    )
    move(db, run, State.QUEUED, "Aprovação consumida; execução persistida na fila transacional.")
    for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
        move(db, run, State.QUEUED, "Teste enfileirado.", item)
    audit(db, actor.id, "run.start", run.id, approval_id=approval.id)
    db.commit() if commit else db.flush()
    return run


def release_lab(db: Session, run: CampaignRun) -> None:
    lab = db.scalar(select(Laboratory).where(Laboratory.id == run.laboratory_id).with_for_update())
    if lab and lab.active_run_id == run.id:
        lab.active_run_id = None


def cancel_run(
    db: Session, run_id: str, actor: User, reject: bool = False, *, commit: bool = True
) -> CampaignRun:
    run = locked_run(db, run_id)
    if run.state in TERMINAL:
        raise HTTPException(409, "Execução já finalizada.")
    if reject and run.state != State.PENDING_APPROVAL:
        raise HTTPException(409, "Só é possível rejeitar solicitações pendentes.")
    run.cancel_requested = True
    if run.state in {State.PENDING_APPROVAL, State.QUEUED}:
        target = State.REJECTED if reject else State.CANCELLED
        move(
            db,
            run,
            target,
            "Solicitação rejeitada." if reject else "Cancelado antes da preparação.",
        )
        run.ended_at = now()
        for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
            move(db, run, target, "Nenhum efeito foi iniciado.", item)
            item.ended_at = now()
        release_lab(db, run)
    audit(db, actor.id, "run.reject" if reject else "run.cancel", run.id)
    db.commit() if commit else db.flush()
    return run
