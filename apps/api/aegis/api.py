import secrets
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from redis.exceptions import RedisError
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis import linux_labs, queries, scheduling, schemas, services, telemetry
from aegis.config import settings
from aegis.db import get_db
from aegis.domain.validation import digest
from aegis.integrations.yaml_import import parse_sigma
from aegis.models import (
    Asset,
    AttackTechnique,
    AuditEvent,
    Campaign,
    CampaignRun,
    CampaignTest,
    DetectionRule,
    Laboratory,
    LabVerification,
    LoginSession,
    RuleVersion,
    Schedule,
    ScheduleAuthorization,
    ScheduleOccurrence,
    TestDefinition,
    User,
)
from aegis.reporting import HTMLReportExporter, build_report
from aegis.security import (
    DUMMY_HASH,
    administrator,
    audit,
    create_session,
    current_user,
    hasher,
    operator,
    rate_limit,
    redis_client,
    token_hash,
    verify_password,
)

router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[User, Depends(current_user)]
Operator = Annotated[User, Depends(operator)]
Admin = Annotated[User, Depends(administrator)]
Offset = Annotated[int, Query(ge=0)]
Limit = Annotated[int, Query(ge=1, le=1000)]


@router.get("/health/live", tags=["Health"])
def live() -> dict:
    return {"status": "ok", "version": "0.2.0", "default_mode": "demo"}


@router.get("/health/ready", tags=["Health"])
def ready(db: DB, response: Response) -> dict:
    try:
        db.execute(text("SELECT 1"))
        redis_client().ping()
    except Exception:
        response.status_code = 503
        return {"status": "unavailable"}
    return {"status": "ready", "database": True, "redis": True}


@router.post("/auth/login", tags=["Identity"])
def login(data: schemas.Login, request: Request, response: Response, db: DB) -> dict:
    if request.headers.get("x-aegis-request") != "browser":
        raise HTTPException(403, "Cabeçalho de proteção do login ausente.")
    host = request.client.host if request.client else "unknown"
    rate_limit("login-ip:" + host, 40)
    rate_limit("login-account:" + data.username.lower(), 10)
    user = db.scalar(select(User).where(User.username == data.username.lower()))
    valid = verify_password(user.password_hash if user else DUMMY_HASH, data.password)
    if not user or not valid or not user.active:
        audit(db, None, "auth.failed", "login")
        db.commit()
        raise HTTPException(401, "Credenciais inválidas.")
    old_token = request.cookies.get("aegis_session")
    if old_token:
        previous = db.get(LoginSession, token_hash(old_token))
        if previous:
            db.delete(previous)
    token, csrf = create_session(db, user)
    if hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(data.password)
    audit(db, user.id, "auth.login", user.id)
    db.commit()
    options = {
        "secure": settings().secure_cookies,
        "samesite": "strict",
        "max_age": settings().session_hours * 3600,
        "path": "/",
    }
    response.set_cookie("aegis_session", token, httponly=True, **options)
    response.set_cookie("aegis_csrf", csrf, httponly=False, **options)
    return {"user": schemas.UserRead.model_validate(user).model_dump(), "csrf_token": csrf}


@router.get("/auth/me", response_model=schemas.UserRead, tags=["Identity"])
def me(user: Viewer):
    return user


@router.post("/auth/logout", status_code=204, tags=["Identity"])
def logout(user: Viewer, request: Request, response: Response, db: DB):
    db.delete(request.state.session)
    audit(db, user.id, "auth.logout", user.id)
    db.commit()
    response.delete_cookie("aegis_session", path="/")
    response.delete_cookie("aegis_csrf", path="/")


@router.get("/users", tags=["Identity"])
def users(user: Admin, db: DB, offset: Offset = 0, limit: Limit = 50) -> dict:
    items = db.scalars(select(User).order_by(User.username).offset(offset).limit(limit)).all()
    return {
        "items": [schemas.UserRead.model_validate(u).model_dump() for u in items],
        "total": db.scalar(select(func.count()).select_from(User)),
    }


@router.post("/users", response_model=schemas.UserRead, status_code=201, tags=["Identity"])
def create_user(data: schemas.UserCreate, user: Admin, db: DB):
    rate_limit("user-create:" + user.id, 30, 3600)
    if db.scalar(select(User).where(User.username == data.username.lower())):
        raise HTTPException(409, "Nome de usuário já cadastrado.")
    item = User(
        username=data.username.lower(), password_hash=hasher.hash(data.password), role=data.role
    )
    db.add(item)
    db.flush()
    audit(db, user.id, "user.create", item.id, role=item.role)
    db.commit()
    return item


@router.get("/labs", tags=["Laboratories"])
def labs(user: Viewer, db: DB) -> dict:
    items = db.scalars(select(Laboratory).order_by(Laboratory.name)).all()
    return {
        "items": [
            {
                **queries.record(lab),
                "synthetic": lab.kind == "demo",
                "active_run_state": (
                    db.get(CampaignRun, lab.active_run_id).state
                    if lab.active_run_id and db.get(CampaignRun, lab.active_run_id)
                    else None
                ),
                "connection_status": "synthetic"
                if lab.kind == "demo"
                else ("connected" if linux_labs.verified(db, lab) else "disconnected"),
                "execution_capability": "demo-only"
                if lab.kind == "demo"
                else ("linux-marker-only" if linux_labs.binding_valid(db, lab) else "disabled"),
                "telemetry_source": "aegis-demo" if lab.kind == "demo" else None,
            }
            for lab in items
        ]
    }


@router.patch("/labs/{lab_id}/authorization", tags=["Laboratories"])
def authorize_lab(lab_id: str, data: schemas.LabAuthorization, user: Admin, db: DB) -> dict:
    lab = db.scalar(select(Laboratory).where(Laboratory.id == lab_id).with_for_update())
    if not lab:
        raise HTTPException(404, "Laboratório não encontrado.")
    if lab.kind not in ("demo", "linux"):
        raise HTTPException(409, "Tipo de laboratório não suportado.")
    if lab.kind == "linux" and data.authorized and not linux_labs.verified(db, lab):
        raise HTTPException(
            409, "Autorização Linux exige binding revisado e preflight mTLS vigente."
        )
    if lab.authorized != data.authorized:
        lab.authorized = data.authorized
        if lab.kind == "demo" or not data.authorized:
            lab.environment_version += 1
        audit(
            db,
            user.id,
            "lab.authorization",
            lab.id,
            authorized=lab.authorized,
            environment_version=lab.environment_version,
        )
    db.commit()
    return queries.record(lab)


@router.post("/labs/linux/register", status_code=201, tags=["Laboratories"])
def register_linux(data: schemas.LinuxRegistration, user: Admin, db: DB) -> dict:
    rate_limit("linux-register:" + user.id, 10, 3600)
    return queries.record(linux_labs.register(db, data, user))


@router.post("/labs/{lab_id}/preflight", tags=["Laboratories"])
def preflight_linux(lab_id: str, data: schemas.Confirm, user: Admin, db: DB) -> dict:
    rate_limit("linux-preflight:" + user.id, 10, 60)
    return queries.record(
        linux_labs.preflight(db, services.get_or_404(db, Laboratory, lab_id), user)
    )


@router.get("/labs/{lab_id}/verifications", tags=["Laboratories"])
def lab_verifications(
    lab_id: str, user: Viewer, db: DB, offset: Offset = 0, limit: Limit = 25
) -> dict:
    services.get_or_404(db, Laboratory, lab_id)
    return queries.page(
        db,
        select(LabVerification)
        .where(LabVerification.laboratory_id == lab_id)
        .order_by(LabVerification.created_at.desc()),
        offset,
        limit,
    )


@router.post("/labs/{lab_id}/recover", tags=["Laboratories"])
def recover_lab(lab_id: str, data: schemas.Confirm, user: Admin, db: DB) -> dict:
    # Lock in the same order as start/cancel: run first, then laboratory.
    observed_lab = services.get_or_404(db, Laboratory, lab_id)
    observed_run_id = observed_lab.active_run_id
    run = services.locked_run(db, observed_run_id) if observed_run_id else None
    lab = db.scalar(
        select(Laboratory)
        .where(Laboratory.id == lab_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if lab.active_run_id != observed_run_id:
        raise HTTPException(409, "Reserva do laboratório mudou durante a revisão.")
    if not run or run.state != "CLEANUP_FAILED" or lab.kind not in ("demo", "linux"):
        raise HTTPException(
            409, "Recuperação disponível apenas para laboratório reservado por CLEANUP_FAILED."
        )
    if lab.kind == "linux":
        linux_labs.recover(db, run)
    lab.active_run_id = None
    audit(db, user.id, "lab.cleanup_reviewed", lab.id, run_id=run.id, synthetic=run.synthetic)
    db.commit()
    return queries.record(lab)


@router.get("/labs/{lab_id}/wazuh-binding", tags=["Integrations"])
def wazuh_binding(lab_id: str, user: Viewer, db: DB) -> dict:
    return telemetry.status(db, services.get_or_404(db, Laboratory, lab_id))


@router.put("/labs/{lab_id}/wazuh-binding", tags=["Integrations"])
def review_wazuh_binding(
    lab_id: str, data: schemas.WazuhBindingReview, user: Admin, db: DB
) -> dict:
    rate_limit("wazuh-binding:" + user.id, 10, 3600)
    lab = db.scalar(select(Laboratory).where(Laboratory.id == lab_id).with_for_update())
    if not lab:
        raise HTTPException(404, "Laboratório não encontrado.")
    return queries.record(telemetry.bind(db, lab, user, data.review))


@router.post("/labs/{lab_id}/wazuh-binding/remove", tags=["Integrations"])
def remove_wazuh_binding(lab_id: str, data: schemas.Confirm, user: Admin, db: DB) -> dict:
    lab = db.scalar(select(Laboratory).where(Laboratory.id == lab_id).with_for_update())
    if not lab:
        raise HTTPException(404, "Laboratório não encontrado.")
    telemetry.unbind(db, lab, user)
    return telemetry.status(db, lab)


@router.get("/assets", tags=["Laboratories"])
def assets(user: Viewer, db: DB) -> dict:
    return {"items": [queries.record(a) for a in db.scalars(select(Asset).order_by(Asset.name))]}


@router.get("/techniques", tags=["ATT&CK"])
def techniques(
    user: Viewer,
    db: DB,
    q: str = Query("", max_length=100),
    tactic: str | None = None,
    platform: str | None = None,
    coverage: str | None = None,
    mode: Literal["demo", "linux"] = "demo",
    offset: Offset = 0,
    limit: Limit = 50,
) -> dict:
    query = select(AttackTechnique).order_by(AttackTechnique.id)
    if q:
        query = query.where(
            AttackTechnique.name.ilike(f"%{q}%") | AttackTechnique.id.ilike(f"%{q}%")
        )
    if tactic:
        query = query.where(AttackTechnique.tactics.any(tactic))
    if platform:
        query = query.where(AttackTechnique.platforms.any(platform))
    outcomes = queries.technique_outcomes(db, mode)
    if coverage:
        ids = [key for key, value in outcomes.items() if value == coverage]
        query = query.where(
            AttackTechnique.id.not_in(outcomes)
            if coverage == "NOT_TESTED"
            else AttackTechnique.id.in_(ids)
        )
    result = queries.page(db, query, offset, limit)
    for item in result["items"]:
        item["coverage"] = outcomes.get(item["id"], "NOT_TESTED")
    return result


@router.get("/techniques/{technique_id}", tags=["ATT&CK"])
def technique_detail(
    technique_id: str, user: Viewer, db: DB, mode: Literal["demo", "linux"] = "demo"
) -> dict:
    technique = services.get_or_404(db, AttackTechnique, technique_id)
    tests = db.scalars(
        select(TestDefinition).where(
            TestDefinition.technique_id == technique_id,
            TestDefinition.execution_kind == ("demo" if mode == "demo" else "linux_marker"),
        )
    ).all()
    history = []
    for result, execution, run in queries.completed_results(db, mode):
        scoped = next(t for t in run.scope["test_definitions"] if t["id"] == execution.test_id)
        if scoped["technique_id"] == technique_id:
            history.append(
                {
                    "run_id": run.id,
                    "outcome": result.outcome,
                    "created_at": result.created_at,
                    "synthetic": run.synthetic,
                }
            )
    return {
        **queries.record(technique),
        "tests": [queries.record(t) for t in tests],
        "coverage_history": history[-30:],
        "mode": mode,
        "telemetry_sources": ["aegis-demo"] if tests else [],
        "operational_rules": [],
        "limitation": "Regras Sigma cadastradas não são regras implantadas no SIEM.",
    }


@router.get("/tests", tags=["Tests"])
def tests(user: Viewer, db: DB) -> dict:
    return {
        "items": [
            queries.record(t)
            for t in db.scalars(select(TestDefinition).order_by(TestDefinition.id))
        ]
    }


@router.get("/campaigns", tags=["Campaigns"])
def campaigns(user: Viewer, db: DB, offset: Offset = 0, limit: Limit = 50) -> dict:
    result = queries.page(db, select(Campaign).order_by(Campaign.created_at.desc()), offset, limit)
    for item in result["items"]:
        item["test_ids"] = list(
            db.scalars(select(CampaignTest.test_id).where(CampaignTest.campaign_id == item["id"]))
        )
    return result


@router.post("/campaigns", status_code=201, tags=["Campaigns"])
def create_campaign(data: schemas.CampaignCreate, user: Operator, db: DB) -> dict:
    if len(set(data.test_ids)) != len(data.test_ids):
        raise HTTPException(422, "Testes duplicados.")
    lab = services.get_or_404(db, Laboratory, data.laboratory_id)
    if not lab.authorized or lab.kind not in ("demo", "linux"):
        raise HTTPException(409, "Selecione laboratório autorizado.")
    for test_id in data.test_ids:
        test = services.get_or_404(db, TestDefinition, test_id)
        if not test.approved or test.execution_kind != (
            "demo" if lab.kind == "demo" else "linux_marker"
        ):
            raise HTTPException(409, "Teste fora da allowlist ou incompatível com laboratório.")
    campaign = Campaign(
        name=data.name, objective=data.objective, laboratory_id=lab.id, created_by=user.id
    )
    db.add(campaign)
    db.flush()
    for test_id in data.test_ids:
        db.add(CampaignTest(campaign_id=campaign.id, test_id=test_id))
    db.flush()
    services.snapshot_scope(db, campaign)
    audit(db, user.id, "campaign.create", campaign.id, test_ids=data.test_ids)
    db.commit()
    return queries.campaign_detail(db, campaign)


@router.post(
    "/campaigns/{campaign_id}/runs",
    response_model=schemas.RunRead,
    status_code=201,
    tags=["Executions"],
)
def request_run(campaign_id: str, data: schemas.RunRequest, user: Operator, db: DB):
    try:
        return services.request_run(db, campaign_id, user, data.idempotency_key)
    except IntegrityError:
        db.rollback()
        # A concurrent request may have committed the same unique key.
        return services.request_run(db, campaign_id, user, data.idempotency_key)


@router.get("/executions", tags=["Executions"])
def executions(
    user: Viewer,
    db: DB,
    state: str | None = None,
    campaign_id: str | None = None,
    mode: Literal["demo", "linux"] | None = None,
    offset: Offset = 0,
    limit: Limit = 50,
) -> dict:
    query = select(CampaignRun).order_by(CampaignRun.created_at.desc())
    if mode is not None:
        query = query.where(CampaignRun.synthetic.is_(mode == "demo"))
    if state:
        query = query.where(CampaignRun.state == state)
    if campaign_id:
        query = query.where(CampaignRun.campaign_id == campaign_id)
    return queries.page(db, query, offset, limit)


@router.get("/executions/{run_id}", tags=["Executions"])
def execution_detail(run_id: str, user: Viewer, db: DB) -> dict:
    return queries.execution_detail(db, run_id)


@router.post("/executions/{run_id}/approve", tags=["Executions"])
def approve(run_id: str, data: schemas.Approve, user: Admin, db: DB) -> dict:
    run = services.locked_run(db, run_id)
    if not secrets.compare_digest(run.scope_hash, data.confirm_scope_hash):
        raise HTTPException(409, "Hash revisado não corresponde ao escopo solicitado.")
    item = services.approve_run(
        db,
        run_id,
        user,
        data.validity_minutes,
        data.max_duration_seconds,
        confirm_real=data.confirm_real_execution,
    )
    return queries.record(item)


@router.post("/executions/{run_id}/start", response_model=schemas.RunRead, tags=["Executions"])
def start(run_id: str, data: schemas.Confirm, user: Operator, db: DB):
    return services.start_run(db, run_id, user)


@router.post("/executions/{run_id}/cancel", response_model=schemas.RunRead, tags=["Executions"])
def cancel(run_id: str, user: Operator, db: DB):
    return services.cancel_run(db, run_id, user)


@router.post("/executions/{run_id}/reject", response_model=schemas.RunRead, tags=["Executions"])
def reject(run_id: str, user: Admin, db: DB):
    return services.cancel_run(db, run_id, user, reject=True)


@router.get("/coverage", tags=["Coverage"])
def coverage(user: Viewer, db: DB, mode: Literal["demo", "linux"] = "demo") -> dict:
    return queries.coverage(db, mode)


@router.get("/schedules", tags=["Scheduling"])
def schedules(user: Viewer, db: DB, offset: Offset = 0, limit: Limit = 50) -> dict:
    return queries.page(db, select(Schedule).order_by(Schedule.created_at.desc()), offset, limit)


@router.post("/schedules", status_code=201, tags=["Scheduling"])
def create_schedule(data: schemas.ScheduleCreate, user: Operator, db: DB) -> dict:
    rate_limit("schedule-create:" + user.id, 30, 3600)
    return queries.record(scheduling.create(db, data, user))


@router.get("/schedules/{schedule_id}", tags=["Scheduling"])
def schedule_detail(schedule_id: str, user: Viewer, db: DB) -> dict:
    item = services.get_or_404(db, Schedule, schedule_id)
    grants = db.scalars(
        select(ScheduleAuthorization)
        .where(ScheduleAuthorization.schedule_id == item.id)
        .order_by(ScheduleAuthorization.created_at.desc())
    ).all()
    return {
        **queries.record(item),
        "authorizations": [queries.record(g) for g in grants],
        "plan": scheduling.plan(item),
        "synthetic": True,
    }


@router.get("/schedules/{schedule_id}/occurrences", tags=["Scheduling"])
def schedule_occurrences(
    schedule_id: str, user: Viewer, db: DB, offset: Offset = 0, limit: Limit = 50
) -> dict:
    services.get_or_404(db, Schedule, schedule_id)
    return queries.page(
        db,
        select(ScheduleOccurrence)
        .where(ScheduleOccurrence.schedule_id == schedule_id)
        .order_by(ScheduleOccurrence.scheduled_for.desc()),
        offset,
        limit,
    )


@router.post("/schedules/{schedule_id}/approve", tags=["Scheduling"])
def approve_schedule(schedule_id: str, data: schemas.ScheduleApprove, user: Admin, db: DB) -> dict:
    return queries.record(scheduling.approve(db, schedule_id, user, data.confirm_plan_hash))


@router.post("/schedules/{schedule_id}/pause", tags=["Scheduling"])
def pause_schedule(schedule_id: str, data: schemas.Confirm, user: Operator, db: DB) -> dict:
    return queries.record(scheduling.stop_schedule(db, schedule_id, user, revoke=False))


@router.post("/schedules/{schedule_id}/revoke", tags=["Scheduling"])
def revoke_schedule(schedule_id: str, data: schemas.Confirm, user: Admin, db: DB) -> dict:
    return queries.record(scheduling.stop_schedule(db, schedule_id, user, revoke=True))


@router.get("/coverage/compare", tags=["Coverage"])
def compare(before: str, after: str, user: Viewer, db: DB) -> dict:
    return queries.compare(db, before, after)


@router.get("/rules", tags=["Sigma"])
def rules(user: Viewer, db: DB, offset: Offset = 0, limit: Limit = 50) -> dict:
    result = queries.page(
        db, select(DetectionRule).order_by(DetectionRule.created_at.desc()), offset, limit
    )
    for item in result["items"]:
        item["status"] = "syntax_validated_not_deployed"
    return result


@router.get("/rules/{rule_id}/versions", tags=["Sigma"])
def rule_versions(rule_id: str, user: Viewer, db: DB) -> dict:
    services.get_or_404(db, DetectionRule, rule_id)
    return {
        "items": [
            queries.record(v)
            for v in db.scalars(
                select(RuleVersion)
                .where(RuleVersion.rule_id == rule_id)
                .order_by(RuleVersion.version.desc())
            )
        ]
    }


@router.post("/rules", status_code=201, tags=["Sigma"])
def import_rule(data: schemas.SigmaImport, user: Operator, db: DB) -> dict:
    try:
        parsed = parse_sigma(data.content)
    except Exception:
        raise HTTPException(
            422,
            "Sigma inválido. Verifique UUID, logsource, detection e condition; aliases YAML são proibidos.",
        ) from None
    if any(not db.get(AttackTechnique, t) for t in parsed["techniques"]):
        raise HTTPException(422, "Técnica referenciada não existe no catálogo ativo.")
    rule = db.scalar(
        select(DetectionRule).where(DetectionRule.sigma_id == parsed["sigma_id"]).with_for_update()
    )
    content_hash = digest(data.content)
    if not rule:
        rule = DetectionRule(title=parsed["title"], sigma_id=parsed["sigma_id"], latest_version=1)
        db.add(rule)
        db.flush()
    else:
        latest = db.scalar(
            select(RuleVersion).where(
                RuleVersion.rule_id == rule.id, RuleVersion.version == rule.latest_version
            )
        )
        if latest and latest.sha256 == content_hash:
            return {**queries.record(rule), "unchanged": True}
        rule.latest_version += 1
        rule.title = parsed["title"]
    version = RuleVersion(
        rule_id=rule.id,
        version=rule.latest_version,
        content=data.content,
        sha256=content_hash,
        techniques=parsed["techniques"],
        created_by=user.id,
    )
    db.add(version)
    audit(db, user.id, "sigma.import", rule.id, version=version.version, sha256=content_hash)
    db.commit()
    return {**queries.record(rule), "status": "syntax_validated_not_deployed"}


@router.get("/reports", tags=["Reports"])
def reports(user: Viewer, db: DB, offset: Offset = 0, limit: Limit = 50) -> dict:
    return queries.page(
        db,
        select(CampaignRun)
        .where(CampaignRun.state == "COMPLETED")
        .order_by(CampaignRun.created_at.desc()),
        offset,
        limit,
    )


@router.get("/reports/{run_id}", tags=["Reports"])
def report(run_id: str, user: Viewer, db: DB, format: Literal["json", "html"] = "json"):
    detail = queries.execution_detail(db, run_id)
    data = build_report(detail)
    audit(db, user.id, "report.export", run_id, format=format)
    db.commit()
    if format == "html":
        return HTMLResponse(
            HTMLReportExporter().export(data),
            headers={"Content-Disposition": f'attachment; filename="aegis-{detail["id"]}.html"'},
        )
    return data


@router.get("/connectors", tags=["Integrations"])
def connectors(user: Viewer) -> dict:
    try:
        worker = redis_client().get("aegis:worker:heartbeat") is not None
    except RedisError:
        worker = False
    return {
        "items": [
            {
                "id": "demo",
                "name": "Adaptador demonstrativo",
                "status": "synthetic",
                "synthetic": True,
                "description": "Eventos gerados em memória e persistidos.",
            },
            {
                "id": "wazuh",
                "name": "Wazuh Indexer",
                "synthetic": False,
                "status": "configured_unverified" if settings().wazuh_url else "disconnected",
                "description": "Somente leitura. Conexão externa ainda não validada.",
            },
        ],
        "worker_online": worker,
        "scheduling": "approved_demo_only",
        "lab_mode": "linux_opt_in" if linux_labs.configured_hash() else "not_configured",
    }


@router.post("/connectors/wazuh/test", tags=["Integrations"])
def test_wazuh(user: Admin, db: DB) -> dict:
    from aegis.integrations.wazuh import configured_provider

    rate_limit("wazuh-test:" + user.id, 5, 60)
    try:
        provider = configured_provider()
        version = provider.test_connection()
    except ValueError:
        raise HTTPException(
            409, "Wazuh não configurado: exige HTTPS, IP fixado, credenciais e CA válida."
        ) from None
    except Exception:
        raise HTTPException(
            502, "Falha na conexão Wazuh. Verifique TLS, acesso e credenciais no ambiente."
        ) from None
    audit(db, user.id, "wazuh.connection_test", "wazuh", success=True)
    db.commit()
    return {
        "status": "connected",
        "version": version,
        "scope": "indexer_read_only",
        "limitation": "Conectividade não comprova ingestão de telemetria nem detecção.",
    }


@router.get("/audit", tags=["Audit"])
def audit_events(user: Admin, db: DB, offset: Offset = 0, limit: Limit = 50) -> dict:
    return queries.page(
        db, select(AuditEvent).order_by(AuditEvent.created_at.desc()), offset, limit
    )
