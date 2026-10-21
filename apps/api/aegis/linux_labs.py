"""Linux registration, bounded preflight and evidence persistence; no arbitrary target input."""

import hashlib
import time
from datetime import timedelta
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations.linux_runner import LinuxRunnerClient, RunnerConnection
from aegis.lab_runner.protocol import TEST_ID, JobSpec, JobView
from aegis.models import (
    Approval,
    Asset,
    CampaignRun,
    Laboratory,
    LabVerification,
    LinuxLabBinding,
    RunnerCleanup,
    RunnerDispatch,
    RunnerReceipt,
    TestDefinition,
    TestExecution,
    User,
    now,
)
from aegis.security import audit

TEST_DEFINITION_ID = "linux-file-marker-v1"


def connection() -> RunnerConnection:
    path = settings().linux_runner_config
    if path is None:
        raise HTTPException(409, "Runner Linux desconectado: configuração opt-in ausente.")
    try:
        return RunnerConnection.model_validate_json(path.read_bytes())
    except Exception:
        raise HTTPException(
            409, "Configuração Linux inválida ou inacessível na implantação."
        ) from None


def descriptor() -> dict:
    config = connection()
    try:
        return {
            "runner_id": str(config.runner_id),
            "laboratory_id": str(config.laboratory_id),
            "asset_id": str(config.asset_id),
            "url": config.url,
            "server_ca_sha256": hashlib.sha256(config.server_ca.read_bytes()).hexdigest(),
            "client_cert_sha256": hashlib.sha256(config.client_cert.read_bytes()).hexdigest(),
            "protocol": "aegis-linux-runner/1",
            "test_id": TEST_ID,
        }
    except OSError:
        raise HTTPException(409, "Certificados públicos Linux indisponíveis.") from None


def client() -> LinuxRunnerClient:
    return LinuxRunnerClient(connection())


def configured_hash() -> str | None:
    try:
        return digest(descriptor())
    except HTTPException:
        return None


def binding_valid(db: Session, lab: Laboratory) -> bool:
    binding = db.get(LinuxLabBinding, lab.id)
    return bool(binding and binding.configuration_hash == configured_hash())


def verified(db: Session, lab: Laboratory) -> bool:
    latest = db.scalar(
        select(LabVerification)
        .where(LabVerification.laboratory_id == lab.id)
        .order_by(LabVerification.created_at.desc(), LabVerification.id.desc())
        .limit(1)
    )
    return bool(
        latest
        and latest.success
        and latest.expires_at > now()
        and latest.environment_version == lab.environment_version
        and latest.configuration_hash == configured_hash()
        and binding_valid(db, lab)
    )


def register(db: Session, data, actor: User) -> Laboratory:
    identity = descriptor()
    lab = db.scalar(
        select(Laboratory).where(Laboratory.id == identity["laboratory_id"]).with_for_update()
    )
    if lab and (lab.kind != "linux" or lab.active_run_id):
        raise HTTPException(409, "Identidade já utilizada ou laboratório reservado.")
    if lab is None:
        lab = Laboratory(
            id=identity["laboratory_id"],
            name=data.name,
            owner=data.owner,
            kind="linux",
            authorized=False,
            description="Runner Linux real: somente marcador benigno revisado.",
            isolation=data.isolation_review,
        )
        db.add(lab)
        db.flush()
        db.add(
            Asset(
                id=identity["asset_id"],
                laboratory_id=lab.id,
                name="endpoint-linux-marker",
                platform="Linux",
                external_id=identity["asset_id"],
                synthetic=False,
            )
        )
    else:
        if lab.authorized:
            raise HTTPException(409, "Revogue a autorização antes de revisar o binding.")
        asset = db.get(Asset, identity["asset_id"])
        if not asset or asset.laboratory_id != lab.id or asset.synthetic:
            raise HTTPException(
                409, "Ativo original difere da configuração; revisão manual necessária."
            )
        lab.name, lab.owner, lab.isolation = data.name, data.owner, data.isolation_review
        lab.environment_version += 1
    binding = db.get(LinuxLabBinding, lab.id)
    if binding is None:
        binding = LinuxLabBinding(laboratory_id=lab.id)
        db.add(binding)
    binding.runner_id, binding.configuration_hash = identity["runner_id"], digest(identity)
    binding.reviewed_by, binding.isolation_review = actor.id, data.isolation_review
    audit(db, actor.id, "lab.linux_register", lab.id, configuration_hash=binding.configuration_hash)
    db.commit()
    return lab


def preflight(db: Session, lab: Laboratory, actor: User) -> LabVerification:
    if lab.kind != "linux" or not binding_valid(db, lab):
        raise HTTPException(409, "Binding Linux não corresponde à implantação revisada.")
    fingerprint, version = configured_hash(), lab.environment_version
    success, reason = (
        False,
        "Preflight mTLS falhou; verifique runner, identidade, rede e certificados.",
    )
    remote = None
    try:
        remote = client()
        identity = remote.preflight()
        success = str(identity.laboratory_id) == lab.id
        if success:
            reason = (
                "mTLS, identidade e allowlist confirmados; não houve execução nem consulta SIEM."
            )
    except Exception:
        pass  # Never persist raw TLS/config errors or private material.
    finally:
        if remote:
            remote.close()
    verification = LabVerification(
        laboratory_id=lab.id,
        checked_by=actor.id,
        configuration_hash=fingerprint,
        environment_version=version,
        success=success,
        expires_at=now() + timedelta(minutes=5),
        reason=reason,
    )
    db.add(verification)
    audit(db, actor.id, "lab.preflight", lab.id, success=success, configuration_hash=fingerprint)
    db.commit()
    return verification


def approval_valid(db: Session, run: CampaignRun, approval: Approval | None) -> bool:
    if run.synthetic:
        return True
    test = db.get(TestDefinition, TEST_DEFINITION_ID)
    asset = db.get(Asset, run.scope.get("asset_id"))
    scoped = run.scope.get("test_definitions", [])
    if (
        not test
        or not test.approved
        or test.execution_kind != "linux_marker"
        or len(scoped) != 1
        or scoped[0]["id"] != TEST_DEFINITION_ID
        or scoped[0]["version"] != test.version
        or scoped[0]["behavior"] != test.behavior
        or not asset
        or asset.synthetic
        or asset.laboratory_id != run.laboratory_id
        or asset.id != run.scope.get("runner", {}).get("asset_id")
    ):
        return False
    requester = db.get(User, run.requested_by)
    approver = db.get(User, approval.approved_by) if approval else None
    lab = db.get(Laboratory, run.laboratory_id)
    current_identity = None
    try:
        current_identity = descriptor()
    except HTTPException:
        return False
    return bool(
        not run.schedule_id
        and approval
        and requester
        and requester.active
        and requester.role in ("operator", "administrator")
        and approver
        and approver.active
        and approver.role == "administrator"
        and approver.id != requester.id
        and approval.expires_at > now()
        and lab
        and lab.kind == "linux"
        and binding_valid(db, lab)
        and run.scope.get("runner") == current_identity
    )


def ensure_dispatch(db: Session, run: CampaignRun, item: TestExecution) -> RunnerDispatch:
    spec = JobSpec(
        job_id=item.id,
        laboratory_id=run.laboratory_id,
        asset_id=item.asset_id,
        runner_id=run.scope["runner"]["runner_id"],
        marker=item.marker,
        scope_hash=run.scope_hash,
        deadline_at=run.deadline_at,
    )
    value = spec.model_dump(mode="json")
    db.execute(
        insert(RunnerDispatch)
        .values(execution_id=item.id, spec=value, spec_hash=digest(value))
        .on_conflict_do_nothing(index_elements=["execution_id"])
    )
    stored = db.scalar(select(RunnerDispatch).where(RunnerDispatch.execution_id == item.id))
    if stored.spec != value or stored.spec_hash != digest(value):
        raise ValueError("Dispatch histórico não corresponde ao escopo; não repetir.")
    return stored


def persist_view(db: Session, execution_id: str, view: JobView) -> None:
    stored = db.scalar(
        select(RunnerDispatch).where(RunnerDispatch.execution_id == execution_id).with_for_update()
    )
    if (
        not stored
        or stored.spec_hash != view.spec_hash
        or stored.spec != view.spec.model_dump(mode="json")
    ):
        raise ValueError("Comprovante não corresponde ao dispatch persistido.")
    generation = str(view.generation)
    if stored.generation and stored.generation != generation:
        raise ValueError("Geração mudou; manter quarentena.")
    stored.generation = generation
    for model, content in (
        (
            RunnerReceipt,
            view.receipt.model_dump(mode="json") if view.receipt else None,
        ),
        (RunnerCleanup, view.model_dump(mode="json") if view.cleanup_state == "CLEANED" else None),
    ):
        if content is None:
            continue
        fingerprint = digest(content)
        db.execute(
            insert(model)
            .values(execution_id=execution_id, content=content, sha256=fingerprint)
            .on_conflict_do_nothing(index_elements=["execution_id"])
        )
        previous = db.scalar(select(model).where(model.execution_id == execution_id))
        if previous.sha256 != fingerprint:
            raise ValueError("Registro histórico imutável divergiu; revisão necessária.")
    if view.state == "SUCCEEDED" and view.receipt:
        item = db.get(TestExecution, execution_id)
        item.executed, item.started_at, item.ended_at = (
            True,
            view.receipt.started_at,
            view.receipt.ended_at,
        )


def recover(db: Session, run: CampaignRun) -> None:
    """Cleanup only; never prepare/start. Caller owns run -> laboratory locks."""
    items = db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)).all()
    dispatches = [
        (item, db.scalar(select(RunnerDispatch).where(RunnerDispatch.execution_id == item.id)))
        for item in items
    ]
    if not any(dispatch for _, dispatch in dispatches):
        return  # No durable intent means no remote preparation was permitted.
    if run.scope.get("runner") != descriptor():
        raise HTTPException(
            409, "Configuração original mudou; recuperação manual do runner original necessária."
        )
    remote = client()
    try:
        remote.preflight()
        for item, dispatch in dispatches:
            if not dispatch:
                continue  # No durable intent => no prepare RPC was permitted.
            spec = JobSpec.model_validate(dispatch.spec)
            view = remote.get(
                spec, generation=UUID(dispatch.generation) if dispatch.generation else None
            )
            if view.state == "RUNNING":
                remote.action(view, "cancel")
                end = time.monotonic() + 4
                while view.state == "RUNNING" and time.monotonic() < end:
                    time.sleep(0.1)
                    view = remote.get(
                        spec, generation=UUID(dispatch.generation) if dispatch.generation else None
                    )
            view = remote.action(view, "cleanup")
            if view.cleanup_state != "CLEANED":
                raise ValueError("Cleanup não confirmado.")
            persist_view(db, item.id, view)
    except Exception:
        raise HTTPException(
            409, "Cleanup real não confirmado; reserva mantida. Inspecione o runner original."
        ) from None
    finally:
        remote.close()
