"""Linux registration, bounded preflight and evidence persistence; no arbitrary target input."""

import hashlib
import time
from datetime import timedelta
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis import binding_review, lab_registry
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations.linux_runner import LinuxRunnerClient, RunnerConnection
from aegis.lab_runner import atomic_policy, behavior_policy
from aegis.lab_runner.protocol import TEST_ID, JobSpec, JobView
from aegis.models import (
    Approval,
    Asset,
    AuditEvent,
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
    return describe(connection())


def describe(config: RunnerConnection) -> dict:
    try:
        value = {
            "runner_id": str(config.runner_id),
            "laboratory_id": str(config.laboratory_id),
            "asset_id": str(config.asset_id),
            "url": config.url,
            "server_ca_sha256": hashlib.sha256(config.server_ca.read_bytes()).hexdigest(),
            "client_cert_sha256": hashlib.sha256(config.client_cert.read_bytes()).hexdigest(),
            "protocol": "aegis-linux-runner/1",
            "test_id": config.test_id,
        }
        if config.test_id == atomic_policy.TEST_ID:
            value["atomic_review"] = atomic_policy.review()
        elif config.test_id in behavior_policy.TEST_IDS.values():
            kind = behavior_policy.kind_for(config.test_id)
            value["behavior_review"] = behavior_policy.review(kind)
        return value
    except OSError:
        raise HTTPException(409, "Certificados públicos Linux indisponíveis.") from None


def client() -> LinuxRunnerClient:
    return LinuxRunnerClient(connection())


def configured_hash() -> str | None:
    try:
        return digest(descriptor())
    except HTTPException:
        return None


def deployment_descriptor(laboratory_id: str) -> dict:
    if settings().linux_runner_registry is None:
        value = descriptor()
    else:
        try:
            entry = lab_registry.entry_for(laboratory_id=laboratory_id)
            value = {
                **describe(entry.connection),
                "registry": lab_registry.public(entry),
            }
        except (ValueError, OSError):
            raise HTTPException(409, "Registro revisado indisponível ou inválido.") from None
    if value["laboratory_id"] != laboratory_id:
        raise HTTPException(409, "Conexão não pertence ao laboratório selecionado.")
    return value


def deployment_hash(laboratory_id: str) -> str | None:
    try:
        return digest(deployment_descriptor(laboratory_id))
    except HTTPException:
        return None


def deployment_client(laboratory_id: str) -> LinuxRunnerClient:
    if settings().linux_runner_registry is None:
        deployment_descriptor(laboratory_id)
        return client()
    try:
        return LinuxRunnerClient(lab_registry.entry_for(laboratory_id=laboratory_id).connection)
    except (ValueError, OSError):
        raise HTTPException(409, "Conexão revisada indisponível.") from None


def scoped_client(run: CampaignRun) -> LinuxRunnerClient:
    expected = run.scope["runner"]
    remote = deployment_client(run.laboratory_id)
    try:
        if (
            describe(remote.config) != {k: v for k, v in expected.items() if k != "registry"}
            or deployment_descriptor(run.laboratory_id) != expected
        ):
            raise HTTPException(409, "Conexão mudou; preservar reserva e runner original.")
        return remote
    except BaseException:
        remote.close()
        raise


def test_matches(test: TestDefinition, identity: dict) -> bool:
    if identity.get("test_id") == TEST_ID:
        return bool(
            test.id == TEST_DEFINITION_ID
            and test.platform == "Linux"
            and test.execution_kind == "linux_marker"
            and test.version == 1
            and test.behavior == "temporary-marker"
        )
    if identity.get("test_id") in behavior_policy.TEST_IDS.values():
        kind = behavior_policy.kind_for(identity["test_id"])
        profile = behavior_policy.PROFILES[kind]
        return bool(
            identity.get("behavior_review") == behavior_policy.review(kind)
            and identity["test_id"]
            == f"linux-{kind}-canary/v1@" + digest(behavior_policy.review(kind))
            and test.id == profile["definition_id"]
            and test.version == 1
            and test.behavior == profile["behavior"]
            and test.technique_id == profile["technique_id"]
            and test.platform == "Linux"
            and test.execution_kind == "linux_marker"
        )
    return bool(
        identity.get("test_id") == atomic_policy.TEST_ID
        and identity.get("atomic_review") == atomic_policy.review()
        and test.id == atomic_policy.DEFINITION_ID
        and test.version == 1
        and test.behavior == atomic_policy.BEHAVIOR
        and test.technique_id == "T1222.002"
        and test.platform == "Linux"
        and test.execution_kind == "linux_marker"
    )


def reviewed_profile_available(test: TestDefinition) -> bool:
    if test.id not in {
        atomic_policy.DEFINITION_ID,
        *(profile["definition_id"] for profile in behavior_policy.PROFILES.values()),
    }:
        return True
    try:
        if settings().linux_runner_registry is not None:
            return any(
                test_matches(test, describe(e.connection)) for e in lab_registry.load().entries
            )
        return test_matches(test, descriptor())
    except (HTTPException, ValueError, OSError):
        return False


def binding_valid(db: Session, lab: Laboratory) -> bool:
    binding = db.get(LinuxLabBinding, lab.id)
    return bool(binding and binding.configuration_hash == deployment_hash(lab.id))


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
        and latest.configuration_hash == deployment_hash(lab.id)
        and binding_valid(db, lab)
    )


def trust_status(db: Session, lab: Laboratory) -> dict | None:
    """Public fingerprints and last explicit review; no paths, keys or PKI contents."""
    if lab.kind != "linux":
        return None
    binding = db.get(LinuxLabBinding, lab.id)
    current = deployment_hash(lab.id)
    review = db.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "lab.linux_register", AuditEvent.resource_id == lab.id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    return {
        "configuration_hash": binding.configuration_hash if binding else None,
        "deployment_configuration_hash": current,
        "matches_deployment": bool(binding and current and binding.configuration_hash == current),
        "reviewed_by": binding.reviewed_by if binding else None,
        "reviewed_at": review.created_at.isoformat() if review else None,
    }


def register(db: Session, data, actor: User, *, continuity_review=None) -> Laboratory:
    entry = None
    if settings().linux_runner_registry is not None:
        try:
            if not data.registry_id or not data.confirm_registry_hash:
                raise ValueError("Seleção explícita obrigatória.")
            entry = lab_registry.entry_for(entry_id=data.registry_id)
            if lab_registry.public(entry)["review_hash"] != data.confirm_registry_hash:
                raise ValueError("Revisão mudou.")
            if data.owner != entry.owner:
                raise ValueError("Responsável difere do registro host-only.")
            identity = deployment_descriptor(str(entry.connection.laboratory_id))
            if identity["registry"]["review_hash"] != data.confirm_registry_hash:
                raise ValueError("Revisão mudou durante o cadastro.")
        except (ValueError, OSError):
            raise HTTPException(409, "Selecione a revisão atual da conexão aprovada.") from None
    else:
        if data.registry_id or data.confirm_registry_hash:
            raise HTTPException(409, "Registro opt-in ausente.")
        identity = descriptor()
    lab = db.scalar(
        select(Laboratory)
        .where(Laboratory.id == identity["laboratory_id"])
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if lab:
        if lab.kind != "linux":
            raise HTTPException(409, "Identidade pertence a outro tipo de laboratório.")
        binding_review.require_review(db, lab)
    other_asset = db.get(Asset, identity["asset_id"])
    if other_asset and (
        other_asset.laboratory_id != identity["laboratory_id"] or other_asset.synthetic
    ):
        raise HTTPException(409, "Identidade de ativo já pertence a outro escopo.")
    if continuity_review is not None:
        from aegis.lab_runner.activation_review import require_current
        from aegis.lab_runner.continuity import ContinuityError

        if lab is None:
            raise HTTPException(409, "Ativação exige o laboratório original preservado.")
        try:
            require_current(db, lab, continuity_review)
            if any(
                identity[key] != str(getattr(continuity_review.identity, key))
                for key in ("runner_id", "laboratory_id", "asset_id")
            ):
                raise ContinuityError("activation_identity_changed")
        except ContinuityError:
            raise HTTPException(
                409, "Continuidade mudou; preserve o vínculo original e revise."
            ) from None
    if lab is None:
        lab = Laboratory(
            id=identity["laboratory_id"],
            name=data.name,
            owner=data.owner,
            kind="linux",
            authorized=False,
            description="Runner Linux real: somente o teste fixo do binding revisado.",
            isolation=entry.isolation if entry else data.isolation_review,
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
        asset = db.get(Asset, identity["asset_id"])
        if (
            not asset
            or asset.laboratory_id != lab.id
            or asset.synthetic
            or asset.platform != "Linux"
        ):
            raise HTTPException(
                409, "Ativo original difere da configuração; revisão manual necessária."
            )
        lab.name, lab.owner, lab.isolation = (
            data.name,
            data.owner,
            entry.isolation if entry else data.isolation_review,
        )
        lab.environment_version += 1
    lab.authorized = False
    binding = db.get(LinuxLabBinding, lab.id)
    if binding is None:
        binding = LinuxLabBinding(laboratory_id=lab.id)
        db.add(binding)
    if entry is not None:
        binding.registry_id = entry.id
    binding.runner_id, binding.configuration_hash = identity["runner_id"], digest(identity)
    binding.reviewed_by, binding.isolation_review = actor.id, data.isolation_review
    audit(
        db,
        actor.id,
        "lab.linux_register",
        lab.id,
        configuration_hash=binding.configuration_hash,
        environment_version=lab.environment_version,
        authorized=False,
        registry=identity.get("registry"),
    )
    db.commit()
    return lab


def preflight(db: Session, lab: Laboratory, actor: User) -> LabVerification:
    if lab.kind != "linux" or not binding_valid(db, lab):
        raise HTTPException(409, "Binding Linux não corresponde à implantação revisada.")
    fingerprint, version = deployment_hash(lab.id), lab.environment_version
    success, reason = (
        False,
        "Preflight mTLS falhou; verifique runner, identidade, rede e certificados.",
    )
    remote = None
    try:
        remote = deployment_client(lab.id)
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
    # Network IO does not hold a laboratory lock. Refresh under the same lock
    # as registration before recording success, so a concurrent rotation cannot
    # publish a successful preflight for the environment it replaced.
    current = db.scalar(
        select(Laboratory)
        .where(Laboratory.id == lab.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if (
        current is None
        or current.environment_version != version
        or deployment_hash(lab.id) != fingerprint
        or not binding_valid(db, current)
    ):
        success = False
        reason = "Ambiente ou confiança mudou durante o preflight; repita a revisão atual."
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
    from aegis.identities import approval_identities_valid

    if not approval_identities_valid(db, run, approval):
        return False
    if run.synthetic:
        return True
    if run.schedule_id:
        from aegis.scheduling import authorization_valid

        if not authorization_valid(db, run, approval):
            return False
    elif approval and approval.schedule_authorization_id:
        return False
    scoped = run.scope.get("test_definitions", [])
    if len(scoped) != 1:
        return False
    test = db.get(TestDefinition, scoped[0]["id"])
    asset = db.get(Asset, run.scope.get("asset_id"))
    if (
        not test
        or not test.approved
        or test.execution_kind != "linux_marker"
        or not test_matches(test, run.scope.get("runner", {}))
        or scoped[0]["version"] != test.version
        or scoped[0]["behavior"] != test.behavior
        or not asset
        or asset.synthetic
        or asset.platform != "Linux"
        or asset.laboratory_id != run.laboratory_id
        or asset.id != run.scope.get("runner", {}).get("asset_id")
    ):
        return False
    requester = db.get(User, run.requested_by)
    approver = db.get(User, approval.approved_by) if approval else None
    lab = db.get(Laboratory, run.laboratory_id)
    from aegis.telemetry import scope_valid

    if not scope_valid(db, run):
        return False
    current_identity = None
    try:
        current_identity = deployment_descriptor(run.laboratory_id)
    except HTTPException:
        return False
    return bool(
        approval
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
        test_id=run.scope["runner"]["test_id"],
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
        if previous.sha256 != fingerprint or previous.content != content:
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
    if run.scope.get("runner") != deployment_descriptor(run.laboratory_id):
        raise HTTPException(
            409, "Configuração original mudou; recuperação manual do runner original necessária."
        )
    remote = scoped_client(run)
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
