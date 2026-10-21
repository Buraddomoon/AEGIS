"""Approved telemetry binding and persisted collection; never runs an offensive action."""

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db import session_factory
from aegis.domain.contracts import Collection, ExecutionContext
from aegis.domain.validation import digest
from aegis.integrations.wazuh import configured_provider
from aegis.integrations.wazuh_config import WazuhCollectionConfig, configured_hash, descriptor
from aegis.integrations.wazuh_polling import WazuhPollingProvider
from aegis.models import (
    Asset,
    CampaignRun,
    Laboratory,
    TelemetryCollection,
    User,
    WazuhBinding,
    now,
)
from aegis.security import audit


class UnavailableProvider:
    def collect(self, context: ExecutionContext) -> Collection:
        return Collection(
            (),
            False,
            False,
            False,
            "SIEM não consultado; binding Wazuh revisado ausente ou indisponível.",
        )


def binding(db: Session, lab_id: str) -> WazuhBinding | None:
    return db.scalar(select(WazuhBinding).where(WazuhBinding.laboratory_id == lab_id))


def status(db: Session, lab: Laboratory) -> dict:
    item = binding(db, lab.id)
    try:
        proposed = descriptor()
    except (ValueError, OSError):
        proposed = None
    fingerprint = digest(proposed) if proposed else None
    return {
        "configuration_available": bool(proposed and proposed["policy"]["laboratory_id"] == lab.id),
        "proposed_policy": proposed["policy"]
        if proposed and proposed["policy"]["laboratory_id"] == lab.id
        else None,
        "status": "unbound"
        if not item
        else (
            "reviewed_unverified"
            if item.configuration_hash == fingerprint
            else "configuration_changed"
        ),
        "binding": {
            "id": item.id,
            "asset_id": item.asset_id,
            "agent_id": item.agent_id,
            "expected_rule": item.expected_rule,
            "configuration_hash": item.configuration_hash,
            "schema_id": item.schema_id,
            "review": item.review,
        }
        if item
        else None,
        "limitation": "Revisão de configuração não comprova conectividade, ingestão ou detecção. Credenciais são somente da implantação.",
    }


def bind(db: Session, lab: Laboratory, actor: User, review: str) -> WazuhBinding:
    if lab.kind != "linux" or lab.authorized or lab.active_run_id:
        raise HTTPException(409, "Binding exige Linux Lab revogado e sem reserva.")
    try:
        value = descriptor()
    except (ValueError, OSError):
        raise HTTPException(
            409, "Política Wazuh/HTTPS/IP/credenciais/CA inválidos ou ausentes na implantação."
        ) from None
    policy = WazuhCollectionConfig.model_validate(value["policy"])
    asset = db.get(Asset, str(policy.asset_id))
    if (
        str(policy.laboratory_id) != lab.id
        or not asset
        or asset.synthetic
        or asset.laboratory_id != lab.id
    ):
        raise HTTPException(409, "Política Wazuh difere do laboratório/ativo Linux cadastrado.")
    item = binding(db, lab.id)
    if item is None:
        item = WazuhBinding(laboratory_id=lab.id)
        db.add(item)
    item.asset_id, item.agent_id, item.expected_rule = (
        asset.id,
        policy.agent_id,
        policy.expected_rule,
    )
    item.configuration_hash, item.schema_id = digest(value), policy.schema_id
    item.reviewed_by, item.review = actor.id, review
    lab.environment_version += 1
    audit(
        db,
        actor.id,
        "wazuh.binding_reviewed",
        lab.id,
        configuration_hash=item.configuration_hash,
        agent_id=item.agent_id,
    )
    db.commit()
    return item


def unbind(db: Session, lab: Laboratory, actor: User):
    if lab.authorized or lab.active_run_id:
        raise HTTPException(
            409, "Revogue o laboratório e conclua cleanup antes de remover binding."
        )
    item = binding(db, lab.id)
    if item:
        db.delete(item)
        lab.environment_version += 1
        audit(
            db,
            actor.id,
            "wazuh.binding_removed",
            lab.id,
            configuration_hash=item.configuration_hash,
        )
    db.commit()


def scope_for(db: Session, lab: Laboratory, asset: Asset) -> dict:
    item = binding(db, lab.id)
    if item is None:
        return {"provider": "unavailable"}
    try:
        value = descriptor()
    except (ValueError, OSError):
        raise HTTPException(
            409, "Configuração Wazuh revisada indisponível; revise o binding."
        ) from None
    if item.asset_id != asset.id or item.configuration_hash != digest(value):
        raise HTTPException(409, "Binding Wazuh mudou; revise antes de solicitar execução.")
    return {**value, "binding_id": item.id, "configuration_hash": item.configuration_hash}


def scope_valid(db: Session, run: CampaignRun) -> bool:
    planned = run.scope.get("telemetry", {})
    if planned.get("provider") != "wazuh-indexer":
        return True  # Older scopes never gain a connector retroactively.
    item = binding(db, run.laboratory_id)
    return bool(
        item
        and item.id == planned.get("binding_id")
        and item.asset_id == run.scope["asset_id"]
        and item.configuration_hash == planned.get("configuration_hash") == configured_hash()
    )


def collect_real(run_id: str, context: ExecutionContext, guard) -> Collection:
    started, poll = now(), None
    result = Collection((), False, False, False, "Coleta interrompida antes da conclusão.")
    with session_factory()() as db:
        run = db.get(CampaignRun, run_id)
        planned = run.scope.get("telemetry", {"provider": "unavailable"})
        allowed, deadline = scope_valid(db, run), run.deadline_at
    try:
        if planned["provider"] != "wazuh-indexer" or not allowed:
            result = UnavailableProvider().collect(context)
        else:
            try:
                policy = WazuhCollectionConfig.model_validate(planned["policy"])
                poll = WazuhPollingProvider(configured_provider(policy), deadline, guard)
                result = poll.collect(context)
            except (ValueError, OSError, httpx.HTTPError):
                result = Collection(
                    (),
                    False,
                    False,
                    False,
                    "Configuração/transporte Wazuh indisponível; nenhum diagnóstico sensível persistido.",
                )
        return result
    finally:
        summary = poll.summary if poll else {}
        with session_factory()() as db:
            db.add(
                TelemetryCollection(
                    execution_id=context.execution_id,
                    provider=planned["provider"],
                    configuration_hash=planned.get("configuration_hash"),
                    schema_id=planned.get("policy", {}).get("schema_id", "none"),
                    started_at=started,
                    ended_at=now(),
                    attempts=summary.get("attempts", 0),
                    complete=result.complete,
                    telemetry_available=result.telemetry_available,
                    alerts_available=result.alerts_available,
                    window_satisfied=summary.get("window_satisfied", False),
                    reason=result.error
                    or "Consulta concluída; interpretação depende da evidência correlacionada.",
                )
            )
            db.commit()
