"""Durable PostgreSQL worker. No imported commands or remote execution path."""
import logging
import signal
import threading
import time
from datetime import timedelta

from redis.exceptions import RedisError
from sqlalchemy import select

from aegis.config import settings
from aegis.db import session_factory
from aegis.domain.contracts import ExecutionAdapter, ExecutionContext
from aegis.domain.states import ACTIVE, State
from aegis.domain.validation import LOGIC_VERSION, digest, validate
from aegis.integrations.demo import DemoExecutionAdapter, DemoTelemetryProvider
from aegis.models import (
    Approval,
    CampaignRun,
    DetectionEvidence,
    Laboratory,
    TelemetryEvent,
    TestExecution,
    ValidationResult,
    now,
)
from aegis.security import redis_client
from aegis.services import move, release_lab

log = logging.getLogger("aegis.worker")
stop = threading.Event()


class Interrupted(Exception):
    def __init__(self, state: State, reason: str):
        self.state = state
        super().__init__(reason)


def claim_next() -> str | None:
    with session_factory()() as db:
        run = db.scalar(select(CampaignRun).where(CampaignRun.state == State.QUEUED)
                        .order_by(CampaignRun.created_at).with_for_update(skip_locked=True).limit(1))
        if not run:
            return None
        approval = db.scalar(select(Approval).where(Approval.run_id == run.id))
        lab = db.get(Laboratory, run.laboratory_id)
        if (not approval or approval.expires_at <= now() or not approval.used_at
                or approval.scope_hash != run.scope_hash or digest(run.scope) != run.scope_hash
                or not lab or not lab.authorized or lab.kind != "demo"
                or lab.active_run_id != run.id
                or lab.environment_version != run.scope["environment_version"]):
            move(db, run, State.REJECTED, "Pré-requisitos ou aprovação deixaram de ser válidos na fila.")
            for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
                # Queued tests may be rejected before any effect.
                move(db, run, State.REJECTED, "Autorização revalidada e rejeitada.", item)
                item.ended_at = now()
            run.ended_at = now()
            release_lab(db, run)
            db.commit()
            return None
        if not run.deadline_at or run.deadline_at <= now():
            move(db, run, State.TIMED_OUT, "Prazo expirou enquanto aguardava worker.")
            for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
                move(db, run, State.TIMED_OUT, "Prazo expirado antes da execução.", item)
                item.ended_at = now()
            run.ended_at = now()
            release_lab(db, run)
            db.commit()
            return None
        move(db, run, State.PREPARING, "Worker adquiriu a execução de forma exclusiva.")
        run.started_at = run.heartbeat_at = now()
        for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
            move(db, run, State.PREPARING, "Verificação de pré-requisitos sintéticos.", item)
        db.commit()
        return run.id


def guard(run_id: str) -> None:
    with session_factory()() as db:
        run = db.scalar(select(CampaignRun).where(CampaignRun.id == run_id).with_for_update())
        if not run or run.state not in ACTIVE:
            raise Interrupted(State.FAILED, "Execução perdeu a posse ou já foi finalizada.")
        if run.cancel_requested:
            raise Interrupted(State.CANCELLED, "Cancelamento solicitado; iniciando cleanup.")
        if not run.deadline_at or run.deadline_at <= now():
            raise Interrupted(State.TIMED_OUT, "Prazo absoluto de execução excedido.")
        lab = db.get(Laboratory, run.laboratory_id)
        if not lab or not lab.authorized or lab.environment_version != run.scope["environment_version"]:
            raise Interrupted(State.FAILED, "Autorização ou versão do laboratório mudou.")
        if stop.is_set():
            raise Interrupted(State.CANCELLED, "Worker encerrando de forma controlada.")
        run.heartbeat_at = now()
        db.commit()


def set_phase(run_id: str, state: State, message: str) -> None:
    guard(run_id)
    with session_factory()() as db:
        run = db.scalar(select(CampaignRun).where(CampaignRun.id == run_id).with_for_update())
        move(db, run, state, message)
        for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run_id)):
            move(db, run, state, message, item)
        db.commit()
    time.sleep(settings().demo_step_seconds)


def context_for(run: CampaignRun, item: TestExecution, test: dict) -> ExecutionContext:
    return ExecutionContext(item.id, run.laboratory_id, item.asset_id, item.marker,
                            test["behavior"], item.started_at or now(), item.ended_at or now(),
                            True, test["expected_rule"])


def process_run(run_id: str, adapter: ExecutionAdapter | None = None) -> None:
    # Fence duplicate deliveries before entering cleanup's finally block.
    with session_factory()() as db:
        owned = db.scalar(select(CampaignRun).where(CampaignRun.id == run_id).with_for_update())
        if not owned or owned.state != State.PREPARING or owned.processing_started:
            return
        owned.processing_started = True
        db.commit()
    adapter = adapter or DemoExecutionAdapter()
    contexts: dict[str, ExecutionContext] = {}
    collections = {}
    target, error = State.COMPLETED, None
    try:
        with session_factory()() as db:
            run = db.get(CampaignRun, run_id)
            if not run or run.state != State.PREPARING:
                return
            tests = {t["id"]: t for t in run.scope["test_definitions"]}
            items = db.scalars(select(TestExecution).where(TestExecution.run_id == run_id)
                               .order_by(TestExecution.test_id)).all()
            for item in items:
                contexts[item.id] = context_for(run, item, tests[item.test_id])
        for context in contexts.values():
            guard(run_id)
            adapter.prepare(context)
        set_phase(run_id, State.RUNNING, "Executando simulações em memória; dados sintéticos.")
        for item in items:
            guard(run_id)
            with session_factory()() as db:
                persisted = db.get(TestExecution, item.id)
                persisted.started_at = now()
                db.commit()
                context = context_for(run, persisted, tests[item.test_id])
            executed = adapter.execute(context)
            guard(run_id)
            with session_factory()() as db:
                persisted = db.get(TestExecution, item.id)
                persisted.executed, persisted.ended_at = executed, now()
                contexts[item.id] = context_for(run, persisted, tests[item.test_id])
                db.commit()
        set_phase(run_id, State.COLLECTING, "Coletando eventos pelo contrato TelemetryProvider.")
        for item in items:
            guard(run_id)
            collection = DemoTelemetryProvider(tests[item.test_id]["demo_outcome"]).collect(contexts[item.id])
            collections[item.id] = collection
            with session_factory()() as db:
                for event in collection.events:
                    db.add(TelemetryEvent(execution_id=item.id, source_id=event.source_id,
                         source=event.source, timestamp=event.timestamp, kind=event.kind,
                         rule_id=event.rule_id, synthetic=event.synthetic,
                         raw=event.raw, sha256=digest(event.raw)))
                db.commit()
        set_phase(run_id, State.VALIDATING, "Correlacionando marcador, ativo, comportamento, regra e tempo.")
        for item in items:
            guard(run_id)
            with session_factory()() as db:
                executed = db.get(TestExecution, item.id).executed
                collection = collections[item.id]
                verdict = validate(contexts[item.id], collection, executed,
                                   run.scope["clock_skew_seconds"], run.scope["ingestion_window_seconds"])
                result = ValidationResult(execution_id=item.id, outcome=verdict.outcome,
                         reason=verdict.reason, logic_version=LOGIC_VERSION, synthetic=True,
                         collection_complete=collection.complete,
                         telemetry_available=collection.telemetry_available,
                         alerts_available=collection.alerts_available)
                db.add(result)
                db.flush()
                for event in verdict.evidence:
                    stored = db.scalar(select(TelemetryEvent).where(
                        TelemetryEvent.execution_id == item.id,
                        TelemetryEvent.source == event.source,
                        TelemetryEvent.source_id == event.source_id))
                    db.add(DetectionEvidence(result_id=result.id, event_id=stored.id,
                                             reason=verdict.reason))
                db.commit()
    except Interrupted as exc:
        target, error = exc.state, str(exc)
    except Exception:
        log.exception("Run %s failed", run_id)
        target, error = State.FAILED, "Falha interna no adaptador; consulte os logs locais do worker."
    finally:
        with session_factory()() as db:
            current = db.scalar(select(CampaignRun).where(CampaignRun.id == run_id).with_for_update())
            if current and current.state in ACTIVE:
                if current.state != State.CLEANING_UP:
                    move(db, current, State.CLEANING_UP, "Cleanup obrigatório de todos os contextos.")
                for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run_id)):
                    if item.state in ACTIVE and item.state != State.CLEANING_UP:
                        move(db, current, State.CLEANING_UP, "Liberando contexto sintético.", item)
                current.requested_outcome = target
                db.commit()
        cleanup_failed = False
        for context in contexts.values():
            try:
                adapter.cleanup(context)
            except Exception:
                cleanup_failed = True
                log.exception("Cleanup failed for execution %s", context.execution_id)
        if cleanup_failed:
            target = State.CLEANUP_FAILED
            error = "Cleanup falhou. Demo: nenhum efeito externo; revise logs, confirme contexto descartado e libere laboratório após inspeção."
        with session_factory()() as db:
            current = db.scalar(select(CampaignRun).where(CampaignRun.id == run_id).with_for_update())
            if current and current.state == State.CLEANING_UP:
                if target == State.COMPLETED and current.cancel_requested:
                    target, error = State.CANCELLED, "Cancelamento confirmado durante cleanup."
                if target == State.COMPLETED and current.deadline_at <= now():
                    target, error = State.TIMED_OUT, "Prazo excedido durante cleanup."
                move(db, current, target, error or "Execução e cleanup demonstrativos concluídos.")
                current.error, current.ended_at, current.heartbeat_at = error, now(), now()
                for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run_id)):
                    if item.state == State.CLEANING_UP:
                        move(db, current, target, error or "Contexto liberado.", item)
                # Cleanup failures keep the lab reserved until an administrator reviews it.
                if target != State.CLEANUP_FAILED:
                    release_lab(db, current)
                db.commit()


def recover_abandoned() -> int:
    """Demo-only safe recovery: no automatic replay of unknown side effects."""
    recovered = 0
    with session_factory()() as db:
        stale = db.scalars(select(CampaignRun).where(
            CampaignRun.state.in_(list(ACTIVE)),
            CampaignRun.deadline_at < now() - timedelta(seconds=30),
            CampaignRun.heartbeat_at < now() - timedelta(seconds=30)
        ).with_for_update(skip_locked=True)).all()
        for run in stale:
            if not run.synthetic:
                continue
            if run.state != State.CLEANING_UP:
                move(db, run, State.CLEANING_UP, "Recuperação após interrupção do worker; nenhuma repetição de testes.")
            for item in db.scalars(select(TestExecution).where(TestExecution.run_id == run.id)):
                if item.state in ACTIVE:
                    if item.state != State.CLEANING_UP:
                        move(db, run, State.CLEANING_UP, "Descartando contexto demonstrativo abandonado.", item)
                    move(db, run, State.TIMED_OUT, "Worker interrompido; contexto sintético liberado.", item)
            move(db, run, State.TIMED_OUT, "Worker interrompido; cleanup sintético recuperado. Revisar resultados parciais.")
            run.error, run.ended_at = "Worker interrompido; execução não repetida.", now()
            release_lab(db, run)
            recovered += 1
        db.commit()
    return recovered


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    log.info("AEGIS worker: transactional PostgreSQL queue; demo adapter only")
    while not stop.is_set():
        try:
            try:
                redis_client().set("aegis:worker:heartbeat", now().isoformat(), ex=15)
            except RedisError:
                log.warning("Redis unavailable; durable queue remains in PostgreSQL")
            recover_abandoned()
            run_id = claim_next()
            if run_id:
                process_run(run_id)
            else:
                stop.wait(settings().worker_poll_seconds)
        except Exception:
            log.exception("Worker polling failed")
            stop.wait(2)


if __name__ == "__main__":
    main()
