import hashlib
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from aegis.domain.validation import digest
from aegis.lab_runner.files import Workspace
from aegis.lab_runner.journal import Journal
from aegis.lab_runner.protocol import (
    LEASE_SECONDS,
    MAX_EFFECT_SECONDS,
    BoundRequest,
    ExecutionReceipt,
    JobSpec,
    JobState,
    JobView,
    RunnerIdentity,
)

log = logging.getLogger("aegis.runner")
MARKER_PROGRAM = Path(__file__).with_name("marker_program.py")


class Conflict(ValueError):
    pass


@dataclass
class ActiveEffect:
    job_id: UUID
    generation: UUID
    deadline: float
    lease_until: float
    cancelled: threading.Event = field(default_factory=threading.Event)
    lease_lock: threading.Lock = field(default_factory=threading.Lock)
    thread: threading.Thread | None = None
    process: subprocess.Popen | None = None


class Runner:
    def __init__(self, identity: RunnerIdentity, work: Path, state: Path):
        if sys.platform != "linux":
            raise ValueError("Runner suporta somente Linux.")
        self.identity, self.workspace = identity, Workspace(work)
        try:
            self.journal = Journal(state)
        except BaseException:
            self.workspace.close()
            raise
        self.control = threading.RLock()
        self.close_lock = threading.Lock()
        self.closed = False
        self.active: ActiveEffect | None = None
        # No replay, no PID loaded from disk, and no implicit cleanup after an ambiguous crash.
        with self.journal.connection() as db:
            fingerprint = digest(identity.model_dump(mode="json"))
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
            if old and old[0] != fingerprint:
                self.journal.close()
                self.workspace.close()
                raise Conflict(
                    "Diário pertence a outra identidade; restaure a configuração original."
                )
            db.execute(
                "INSERT OR IGNORE INTO metadata(key,value) VALUES ('identity',?)", (fingerprint,)
            )
            db.execute(
                "UPDATE jobs SET state='INTERRUPTED', reason='Runner reiniciado; efeito não repetido; cleanup explícito obrigatório.' WHERE state='RUNNING'"
            )

    def close(self):
        with self.close_lock:
            if self.closed:
                return
            with self.control:
                active = self.active
                if active:
                    active.cancelled.set()
            if active and active.thread:
                active.thread.join(timeout=7)
                if active.thread.is_alive():
                    raise RuntimeError("Supervisor não encerrou; não liberar instância.")
            self.journal.close()
            self.workspace.close()
            self.closed = True

    def prepare(self, spec: JobSpec) -> JobView:
        if (spec.runner_id, spec.laboratory_id, spec.asset_id) != (
            self.identity.runner_id,
            self.identity.laboratory_id,
            self.identity.asset_id,
        ):
            raise Conflict("Identidade não corresponde ao laboratório configurado.")
        fingerprint = digest(spec.model_dump(mode="json"))
        with self.control, self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM jobs WHERE id=?", (str(spec.job_id),)).fetchone()
            if previous:
                if previous["spec_hash"] != fingerprint:
                    raise Conflict("UUID já utilizado com outro escopo.")
                return self.journal.view(previous)
            delta = (spec.deadline_at - datetime.now(UTC)).total_seconds()
            if not 0 < delta <= 300:
                raise Conflict("Prazo deve estar no futuro, dentro de 300 segundos.")
            if db.execute("SELECT 1 FROM jobs WHERE cleanup_state != 'CLEANED' LIMIT 1").fetchone():
                raise Conflict("Runner reservado; finalize e confirme cleanup do job anterior.")
            if db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= 10000:
                raise Conflict("Limite do diário atingido; arquivamento offline necessário.")
            generation = uuid4()
            db.execute(
                "INSERT INTO jobs(id,spec,spec_hash,generation,state) VALUES (?,?,?,?,?)",
                (
                    str(spec.job_id),
                    spec.model_dump_json(),
                    fingerprint,
                    str(generation),
                    "PREPARED",
                ),
            )
            self.journal.event(db, spec.job_id, "PREPARED")
        return self.journal.get(spec.job_id)

    def bound(self, identifier: UUID, request: BoundRequest) -> JobView:
        view = self.journal.get(identifier)
        if request.spec_hash != view.spec_hash or request.generation != view.generation:
            raise Conflict("Escopo ou geração da operação não corresponde ao job.")
        return view

    def start(self, identifier: UUID, request: BoundRequest) -> JobView:
        with self.control:
            view = self.bound(identifier, request)
            if view.state != JobState.PREPARED:
                return view  # Lost RPC response never replays an effect, including after restart.
            if view.cleanup_state != "PENDING":
                raise Conflict("Job já limpo; não pode iniciar.")
            if self.active:
                raise Conflict("Outro efeito está ativo.")
            remaining = (view.spec.deadline_at - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                self.journal.update(
                    identifier, state="TIMED_OUT", reason="Prazo expirou antes do início."
                )
                return self.journal.get(identifier)
            instant = time.monotonic()
            active = ActiveEffect(
                identifier,
                view.generation,
                instant + min(MAX_EFFECT_SECONDS, remaining),
                instant + min(LEASE_SECONDS, remaining),
            )
            # Durable intent BEFORE any filesystem effect or subprocess spawn.
            self.journal.update(identifier, state="RUNNING")
            self.active = active
            active.thread = threading.Thread(
                target=self.supervise, args=(view.spec, active), daemon=True
            )
            try:
                active.thread.start()
            except BaseException:
                self.active = None
                self.journal.update(
                    identifier, state="INTERRUPTED", reason="Supervisor não iniciou; sem replay."
                )
                raise
        return self.journal.get(identifier)

    def renew(self, identifier: UUID, request: BoundRequest) -> JobView:
        with self.control:
            view = self.bound(identifier, request)
            active = self.active
            if view.state != "RUNNING" or not active or active.job_id != identifier:
                raise Conflict("Nenhum lease renovável para este job.")
            with active.lease_lock:
                instant = time.monotonic()
                if instant >= min(active.lease_until, active.deadline) or active.cancelled.is_set():
                    raise Conflict("Lease expirado ou cancelado; renovação não ressuscita efeito.")
                active.lease_until = min(instant + LEASE_SECONDS, active.deadline)
        return self.journal.get(identifier)

    def cancel(self, identifier: UUID, request: BoundRequest) -> JobView:
        with self.control:
            view = self.bound(identifier, request)
            if self.active and self.active.job_id == identifier:
                self.active.cancelled.set()
            elif view.state == "PREPARED":
                self.journal.update(
                    identifier, state="CANCELLED", reason="Cancelado antes do efeito."
                )
        return self.journal.get(identifier)

    @staticmethod
    def terminate(process: subprocess.Popen):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)

    def supervise(self, spec: JobSpec, active: ActiveEffect):
        outcome, reason, receipt = "FAILED", "Programa não confirmou efeito.", None
        process = None
        try:
            directory = self.workspace.create(spec.job_id)
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", str(MARKER_PROGRAM)],
                cwd=directory,
                env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                start_new_session=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            active.process = process
            try:
                process.stdin.write(
                    json.dumps({"marker": spec.marker, "parent_pid": os.getpid()}).encode()
                )
                process.stdin.close()
            except BrokenPipeError:
                pass
            while True:
                instant = time.monotonic()
                with active.lease_lock:
                    expired = instant >= min(active.deadline, active.lease_until)
                if active.cancelled.is_set() or expired:
                    outcome = "CANCELLED" if active.cancelled.is_set() else "TIMED_OUT"
                    reason = (
                        "Cancelamento solicitado."
                        if outcome == "CANCELLED"
                        else "Prazo/lease expirado; grupo encerrado."
                    )
                    self.terminate(process)
                    break
                if process.poll() is not None:
                    if process.returncode == 0:
                        raw = json.loads(self.workspace.read(spec.job_id, "receipt.json", 8192))
                        content = self.workspace.read(spec.job_id, "proof.marker", 256)
                        expected = (spec.marker + "\n").encode("ascii")
                        if (
                            content != expected
                            or raw["artifact_sha256"] != hashlib.sha256(expected).hexdigest()
                            or raw["artifact_bytes"] != len(expected)
                        ):
                            raise ValueError("Comprovante não corresponde ao artefato esperado.")
                        receipt = ExecutionReceipt(
                            **raw,
                            job_id=spec.job_id,
                            runner_id=spec.runner_id,
                            laboratory_id=spec.laboratory_id,
                            asset_id=spec.asset_id,
                            marker=spec.marker,
                            scope_hash=spec.scope_hash,
                        )
                        if not datetime.now(UTC) >= receipt.ended_at >= receipt.started_at:
                            raise ValueError("Tempo do comprovante inválido.")
                        outcome, reason = (
                            "SUCCEEDED",
                            "Criação e hash do marcador confirmados pelo executor; sem evidência defensiva.",
                        )
                    break
                time.sleep(0.025)
        except Exception:
            log.exception("Fixed marker job failed: %s", spec.job_id)
            reason = "Falha local no programa fixo ou verificação do artefato; inspecione logs do runner."
        finally:
            # Kill/reap before touching SQLite. A locked journal cannot extend effect lifetime.
            if process is not None:
                if process.poll() is None:
                    self.terminate(process)
                else:
                    process.wait()
            value = receipt.model_dump(mode="json") if receipt else None
            try:
                self.journal.update(
                    spec.job_id,
                    state=outcome,
                    reason=reason,
                    receipt=value,
                    receipt_hash=digest(value) if value else None,
                )
            except Exception:
                log.exception(
                    "Result persistence failed; job remains fenced pending explicit cleanup"
                )
            finally:
                with self.control:
                    if self.active is active:
                        self.active = None

    def cleanup(self, identifier: UUID, request: BoundRequest) -> JobView:
        with self.control:
            view = self.bound(identifier, request)
            if view.cleanup_state == "CLEANED":
                return view
            if self.active:
                raise Conflict("Aguarde término/encerramento do processo antes do cleanup.")
            if view.state == "RUNNING":
                self.journal.update(
                    identifier,
                    state="INTERRUPTED",
                    reason="Resultado não confirmado; efeito não repetido.",
                )
            elif view.state == "PREPARED":
                self.journal.update(
                    identifier, state="CANCELLED", reason="Preparação encerrada sem execução."
                )
            try:
                self.workspace.cleanup(identifier)
            except Exception:
                self.journal.update(
                    identifier,
                    cleanup_state="FAILED",
                    reason="Cleanup recusado/falhou; reserva mantida. Inspecione volume /work sem apagar arquivos desconhecidos.",
                )
                raise Conflict("Cleanup falhou; runner continua reservado.") from None
            self.journal.update(identifier, cleanup_state="CLEANED", reason=view.reason)
        return self.journal.get(identifier)
