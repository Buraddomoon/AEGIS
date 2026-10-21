"""Deployment-pinned mTLS client. Not wired into the Demo worker."""

import hashlib
import ipaddress
import json
import ssl
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, field_validator

from aegis.domain.contracts import ExecutionContext
from aegis.domain.validation import digest
from aegis.lab_runner.protocol import (
    PROTOCOL,
    TEST_ID,
    BoundRequest,
    JobSpec,
    JobView,
    RunnerIdentity,
)


class RunnerConnection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    url: str
    runner_id: UUID
    laboratory_id: UUID
    asset_id: UUID
    server_ca: Path
    client_cert: Path
    client_key: Path

    @field_validator("url")
    @classmethod
    def endpoint(cls, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or parsed.port != 8443
        ):
            raise ValueError(
                "Runner exige HTTPS no IP RFC1918 fixado, porta 8443 e sem caminho/credenciais."
            )
        address = ipaddress.ip_address(parsed.hostname or "")
        allowed = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        if address.version != 4 or not any(
            address in ipaddress.ip_network(network) for network in allowed
        ):
            raise ValueError("Somente IP IPv4 privado RFC1918 explicitamente autorizado.")
        return value.rstrip("/")


class RunnerUnavailable(RuntimeError):
    pass


class LinuxRunnerClient:
    def __init__(self, config: RunnerConnection, *, transport: httpx.BaseTransport | None = None):
        self.config = config
        context = ssl.create_default_context(cafile=str(config.server_ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(config.client_cert), str(config.client_key))
        self.http = httpx.Client(
            base_url=config.url,
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(3, connect=2),
            limits=httpx.Limits(max_connections=2),
            transport=transport,
            headers={"X-Aegis-Runner-Protocol": PROTOCOL},
        )

    def close(self):
        self.http.close()

    def request(self, method: str, path: str, data: dict | None = None) -> dict:
        try:
            with self.http.stream(method, path, json=data) as response:
                if not 200 <= response.status_code < 300:
                    raise RunnerUnavailable(
                        f"Runner retornou HTTP {response.status_code}; consulte seu diário."
                    )
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 32768:
                        raise RunnerUnavailable("Resposta do runner excedeu o limite.")
                    chunks.append(chunk)
                return json.loads(b"".join(chunks))
        except (httpx.HTTPError, ValueError):
            raise RunnerUnavailable(
                "Runner indisponível ou resposta inválida; não repetir efeito sem consultar estado."
            ) from None

    def preflight(self) -> RunnerIdentity:
        identity = RunnerIdentity.model_validate(self.request("GET", "/v1/identity"))
        if (identity.runner_id, identity.laboratory_id, identity.asset_id, identity.tests) != (
            self.config.runner_id,
            self.config.laboratory_id,
            self.config.asset_id,
            (TEST_ID,),
        ):
            raise RunnerUnavailable("Identidade ou allowlist diferente da configuração revisada.")
        return identity

    def check(self, raw: dict, spec: JobSpec) -> JobView:
        view = JobView.model_validate(raw)
        if view.spec != spec or view.spec_hash != digest(spec.model_dump(mode="json")):
            raise RunnerUnavailable("Escopo devolvido não corresponde ao job solicitado.")
        if view.receipt:
            artifact = (spec.marker + "\n").encode("ascii")
            expected = {
                key: getattr(spec, key)
                for key in (
                    "job_id",
                    "runner_id",
                    "laboratory_id",
                    "asset_id",
                    "test_id",
                    "marker",
                    "scope_hash",
                )
            }
            if (
                any(getattr(view.receipt, key) != value for key, value in expected.items())
                or view.receipt_sha256 != digest(view.receipt.model_dump(mode="json"))
                or view.receipt.artifact_sha256 != hashlib.sha256(artifact).hexdigest()
                or view.receipt.artifact_bytes != len(artifact)
            ):
                raise RunnerUnavailable(
                    "Comprovante não corresponde à identidade/escopo/integridade esperada."
                )
        elif view.receipt_sha256 or view.state == "SUCCEEDED":
            raise RunnerUnavailable("Sucesso sem comprovante verificável.")
        return view

    def prepare(self, spec: JobSpec) -> JobView:
        return self.check(self.request("POST", "/v1/jobs", spec.model_dump(mode="json")), spec)

    def get(self, spec: JobSpec, generation: UUID | None = None) -> JobView:
        result = self.check(self.request("GET", f"/v1/jobs/{spec.job_id}"), spec)
        if generation is not None and result.generation != generation:
            raise RunnerUnavailable("Geração do job mudou; não repetir efeito.")
        return result

    def action(self, view: JobView, action: str) -> JobView:
        if action not in ("start", "renew", "cancel", "cleanup"):
            raise ValueError("Ação fora da allowlist.")
        bound = BoundRequest(spec_hash=view.spec_hash, generation=view.generation)
        result = self.check(
            self.request(
                "POST", f"/v1/jobs/{view.spec.job_id}/{action}", bound.model_dump(mode="json")
            ),
            view.spec,
        )
        if result.generation != view.generation:
            raise RunnerUnavailable("Geração do job mudou; efeito não confiável.")
        return result


class LinuxMarkerAdapter:
    """Same ExecutionAdapter contract, with guard supplied by the future orchestrator."""

    def __init__(
        self,
        client: LinuxRunnerClient,
        deadline: datetime,
        scope_hash: str,
        guard: Callable[[], None],
    ):
        self.client, self.deadline, self.scope_hash, self.guard = (
            client,
            deadline,
            scope_hash,
            guard,
        )
        self.jobs: dict[str, JobView] = {}
        self.pending: dict[str, JobSpec] = {}

    def prepare(self, context: ExecutionContext) -> None:
        if context.synthetic or context.behavior != "temporary-marker":
            raise ValueError("Adapter aceita somente teste marcador Linux real revisado.")
        self.guard()
        identity = self.client.preflight()
        if (str(identity.laboratory_id), str(identity.asset_id)) != (
            context.laboratory_id,
            context.asset_id,
        ):
            raise RunnerUnavailable("Ativo/contexto não corresponde ao runner.")
        spec = JobSpec(
            job_id=context.execution_id,
            laboratory_id=context.laboratory_id,
            asset_id=context.asset_id,
            runner_id=identity.runner_id,
            marker=context.marker,
            scope_hash=self.scope_hash,
            deadline_at=self.deadline,
        )
        self.pending[context.execution_id] = (
            spec  # Retain scope even if the prepare response is lost.
        )
        self.jobs[context.execution_id] = self.client.prepare(spec)

    def execute(self, context: ExecutionContext) -> bool:
        view = self.jobs[context.execution_id]
        try:
            self.guard()
            view = self.client.action(view, "start")
            end = time.monotonic() + 6
            while view.state == "RUNNING":
                self.guard()
                if time.monotonic() >= end:
                    raise TimeoutError("Prazo local de supervisão excedido.")
                time.sleep(0.1)
                view = self.client.get(view.spec, view.generation)
                if view.state == "RUNNING":
                    try:
                        view = self.client.action(view, "renew")
                    except RunnerUnavailable:
                        # Effect may finish between GET and renew. Never retry start.
                        fresh = self.client.get(view.spec, view.generation)
                        if fresh.state == "RUNNING":
                            raise
                        view = fresh
            self.jobs[context.execution_id] = view
            return view.state == "SUCCEEDED" and view.receipt is not None
        except BaseException:
            try:
                self.client.action(view, "cancel")
            except Exception:
                pass  # Runner lease expires independently; cleanup must still be confirmed.
            raise

    def cleanup(self, context: ExecutionContext) -> None:
        view = self.jobs.get(context.execution_id)
        if not view:
            spec = self.pending.get(context.execution_id)
            if not spec:
                return
            view = self.client.get(spec)
        view = self.client.get(view.spec, view.generation)
        if view.state == "RUNNING":
            self.client.action(view, "cancel")
            end = time.monotonic() + 3
            while view.state == "RUNNING" and time.monotonic() < end:
                time.sleep(0.05)
                view = self.client.get(view.spec, view.generation)
        view = self.client.action(view, "cleanup")
        if view.cleanup_state != "CLEANED":
            raise RunnerUnavailable("Cleanup não confirmado; mantenha reserva do laboratório.")
        self.jobs[context.execution_id] = view
