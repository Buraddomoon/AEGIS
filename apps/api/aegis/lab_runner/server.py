"""Supported entrypoint always uses mutual TLS, one worker and no proxy headers."""

import logging
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings, SettingsConfigDict

from aegis.lab_runner.engine import Conflict, Runner
from aegis.lab_runner.protocol import PROTOCOL, BoundRequest, JobSpec, RunnerIdentity


class RunnerConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_RUNNER_", extra="ignore")
    runner_id: UUID
    laboratory_id: UUID
    asset_id: UUID
    work_dir: Path = Path("/work")
    state_dir: Path = Path("/state")
    server_cert: Path = Path("/run/secrets/runner_server_cert")
    server_key: Path = Path("/run/secrets/runner_server_key")
    client_ca: Path = Path("/run/secrets/runner_client_ca")


def create_app(runner: Runner) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            runner.close()

    app = FastAPI(
        title="AEGIS Linux Runner",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def protect(request: Request, call_next):
        if request.url.scheme != "https":
            return JSONResponse({"error": "HTTPS com mTLS obrigatório."}, status_code=403)
        if request.method == "POST":
            if request.headers.get("x-aegis-runner-protocol") != PROTOCOL:
                return JSONResponse({"error": "Protocolo explícito obrigatório."}, status_code=403)
            size, chunks = 0, []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 8192:
                    return JSONResponse({"error": "Payload excessivo."}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        try:
            response = await call_next(request)
        except Exception:
            logging.getLogger("aegis.runner").exception("Runner request failed")
            response = JSONResponse(
                {"error": "Falha interna; efeito não será repetido automaticamente."},
                status_code=500,
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(Conflict)
    async def conflict(request: Request, exc: Conflict):
        return JSONResponse({"error": str(exc)}, status_code=409)

    @app.exception_handler(LookupError)
    async def missing(request: Request, exc: LookupError):
        return JSONResponse({"error": "Job não encontrado."}, status_code=404)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError):
        return JSONResponse(
            {"error": "Mensagem inválida; confira UUIDs, hash, marcador, prazo e allowlist."},
            status_code=422,
        )

    @app.get("/v1/identity")
    def identity():
        return runner.identity

    @app.post("/v1/jobs", status_code=201)
    def prepare(spec: JobSpec):
        return runner.prepare(spec)

    @app.get("/v1/jobs/{identifier}")
    def get(identifier: UUID):
        return runner.journal.get(identifier)

    @app.post("/v1/jobs/{identifier}/start")
    def start(identifier: UUID, request: BoundRequest):
        return runner.start(identifier, request)

    @app.post("/v1/jobs/{identifier}/renew")
    def renew(identifier: UUID, request: BoundRequest):
        return runner.renew(identifier, request)

    @app.post("/v1/jobs/{identifier}/cancel")
    def cancel(identifier: UUID, request: BoundRequest):
        return runner.cancel(identifier, request)

    @app.post("/v1/jobs/{identifier}/cleanup")
    def cleanup(identifier: UUID, request: BoundRequest):
        return runner.cleanup(identifier, request)

    return app


def main():
    configuration = RunnerConfig()
    # Uvicorn's TLS layer validates clients; FastAPI never trusts identity headers.
    identity = RunnerIdentity(
        runner_id=configuration.runner_id,
        laboratory_id=configuration.laboratory_id,
        asset_id=configuration.asset_id,
    )
    runner = Runner(identity, configuration.work_dir, configuration.state_dir)
    uvicorn.run(
        create_app(runner),
        host="0.0.0.0",
        port=8443,
        workers=1,
        ssl_keyfile=str(configuration.server_key),
        ssl_certfile=str(configuration.server_cert),
        ssl_ca_certs=str(configuration.client_ca),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        proxy_headers=False,
        access_log=False,
        limit_concurrency=16,
        timeout_keep_alive=2,
        timeout_graceful_shutdown=8,
    )


if __name__ == "__main__":
    main()
