import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from aegis.config import Settings, settings


async def http_error(request: Request, exc: HTTPException):
    return JSONResponse(
        {
            "error": {
                "code": exc.status_code,
                "message": str(exc.detail),
                "request_id": getattr(request.state, "request_id", None),
            }
        },
        status_code=exc.status_code,
        headers=exc.headers,
    )


async def validation_error(request: Request, exc: RequestValidationError):
    # Never echo input: it may contain a password or connector secret.
    return JSONResponse(
        {
            "error": {
                "code": 422,
                "message": "Dados inválidos.",
                "fields": [
                    {"field": ".".join(map(str, e["loc"])), "type": e["type"]} for e in exc.errors()
                ],
                "request_id": request.state.request_id,
            }
        },
        status_code=422,
    )


async def protections(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    if request.app.state.operating_mode == "recovery" and (
        request.method != "GET"
        or request.url.path
        not in {"/api/v1/health/live", "/api/v1/health/ready", "/api/v1/recovery/review"}
    ):
        return JSONResponse(
            {"error": {"code": 503, "message": "Aplicação em quarentena de recuperação."}},
            status_code=503,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin and origin != settings().public_origin:
            return JSONResponse(
                {"error": {"code": 403, "message": "Origem não autorizada."}}, status_code=403
            )
        size, chunks = 0, []
        async for chunk in request.stream():
            size += len(chunk)
            if size > 262144:
                return JSONResponse(
                    {"error": {"code": 413, "message": "Payload excede o limite."}}, status_code=413
                )
            chunks.append(chunk)
        request._body = b"".join(chunks)
    try:
        response = await call_next(request)
    except Exception:
        logging.getLogger("aegis.api").exception("Request failed: %s", request.state.request_id)
        response = JSONResponse(
            {
                "error": {
                    "code": 500,
                    "message": "Falha interna.",
                    "request_id": request.state.request_id,
                }
            },
            status_code=500,
        )
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = (
        "no-store" if request.url.path.startswith("/api/") else "no-cache"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if request.url.path != "/api/docs"
        else "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
    )
    if settings().secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def create_app(config: Settings | None = None):
    config = config or settings()
    recovery = config.operating_mode == "recovery"
    app = FastAPI(
        title="ÆGIS — Purple Team Validation",
        version="0.2.0",
        description="Aplicação em quarentena de recuperação."
        if recovery
        else "Validação apoiada em evidências; Demo sintético e Linux opt-in.",
        docs_url=None if recovery else "/api/docs",
        openapi_url=None if recovery else "/api/openapi.json",
        redoc_url=None,
    )
    app.state.operating_mode = config.operating_mode
    if recovery:
        from aegis.operations.recovery import recovery_router

        token = config.recovery_access_token
        if token is None or len(token.get_secret_value()) < 32:
            raise RuntimeError(
                "Recovery requires an independent access token of at least 32 characters"
            )
        identity, fingerprint = (
            config.recovery_reconciliation_id,
            config.recovery_reconciliation_hash,
        )
        if bool(identity) != bool(fingerprint):
            raise RuntimeError("Recovery reconciliation identity and hash must be paired")
        expected = (identity, fingerprint) if identity else None
        app.include_router(recovery_router(token.get_secret_value(), expected))
    else:
        from aegis.api import router
        from aegis.catalog.store import CatalogError

        async def catalog_error(request: Request, exc: CatalogError):
            return await http_error(
                request,
                HTTPException(
                    409, "Catálogo ATT&CK indisponível ou divergente; revisão necessária."
                ),
            )

        app.add_exception_handler(CatalogError, catalog_error)
        app.include_router(router)
        if config.web_dist.is_dir():
            app.mount("/", StaticFiles(directory=config.web_dist, html=True), name="web")
    app.add_exception_handler(HTTPException, http_error)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.middleware("http")(protections)
    return app


app = create_app()
