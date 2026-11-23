"""Authenticated read-only catalog provenance and immutable release browsing."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, load_only

from aegis.catalog import review, store
from aegis.db import get_db, session_factory
from aegis.models import AttackCatalogRelease, AttackTechnique, User
from aegis.security import administrator, current_user, rate_limit

router = APIRouter(prefix="/catalog/attack", tags=["ATT&CK"])
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[User, Depends(current_user)]
Administrator = Annotated[User, Depends(administrator)]


def review_db():
    # Separate from session authentication: isolation must be set before any read.
    with session_factory()() as db, db.begin():
        db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        db.execute(text("SET LOCAL statement_timeout = '10s'"))
        db.execute(text("SET LOCAL lock_timeout = '1s'"))
        yield db


ReviewDB = Annotated[Session, Depends(review_db)]
Identity = Annotated[str, Path(pattern=r"^[a-f0-9]{64}$")]
METADATA_FIELDS = (
    "id",
    "dataset_version",
    "provenance",
    "source_url",
    "source_commit",
    "source_sha256",
    "license_sha256",
    "created_at",
    "applied_by",
)


def review_root(response, user):
    response.headers["Cache-Control"] = "no-store"
    rate_limit("attack-review:" + user.id, limit=60, seconds=60)
    return review.root()


@router.get("/reviews")
def reviews(
    user: Administrator,
    response: Response,
    offset: int = Query(0, ge=0, le=100),
    limit: int = Query(20, ge=1, le=50),
):
    try:
        path = review_root(response, user)
        items = review.inventory(path) if path else []
    except (ValueError, TypeError, KeyError, OSError, RecursionError, SQLAlchemyError):
        raise HTTPException(
            409, "Cache de revisão indisponível ou divergente; revisar no host."
        ) from None
    return {
        "status": "available" if path else "disabled",
        "items": items[offset : offset + limit],
        "total": len(items),
        "offset": offset,
        "limit": limit,
    }


def checked_review(db, response, user, plan_id):
    try:
        path = review_root(response, user)
        if path is None:
            raise HTTPException(409, "Revisão web não habilitada na implantação.")
        return review.checked(db, path, plan_id)
    except (ValueError, TypeError, KeyError, OSError, RecursionError, SQLAlchemyError):
        raise HTTPException(
            409, "Plano/candidato mudou ou está indisponível; gere e revise outro plano no host."
        ) from None


@router.get("/reviews/{plan_id}")
def review_detail(
    plan_id: Identity,
    user: Administrator,
    db: ReviewDB,
    response: Response,
    offset: int = Query(0, ge=0, le=100_000),
    test_offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(20, ge=1, le=50),
):
    plan, document = checked_review(db, response, user, plan_id)
    return {
        **{
            k: v
            for k, v in plan.items()
            if k not in {"changes", "test_references", "tests_requiring_review"}
        },
        "provenance": document.provenance,
        "source_url": document.source_url,
        "publication_status": "already_applied"
        if plan["action"] == "already_applied"
        else "not_applied",
        "changes": review.changes(db, plan, document, offset, limit),
        "tests_requiring_review": {
            "items": plan["tests_requiring_review"][test_offset : test_offset + limit],
            "total": len(plan["tests_requiring_review"]),
            "offset": test_offset,
            "limit": limit,
        },
        "test_reference_count": len(plan["test_references"]),
        "authorization_policy": "Publicação invalida o contexto de catálogo de escopos anteriores para novos efeitos. Aprovações, grants, cobertura e relatórios históricos permanecem preservados. Agendamentos retomáveis, runs pendentes e reservas bloqueiam apply.",
    }


@router.get("/reviews/{plan_id}/instruction")
def review_instruction(plan_id: Identity, user: Administrator, db: ReviewDB, response: Response):
    plan, _ = checked_review(db, response, user, plan_id)
    if plan["blockers"] or plan["action"] != "apply":
        raise HTTPException(409, "Plano bloqueado ou já aplicado; nenhuma instrução de publicação.")
    return {
        "plan_sha256": plan_id,
        "candidate_id": plan["candidate_id"],
        "status": "host_only_not_applied",
        "command": f".venv/bin/python scripts/update_attack.py apply {plan['candidate_id']} --confirm-plan {plan_id} --actor {user.id}",
        "limitation": "Execute somente no host confiável, no destino revisado e com credencial SQL de implantação. A CLI revalida plano, ator e bloqueadores sob locks antes de publicar; esta consulta não concede autorização nem publica.",
    }


def metadata_query():
    return select(AttackCatalogRelease).options(
        load_only(*(getattr(AttackCatalogRelease, key) for key in METADATA_FIELDS))
    )


def metadata(record):
    return {
        key: getattr(record, key)
        for key in (
            "id",
            "dataset_version",
            "provenance",
            "source_url",
            "source_commit",
            "source_sha256",
            "license_sha256",
            "created_at",
            "applied_by",
        )
    }


@router.get("")
def status(user: Viewer, db: DB):
    try:
        reference = store.reference(db)
    except store.CatalogError:
        return {
            "status": "uninitialized",
            "current": None,
            "counts": None,
            "limitation": "Catálogo pendente de inicialização/revisão; não assumir a origem dos dados existentes.",
        }
    release = db.scalar(metadata_query().where(AttackCatalogRelease.id == reference["release_id"]))
    counts = dict.fromkeys(("active", "revoked", "deprecated", "absent"), 0)
    groups = db.execute(
        select(
            AttackTechnique.present_in_current,
            AttackTechnique.revoked,
            AttackTechnique.deprecated,
            func.count(),
        ).group_by(
            AttackTechnique.present_in_current, AttackTechnique.revoked, AttackTechnique.deprecated
        )
    )
    for present, revoked, deprecated, count in groups:
        counts[
            "absent"
            if not present
            else "revoked"
            if revoked
            else "deprecated"
            if deprecated
            else "active"
        ] += count
    return {
        "status": "ready",
        "current": metadata(release),
        "counts": counts,
        "limitation": "A cobertura atual exige avaliação da mesma release. Histórico sem versão registrada permanece desconhecido; importação não implanta regras nem executa testes.",
    }


@router.get("/releases")
def releases(
    user: Viewer, db: DB, offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)
):
    store.shared(db)
    # Omit the external snapshot document from this listing.
    rows = db.scalars(
        metadata_query()
        .order_by(AttackCatalogRelease.created_at.desc(), AttackCatalogRelease.id)
        .offset(offset)
        .limit(limit)
    )
    return {
        "items": [metadata(row) for row in rows],
        "total": db.scalar(select(func.count()).select_from(AttackCatalogRelease)),
        "offset": offset,
        "limit": limit,
    }


@router.get("/releases/{release_id}/techniques")
def snapshot(
    release_id: Identity,
    user: Viewer,
    db: DB,
    q: str = Query("", max_length=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
):
    release = db.get(AttackCatalogRelease, release_id)
    if release is None:
        raise HTTPException(404, "Release ATT&CK não encontrada.")
    try:
        document = store.checked(release)
    except ValueError:
        raise HTTPException(409, "Integridade da release ATT&CK divergente.") from None
    filtered = [t for t in document.techniques if q.lower() in (t.id + " " + t.name).lower()]
    return {
        "items": [t.model_dump() for t in filtered[offset : offset + limit]],
        "total": len(filtered),
        "offset": offset,
        "limit": limit,
        "release": metadata(release),
        "limitation": "Snapshot histórico de metadados. Presença no catálogo não demonstra execução ou detecção.",
    }
