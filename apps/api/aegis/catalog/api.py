"""Authenticated read-only catalog provenance and immutable release browsing."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, load_only

from aegis.catalog import store
from aegis.db import get_db
from aegis.models import AttackCatalogRelease, AttackTechnique, User
from aegis.security import current_user

router = APIRouter(prefix="/catalog/attack", tags=["ATT&CK"])
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[User, Depends(current_user)]
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
