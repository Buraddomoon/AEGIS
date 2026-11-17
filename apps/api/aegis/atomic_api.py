"""Authenticated metadata-only import, browsing and append-only review."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import any_, func, or_, select, text
from sqlalchemy.orm import Session, defer

from aegis import atomic_catalog
from aegis.catalog.store import lifecycle
from aegis.db import get_db
from aegis.models import AtomicDocument, AtomicEntry, AtomicReview, AttackTechnique, User
from aegis.security import administrator, audit, current_user, rate_limit

router = APIRouter(prefix="/catalog/atomic", tags=["Atomic metadata"])
DB = Annotated[Session, Depends(get_db)]
Viewer = Annotated[User, Depends(current_user)]
Admin = Annotated[User, Depends(administrator)]
LIMITATION = "Metadados não confiáveis; origem declarada pelo operador, sem autenticação upstream. Revisão não autoriza execução, instalação ou campanha. Risco operacional não avaliado."


class Import(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content: str = Field(min_length=1, max_length=65536)

    @field_validator("content")
    @classmethod
    def byte_budget(cls, value):
        if len(value.encode()) > 65536:
            raise ValueError("Atomic limitado a 64 KiB UTF-8.")
        return value


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    decision: Literal["reviewed", "rejected"]
    note: str = Field(min_length=1, max_length=2000)
    expected_sequence: int = Field(ge=0)

    @field_validator("note")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Justificativa obrigatória.")
        return value


def latest(db, identifier):
    return db.scalar(
        select(AtomicReview)
        .where(AtomicReview.entry_id == identifier)
        .order_by(AtomicReview.sequence.desc())
        .limit(1)
    )


def review_record(row):
    return (
        {
            key: getattr(row, key)
            for key in ("id", "sequence", "decision", "note", "created_at", "reviewed_by")
        }
        if row
        else None
    )


def entry_or_404(db, identifier):
    entry = db.get(AtomicEntry, str(identifier))
    if entry is None:
        raise HTTPException(404, "Metadado Atomic não encontrado.")
    return entry


def summary(db, entry, document):
    technique = db.get(AttackTechnique, document.technique_id)
    current = latest(db, entry.id)
    return {
        "id": entry.id,
        "guid": entry.guid,
        "name": entry.name,
        "platforms": entry.platforms,
        "technique_id": document.technique_id,
        "attack_mapping_status": lifecycle(technique) if technique else "unknown",
        "source": atomic_catalog.source(document),
        "review_status": current.decision if current else "pending",
        "review_sequence": current.sequence if current else 0,
        "approved": False,
        "executable": False,
        "available_for_new_scope": False,
    }


@router.post("/imports", status_code=201)
def import_metadata(data: Import, user: Admin, db: DB, response: Response):
    rate_limit("atomic-import:" + user.id, limit=10)
    try:
        document, unchanged = atomic_catalog.import_document(
            db, data.content, data.source_commit, data.source_sha256, user.id
        )
    except atomic_catalog.AtomicError as exc:
        db.rollback()
        audit(
            db,
            user.id,
            "atomic.import_rejected",
            "atomic",
            reason="invalid_or_conflicting_document",
        )
        db.commit()
        raise HTTPException(422, str(exc)) from None
    db.commit()
    if unchanged:
        response.status_code = 200
    return {
        "source": atomic_catalog.source(document),
        "unchanged": unchanged,
        "limitation": LIMITATION,
    }


@router.get("/documents")
def documents(
    user: Viewer,
    db: DB,
    offset: int = Query(0, ge=0, le=1000000),
    limit: int = Query(20, ge=1, le=100),
):
    rows = db.scalars(
        select(AtomicDocument)
        .order_by(AtomicDocument.created_at.desc(), AtomicDocument.id)
        .offset(offset)
        .limit(limit)
    )
    return {
        "items": [atomic_catalog.source(row) | {"technique_id": row.technique_id} for row in rows],
        "total": db.scalar(select(func.count()).select_from(AtomicDocument)),
        "offset": offset,
        "limit": limit,
    }


@router.get("")
def entries(
    user: Viewer,
    db: DB,
    q: str = Query("", max_length=100),
    platform: str = Query("", max_length=40),
    review_status: Literal["", "pending", "reviewed", "rejected"] = "",
    document_id: UUID | None = None,
    offset: int = Query(0, ge=0, le=1000000),
    limit: int = Query(20, ge=1, le=100),
):
    decision = (
        select(AtomicReview.decision)
        .where(AtomicReview.entry_id == AtomicEntry.id)
        .order_by(AtomicReview.sequence.desc())
        .limit(1)
        .correlate(AtomicEntry)
        .scalar_subquery()
    )
    query = select(AtomicEntry, AtomicDocument).join(
        AtomicDocument, AtomicDocument.id == AtomicEntry.document_id
    )
    if q:
        query = query.where(
            or_(
                AtomicEntry.name.icontains(q, autoescape=True),
                AtomicEntry.guid.icontains(q, autoescape=True),
                AtomicDocument.technique_id.icontains(q, autoescape=True),
                AtomicDocument.source_commit.icontains(q, autoescape=True),
            )
        )
    if platform:
        query = query.where(platform == any_(AtomicEntry.platforms))
    if review_status:
        query = query.where(func.coalesce(decision, "pending") == review_status)
    if document_id:
        query = query.where(AtomicDocument.id == str(document_id))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.execute(
        query.options(defer(AtomicEntry.metadata_projection))
        .order_by(AtomicDocument.created_at.desc(), AtomicDocument.id, AtomicEntry.guid)
        .offset(offset)
        .limit(limit)
    )
    return {
        "items": [summary(db, entry, document) for entry, document in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
        "limitation": LIMITATION,
    }


@router.get("/entries/{entry_id}")
def detail(entry_id: UUID, user: Viewer, db: DB):
    entry = entry_or_404(db, entry_id)
    result = summary(db, entry, db.get(AtomicDocument, entry.document_id))
    return {
        **entry.metadata_projection,
        **result,
        "latest_review": review_record(latest(db, entry.id)),
        "limitation": LIMITATION,
    }


@router.get("/entries/{entry_id}/reviews")
def history(
    entry_id: UUID,
    user: Viewer,
    db: DB,
    offset: int = Query(0, ge=0, le=1000000),
    limit: int = Query(20, ge=1, le=100),
):
    entry = entry_or_404(db, entry_id)
    query = select(AtomicReview).where(AtomicReview.entry_id == entry.id)
    rows = db.scalars(query.order_by(AtomicReview.sequence.desc()).offset(offset).limit(limit))
    return {
        "items": [review_record(row) for row in rows],
        "total": db.scalar(select(func.count()).select_from(query.subquery())),
        "offset": offset,
        "limit": limit,
    }


@router.post("/entries/{entry_id}/reviews", status_code=201)
def review(entry_id: UUID, data: Review, user: Admin, db: DB):
    rate_limit("atomic-review:" + user.id, limit=30)
    entry = entry_or_404(db, entry_id)
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || :identity, 1313))"),
        {"identity": ":atomic-review:" + entry.id},
    )
    previous = latest(db, entry.id)
    sequence = previous.sequence if previous else 0
    if sequence != data.expected_sequence:
        raise HTTPException(409, "Revisão Atomic alterada; recarregue antes de decidir.")
    row = AtomicReview(
        entry_id=entry.id,
        sequence=sequence + 1,
        decision=data.decision,
        note=data.note,
        reviewed_by=user.id,
    )
    db.add(row)
    db.flush()
    audit(
        db,
        user.id,
        "atomic.metadata_review",
        entry.id,
        review_id=row.id,
        sequence=row.sequence,
        decision=row.decision,
    )
    db.commit()
    return {
        "review": review_record(row),
        "approved": False,
        "executable": False,
        "available_for_new_scope": False,
        "limitation": LIMITATION,
    }
