"""Bounded, read-only scope selection shared by coverage and report views."""

import re
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Literal

from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from aegis.catalog import store as catalog
from aegis.domain.validation import digest
from aegis.models import AttackCatalogRelease, CampaignRun

MAX_RUNS = 5000
RELEASE_PATTERN = r"^(all|current|legacy|[a-f0-9]{64})$"


class Selection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    mode: Literal["demo", "linux"] = "demo"
    catalog_release: str = Field(default="all", pattern=RELEASE_PATTERN)
    requested_from: AwareDatetime | None = None
    requested_before: AwareDatetime | None = None

    @field_validator("requested_from", "requested_before", mode="before")
    @classmethod
    def explicit_timestamp(cls, value):
        if value is None or isinstance(value, datetime):
            return value
        if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}[Tt].+(?:[Zz]|[+-]\d{2}:\d{2})", value
        ):
            raise ValueError("Use data/hora RFC3339 com offset explícito.")
        return value

    @field_validator("requested_from", "requested_before")
    @classmethod
    def utc(cls, value):
        try:
            return value.astimezone(UTC) if value is not None else None
        except (OverflowError, ValueError):
            raise ValueError("Timestamp fora do intervalo UTC suportado.") from None

    @model_validator(mode="after")
    def ordered(self):
        if self.requested_from and self.requested_before:
            if self.requested_from >= self.requested_before:
                raise ValueError("O início deve ser anterior ao limite final exclusivo.")
        return self


@contextmanager
def read_snapshot(db: Session):
    # Authentication already queried its transaction; use a separate one with
    # isolation selected before the first statement, on the same trusted bind.
    with Session(db.get_bind(), expire_on_commit=False) as snapshot:
        snapshot.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        snapshot.execute(text("SET TRANSACTION READ ONLY"))
        snapshot.execute(text("SET LOCAL statement_timeout='15s'"))
        yield snapshot


def release_reference(record):
    return {
        "release_id": record.id,
        "version": record.dataset_version,
        "provenance": record.provenance,
        "source_sha256": record.source_sha256,
        "source_commit": record.source_commit,
    }


def catalog_identity(scope):
    context = scope.get("attack_catalog")
    return context.get("release_id") if isinstance(context, dict) else None


def resolve(db: Session, selection: Selection):
    current = catalog.reference(db)
    chosen = selection.catalog_release
    identity = current["release_id"] if chosen in ("all", "current") else chosen
    reference, active = None, None
    if chosen != "legacy":
        record = db.get(AttackCatalogRelease, identity)
        if record is None:
            raise HTTPException(404, "Release ATT&CK não encontrada.")
        document = catalog.checked(record)
        active = {t.id for t in document.techniques if not t.revoked and not t.deprecated}
        reference = release_reference(record)
    scope = {
        "version": "aegis-coverage-scope/1",
        **selection.model_dump(mode="json"),
        "resolved_catalog_release_id": identity if chosen not in ("all", "legacy") else None,
        "evaluation_catalog": reference,
        "time_basis": "CampaignRun.created_at",
        "interval": "[requested_from, requested_before)",
    }
    return scope, digest(scope), current, active


def run_query(scope):
    identity = CampaignRun.scope["attack_catalog"]["release_id"].as_string()
    query = select(CampaignRun).where(CampaignRun.synthetic.is_(scope["mode"] == "demo"))
    if scope["catalog_release"] == "legacy":
        query = query.where(identity.is_(None) | (identity == ""))
    elif scope["resolved_catalog_release_id"]:
        query = query.where(identity == scope["resolved_catalog_release_id"])
    if scope["requested_from"]:
        query = query.where(
            CampaignRun.created_at >= datetime.fromisoformat(scope["requested_from"])
        )
    if scope["requested_before"]:
        query = query.where(
            CampaignRun.created_at < datetime.fromisoformat(scope["requested_before"])
        )
    return query.order_by(CampaignRun.created_at, CampaignRun.id)


def bounded_runs(db, scope):
    rows = list(db.scalars(run_query(scope).limit(MAX_RUNS + 1)))
    if len(rows) > MAX_RUNS:
        raise HTTPException(422, f"Recorte excede {MAX_RUNS} execuções; reduza o período/release.")
    return rows


def run_count(db, query):
    limited = query.with_only_columns(CampaignRun.id).order_by(None).limit(MAX_RUNS + 1)
    count = db.scalar(select(func.count()).select_from(limited.subquery()))
    if count > MAX_RUNS:
        raise HTTPException(422, f"Recorte excede {MAX_RUNS} execuções; reduza o período/release.")
    return count
