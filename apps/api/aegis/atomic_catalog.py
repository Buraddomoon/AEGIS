"""Offline Atomic version storage; separate from the executable allowlist."""

import hashlib
import re

import yaml
from sqlalchemy import select, text

from aegis.integrations.yaml_import import AtomicMetadataProvider
from aegis.models import AtomicDocument, AtomicEntry
from aegis.security import audit

SOURCE = "https://github.com/redcanaryco/atomic-red-team/blob/"


class AtomicError(ValueError):
    pass


def import_document(db, content, commit, expected_sha256, actor):
    if (
        not isinstance(content, str)
        or len(content.encode()) > 65536
        or not isinstance(commit, str)
        or not re.fullmatch(r"[a-f0-9]{40}", commit)
        or not isinstance(expected_sha256, str)
        or hashlib.sha256(content.encode()).hexdigest() != expected_sha256
    ):
        raise AtomicError("Commit, hash ou limite Atomic inválido.")
    try:
        entries = AtomicMetadataProvider().import_metadata(content)
    except (ValueError, TypeError, yaml.YAMLError):
        raise AtomicError(
            "Documento Atomic inválido; revise formato, identidades e limites."
        ) from None
    technique = entries[0]["technique_id"]
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || :identity, 1313))"),
        {"identity": f":atomic:{commit}:{technique}"},
    )
    previous = db.scalar(
        select(AtomicDocument).where(
            AtomicDocument.source_commit == commit, AtomicDocument.technique_id == technique
        )
    )
    if previous:
        if previous.source_sha256 != expected_sha256:
            raise AtomicError("Mesmo commit/técnica com bytes diferentes; versão preservada.")
        audit(db, actor, "atomic.import_unchanged", previous.id)
        return previous, True
    document = AtomicDocument(
        source_commit=commit,
        source_sha256=expected_sha256,
        technique_id=technique,
        imported_by=actor,
    )
    db.add(document)
    db.flush()
    for entry in entries:
        db.add(
            AtomicEntry(
                document_id=document.id,
                guid=entry["guid"],
                name=entry["name"],
                platforms=entry["platforms"],
                metadata_projection=entry,
            )
        )
    audit(
        db, actor, "atomic.import", document.id, count=len(entries), source_sha256=expected_sha256
    )
    db.flush()
    return document, False


def source(document):
    path = f"atomics/{document.technique_id}/{document.technique_id}.yaml"
    return {
        "document_id": document.id,
        "source_commit": document.source_commit,
        "source_sha256": document.source_sha256,
        "source_path": path,
        "source_url": SOURCE + document.source_commit + "/" + path,
        "provenance": "operator_supplied",
        "imported_at": document.created_at,
        "imported_by": document.imported_by,
    }
