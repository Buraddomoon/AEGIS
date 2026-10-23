"""Transactional publication, provenance and scope references for ATT&CK."""

from sqlalchemy import func, select, text

from aegis.catalog.document import Document, Technique, bundled_document
from aegis.config import require_normal_operation
from aegis.domain.states import TERMINAL
from aegis.domain.validation import digest
from aegis.models import (
    AttackCatalogRelease,
    AttackCatalogState,
    AttackTechnique,
    CampaignRun,
    Laboratory,
    Schedule,
    TestDefinition,
    User,
    now,
)
from aegis.security import audit

LOCK_KEY = 0x414547495341544B  # Seed for schema-local catalog advisory locks.
PLAN_FORMAT = "aegis-attack-catalog-plan/1"
FIELDS = tuple(Technique.model_fields)


class CatalogError(ValueError):
    pass


def version(value):
    return tuple(int(p) for p in value.split("."))


def shared(db):
    # Row locks would require UPDATE, intentionally denied to API/worker roles.
    db.execute(
        text("SELECT pg_advisory_xact_lock_shared(hashtextextended(current_schema(), :key))"),
        {"key": LOCK_KEY},
    )


def projection(db):
    return {
        t.id: {
            **{key: getattr(t, key) for key in FIELDS},
            "present_in_current": t.present_in_current,
        }
        for t in db.scalars(select(AttackTechnique).order_by(AttackTechnique.id))
    }


def add_release(db, document, actor):
    record = AttackCatalogRelease(
        id=document.identity,
        dataset_version=document.version,
        provenance=document.provenance,
        source_url=document.source_url,
        source_commit=document.source_commit,
        source_sha256=document.source_sha256,
        license_sha256=document.license_sha256,
        document=document.model_dump(mode="json"),
        applied_by=actor,
    )
    db.add(record)
    db.flush()
    return record


def initialize(db, raw, license_raw):
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(), :key))"),
        {"key": LOCK_KEY},
    )
    state = db.get(AttackCatalogState, 1)
    if state:
        return state
    document = bundled_document(raw, license_raw)
    current = projection(db)
    expected = {t.id: {**t.model_dump(), "present_in_current": True} for t in document.techniques}
    if current and current != expected:
        raise CatalogError(
            "Catálogo legado diverge do snapshot distribuído; revisão manual necessária."
        )
    if not current:
        db.add_all(
            AttackTechnique(**entry.model_dump(), present_in_current=True)
            for entry in document.techniques
        )
        db.flush()
    release = add_release(db, document, None)
    state = AttackCatalogState(id=1, release_id=release.id)
    db.add(state)
    audit(
        db,
        None,
        "catalog.bootstrap",
        release.id,
        version=release.dataset_version,
        provenance="bundled",
    )
    db.flush()
    return state


def reference(db):
    shared(db)
    row = (
        db.execute(
            select(
                AttackCatalogRelease.id,
                AttackCatalogRelease.dataset_version,
                AttackCatalogRelease.provenance,
                AttackCatalogRelease.source_sha256,
                AttackCatalogRelease.source_commit,
            )
            .join(AttackCatalogState, AttackCatalogState.release_id == AttackCatalogRelease.id)
            .where(AttackCatalogState.id == 1)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise CatalogError(
            "Catálogo ATT&CK ainda não inicializado; revisão de implantação necessária."
        )
    return {
        "release_id": row["id"],
        "version": row["dataset_version"],
        "provenance": row["provenance"],
        "source_sha256": row["source_sha256"],
        "source_commit": row["source_commit"],
    }


def lifecycle(t):
    if not t.present_in_current:
        return "absent"
    if t.revoked:
        return "revoked"
    if t.deprecated:
        return "deprecated"
    return "active"


def checked(record):
    document = Document.model_validate(record.document)
    if document.identity != record.id or any(
        getattr(record, k) != getattr(document, v)
        for k, v in (
            ("dataset_version", "version"),
            ("provenance", "provenance"),
            ("source_sha256", "source_sha256"),
            ("license_sha256", "license_sha256"),
            ("source_url", "source_url"),
            ("source_commit", "source_commit"),
        )
    ):
        raise CatalogError("Integridade do histórico ATT&CK divergente.")
    return document


def logical(document):
    data = document.model_dump(mode="json")
    for key in ("source_commit", "source_url"):
        data.pop(key)
    return digest(data)


def plan(db, document, license_sha256):
    shared(db)
    connection = db.connection()
    database, schema = connection.execute(text("SELECT current_database(), current_schema()")).one()
    target = connection.engine.url
    database_scope = {
        "host": target.host or "local-socket",
        "port": target.port or 5432,
        "database": database,
        "schema": schema,
    }
    document = Document.model_validate(document.model_dump())
    if document.provenance != "official_commit":
        raise CatalogError("Somente candidatos oficiais fixados por commit podem ser publicados.")
    state = db.get(AttackCatalogState, 1)
    if not state:
        raise CatalogError("Inicialize/revise o snapshot legado antes de planejar uma atualização.")
    records = list(db.scalars(select(AttackCatalogRelease)))
    documents = {r.id: checked(r) for r in records}
    current = documents[state.release_id]
    rows = projection(db)
    expected = {}
    ordered = sorted(
        records,
        key=lambda r: (
            version(r.dataset_version),
            r.provenance == "official_commit",
            r.created_at,
            r.id,
        ),
    )
    for release in ordered:
        expected.update({t.id: t.model_dump() for t in documents[release.id].techniques})
    current_ids = {t.id for t in current.techniques}
    expected = {
        key: {**item, "present_in_current": key in current_ids} for key, item in expected.items()
    }
    proposed = {key: {**item, "present_in_current": False} for key, item in rows.items()}
    proposed.update(
        {t.id: {**t.model_dump(), "present_in_current": True} for t in document.techniques}
    )
    blockers = []
    if rows != expected or version(current.version) != max(
        version(d.version) for d in documents.values()
    ):
        blockers.append("projection_or_state_drift")
    if document.license_sha256 != license_sha256:
        blockers.append("license_review_required")
    if version(document.version) < version(current.version):
        blockers.append("catalog_downgrade")
    if (
        current.provenance == "bundled"
        and document.version == current.version
        and document.source_sha256 != current.source_sha256
    ):
        blockers.append("same_version_source_changed")
    conflicts = [
        d
        for d in documents.values()
        if d.provenance == "official_commit"
        and d.version == document.version
        and logical(d) != logical(document)
    ]
    if conflicts:
        blockers.append("immutable_version_conflict")
    old_stix = {item["stix_id"]: key for key, item in rows.items()}
    if any(
        (t.id in rows and rows[t.id]["stix_id"] != t.stix_id)
        or old_stix.get(t.stix_id, t.id) != t.id
        for t in document.techniques
    ):
        blockers.append("technique_identity_conflict")
    pending = db.scalar(
        select(func.count()).select_from(CampaignRun).where(CampaignRun.state.not_in(TERMINAL))
    )
    reservations = db.scalar(
        select(func.count()).select_from(Laboratory).where(Laboratory.active_run_id.is_not(None))
    )
    schedules = db.scalar(
        select(func.count())
        .select_from(Schedule)
        .where(Schedule.state.in_(("ACTIVE", "PAUSED", "PENDING_APPROVAL")))
    )
    if pending or reservations or schedules:
        blockers.append("execution_or_schedule_in_scope")
    tests = [
        {"id": t.id, "version": t.version, "technique_id": t.technique_id, "approved": t.approved}
        for t in db.scalars(select(TestDefinition).order_by(TestDefinition.id))
    ]
    changes = []
    for key in sorted(proposed):
        old, new = rows.get(key), proposed[key]
        fields = [field for field in new if old is None or old[field] != new[field]]
        if fields:
            changes.append(
                {
                    "id": key,
                    "name": new["name"],
                    "kind": "added"
                    if old is None
                    else "absent"
                    if not new["present_in_current"]
                    else "changed",
                    "fields": fields,
                    "before_sha256": digest(old) if old else None,
                    "after_sha256": digest(new),
                }
            )
    impacted = [
        t
        for t in tests
        if t["technique_id"]
        and (
            not proposed[t["technique_id"]]["present_in_current"]
            or proposed[t["technique_id"]]["revoked"]
            or proposed[t["technique_id"]]["deprecated"]
        )
    ]
    action = (
        "already_applied"
        if current.provenance == "official_commit" and logical(current) == logical(document)
        else "apply"
    )
    result = {
        "format": PLAN_FORMAT,
        "database_scope": database_scope,
        "action": action,
        "base_release_id": current.identity,
        "base_projection_sha256": digest(rows),
        "candidate_id": document.identity,
        "candidate_version": document.version,
        "source_commit": document.source_commit,
        "source_sha256": document.source_sha256,
        "license_sha256": document.license_sha256,
        "changes": changes,
        "counts": {
            "active": sum(
                t["present_in_current"] and not t["revoked"] and not t["deprecated"]
                for t in proposed.values()
            ),
            "added": sum(c["kind"] == "added" for c in changes),
            "changed": sum(c["kind"] == "changed" for c in changes),
            "absent": sum(not t["present_in_current"] for t in proposed.values()),
            "pending_runs": pending,
            "reservations": reservations,
            "resumable_schedules": schedules,
        },
        "test_references": tests,
        "tests_requiring_review": impacted,
        "blockers": blockers,
    }
    return {**result, "plan_sha256": digest(result)}


def apply(db, document, confirmed_hash, actor_id, license_sha256):
    require_normal_operation()
    # Both locks fail immediately: don't wait while holding a lock needed by a
    # scope reader/scheduler/worker using another ordering.
    db.execute(
        text(
            "LOCK TABLE campaign_runs, schedules, laboratories, attack_techniques, attack_catalog_state, attack_catalog_releases IN SHARE ROW EXCLUSIVE MODE NOWAIT"
        )
    )
    if (
        db.scalar(
            text("SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema(), :key))"),
            {"key": LOCK_KEY},
        )
        is not True
    ):
        raise CatalogError("Catálogo em uso; nenhuma alteração aplicada.")
    actor = db.scalar(
        select(User)
        .where(User.id == actor_id)
        .with_for_update(read=True, nowait=True)
        .execution_options(populate_existing=True)
    )
    if not actor or not actor.active or actor.role != "administrator":
        raise CatalogError("Atribuição exige administrador ativo e credencial de implantação.")
    reviewed = plan(db, document, license_sha256)
    if reviewed["plan_sha256"] != confirmed_hash:
        raise CatalogError("Plano mudou; gere e revise um novo plano.")
    if reviewed["blockers"]:
        raise CatalogError("Plano bloqueado; nenhuma atualização aplicada.")
    if reviewed["action"] == "already_applied":
        return {
            "status": "already_applied",
            "release_id": reviewed["base_release_id"],
            "plan_sha256": confirmed_hash,
        }
    new_ids = {t.id for t in document.techniques}
    for technique in db.scalars(select(AttackTechnique)):
        if technique.id not in new_ids:
            technique.present_in_current = False
    for entry in document.techniques:
        row = db.get(AttackTechnique, entry.id)
        if row is None:
            db.add(AttackTechnique(**entry.model_dump(), present_in_current=True))
        else:
            for key, value in entry.model_dump().items():
                setattr(row, key, value)
            row.present_in_current = True
    release = add_release(db, document, actor.id)
    state = db.get(AttackCatalogState, 1)
    state.release_id, state.updated_at = release.id, now()
    audit(
        db,
        actor.id,
        "catalog.apply",
        release.id,
        plan_sha256=confirmed_hash,
        previous_release_id=reviewed["base_release_id"],
        version=document.version,
        source_commit=document.source_commit,
        source_sha256=document.source_sha256,
        tests_requiring_review=[t["id"] for t in reviewed["tests_requiring_review"]],
    )
    db.flush()
    return {"status": "applied", "release_id": release.id, "plan_sha256": confirmed_hash}
