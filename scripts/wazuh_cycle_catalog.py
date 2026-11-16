"""Owner-helper primitives for explicit Wazuh legacy catalog adoption.

No CLI, connection discovery, seed, startup or automatic commit. The native
coordinator must bind the supplied session to the reviewed original volume and
obtain specific approval before calling apply. Tests use disposable schemas.
"""

from aegis.domain.validation import digest

FORMAT = "aegis-wazuh-catalog-adoption/1"
REVISION = "b7f3c2d91a06"
CATALOG_TABLES = {"attack_catalog_state", "attack_catalog_releases"}
MAX_TABLE_ROWS = 100000


def _row_hashes(db, name):
    from sqlalchemy import text

    rows = []
    for row in db.scalars(
        text(f'SELECT to_jsonb(t) FROM ONLY "{name}" t LIMIT {MAX_TABLE_ROWS + 1}')
    ):
        rows.append(digest(row))
    if len(rows) > MAX_TABLE_ROWS:
        raise ValueError("wazuh_catalog_inventory_limit")
    return sorted(rows)


def _snapshot(db):
    from aegis.models import Base

    # Only code-owned table names. JSON stays in memory; no rows or verifiers
    # appear in the proposal. Hash every old table, including users/evidence.
    return {
        name: digest(_row_hashes(db, name))
        for name in sorted(Base.metadata.tables)
        if name not in CATALOG_TABLES
    }


def _review(db, raw, license_raw):
    from aegis.catalog.document import bundled_document
    from aegis.catalog.store import projection
    from sqlalchemy import text

    if db.scalar(text("SELECT version_num FROM alembic_version")) != REVISION:
        raise ValueError("wazuh_catalog_explicit_b7_upgrade_required")
    for name in CATALOG_TABLES:
        if db.scalar(text(f'SELECT count(*) FROM ONLY "{name}"')):
            raise ValueError("wazuh_catalog_must_be_uninitialized")
    if db.scalar(
        text(
            "SELECT count(*) FROM laboratories WHERE (kind='linux' AND authorized) OR active_run_id IS NOT NULL"
        )
    ):
        raise ValueError("wazuh_catalog_revoked_idle_labs_required")
    if db.scalar(
        text(
            "SELECT count(*) FROM campaign_runs WHERE state NOT IN ('COMPLETED','FAILED','TIMED_OUT','CANCELLED','REJECTED')"
        )
    ):
        raise ValueError("wazuh_catalog_pending_runs")
    if db.scalar(text("SELECT count(*) FROM schedules WHERE state='ACTIVE'")) or db.scalar(
        text("SELECT count(*) FROM scheduled_reports WHERE state IN ('PENDING','PROCESSING')")
    ):
        raise ValueError("wazuh_catalog_pending_automation")
    document = bundled_document(raw, license_raw)
    current = projection(db)
    expected = {
        item.id: {**item.model_dump(), "present_in_current": True} for item in document.techniques
    }
    if not current or current != expected:
        raise ValueError("wazuh_catalog_legacy_projection_differs")
    return document, {
        "format": FORMAT,
        "schema": REVISION,
        "release_id": document.identity,
        "source_sha256": document.source_sha256,
        "license_sha256": document.license_sha256,
        "projection_sha256": digest(current),
        "preserved_tables": _snapshot(db),
        "effects_authorized": False,
    }


def plan(db, raw: bytes, license_raw: bytes):
    """Requires a fresh session. Read-only and repeatable; never commits."""
    from sqlalchemy import text

    db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
    db.execute(text("SET TRANSACTION READ ONLY"))
    db.execute(text("SET LOCAL statement_timeout='15s'"))
    db.execute(text("SET LOCAL row_security=off"))
    _, proposal = _review(db, raw, license_raw)
    return proposal


def apply(db, raw: bytes, license_raw: bytes, proposal: dict, expected_sha256: str):
    """Stage only version metadata and its audit row; caller controls commit.

    A stale proposal aborts before writes. Locks cover historical rows and
    metadata through the caller's transaction; failure requires rollback.
    """
    from aegis.catalog.store import initialize, projection
    from aegis.models import Base
    from sqlalchemy import text

    if digest(proposal) != expected_sha256:
        raise ValueError("wazuh_catalog_proposal_integrity_mismatch")
    db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
    db.execute(text("SET LOCAL statement_timeout='15s'"))
    db.execute(text("SET LOCAL lock_timeout='3s'"))
    db.execute(text("SET LOCAL row_security=off"))
    names = ["alembic_version", *sorted(Base.metadata.tables)]
    db.execute(
        text(
            "LOCK TABLE " + ", ".join(f'ONLY "{name}"' for name in names) + " IN SHARE MODE NOWAIT"
        )
    )
    document, current = _review(db, raw, license_raw)
    if current != proposal:
        raise ValueError("wazuh_catalog_proposal_stale")
    before = current["preserved_tables"]
    audits_before = db.scalar(text("SELECT count(*) FROM audit_events"))
    audit_rows_before = set(_row_hashes(db, "audit_events"))
    state = initialize(db, raw, license_raw)
    after = _snapshot(db)
    # Only the explicit bootstrap audit entry may differ. No old technique or
    # historical run/account/receipt/approval can be rewritten to pass the gate.
    if (
        {key: value for key, value in after.items() if key != "audit_events"}
        != {key: value for key, value in before.items() if key != "audit_events"}
        or state.release_id != document.identity
        or digest(projection(db)) != proposal["projection_sha256"]
        or db.scalar(text("SELECT count(*) FROM attack_catalog_releases")) != 1
        or db.scalar(text("SELECT count(*) FROM attack_catalog_state")) != 1
        or db.scalar(text("SELECT count(*) FROM audit_events")) != audits_before + 1
        or not audit_rows_before <= set(_row_hashes(db, "audit_events"))
    ):
        raise ValueError("wazuh_catalog_preservation_unconfirmed")
    return {
        "status": "wazuh_catalog_adoption_staged_commit_required",
        "proposal_sha256": expected_sha256,
        "release_id": document.identity,
        "preserved_tables_sha256": digest(
            {key: value for key, value in after.items() if key != "audit_events"}
        ),
        "techniques_rewritten": False,
        "general_seed_executed": False,
    }
