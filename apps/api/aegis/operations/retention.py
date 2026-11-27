"""Host-only retention of complete, explicitly enrolled snapshot copies.

No API/worker imports, SQL DELETE, automatic TTL, global prune or original source
mutation. All database categories stay together in the immutable database dump.
"""

import re
from datetime import UTC, datetime, timedelta

from aegis.domain.validation import digest
from aegis.operations import backup, vault

FORMAT = "aegis-history-retention/1"
POLICY_FORMAT = "aegis-history-retention-policy/1"
CATEGORIES = {
    "events": {"telemetry_events", "telemetry_collections", "execution_steps"},
    "evidence": {"validation_results", "detection_evidence"},
    "audit": {"audit_events"},
    "receipts": {"runner_receipts", "runner_cleanups", "runner_dispatches"},
    "reports": {"scheduled_reports"},
}


def instant(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Retention timestamps require timezone")
    return parsed.astimezone(UTC)


def policy(value):
    """The operator supplies an explicit policy; defaults never authorize effects."""
    if set(value) != {"format", "retain_days", "minimum_snapshots", "legal_holds"}:
        raise ValueError("Explicit retention policy fields required")
    if (
        value["format"] != POLICY_FORMAT
        or type(value["retain_days"]) is not int
        or not 30 <= value["retain_days"] <= 36500
        or type(value["minimum_snapshots"]) is not int
        or not 7 <= value["minimum_snapshots"] <= 1000
        or not isinstance(value["legal_holds"], list)
        or len(value["legal_holds"]) > 1000
        or len(set(value["legal_holds"])) != len(value["legal_holds"])
        or any(not re.fullmatch(vault.BACKUP_ID, x) for x in value["legal_holds"])
    ):
        raise ValueError("Retention policy outside reviewed bounds")
    return {**value, "legal_holds": sorted(value["legal_holds"])}


def database_categories(manifest):
    """Counts from the backup inventory, never inferred sizes of database rows."""
    groups = {name: {} for name in (*CATEGORIES, "context")}
    for table, entry in manifest["inventory"]["tables"].items():
        group = next((name for name, tables in CATEGORIES.items() if table in tables), "context")
        if type(entry["rows"]) is not int or entry["rows"] < 0:
            raise ValueError("Invalid table count")
        groups[group][table] = entry["rows"]
    return {
        name: {
            "tables": tables,
            "rows": sum(tables.values()),
            "bytes": None,
            "action": "preserve_in_complete_snapshot",
            "reason": "immutable_history_and_cross_references",
        }
        for name, tables in groups.items()
    }


def plan(records, selected_policy, *, store_id, at, expires_at):
    """Pure review artifact. Hash includes *all* members, holds and verification.

    A snapshot means a distinct complete inventory, not a second envelope/ID of
    the same data. Unverified/incomplete copies never satisfy the safety floor.
    """
    selected_policy = policy(selected_policy)
    at, expires_at = instant(at), instant(expires_at)
    if not at < expires_at <= at + timedelta(hours=1):
        raise ValueError("Plan validity must be positive and at most one hour")
    if not re.fullmatch(r"[a-f0-9]{32}", store_id):
        raise ValueError("Invalid retention store ID")
    rows = sorted(records, key=lambda r: r["id"])
    if len({r["id"] for r in rows}) != len(rows):
        raise ValueError("Duplicate snapshot ID")
    verified = {}
    for row in rows:
        if not re.fullmatch(vault.BACKUP_ID, row["id"]):
            raise ValueError("Invalid snapshot ID")
        if row["complete"] and row["restore_verified"]:
            identity = row["snapshot_sha256"]
            created = instant(row["created_at"])
            if created > at:
                raise ValueError("Future snapshot timestamp")
            verified[identity] = max(verified.get(identity, created), created)
    newest = sorted(verified, key=lambda identity: (verified[identity], identity), reverse=True)
    minimum = set(newest[: selected_policy["minimum_snapshots"]])
    result = []
    for row in rows:
        reasons = []
        if row["id"] in selected_policy["legal_holds"]:
            reasons.append("legal_hold")
        if not row["complete"]:
            reasons.append("incomplete_or_unsupported_snapshot")
        if not row["restore_verified"]:
            reasons.append("archive_restore_not_verified")
        if row["complete"]:
            if instant(row["created_at"]) >= at - timedelta(days=selected_policy["retain_days"]):
                reasons.append("within_retention_window")
            if row["snapshot_sha256"] in minimum:
                reasons.append("minimum_distinct_verified_snapshots")
        result.append(
            {
                **row,
                "action": "keep" if reasons else "remove_enrolled_plaintext_copy",
                "reasons": reasons or ["archived_verified_older_than_policy"],
            }
        )
    body = {
        "format": FORMAT,
        "store_id": store_id,
        "created_at": at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "policy": selected_policy,
        "members": result,
        "distinct_verified_snapshots": len(verified),
        "copies": len(result),
        "bytes": sum(r["bytes"] for r in result),
        "candidate_bytes": sum(r["bytes"] for r in result if r["action"] != "keep"),
        "deletion_performed": False,
        "scope": "enrolled_plaintext_copies_only_archives_and_source_databases_preserved",
        "limitations": [
            "Database categories are indivisible; no row TTL or SQL deletion",
            "Row sizes are unknown; byte counts describe complete files only",
            "Local hashes and receipts are not signatures or independent custody",
            "Fresh isolated restore and explicit approval required before each deletion",
        ],
    }
    return {**body, "sha256": digest(body)}


def check_plan(value, expected_sha256, *, at):
    body = {k: v for k, v in value.items() if k != "sha256"}
    if (
        not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        or value.get("format") != FORMAT
        or value.get("sha256") != expected_sha256
        or digest(body) != expected_sha256
    ):
        raise ValueError("Retention plan hash mismatch")
    current = instant(at)
    if not instant(value["created_at"]) <= current < instant(value["expires_at"]):
        raise ValueError("Retention plan expired or not yet valid")
    return value


def manifest_summary(value, identifier):
    if (
        value.get("format") != backup.FORMAT
        or value.get("id") != identifier
        or value.get("inventory", {}).get("format") != backup.INVENTORY_FORMAT
    ):
        raise ValueError("Unsupported snapshot manifest")
    instant(value["created_at"])
    return {
        "created_at": value["created_at"],
        "snapshot_sha256": digest(value["inventory"]),
        "categories": database_categories(value),
    }
