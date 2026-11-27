import copy
from datetime import UTC, datetime, timedelta

import pytest
from aegis.operations import retention as r

AT = datetime(2026, 11, 27, tzinfo=UTC)
POLICY = {"format": r.POLICY_FORMAT, "retain_days": 30, "minimum_snapshots": 7, "legal_holds": []}


def records(count=10):
    return [
        {
            "id": "20260901T000000Z-" + f"{i:032x}",
            "created_at": (AT - timedelta(days=40 + i)).isoformat(),
            "snapshot_sha256": f"{i:064x}",
            "complete": True,
            "restore_verified": True,
            "bytes": i + 10,
            "files": {"database.dump": {"sha256": "a" * 64, "bytes": i + 10}},
        }
        for i in range(count)
    ]


def plan(rows, policy=POLICY):
    return r.plan(
        rows,
        policy,
        store_id="a" * 32,
        at=AT.isoformat(),
        expires_at=(AT + timedelta(minutes=10)).isoformat(),
    )


def test_policy_is_explicit_bounded_and_cannot_reduce_existing_safety_floor():
    for value in (
        {},
        {**POLICY, "retain_days": 29},
        {**POLICY, "minimum_snapshots": 6},
        {**POLICY, "minimum_snapshots": True},
        {**POLICY, "extra": True},
        {**POLICY, "legal_holds": ["../escape"]},
    ):
        with pytest.raises((ValueError, TypeError)):
            r.policy(value)


def test_minimum_age_counts_bytes_reasons_hash_and_no_mutation():
    rows = records()
    original = copy.deepcopy(rows)
    value = plan(rows)
    assert rows == original
    assert [x["action"] for x in value["members"]] == ["keep"] * 7 + [
        "remove_enrolled_plaintext_copy"
    ] * 3
    assert value["candidate_bytes"] == sum(x["bytes"] for x in rows[7:])
    assert value["bytes"] == sum(x["bytes"] for x in rows)
    assert value["distinct_verified_snapshots"] == 10
    assert plan(list(reversed(rows))) == value
    assert not value["deletion_performed"]
    r.check_plan(value, value["sha256"], at=AT.isoformat())
    changed = copy.deepcopy(value)
    changed["members"][0]["files"]["database.dump"]["sha256"] = "b" * 64
    with pytest.raises(ValueError, match="hash"):
        r.check_plan(changed, value["sha256"], at=AT.isoformat())


def test_duplicates_incomplete_and_unverified_never_fill_minimum():
    rows = records()
    rows[0]["snapshot_sha256"] = rows[1]["snapshot_sha256"]
    rows[2]["complete"] = False
    rows[3]["restore_verified"] = False
    value = plan(rows)
    assert value["distinct_verified_snapshots"] == 7
    assert all(x["action"] == "keep" for x in value["members"])


def test_legal_hold_and_recent_snapshot_preserved_even_above_minimum():
    rows = records()
    rows[8]["created_at"] = AT.isoformat()
    value = plan(rows, {**POLICY, "legal_holds": [rows[9]["id"]]})
    assert "within_retention_window" in value["members"][8]["reasons"]
    assert value["members"][9]["reasons"] == ["legal_hold"]
    assert value["members"][9]["action"] == "keep"


def test_expiry_policy_and_set_drift_require_new_plan():
    value = plan(records())
    with pytest.raises(ValueError, match="expired"):
        r.check_plan(value, value["sha256"], at=value["expires_at"])
    assert plan(records()[:-1])["sha256"] != value["sha256"]
    assert plan(records(), {**POLICY, "retain_days": 31})["sha256"] != value["sha256"]
    with pytest.raises(ValueError, match="one hour"):
        r.plan(
            [],
            POLICY,
            store_id="a" * 32,
            at=AT.isoformat(),
            expires_at=(AT + timedelta(hours=2)).isoformat(),
        )


def test_categories_preserve_relationships_without_inventing_row_sizes():
    tables = {
        name: {"rows": 1, "sha256": "a" * 64}
        for name in [
            "telemetry_events",
            "detection_evidence",
            "runner_receipts",
            "audit_events",
            "scheduled_reports",
            "approvals",
            "attack_catalog_releases",
        ]
    }
    groups = r.database_categories({"inventory": {"tables": tables}})
    assert groups["evidence"]["tables"] == {"detection_evidence": 1}
    assert groups["context"]["rows"] == 2
    assert all(
        g["bytes"] is None and g["action"] == "preserve_in_complete_snapshot"
        for g in groups.values()
    )
