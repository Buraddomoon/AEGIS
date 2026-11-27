import copy
import json

import pytest
from aegis.operations import retention_apply as a
from aegis.operations import retention_store as s
from aegis.operations import vault
from test_retention_policy import AT, POLICY
from test_retention_store import ID, restore_fixture, source_at
from test_retention_store import store as store


@pytest.fixture
def ready(store, tmp_path):
    root, original, key, identity = store
    for number in range(1, 9):
        source = source_at(tmp_path, "20260901T000000Z-" + f"{number:032x}", number)
        s.enroll(root, source)
    for folder in (root / "snapshots").iterdir():
        envelope = s.archive(root, folder.name, key["recipient"])
        s.verify(root, envelope["id"], envelope["ciphertext_sha256"], identity, restore_fixture)
    plan = s.build_plan(root, at=AT.isoformat())
    auth = {
        "format": a.APPROVAL_FORMAT,
        "store_id": plan["store_id"],
        "plan_sha256": plan["sha256"],
        "decision": "approve_enrolled_plaintext_removal",
        "approved_by": "fixture-only",
        "approved_at": AT.isoformat(),
        "expires_at": plan["expires_at"],
    }
    return root, original, identity, plan, auth


def execute(ready, **kwargs):
    root, _, identity, plan, auth = ready
    options = {
        "authorization": auth,
        "identity": identity,
        "restore": restore_fixture,
        "confirm": True,
        "dry_run": False,
        "clock": lambda: AT.isoformat(),
    }
    options.update(kwargs)
    return a.apply(root, plan, plan["sha256"], **options)


def test_dry_run_is_read_only_and_never_requests_key_or_starts_restore(ready):
    root, _, _, plan, _ = ready
    before = {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = a.apply(root, plan, plan["sha256"], clock=lambda: AT.isoformat())
    assert result["status"] == "dry_run" and not result["deletion_performed"]
    assert len(result["candidate_ids"]) == 2
    assert before == {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_apply_freshly_restores_all_candidates_and_removes_only_owned_copies_once(ready):
    root, original, _, plan, _ = ready
    before = s.files(original)
    archives = {str(p): p.read_bytes() for p in (root / "archives").rglob("*") if p.is_file()}
    calls = []

    def restore(identifier, folder):
        assert len(list((root / "snapshots").iterdir())) == 9
        calls.append(identifier)
        return restore_fixture(identifier, folder)

    result = execute(ready, restore=restore)
    assert result["status"] == "applied"
    assert len(result["removed_ids"]) == len(calls) == 2
    assert len(list((root / "snapshots").iterdir())) == 7
    assert s.files(original) == before
    assert archives == {
        str(p): p.read_bytes() for p in (root / "archives").rglob("*") if p.is_file()
    }
    assert s.build_plan(root, at=AT.isoformat())["distinct_verified_snapshots"] == 7
    assert list((root / "work").iterdir()) == []
    with pytest.raises(ValueError):
        execute(ready)
    audit = s.read_json(root / "receipts" / (plan["sha256"] + "-result.json"))
    assert audit["status"] == "applied" and len(audit["fresh_restores"]) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("decision", "yes"),
        ("store_id", "0" * 32),
        ("plan_sha256", "0" * 64),
        ("expires_at", AT.isoformat()),
        ("approved_by", ""),
    ],
)
def test_exact_current_approval_is_required(ready, field, value):
    auth = {**ready[4], field: value}
    with pytest.raises(ValueError, match="approval"):
        execute(ready, authorization=auth)
    assert not list((ready[0] / "receipts").iterdir())


def test_generic_confirmation_or_missing_identity_cannot_delete(ready):
    for change in (
        {"confirm": False},
        {"identity": None},
        {"authorization": None},
        {"restore": None},
    ):
        with pytest.raises(ValueError, match="confirmation"):
            execute(ready, **change)
    assert len(list((ready[0] / "snapshots").iterdir())) == 9


@pytest.mark.parametrize("change", ["hold", "file", "new_member", "new_receipt", "owner"])
def test_drift_aborts_before_durable_intent_or_deletion(ready, tmp_path, change):
    root, _, _, plan, _ = ready
    if change == "hold":
        path = root / "policy.json"
        path.write_text(json.dumps({**POLICY, "legal_holds": [plan["members"][-1]["id"]]}))
    elif change == "file":
        (root / "snapshots" / ID / "database.dump").write_bytes(b"drift")
    elif change == "new_member":
        s.enroll(root, source_at(tmp_path, "20260901T000000Z-" + "e" * 32, 10))
    elif change == "new_receipt":
        target = next((root / "archives").iterdir())
        vault.write_json(target / ("verification-" + "e" * 32 + ".json"), {"failed": True})
    else:
        marker = s.read_json(root / "owner.json")
        marker["store_id"] = "0" * 32
        (root / "owner.json").write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="drift"):
        execute(ready)
    assert not list((root / "receipts").iterdir())


def test_restore_failure_keeps_every_copy_and_consumes_plan_with_failed_audit(ready):
    def failed(identifier, folder):
        return {**restore_fixture(identifier, folder), "clone_removed": False}

    with pytest.raises(ValueError, match="cleanup"):
        execute(ready, restore=failed)
    root, _, _, plan, _ = ready
    assert len(list((root / "snapshots").iterdir())) == 9
    result = s.read_json(root / "receipts" / (plan["sha256"] + "-result.json"))
    assert result["status"] == "failed_or_interrupted" and not result["deletion_started"]
    with pytest.raises(ValueError, match="consumed"):
        execute(ready)


def test_expiration_during_fresh_restore_aborts_before_deleting(ready):
    current = [AT.isoformat()]

    def slow(identifier, folder):
        current[0] = ready[3]["expires_at"]
        return restore_fixture(identifier, folder)

    with pytest.raises(ValueError):
        execute(ready, restore=slow, clock=lambda: current[0])
    assert len(list((ready[0] / "snapshots").iterdir())) == 9


def test_drift_during_restore_is_rechecked_for_the_entire_plan(ready):
    def changed(identifier, folder):
        path = ready[0] / "snapshots" / ID / "database.dump"
        path.write_bytes(b"changed while restoring another member")
        return restore_fixture(identifier, folder)

    with pytest.raises(ValueError, match="drift"):
        execute(ready, restore=changed)
    assert len(list((ready[0] / "snapshots").iterdir())) == 9


def test_removal_failure_keeps_protected_archive_and_audits_partial_copy(ready, monkeypatch):
    root, _, _, plan, _ = ready
    real = a.os.unlink

    def fail_copy(name, *, dir_fd=None):
        if (
            dir_fd is not None
            and "/snapshots/" in a.os.readlink(f"/proc/self/fd/{dir_fd}")
            and name == "manifest.json"
        ):
            raise OSError("fixture removal failure")
        return real(name, dir_fd=dir_fd)

    monkeypatch.setattr(a.os, "unlink", fail_copy)
    with pytest.raises(OSError, match="removal"):
        execute(ready)
    result = s.read_json(root / "receipts" / (plan["sha256"] + "-result.json"))
    assert result["status"] == "failed_or_interrupted" and result["deletion_started"]
    assert not result["removed_ids"]
    assert len(list((root / "archives").iterdir())) == 9
    current = s.build_plan(root, at=AT.isoformat())
    assert any(not x["complete"] and x["action"] == "keep" for x in current["members"])


def test_plan_tampering_never_passes_even_with_matching_local_authorization(ready):
    root, _, identity, plan, auth = ready
    changed = copy.deepcopy(plan)
    changed["members"][0]["action"] = "remove_enrolled_plaintext_copy"
    with pytest.raises(ValueError, match="hash"):
        a.apply(
            root,
            changed,
            plan["sha256"],
            authorization=auth,
            identity=identity,
            restore=restore_fixture,
            confirm=True,
            dry_run=False,
            clock=lambda: AT.isoformat(),
        )


def test_ownership_drift_during_restore_aborts_before_deletion(ready):
    def changed(identifier, folder):
        marker = s.read_json(ready[0] / "owner.json")
        marker["store_id"] = "0" * 32
        (ready[0] / "owner.json").write_text(json.dumps(marker))
        return restore_fixture(identifier, folder)

    with pytest.raises(ValueError, match="ownership drift"):
        execute(ready, restore=changed)
    assert len(list((ready[0] / "snapshots").iterdir())) == 9
