import copy
import io
import tarfile
from datetime import UTC, datetime, timedelta

import pyrage
import pytest
from aegis.operations import operational_recovery as recovery

NOW = datetime(2026, 11, 28, tzinfo=UTC)


@pytest.fixture
def plan():
    return {
        "format": recovery.FORMAT,
        "profile": recovery.PROFILE,
        "workflow_run": "46100000000",
        "source_commit": "a" * 40,
        "approved_by": "Buraddomoon",
        "prepared_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=45)).isoformat(),
        "recipient": str(pyrage.x25519.Identity.generate().to_public()),
        "source_host": "a" * 64,
        "schema": "f3b28c5d901a",
        "destination": "fresh-ubuntu-24.04-job-destination-same-workflow",
        "secret_name": "AEGIS_RECOVERY29_46100000000",
        "images": {
            role: {"id": "sha256:" + letter * 64, "os": "linux", "architecture": "amd64"}
            for role, letter in (("application", "a"), ("postgres", "b"), ("redis", "c"))
        },
        "budget": {
            "source_normal_api": 1,
            "source_worker": 0,
            "destination_restores": 3,
            "destination_runs": 1,
            "destination_synthetic_tests": 4,
            "originals": False,
            "external_targets": False,
            "persistent_service": False,
            "encrypted_artifact_days": 1,
            "maximum_bytes": recovery.MAX_BYTES,
        },
    }


def test_exact_plan_and_later_own_approval(plan):
    assert recovery.validate_plan(plan) is plan
    comment = {
        "user": {"login": "Buraddomoon"},
        "body": recovery.approval_text(plan),
        "created_at": (NOW + timedelta(minutes=1)).isoformat(),
    }
    assert recovery.approved(comment, plan, NOW + timedelta(minutes=2))
    for key, value in (
        ("body", "autorizo"),
        ("body", comment["body"] + "\nextra"),
        ("user", {"login": "someone-else"}),
        ("created_at", (NOW - timedelta(seconds=1)).isoformat()),
    ):
        altered = {**comment, key: value}
        assert not recovery.approved(altered, plan, NOW + timedelta(minutes=2))
    assert not recovery.approved(comment, plan, NOW + timedelta(minutes=45))
    changed = copy.deepcopy(plan)
    changed["source_commit"] = "b" * 40
    assert not recovery.approved(comment, changed, NOW + timedelta(minutes=2))


@pytest.mark.parametrize(
    "key,value",
    [
        ("profile", "human-backup"),
        ("schema", "b7"),
        ("recipient", "private-key"),
        ("source_commit", "main"),
        ("workflow_run", "../old"),
        ("source_host", "host"),
        ("secret_name", "EXISTING_SECRET"),
        ("destination", "original-host"),
        ("expires_at", (NOW + timedelta(hours=1)).isoformat()),
        ("expires_at", NOW.isoformat()),
    ],
)
def test_unreviewed_plan_refuses(plan, key, value):
    plan[key] = value
    with pytest.raises(ValueError):
        recovery.validate_plan(plan)


@pytest.mark.parametrize(
    "key",
    [
        "source_worker",
        "destination_runs",
        "originals",
        "external_targets",
        "persistent_service",
        "encrypted_artifact_days",
    ],
)
def test_effect_budget_cannot_expand(plan, key):
    plan["budget"][key] = 2
    with pytest.raises(ValueError):
        recovery.validate_plan(plan)


@pytest.mark.parametrize(
    "key,value", [("id", "latest"), ("os", "windows"), ("architecture", "arm64")]
)
def test_images_must_match_reviewed_platform(plan, key, value):
    plan["images"]["application"][key] = value
    with pytest.raises(ValueError):
        recovery.validate_plan(plan)


def members():
    result = []
    for name in recovery.FILES:
        item = tarfile.TarInfo(name)
        item.size = 1
        result.append(item)
    return result


def test_archive_fixed_complete_files_only():
    recovery.validate_members(members())
    for altered in (members()[:-1], members() + members()[:1]):
        with pytest.raises(ValueError):
            recovery.validate_members(altered)


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../manifest.json", tarfile.REGTYPE),
        ("/database.dump", tarfile.REGTYPE),
        ("images.tar", tarfile.SYMTYPE),
        ("images.tar", tarfile.LNKTYPE),
        ("images.tar", tarfile.FIFOTYPE),
    ],
)
def test_archive_paths_and_special_files_refuse(name, kind):
    entries = members()
    entries[0].name, entries[0].type = name, kind
    with pytest.raises(ValueError):
        recovery.validate_members(entries)


def test_archive_aggregate_limit():
    entries = members()
    entries[0].size = recovery.MAX_BYTES
    with pytest.raises(ValueError):
        recovery.validate_members(entries)


def test_transport_binds_same_run_images_and_distinct_host(plan):
    envelope = {
        "format": recovery.FORMAT,
        "synthetic": True,
        "source_cleaned": True,
        "plan": plan,
        "ciphertext_sha256": "c" * 64,
        "ciphertext_bytes": 123,
    }
    arguments = {
        "expected_hash": recovery.fingerprint(envelope),
        "plan_hash": recovery.fingerprint(plan),
        "run": plan["workflow_run"],
        "source_commit": plan["source_commit"],
        "host": "b" * 64,
    }
    assert recovery.validate_envelope(envelope, **arguments) is envelope
    for key, value in (
        ("host", plan["source_host"]),
        ("run", "46100000001"),
        ("source_commit", "b" * 40),
        ("expected_hash", "0" * 64),
        ("plan_hash", "0" * 64),
    ):
        with pytest.raises(ValueError):
            recovery.validate_envelope(envelope, **{**arguments, key: value})
    altered = {**envelope, "source_cleaned": False}
    with pytest.raises(ValueError):
        recovery.validate_envelope(
            altered, **{**arguments, "expected_hash": recovery.fingerprint(altered)}
        )


def test_measured_rpo_requires_final_snapshot_after_fence():
    result = recovery.timing(
        NOW.isoformat(),
        (NOW + timedelta(seconds=4)).isoformat(),
        (NOW + timedelta(seconds=90)).isoformat(),
    )
    assert result["rto_observed_seconds"] == 90 and result["rpo_observed_seconds"] == 0
    assert result["sla"] is False
    for snapshot, accepted in (
        (NOW - timedelta(seconds=1), NOW),
        (NOW, NOW - timedelta(seconds=1)),
        (NOW, NOW + timedelta(hours=3)),
    ):
        with pytest.raises(ValueError):
            recovery.timing(NOW.isoformat(), snapshot.isoformat(), accepted.isoformat())


def test_archive_does_not_extract_any_entry_while_inventory_is_rejected():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        entry = tarfile.TarInfo("../escape")
        entry.size = 3
        archive.addfile(entry, io.BytesIO(b"bad"))
    stream.seek(0)
    with tarfile.open(fileobj=stream) as archive, pytest.raises(ValueError):
        recovery.validate_members(archive.getmembers())
