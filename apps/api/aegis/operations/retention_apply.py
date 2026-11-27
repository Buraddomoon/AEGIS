"""One-use, explicitly approved removal of owned plaintext snapshot copies only."""

import hashlib
import os
import stat
from datetime import UTC, datetime

from aegis.operations import retention, vault
from aegis.operations import retention_store as store

APPROVAL_FORMAT = "aegis-history-retention-approval/1"


def now():
    return datetime.now(UTC).isoformat()


def approval(value, plan, *, at):
    if set(value) != {
        "format",
        "store_id",
        "plan_sha256",
        "decision",
        "approved_by",
        "approved_at",
        "expires_at",
    }:
        raise ValueError("Exact retention approval fields required")
    if (
        value["format"] != APPROVAL_FORMAT
        or value["store_id"] != plan["store_id"]
        or value["plan_sha256"] != plan["sha256"]
        or value["decision"] != "approve_enrolled_plaintext_removal"
        or not isinstance(value["approved_by"], str)
        or not 1 <= len(value["approved_by"].strip()) <= 120
        or not retention.instant(plan["created_at"])
        <= retention.instant(value["approved_at"])
        <= retention.instant(at)
        < retention.instant(value["expires_at"])
        <= retention.instant(plan["expires_at"])
    ):
        raise ValueError("Specific current retention approval required")
    return value


def recheck(root, marker, plan, expected_sha256, clock):
    retention.check_plan(plan, expected_sha256, at=clock())
    if store.read_json(root / "owner.json") != marker:
        raise ValueError("Retention ownership drift")
    current = store.plan_locked(root, marker, at=plan["created_at"], expires_at=plan["expires_at"])
    if current != plan:
        raise ValueError("Retention drift; new plan and approval required")
    retention.check_plan(plan, expected_sha256, at=clock())


def signature(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def remove_copy(root, marker, member, before_unlink):
    """Pin owned directory and members; never recurse or follow a replacement."""
    identifier = member["id"]
    folder, observed, _ = store.enrolled(root, identifier, marker)
    if observed != member["files"]:
        raise ValueError("Snapshot changed before removal")
    parent_fd = os.open(root / "snapshots", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    folder_fd = None
    try:
        folder_fd = os.open(
            identifier, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd
        )
        folder_info = os.fstat(folder_fd)
        if signature(folder_info) != signature(folder.stat()) or set(os.listdir(folder_fd)) != set(
            observed
        ):
            raise ValueError("Snapshot directory changed")
        signatures = {}
        for name, expected in observed.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or info.st_size != expected["bytes"]
                    or hashlib.file_digest(stream, "sha256").hexdigest() != expected["sha256"]
                    or signature(os.fstat(stream.fileno())) != signature(info)
                ):
                    raise ValueError("Snapshot member changed")
                signatures[name] = signature(info)
        # All candidates were freshly restored before the first call. Leave an
        # incomplete tombstone on interruption; a new plan will preserve it.
        for name in sorted(observed):
            before_unlink()
            if (
                signature(os.stat(name, dir_fd=folder_fd, follow_symlinks=False))
                != signatures[name]
            ):
                raise ValueError("Snapshot member replaced")
            os.unlink(name, dir_fd=folder_fd)
            os.fsync(folder_fd)
        before_unlink()
        current = os.stat(identifier, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (folder_info.st_dev, folder_info.st_ino):
            raise ValueError("Snapshot directory replaced")
        os.rmdir(identifier, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if folder_fd is not None:
            os.close(folder_fd)
        os.close(parent_fd)


def apply(
    root,
    plan,
    expected_sha256,
    *,
    authorization=None,
    identity=None,
    restore=None,
    confirm=False,
    dry_run=True,
    clock=now,
):
    with store.locked(root) as marker:
        recheck(root, marker, plan, expected_sha256, clock)
        candidates = [r for r in plan["members"] if r["action"] == "remove_enrolled_plaintext_copy"]
        begin_path = root / "receipts" / (expected_sha256 + "-begin.json")
        if begin_path.exists():
            raise ValueError("Retention plan already consumed; inspect its private audit")
        if dry_run:
            return {
                "status": "dry_run",
                "plan_sha256": expected_sha256,
                "candidate_ids": [r["id"] for r in candidates],
                "deletion_performed": False,
            }
        if not confirm or authorization is None or identity is None or restore is None:
            raise ValueError(
                "Explicit confirmation, authorization and restore coordinator required"
            )
        approval(authorization, plan, at=clock())
        # Exclusive durable intent consumes the approved plan even if a later
        # restore/cleanup/delete fails. No automatic retry/replay is permitted.
        vault.write_json(
            begin_path,
            {
                "format": retention.FORMAT,
                "status": "begin",
                "plan_sha256": expected_sha256,
                "authorization": authorization,
                "plan": plan,
                "candidate_ids": [r["id"] for r in candidates],
                "at": clock(),
            },
        )
        result = {
            "format": retention.FORMAT,
            "plan_sha256": expected_sha256,
            "status": "failed_or_interrupted",
            "removed_ids": [],
            "fresh_restores": [],
            "deletion_started": False,
        }
        try:
            for member in candidates:
                selected = next(
                    (
                        a
                        for a in member["archives"]
                        if a["restore_verified"] and a.get("snapshot_files") == member["files"]
                    ),
                    None,
                )
                if selected is None:
                    raise ValueError("Protected archive unavailable")
                approval(authorization, plan, at=clock())
                result["fresh_restores"].append(
                    store.verify_locked(
                        root,
                        selected["id"],
                        selected["ciphertext_sha256"],
                        identity,
                        restore,
                        publish=False,
                    )
                )
            # Verify *all* members/holds/archives again after potentially slow IO.
            recheck(root, marker, plan, expected_sha256, clock)
            for member in candidates:

                def authorized():
                    retention.check_plan(plan, expected_sha256, at=clock())
                    if store.read_json(root / "owner.json") != marker:
                        raise ValueError("Retention ownership drift")
                    approval(authorization, plan, at=clock())
                    if retention.policy(store.read_json(root / "policy.json")) != plan["policy"]:
                        raise ValueError("Retention policy or hold changed")

                authorized()
                result["deletion_started"] = True
                remove_copy(root, marker, member, authorized)
                result["removed_ids"].append(member["id"])
            result["status"] = "applied"
            return result
        except BaseException as error:
            result["failure_type"] = type(error).__name__
            raise
        finally:
            result["finished_at"] = clock()
            vault.write_json(root / "receipts" / (expected_sha256 + "-result.json"), result)
