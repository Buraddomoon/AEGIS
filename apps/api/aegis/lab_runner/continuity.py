"""Review stopped runner journals without initializing or changing their source."""

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import struct
import tempfile
import time
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from uuid import UUID

from aegis.domain.validation import digest
from aegis.lab_runner.protocol import JobSpec, JobView, RunnerIdentity

FILES = {
    "instance.lock": 0,
    "journal.sqlite3": 32 * 1024 * 1024,
    "journal.sqlite3-wal": 8 * 1024 * 1024,
    "journal.sqlite3-shm": 64 * 1024,
}
MAX_JOBS = 10000
MAX_EVENTS = 100000
SCHEMA = {
    "jobs": """CREATE TABLE jobs (
        id TEXT PRIMARY KEY, spec TEXT NOT NULL, spec_hash TEXT NOT NULL,
        generation TEXT NOT NULL, state TEXT NOT NULL,
        cleanup_state TEXT NOT NULL DEFAULT 'PENDING', reason TEXT,
        receipt TEXT, receipt_sha256 TEXT)""",
    "events": """CREATE TABLE events (
        sequence INTEGER PRIMARY KEY, job_id TEXT NOT NULL,
        action TEXT NOT NULL, timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        FOREIGN KEY(job_id) REFERENCES jobs(id))""",
    "metadata": "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
}


class ContinuityError(ValueError):
    """Static diagnostic codes only; never echo journal rows or paths."""


def _signature(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read(fd, maximum):
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while chunk := os.read(fd, min(65536, maximum + 1 - len(data))):
        data.extend(chunk)
        if len(data) > maximum:
            raise ContinuityError("journal_file_limit")
    return bytes(data)


def _files(root_fd, stack):
    names = set(os.listdir(root_fd))
    if not {"instance.lock", "journal.sqlite3"} <= names or not names <= FILES.keys():
        raise ContinuityError("journal_files_unexpected_or_missing")
    opened = {}
    for name in sorted(names):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in (0o600, 0o644)
            or info.st_size > FILES[name]
        ):
            raise ContinuityError("journal_file_unsafe")
        opened[name] = fd, _signature(info)
    try:
        fcntl.flock(opened["instance.lock"][0], fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ContinuityError("journal_instance_busy") from None
    return opened


def _json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ContinuityError("journal_json_duplicate_field")
            result[key] = item
        return result

    if not isinstance(value, str) or len(value.encode()) > 16384:
        raise ContinuityError("journal_json_invalid")
    return json.loads(value, object_pairs_hook=unique)


def _wal(database, wal):
    """Conservative format guard, not recovery or cryptographic authentication."""
    if not database.startswith(b"SQLite format 3\0") or len(database) < 100:
        raise ContinuityError("journal_database_header_invalid")
    page = int.from_bytes(database[16:18])
    page = 65536 if page == 1 else page
    if page not in {2**power for power in range(9, 17)} or len(database) % page:
        raise ContinuityError("journal_database_page_invalid")
    if not wal:
        return
    if len(wal) < 32:
        raise ContinuityError("journal_wal_invalid")
    magic, version, wal_page, _, salt1, salt2, check1, check2 = struct.unpack(">8I", wal[:32])
    if (
        magic not in {0x377F0682, 0x377F0683}
        or version != 3007000
        or wal_page != page
        or database[18:20] != b"\x02\x02"
        or (len(wal) - 32) % (page + 24)
    ):
        raise ContinuityError("journal_wal_invalid")
    order = "<" if magic == 0x377F0682 else ">"

    def checksum(content, first=0, second=0):
        for left, right in struct.iter_unpack(order + "2I", content):
            first = (first + left + second) & 0xFFFFFFFF
            second = (second + right + first) & 0xFFFFFFFF
        return first, second

    check = checksum(wal[:24])
    if check != (check1, check2):
        raise ContinuityError("journal_wal_checksum_invalid")
    committed = True
    for offset in range(32, len(wal), page + 24):
        frame = wal[offset : offset + page + 24]
        number, size, first_salt, second_salt, first_check, second_check = struct.unpack(
            ">6I", frame[:24]
        )
        if (
            not 1 <= number <= FILES["journal.sqlite3"] // page
            or size > FILES["journal.sqlite3"] // page
            or (first_salt, second_salt) != (salt1, salt2)
        ):
            raise ContinuityError("journal_wal_frame_invalid")
        check = checksum(frame[:8] + frame[24:], *check)
        if check != (first_check, second_check):
            raise ContinuityError("journal_wal_checksum_invalid")
        committed = size != 0
    if not committed:
        raise ContinuityError("journal_wal_uncommitted_tail")


def _authorize(action, first, second, database, context):
    if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ}:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and (first, second) in {
        ("user_version", None),
        ("integrity_check", "1"),
        ("foreign_key_check", None),
    }:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_TRANSACTION and first == "ROLLBACK":
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _job(row, identity):
    raw_spec = _json(row["spec"])
    spec = JobSpec.model_validate(raw_spec)
    data = dict(row)
    identifier = data.pop("id")
    data["spec"] = spec
    data["receipt"] = _json(row["receipt"]) if row["receipt"] is not None else None
    view = JobView.model_validate(data)
    if (
        str(spec.job_id) != identifier
        or digest(raw_spec) != digest(spec.model_dump(mode="json"))
        or str(view.generation) != row["generation"]
        or view.spec_hash != digest(spec.model_dump(mode="json"))
        or view.cleanup_state != "CLEANED"
        or view.state in {"PREPARED", "RUNNING"}
        or any(
            getattr(spec, key) != getattr(identity, key)
            for key in ("runner_id", "laboratory_id", "asset_id")
        )
    ):
        raise ContinuityError("journal_job_unresolved_or_invalid")
    receipt = view.receipt
    if receipt is None:
        if view.state == "SUCCEEDED" or view.receipt_sha256 is not None:
            raise ContinuityError("journal_receipt_missing")
    else:
        content = (spec.marker + "\n").encode("ascii")
        if (
            view.state != "SUCCEEDED"
            or digest(data["receipt"]) != digest(receipt.model_dump(mode="json"))
            or digest(receipt.model_dump(mode="json")) != view.receipt_sha256
            or any(
                getattr(receipt, key) != getattr(spec, key)
                for key in (
                    "job_id",
                    "runner_id",
                    "laboratory_id",
                    "asset_id",
                    "test_id",
                    "marker",
                    "scope_hash",
                )
            )
            or receipt.artifact_bytes != len(content)
            or receipt.artifact_sha256 != hashlib.sha256(content).hexdigest()
            or not receipt.started_at <= receipt.ended_at <= spec.deadline_at
        ):
            raise ContinuityError("journal_receipt_invalid")
    return view


def _history(view, rows):
    actions = [row["action"] for row in rows]
    if len(actions) < 3 or actions[0] != "PREPARED" or actions[-1] != "CLEANED":
        raise ContinuityError("journal_event_history_invalid")
    state = "PREPARED"
    implicit_restart = False
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED"}
    for action in actions[1:-1]:
        if state == "PREPARED" and action in {"RUNNING", "CANCELLED", "TIMED_OUT"}:
            state = action
        elif state == "RUNNING" and action == "FAILED" and view.state == "INTERRUPTED":
            # The persisted final outcome disambiguates a cleanup failure after
            # restart from a FAILED execution (which restart would not change).
            state, implicit_restart = "INTERRUPTED", True
        elif state == "RUNNING" and action in terminal:
            state = action
        elif state in terminal and action == "FAILED":
            pass  # Cleanup failure can be retried, without changing execution outcome.
        else:
            raise ContinuityError("journal_event_transition_invalid")
    # Runner restart historically changed RUNNING to INTERRUPTED without an event.
    implicit_restart = implicit_restart or (state == "RUNNING" and view.state == "INTERRUPTED")
    if state != view.state and not implicit_restart:
        raise ContinuityError("journal_event_state_mismatch")
    for row in rows:
        timestamp = datetime.fromisoformat(row["timestamp"])
        if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
            raise ContinuityError("journal_event_time_invalid")
    return implicit_restart


def _inspect(db, identity, expected):
    if db.execute("PRAGMA user_version").fetchone()[0] != 1:
        raise ContinuityError("journal_schema_version")
    objects = db.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name"
    ).fetchall()
    tables = {row["name"]: row["sql"] for row in objects if row["type"] == "table"}
    if {key: " ".join(value.split()) for key, value in tables.items()} != {
        key: " ".join(value.split()) for key, value in SCHEMA.items()
    } or any(
        row["type"] != "table"
        and not (
            row["type"] == "index"
            and row["sql"] is None
            and row["name"] in {"sqlite_autoindex_jobs_1", "sqlite_autoindex_metadata_1"}
        )
        for row in objects
    ):
        raise ContinuityError("journal_schema_mismatch")
    if [row[0] for row in db.execute("PRAGMA integrity_check(1)")] != ["ok"] or db.execute(
        "PRAGMA foreign_key_check"
    ).fetchone():
        raise ContinuityError("journal_integrity_failed")
    metadata = [dict(row) for row in db.execute("SELECT * FROM metadata ORDER BY key LIMIT 3")]
    if metadata != [{"key": "identity", "value": digest(identity.model_dump(mode="json"))}]:
        raise ContinuityError("journal_identity_mismatch")
    rows = db.execute("SELECT * FROM jobs ORDER BY id LIMIT ?", (MAX_JOBS + 1,)).fetchall()
    events = [
        dict(row)
        for row in db.execute("SELECT * FROM events ORDER BY sequence LIMIT ?", (MAX_EVENTS + 1,))
    ]
    if len(rows) > MAX_JOBS or len(events) > MAX_EVENTS:
        raise ContinuityError("journal_history_limit")
    jobs = {row["id"]: _job(row, identity) for row in rows}
    histories = {key: [] for key in jobs}
    for event in events:
        if (
            event["job_id"] not in jobs
            or type(event["sequence"]) is not int
            or event["sequence"] <= 0
        ):
            raise ContinuityError("journal_event_orphan_or_sequence")
        histories[event["job_id"]].append(event)
    implicit = sum(_history(view, histories[key]) for key, view in jobs.items())
    for identifier, proof in expected.items():
        if (
            not isinstance(identifier, UUID)
            or not isinstance(proof, JobView)
            or proof.spec.job_id != identifier
            or str(identifier) not in jobs
            or digest(proof.model_dump(mode="json"))
            != digest(jobs[str(identifier)].model_dump(mode="json"))
        ):
            raise ContinuityError("journal_expected_proof_mismatch")
    inventory = {
        "metadata": metadata,
        "jobs": {key: view.model_dump(mode="json") for key, view in jobs.items()},
        "events": events,
    }
    return {
        "format": "aegis-runner-journal-review/1",
        "status": "snapshot_consistent_with_supplied_proofs",
        "identity_sha256": digest(identity.model_dump(mode="json")),
        "inventory_sha256": digest(inventory),
        "jobs_reviewed": len(jobs),
        "events_reviewed": len(events),
        "expected_proofs_matched": len(expected),
        "additional_jobs_reviewed": len(jobs) - len(expected),
        "implicit_restart_histories": implicit,
        "source_modified": False,
        "volume_binding_verified": False,
        "database_binding_verified": False,
        "activation_permitted": False,
        "normal_operation_permitted": False,
    }


def review(root: Path, identity: RunnerIdentity, expected: dict[UUID, JobView]):
    """For an authorized stopped-volume probe; tests pass temporary journals only."""
    if (
        not isinstance(identity, RunnerIdentity)
        or not isinstance(expected, dict)
        or not 1 <= len(expected) <= MAX_JOBS
    ):
        raise ContinuityError("journal_known_proofs_required")
    try:
        with ExitStack() as stack:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, root_fd)
            info = os.fstat(root_fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ContinuityError("journal_directory_unsafe")
            opened = _files(root_fd, stack)
            original = {name: _read(fd, FILES[name]) for name, (fd, _) in opened.items()}
            _wal(original["journal.sqlite3"], original.get("journal.sqlite3-wal", b""))
            with tempfile.TemporaryDirectory(prefix="aegis-journal-review-") as scratch:
                for name in ("journal.sqlite3", "journal.sqlite3-wal"):
                    if name in original:
                        target = Path(scratch) / name
                        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(original[name])
                # mode=ro sees committed WAL; SHM may be reconstructed only in scratch.
                with ExitStack() as connections:
                    db = sqlite3.connect(
                        (Path(scratch) / "journal.sqlite3").as_uri() + "?mode=ro",
                        uri=True,
                        timeout=0.1,
                        cached_statements=0,
                    )
                    connections.callback(db.close)
                    db.row_factory = sqlite3.Row
                    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
                    db.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
                    db.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
                    db.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, False)
                    db.execute("PRAGMA query_only=ON")
                    deadline = time.monotonic() + 5
                    steps = 0

                    def progress():
                        nonlocal steps
                        steps += 1000
                        return steps > 5000000 or time.monotonic() > deadline

                    db.set_progress_handler(progress, 1000)
                    db.execute("BEGIN")
                    db.set_authorizer(_authorize)
                    result = _inspect(db, identity, expected)
                    if time.monotonic() > deadline:
                        raise ContinuityError("journal_review_time_limit")
            # No success if source changed while SQLite interpreted the private copy.
            if set(os.listdir(root_fd)) != set(opened) or _signature(
                os.stat(root, follow_symlinks=False)
            ) != _signature(info):
                raise ContinuityError("journal_source_changed")
            for name, (fd, signature) in opened.items():
                if (
                    _signature(os.fstat(fd)) != signature
                    or _signature(os.stat(name, dir_fd=root_fd, follow_symlinks=False)) != signature
                    or _read(fd, FILES[name]) != original[name]
                ):
                    raise ContinuityError("journal_source_changed")
            return result
    except ContinuityError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        sqlite3.Error,
    ):
        raise ContinuityError("journal_review_failed") from None
