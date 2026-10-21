import fcntl
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

from aegis.lab_runner.protocol import ExecutionReceipt, JobSpec, JobView


class Journal:
    def __init__(self, root: Path):
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Estado deve ser diretório privado 0700 do runner.")
        self.path = root / "journal.sqlite3"
        self.lock_fd = os.open(
            root / "instance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.connection() as db:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1):
                    raise ValueError("Versão de diário não suportada.")
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("""CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, spec TEXT NOT NULL, spec_hash TEXT NOT NULL,
                    generation TEXT NOT NULL, state TEXT NOT NULL,
                    cleanup_state TEXT NOT NULL DEFAULT 'PENDING', reason TEXT,
                    receipt TEXT, receipt_sha256 TEXT)""")
                db.execute("""CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY, job_id TEXT NOT NULL,
                    action TEXT NOT NULL, timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    FOREIGN KEY(job_id) REFERENCES jobs(id))""")
                db.execute("PRAGMA user_version=1")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
        except BaseException:
            os.close(self.lock_fd)
            raise

    def close(self):
        os.close(self.lock_fd)

    @contextmanager
    def connection(self):
        # Never held by the watchdog while an effect is running.
        db = sqlite3.connect(self.path, timeout=0.1)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def view(row) -> JobView:
        return JobView(
            spec=JobSpec.model_validate_json(row["spec"]),
            spec_hash=row["spec_hash"],
            generation=UUID(row["generation"]),
            state=row["state"],
            cleanup_state=row["cleanup_state"],
            reason=row["reason"],
            receipt=ExecutionReceipt.model_validate_json(row["receipt"])
            if row["receipt"]
            else None,
            receipt_sha256=row["receipt_sha256"],
        )

    def get(self, identifier: UUID) -> JobView:
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (str(identifier),)).fetchone()
            if not row:
                raise LookupError("Job não encontrado.")
            return self.view(row)

    @staticmethod
    def event(db, identifier: UUID, action: str):
        db.execute("INSERT INTO events(job_id, action) VALUES (?,?)", (str(identifier), action))

    def update(
        self,
        identifier: UUID,
        *,
        state: str | None = None,
        cleanup_state: str | None = None,
        reason: str | None = None,
        receipt: dict | None = None,
        receipt_hash: str | None = None,
    ):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """UPDATE jobs SET state=coalesce(?,state), cleanup_state=coalesce(?,cleanup_state),
                reason=?, receipt=coalesce(?,receipt), receipt_sha256=coalesce(?,receipt_sha256) WHERE id=?""",
                (
                    state,
                    cleanup_state,
                    reason,
                    json.dumps(receipt) if receipt else None,
                    receipt_hash,
                    str(identifier),
                ),
            )
            self.event(db, identifier, cleanup_state or state or "update")
