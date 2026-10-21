"""Bounded, durable JSONL sink for passive observations; no rotation or execution."""

import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from uuid import UUID

MAX_BYTES = 1024 * 1024
MAX_LINE = 4096


class ObservationLog:
    def __init__(self, directory: Path, laboratory_id: UUID, asset_id: UUID):
        self.laboratory_id, self.asset_id = str(laboratory_id), str(asset_id)
        self.seen: set[str] = set()
        self.fingerprints: dict[str, tuple[str, str]] = {}
        self.fd = -1
        root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(root)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("Diretório do log precisa ser privado e pertencer ao observador.")
            self.fd = os.open(
                "observations.jsonl",
                os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=root,
            )
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(root)
            metadata = os.fstat(self.fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_dev != os.fstat(root).st_dev
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_BYTES
            ):
                raise ValueError("Log inseguro ou acima do limite; preservar e revisar.")
            content = os.read(self.fd, MAX_BYTES + 1)
            if len(content) != metadata.st_size:
                raise ValueError("Leitura incompleta do log; preservar e revisar.")
            if content and not content.endswith(b"\n"):
                raise ValueError("Log incompleto; preservar evidências e revisar sem truncar.")
            for line in content.splitlines():
                if len(line) > MAX_LINE:
                    raise ValueError("Registro acima do limite.")
                record = json.loads(line)
                identifier = self._identity(record)
                self._check_fingerprint(identifier, record)
                self.seen.add(identifier)
        except BaseException:
            self.close()
            raise
        finally:
            os.close(root)

    def _identity(self, record: dict) -> str:
        try:
            event = record["aegis"]
            identifier = str(UUID(event["execution_id"]))
            marker = "aegis-" + str(UUID(event["marker"].removeprefix("aegis-")))
            valid = (
                set(record) == {"aegis"}
                and event["schema"] == "aegis-json/1"
                and event["observation"] == "marker_file_read"
                and event["behavior"] == "temporary-marker"
                and event["laboratory_id"] == self.laboratory_id
                and event["asset_id"] == self.asset_id
                and event["execution_id"] == identifier
                and event["marker"] == marker
                and event["artifact_bytes"] == 43
                and re.fullmatch(r"[0-9a-f]{64}", event["artifact_sha256"])
                and event["artifact_sha256"] == hashlib.sha256((marker + "\n").encode()).hexdigest()
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            valid = False
        if not valid:
            raise ValueError(
                "Log contém observação incompatível; não reutilizar nem fabricar dados."
            )
        return identifier

    def _check_fingerprint(self, identifier: str, record: dict):
        event = record["aegis"]
        fingerprint = (event["marker"], event["artifact_sha256"])
        if identifier in self.fingerprints and self.fingerprints[identifier] != fingerprint:
            raise ValueError("Observações conflitantes da mesma execução; preservar log e revisar.")
        self.fingerprints[identifier] = fingerprint

    def append(self, record: dict) -> bool:
        identifier = self._identity(record)
        self._check_fingerprint(identifier, record)
        if identifier in self.seen:
            return False
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        if len(line) > MAX_LINE or os.fstat(self.fd).st_size + len(line) > MAX_BYTES:
            raise ValueError("Log atingiu limite; preservar e revisar, sem descartar evidências.")
        # Exactly one writer per volume. A partial write/crash is rejected on restart.
        if os.write(self.fd, line) != len(line):
            raise OSError("Escrita parcial no log; observador interrompido.")
        os.fsync(self.fd)
        self.seen.add(identifier)
        return True

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
