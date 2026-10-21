"""Only two fixed filenames inside a UUID directory. Never recursive cleanup."""

import os
import stat
from pathlib import Path
from uuid import UUID

ARTIFACTS = frozenset(("proof.marker", "receipt.json"))


class Workspace:
    def __init__(self, root: Path):
        self.root = root
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata = os.fstat(self.fd)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            os.close(self.fd)
            raise ValueError("Workspace deve pertencer ao runner e usar modo 0700.")

    def close(self):
        os.close(self.fd)

    def name(self, job_id: UUID) -> str:
        return job_id.hex

    def create(self, job_id: UUID) -> Path:
        os.mkdir(self.name(job_id), mode=0o700, dir_fd=self.fd)
        return self.root / self.name(job_id)

    def open_job(self, job_id: UUID) -> int:
        fd = os.open(
            self.name(job_id), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd
        )
        meta = os.fstat(fd)
        if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) & 0o077:
            os.close(fd)
            raise ValueError("Diretório de job inseguro.")
        return fd

    def read(self, job_id: UUID, name: str, max_bytes: int) -> bytes:
        if name not in ARTIFACTS:
            raise ValueError("Arquivo fora da allowlist.")
        job_fd = self.open_job(job_id)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=job_fd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
                    raise ValueError("Artefato inválido ou excessivo.")
                value = os.read(fd, max_bytes + 1)
                if len(value) > max_bytes:
                    raise ValueError("Artefato excedeu o limite.")
                return value
            finally:
                os.close(fd)
        finally:
            os.close(job_fd)

    def cleanup(self, job_id: UUID) -> None:
        try:
            job_fd = self.open_job(job_id)
        except FileNotFoundError:
            return
        try:
            entries = set(os.listdir(job_fd))
            if not entries <= ARTIFACTS:
                raise ValueError("Workspace contém arquivos desconhecidos; intervenção necessária.")
            for name in entries:
                info = os.stat(name, dir_fd=job_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Artefato inesperado; cleanup automático recusado.")
            for name in entries:
                os.unlink(name, dir_fd=job_fd)
        finally:
            os.close(job_fd)
        os.rmdir(self.name(job_id), dir_fd=self.fd)
