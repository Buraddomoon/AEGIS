"""Create private local configuration; refuse unsafe or incomplete existing files."""

import os
import secrets
import stat
import sys
from pathlib import Path

MAX_BYTES = 64 * 1024
REQUIRED_SECRETS = ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "APP_DB_PASSWORD")


class ConfigurationError(ValueError):
    """Safe message: never include configuration values or filesystem contents."""


def configuration() -> str:
    password, redis_password, runtime_password = (secrets.token_hex(24) for _ in range(3))
    return (
        f"POSTGRES_PASSWORD={password}\nREDIS_PASSWORD={redis_password}\n"
        f"APP_DB_PASSWORD={runtime_password}\n"
        f"DATABASE_URL=postgresql+psycopg://aegis:{password}@localhost:18782/aegis\n"
        f"REDIS_URL=redis://:{redis_password}@localhost:18783/0\n"
        "PUBLIC_ORIGIN=http://localhost:18780\nSECURE_COOKIES=false\n"
    )


def validate(content: str) -> bool:
    """Allow the historic missing runtime secret, never blank/example credentials."""
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition("=")
        if key in REQUIRED_SECRETS:
            if not separator or key in values:
                raise ConfigurationError("Configuração contém segredo duplicado ou inválido.")
            value = value.strip().strip("\"'")
            if not value or value.upper() in {"GENERATE", "CHANGEME", "CHANGE_ME"}:
                raise ConfigurationError(
                    "Preencha os segredos locais; não use .env.example como .env."
                )
            values[key] = value
    if any(key not in values for key in REQUIRED_SECRETS[:2]):
        raise ConfigurationError("Configuração incompleta: faltam segredos do PostgreSQL/Redis.")
    return REQUIRED_SECRETS[2] not in values


def initialize(path: Path = Path(".env")) -> str:
    # No truncation, chmod, symlink following, or blocking on a FIFO/device.
    # The project directory is trusted; the configuration itself is checked by FD.
    import fcntl

    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    created = False
    try:
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            fd = os.open(path, flags)
        with os.fdopen(fd, "r+", encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_size > MAX_BYTES
            ):
                raise ConfigurationError(
                    ".env deve ser arquivo próprio, regular, exclusivo e modo 0600."
                )
            if created:
                stream.write(configuration())
                message = ".env criado com segredos aleatórios e permissão 0600."
            else:
                content = stream.read(MAX_BYTES + 1)
                if len(content.encode("utf-8")) > MAX_BYTES:
                    raise ConfigurationError("Configuração excede o limite local de 64 KiB.")
                missing_runtime = validate(content)
                if not missing_runtime:
                    return ".env já existe; preservado."
                suffix = ("" if content.endswith("\n") else "\n") + (
                    "APP_DB_PASSWORD=" + secrets.token_hex(24) + "\n"
                )
                if len(content.encode("utf-8")) + len(suffix) > MAX_BYTES:
                    raise ConfigurationError("Configuração excede o limite local de 64 KiB.")
                stream.write(suffix)
                message = "Segredo independente do papel runtime adicionado; configuração anterior preservada."
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return message
    except ConfigurationError:
        raise
    except (OSError, UnicodeError):
        raise ConfigurationError(
            "Não foi possível validar .env; confira tipo, permissões e uso concorrente."
        ) from None


def main() -> int:
    try:
        print(initialize())
        return 0
    except ConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
