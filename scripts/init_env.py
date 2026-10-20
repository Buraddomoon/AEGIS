"""Create a private local configuration without published credentials."""
import os
import secrets
from pathlib import Path

path = Path(".env")
if path.exists():
    print(".env já existe; preservado.")
else:
    password = secrets.token_hex(24)
    redis_password = secrets.token_hex(24)
    content = (
        f"POSTGRES_PASSWORD={password}\nREDIS_PASSWORD={redis_password}\n"
        f"DATABASE_URL=postgresql+psycopg://aegis:{password}@localhost:18782/aegis\n"
        f"REDIS_URL=redis://:{redis_password}@localhost:18783/0\n"
        "PUBLIC_ORIGIN=http://localhost:18780\nSECURE_COOKIES=false\n"
    )
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
    print(".env criado com segredos aleatórios e permissão 0600.")
