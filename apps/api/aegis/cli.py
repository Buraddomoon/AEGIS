import argparse
import getpass
import os
import re

from sqlalchemy import select

from aegis.config import require_normal_operation
from aegis.db import session_factory
from aegis.models import User
from aegis.security import audit, hasher
from aegis.seed import seed


def main():
    require_normal_operation()
    parser = argparse.ArgumentParser(description="Administração local ÆGIS")
    parser.add_argument("command", choices=["bootstrap", "seed", "grant-runtime"])
    args = parser.parse_args()
    if args.command == "grant-runtime":
        grant_runtime()
        return
    with session_factory()() as db:
        if args.command == "seed":
            print(seed(db))
            return
        username = input("Nome do administrador: ").strip().lower()
        if not re.fullmatch(r"[a-z0-9_.@-]{3,80}", username):
            parser.error("Nome inválido.")
        if db.scalar(select(User).where(User.username == username)):
            parser.error("Usuário já existe; nenhum dado alterado.")
        password = getpass.getpass("Senha (mínimo 12 caracteres): ")
        if (
            len(password) < 12
            or len(password) > 128
            or password != getpass.getpass("Repita a senha: ")
        ):
            parser.error("Senha inválida ou confirmação diferente.")
        user = User(username=username, password_hash=hasher.hash(password), role="administrator")
        db.add(user)
        db.flush()
        audit(db, user.id, "user.bootstrap", user.id)
        db.commit()
        print("Administrador criado. Senha não foi registrada em arquivos ou logs.")


def grant_runtime():
    """Deployment-only grants; runtime containers never receive owner credentials."""
    require_normal_operation()
    from psycopg import sql

    from aegis.db import engine

    password = os.environ.get("APP_DB_PASSWORD", "")
    if len(password) < 24:
        raise SystemExit(
            "APP_DB_PASSWORD deve ser um segredo aleatório de pelo menos 24 caracteres."
        )
    with engine().raw_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app'")
            exists = cursor.fetchone()
            verb = "ALTER" if exists else "CREATE"
            cursor.execute(
                sql.SQL(
                    verb
                    + " ROLE aegis_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {}"
                ).format(sql.Literal(password))
            )
            from aegis.operations.runtime_grants import RUNTIME_PERMISSIONS

            for statement in RUNTIME_PERMISSIONS:
                cursor.execute(statement)
        connection.commit()
    print(
        "Papel runtime configurado sem privilégios administrativos; evidências e auditoria append-only."
    )


if __name__ == "__main__":
    main()
