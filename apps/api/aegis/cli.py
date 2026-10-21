import argparse
import getpass
import os
import re

from sqlalchemy import select

from aegis.db import session_factory
from aegis.models import User
from aegis.security import audit, hasher
from aegis.seed import seed


def main():
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
            cursor.execute("GRANT USAGE ON SCHEMA public TO aegis_app")
            cursor.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app"
            )
            cursor.execute("REVOKE ALL ON alembic_version FROM aegis_app")
            cursor.execute(
                "REVOKE UPDATE, DELETE ON audit_events, telemetry_events, detection_evidence, validation_results, rule_versions, schedule_occurrences, lab_verifications, runner_receipts, runner_cleanups, telemetry_collections FROM aegis_app"
            )
            cursor.execute(
                "REVOKE UPDATE, DELETE ON schedules, schedule_authorizations, runner_dispatches FROM aegis_app"
            )
            cursor.execute(
                "GRANT UPDATE (state, reason, next_due_at, occurrences_count) ON schedules TO aegis_app"
            )
            cursor.execute("GRANT UPDATE (generation) ON runner_dispatches TO aegis_app")
            cursor.execute("GRANT UPDATE (revoked_at) ON schedule_authorizations TO aegis_app")
        connection.commit()
    print(
        "Papel runtime configurado sem privilégios administrativos; evidências e auditoria append-only."
    )


if __name__ == "__main__":
    main()
