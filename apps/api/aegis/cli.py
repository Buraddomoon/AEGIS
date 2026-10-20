import argparse
import getpass
import re

from sqlalchemy import select

from aegis.db import session_factory
from aegis.models import User
from aegis.security import audit, hasher
from aegis.seed import seed


def main():
    parser = argparse.ArgumentParser(description="Administração local ÆGIS")
    parser.add_argument("command", choices=["bootstrap", "seed"])
    args = parser.parse_args()
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
        if len(password) < 12 or len(password) > 128 or password != getpass.getpass("Repita a senha: "):
            parser.error("Senha inválida ou confirmação diferente.")
        user = User(username=username, password_hash=hasher.hash(password), role="administrator")
        db.add(user)
        db.flush()
        audit(db, user.id, "user.bootstrap", user.id)
        db.commit()
        print("Administrador criado. Senha não foi registrada em arquivos ou logs.")


if __name__ == "__main__":
    main()
