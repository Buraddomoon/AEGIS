"""Prepare, review and explicitly publish an official ATT&CK candidate locally."""

import argparse
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

import httpx
from aegis.catalog import artifacts, store
from aegis.catalog.document import HEX64
from aegis.config import require_normal_operation, settings
from aegis.db import session_factory
from aegis.operations.recovery import required_revision
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".local/attack-catalog"


def fingerprint(value):
    if not re.fullmatch(HEX64, value):
        raise argparse.ArgumentTypeError("Use um SHA256 completo em minúsculas.")
    return value


def actor(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError("Use o UUID canônico do administrador ativo.") from None
    return value


def schema_guard(db):
    revisions = list(db.scalars(text("SELECT version_num FROM alembic_version")))
    if revisions != [required_revision()]:
        raise store.CatalogError(
            "Schema incompatível; revise/aplique as migrações antes de publicar."
        )


def main(argv=None):
    require_normal_operation()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    preparation = sub.add_parser("prepare")
    preparation.add_argument("--version", required=True)
    preparation.add_argument("--commit", required=True)
    review = sub.add_parser("plan")
    review.add_argument("candidate_id", type=fingerprint)
    publish = sub.add_parser("apply")
    publish.add_argument("candidate_id", type=fingerprint)
    publish.add_argument("--confirm-plan", required=True, type=fingerprint)
    publish.add_argument("--actor", required=True, type=actor)
    args = parser.parse_args(argv)
    os.chdir(ROOT)
    try:
        reviewed_license = hashlib.sha256(
            (settings().fixtures_path / "attack/LICENSE.txt").read_bytes()
        ).hexdigest()
        if args.action == "prepare":
            identity = artifacts.prepare(CACHE, args.version, args.commit)
            document = artifacts.load(CACHE, identity)
            result = {
                "status": "prepared_not_applied",
                "candidate_id": identity,
                "version": document.version,
                "source_commit": document.source_commit,
                "source_sha256": document.source_sha256,
                "license_matches_reviewed": document.license_sha256 == reviewed_license,
                "techniques": len(document.techniques),
                "active": sum(not t.revoked and not t.deprecated for t in document.techniques),
            }
        else:
            document = artifacts.load(CACHE, args.candidate_id)
            with session_factory()() as db, db.begin():
                if args.action == "plan":
                    db.execute(text("SET TRANSACTION READ ONLY"))
                schema_guard(db)
                if args.action == "plan":
                    planned = store.plan(db, document, reviewed_license)
                else:
                    result = store.apply(
                        db, document, args.confirm_plan, args.actor, reviewed_license
                    )
            if args.action == "plan":
                path = artifacts.save_plan(CACHE, planned)
                result = {
                    key: planned[key]
                    for key in (
                        "format",
                        "action",
                        "candidate_id",
                        "candidate_version",
                        "source_commit",
                        "source_sha256",
                        "plan_sha256",
                        "counts",
                        "blockers",
                    )
                }
                result["review_file"] = str(path)
                result["tests_requiring_review"] = planned["tests_requiring_review"]
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except store.CatalogError as error:
        raise SystemExit(str(error)) from None
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        RecursionError,
        SQLAlchemyError,
        httpx.HTTPError,
    ):
        raise SystemExit(
            "Operação ATT&CK recusada ou indisponível; nenhum sucesso declarado. Revise candidato/schema/permissões; dados sensíveis não foram exibidos."
        ) from None


if __name__ == "__main__":
    main()
