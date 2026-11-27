"""Host-only complete-snapshot retention; no automatic or original-data deletion."""

import argparse
import json
from pathlib import Path

import demo_backup
from aegis.operations import retention_store as store
from aegis.operations import vault


def restore(identifier, folder):
    # Fixed coordinator: local image, offline fresh clone, no app/worker/volumes.
    return demo_backup.rehearse(identifier, _archive_folder=folder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init")
    init.add_argument("--policy", type=Path, required=True)
    enroll = actions.add_parser("enroll")
    enroll.add_argument("--source", type=Path, required=True)
    archive = actions.add_parser("archive")
    archive.add_argument("backup_id")
    archive.add_argument("--recipient", required=True)
    verify = actions.add_parser("verify")
    verify.add_argument("archive_id")
    verify.add_argument("--expected-sha256", required=True)
    verify.add_argument("--keys", type=Path, required=True)
    verify.add_argument("--key-id", required=True)
    actions.add_parser("plan")
    args = parser.parse_args()
    try:
        if args.action == "init":
            result = store.initialize(args.store, store.read_json(args.policy))
        elif args.action == "enroll":
            result = store.enroll(args.store, args.source)
        elif args.action == "archive":
            result = store.archive(args.store, args.backup_id, args.recipient)
        elif args.action == "verify":
            identity = vault.load_key(args.keys, args.key_id)
            result = store.verify(
                args.store, args.archive_id, args.expected_sha256, identity, restore
            )
        else:
            result = store.build_plan(args.store)
        print(json.dumps(result, indent=2))
    except Exception:
        # Native tools/parser errors may contain rows, keys or host paths.
        raise SystemExit(
            "Retention refused or incomplete; review private artifacts and owned clone status. No sensitive details displayed."
        ) from None


if __name__ == "__main__":
    main()
