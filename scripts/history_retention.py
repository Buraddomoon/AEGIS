"""Host-only complete-snapshot retention; no automatic or original-data deletion."""

import argparse
import json
from pathlib import Path

import demo_backup
from aegis.operations import retention_apply, vault
from aegis.operations import retention_store as store


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
    apply = actions.add_parser("apply")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--expected-sha256", required=True)
    mode = apply.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--confirm-remove-copies", action="store_true")
    apply.add_argument("--authorization", type=Path)
    apply.add_argument("--keys", type=Path)
    apply.add_argument("--key-id")
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
        elif args.action == "apply":
            authorization, identity = None, None
            if not args.dry_run:
                if not (args.authorization and args.keys and args.key_id):
                    raise ValueError("Specific authorization and key required")
                authorization = store.read_json(args.authorization)
                identity = vault.load_key(args.keys, args.key_id)
            result = retention_apply.apply(
                args.store,
                store.read_json(args.plan),
                args.expected_sha256,
                authorization=authorization,
                identity=identity,
                restore=restore,
                confirm=args.confirm_remove_copies,
                dry_run=args.dry_run,
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
