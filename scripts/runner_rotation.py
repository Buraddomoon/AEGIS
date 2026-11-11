"""Opt-in native rotation plan/run/cleanup; no lab starts from import, help or tests."""

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import runner_activation as base
import runner_activation_cleanup as closure
import runner_activation_metadata as metadata
import runner_activation_ownership as ownership
import runner_rotation_package as package
from aegis.lab_runner.persisted_probe import _unique
from runner_activation_intents import DEFAULT_ROOT, ActivationIntents
from runner_activation_metadata import ActivationError
from runner_rotation_native import ALL_ROLES, NativeRotation


def run(path, expected, authorized, password, *, confirm=False):
    if confirm is not True or authorized != expected:
        raise ActivationError("rotation_explicit_specific_confirmation_required")
    item, artifact = package.load(path, expected)
    base_path = Path(item["base_plan_path"])
    fence = base_path.parent / "native-rotation-requested.json"
    if fence.exists() or fence.is_symlink():
        raise ActivationError("rotation_native_plan_consumed")
    with ActivationIntents(DEFAULT_ROOT) as store:
        if store.has_plan_history(item["base_plan_sha256"]):
            raise ActivationError("rotation_native_prior_plan_history")
        base.recheck(base_path, item["base_plan_sha256"])
        store.begin(artifact["id"], item["base_plan_sha256"], artifact["scope_sha256"])
        try:
            c = package.NativeConfirmation(path, expected, authorized, store)
            store.append(
                "rotation_scope_confirmed",
                {"package_sha256": expected, "expires_at": c.expires.isoformat()},
            )
            return NativeRotation(c, password).execute()
        except BaseException:
            if not store.poisoned:
                state = store.review()
                if not state["resources"] and not state["closed"]:
                    store.append(
                        "closed",
                        {
                            "evidence_sha256": base.digest(
                                {
                                    "empty_native_rotation": c.operation
                                    if "c" in locals()
                                    else store.summary()["id"]
                                }
                            )
                        },
                    )
            raise


def cleanup(path, expected, operation, begin_sha256):
    item, artifact = package.load(path, expected, current=False)
    images = {k: artifact["metadata"]["images"][k]["id"] for k in metadata.IMAGES}
    with ActivationIntents(DEFAULT_ROOT) as store:
        store.resume(operation, begin_sha256)
        state = store.review()
        if (
            state["header"]
            != {
                "plan_id": artifact["id"],
                "plan_sha256": item["base_plan_sha256"],
                "scope_sha256": artifact["scope_sha256"],
            }
            or state.get("rotation_scope", {}).get("package_sha256") != expected
            or not set(state["resources"]) <= ALL_ROLES
        ):
            raise ActivationError("rotation_cleanup_original_scope_required")

        def query(kind, operation_id, plan_sha256, role, known_id=None):
            if (operation_id, plan_sha256) != (
                operation,
                item["base_plan_sha256"],
            ) or role not in ALL_ROLES:
                raise ActivationError("rotation_cleanup_foreign_query")
            return metadata._execute(
                ownership.command(kind, operation_id, plan_sha256, role, known_id)
            )

        def effect(kind, operation_id, plan_sha256, role, known_id):
            if (operation_id, plan_sha256) != (
                operation,
                item["base_plan_sha256"],
            ) or role not in ALL_ROLES:
                raise ActivationError("rotation_cleanup_foreign_effect")
            return metadata._execute(
                closure.command(kind, operation_id, plan_sha256, role, known_id)
            )

        # No constructor of operational gates, credential read, create/start,
        # PKI renewal or migration. Expired approval cannot block own cleanup.
        return closure.cleanup(
            store,
            images,
            docker=SimpleNamespace(effect=effect),
            ownership_docker=SimpleNamespace(query=query),
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--base-plan", type=Path, required=True)
    prepare.add_argument("--base-sha256", required=True)
    prepare.add_argument("--review-input", type=Path, required=True)
    for command in ("run", "cleanup"):
        p = sub.add_parser(command)
        p.add_argument("--package", type=Path, required=True)
        p.add_argument("--expected-sha256", required=True)
        if command == "run":
            p.add_argument("--authorized-package-sha256", required=True)
            p.add_argument("--confirm-native-rotation", action="store_true", required=True)
        else:
            p.add_argument("--operation-id", required=True)
            p.add_argument("--begin-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            value = json.loads(
                base.pki.read(args.review_input, modes=(0o600,), maximum=4 * 1024**2),
                object_pairs_hook=_unique,
            )
            if not isinstance(value, dict) or set(value) != {
                "build_inputs",
                "postgres_origin",
                "clone_evidence",
                "clone_sha256",
                "actor_id",
                "registration",
            }:
                raise ActivationError("rotation_review_input_closed_fields_required")
            result = package.prepare(args.base_plan, args.base_sha256, **value)
        elif args.command == "run":
            if not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode):
                raise ActivationError("rotation_private_password_pipe_required")
            secret = json.loads(sys.stdin.buffer.read(16385), object_pairs_hook=_unique)
            if not isinstance(secret, dict) or set(secret) != {"database_password"}:
                raise ActivationError("rotation_private_password_input_invalid")
            result = run(
                args.package,
                args.expected_sha256,
                args.authorized_package_sha256,
                secret["database_password"],
                confirm=args.confirm_native_rotation,
            )
        else:
            result = cleanup(
                args.package, args.expected_sha256, args.operation_id, args.begin_sha256
            )
    except Exception:
        print(
            json.dumps(
                {"status": "rotation_request_unconfirmed", "normal_operation_permitted": False}
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    if args.command == "prepare":
        return 0
    return (
        0
        if result.get("status") == "native_rotation_verified_and_closed"
        or result.get("managed_resources_absence_verified") is True
        and args.command == "cleanup"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
