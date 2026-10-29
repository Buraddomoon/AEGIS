"""Opt-in host diagnostic and owned cleanup; requires a fresh specifically authorized scope."""

import argparse
import json
import re
import subprocess
from datetime import timedelta
from uuid import uuid4

import runner_diagnostic_coordinator as coordinator
from runner_activation_intents import DEFAULT_ROOT, ActivationIntents, _hash, _identifier
from runner_activation_metadata import ActivationError

gates = coordinator.gates
plan = gates.facts.plan


def _password(repo):
    """Fixed source/secret only, no dotenv evaluation, interpolation or environment fallback."""
    content = plan.pki.read(repo / ".env", modes=(0o600,), maximum=65536).decode("utf-8")
    candidates = [
        line for line in content.splitlines() if line.split("=", 1)[0].strip() == "APP_DB_PASSWORD"
    ]
    if len(candidates) != 1 or not re.fullmatch(r"APP_DB_PASSWORD=[a-f0-9]{48,128}", candidates[0]):
        raise ActivationError("diagnostic_existing_runtime_credential_profile_required")
    return candidates[0].split("=", 1)[1]


def run(folder, plan_sha256, authorized_scope_sha256, *, confirm_original_database_start=False):
    if confirm_original_database_start is not True:
        raise ActivationError("diagnostic_original_database_confirmation_required")
    _hash(authorized_scope_sha256)
    artifact = plan.load(folder, plan_sha256)
    if authorized_scope_sha256 != artifact["scope_sha256"]:
        raise ActivationError("diagnostic_authorized_scope_mismatch")
    if (folder / "diagnostic-requested.json").exists():
        raise ActivationError("diagnostic_plan_already_consumed")
    # A shared project lock excludes concurrent diagnostics/PKI lifecycles.
    # Recheck before reading credentials or publishing the first operation intent.
    with ActivationIntents(DEFAULT_ROOT) as store:
        if (folder / "diagnostic-requested.json").exists():
            raise ActivationError("diagnostic_plan_already_consumed")
        plan.recheck(folder, plan_sha256)
        password = _password(plan.ROOT)
        store.begin(artifact["id"], plan_sha256, artifact["scope_sha256"])
        try:
            context = gates.DiagnosticGates(
                folder,
                plan_sha256,
                store,
                authorized_scope_sha256,
                (plan.pki.clock() + timedelta(seconds=300)).isoformat(),
            )
            return coordinator.execute(context, password)
        except BaseException:
            if not store.poisoned:
                state = store.review()
                if not state["resources"] and not state["closed"]:
                    images = {
                        key: artifact["snapshot"]["metadata"]["images"][key]["id"]
                        for key in plan.metadata.IMAGES
                    }
                    coordinator.closure.cleanup(store, images)
            raise


def cleanup(folder, plan_sha256, operation_id, begin_sha256):
    artifact = plan.load_for_cleanup(folder, plan_sha256)
    request = plan.image_build._json(folder / "diagnostic-requested.json")
    if request != {
        "plan_sha256": plan_sha256,
        "scope_sha256": artifact["scope_sha256"],
        "operation_id": _identifier(operation_id),
        "begin_sha256": _hash(begin_sha256),
    }:
        raise ActivationError("diagnostic_cleanup_original_request_required")
    images = {
        key: artifact["snapshot"]["metadata"]["images"][key]["id"] for key in plan.metadata.IMAGES
    }
    with ActivationIntents(DEFAULT_ROOT) as store:
        store.resume(operation_id, begin_sha256)
        if store.review()["header"] != {
            "plan_id": artifact["id"],
            "plan_sha256": plan_sha256,
            "scope_sha256": artifact["scope_sha256"],
        }:
            raise ActivationError("diagnostic_cleanup_plan_mismatch")
        result = coordinator.closure.cleanup(store, images)
        folder = plan.pki.private_directory(gates.database.server.policy.DEFAULT_ROOT, create=True)
        folder = plan.pki.private_directory(folder / operation_id, create=True)
        plan.image_build._write(
            folder / ("cleanup-" + uuid4().hex + ".json"),
            json.dumps(result, sort_keys=True).encode(),
        )
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("run", "cleanup"):
        child = commands.add_parser(command)
        child.add_argument("--plan-id", required=True)
        child.add_argument("--expected-sha256", required=True)
        if command == "run":
            child.add_argument("--authorized-scope-sha256", required=True)
            child.add_argument(
                "--confirm-original-database-start", required=True, action="store_true"
            )
        else:
            child.add_argument("--operation-id", required=True)
            child.add_argument("--begin-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        folder = plan.OUTPUT / _identifier(args.plan_id)
        if args.command == "run":
            result = run(
                folder,
                args.expected_sha256,
                args.authorized_scope_sha256,
                confirm_original_database_start=args.confirm_original_database_start,
            )
            success = result["diagnostic_verified"] is True
        else:
            result = cleanup(folder, args.expected_sha256, args.operation_id, args.begin_sha256)
            success = (
                result["managed_resources_absence_verified"] is True
                and result["operation_closed"] is True
            )
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in ("format", "status", "operation_id", "normal_operation_permitted")
                }
            )
        )
        return 0 if success else 1
    except (ValueError, OSError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "code": "diagnostic_action_unconfirmed",
                    "normal_operation_permitted": False,
                }
            )
        )
        return 1
    except KeyboardInterrupt:
        print(
            json.dumps(
                {
                    "status": "interrupted",
                    "code": "inspect_private_receipt_and_owned_cleanup",
                    "normal_operation_permitted": False,
                }
            )
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
