"""Prepare/execute a separate one-use identity cleanup scope; never resume an assay."""

import argparse
import json
import subprocess
import time
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import runner_activation as plan
import runner_activation_cleanup as closure
import runner_activation_metadata as metadata
import runner_activation_ownership as ownership
import runner_identity_artifacts as artifacts
from aegis.domain.validation import digest
from build_review_runner import _write
from runner_activation_intents import DEFAULT_ROOT, ActivationIntents, _hash, _identifier
from runner_activation_metadata import ActivationError
from runner_identity_budget import ROLES

ROOT = plan.ROOT / ".local/pki-identity-cleanup"
FORMAT = "aegis-identity-cleanup-plan/1"
TTL = timedelta(minutes=15)
PROFILE = {
    "roles": sorted(ROLES),
    "max_seconds": 120,
    "stop_signal": "SIGTERM",
    "stop_timeout": 5,
    "create_permitted": False,
    "start_permitted": False,
    "force_permitted": False,
    "volume_removal_permitted": False,
    "normal_operation_permitted": False,
}
FIELDS = {
    "format",
    "id",
    "created_at",
    "expires_at",
    "tool_commit",
    "profile",
    "snapshot",
    "scope_sha256",
}
ERRORS = (
    ValueError,
    OSError,
    TypeError,
    KeyError,
    AttributeError,
    RecursionError,
    subprocess.SubprocessError,
)


def _snapshot(path, expected, store, runtime_root):
    if not isinstance(store, ActivationIntents):
        raise ActivationError("identity_cleanup_locked_intent_required")
    original = plan.load_for_cleanup(path, expected)
    state, summary = store.review(), store.summary()
    anchor = {
        "operation_id": summary["id"],
        "begin_sha256": summary["begin_sha256"],
        "plan_sha256": expected,
        "scope_sha256": original["scope_sha256"],
    }
    if (
        state["closed"]
        or not state["resources"]
        or not set(state["resources"]) <= ROLES
        or state["header"]
        != {
            "plan_id": original["id"],
            "plan_sha256": expected,
            "scope_sha256": original["scope_sha256"],
        }
    ):
        raise ActivationError("identity_cleanup_open_identity_operation_required")
    runtime_root = artifacts.pki.private_directory(runtime_root)
    folder = artifacts.pki.private_directory(runtime_root / summary["id"])
    raw = artifacts.pki.read(folder / "requested.json", modes=(0o600,), maximum=artifacts.MAX_BYTES)
    requested = artifacts.decode_record(raw, "requested", anchor)
    use = metadata.document(
        artifacts.pki.read(path.parent / "identity-assay-requested.json", modes=(0o600,))
    )
    if use != {
        "format": "aegis-identity-assay-plan-use/1",
        **anchor,
        "requested_artifact_sha256": digest(requested),
    }:
        raise ActivationError("identity_cleanup_original_plan_use_unconfirmed")
    images = {key: original["metadata"]["images"][key]["id"] for key in metadata.IMAGES}
    for image in images.values():
        metadata.image_id(image)
    if len(set(images.values())) != len(metadata.IMAGES):
        raise ActivationError("identity_cleanup_distinct_original_images_required")
    return {
        **anchor,
        "plan_path": str(path),
        "runtime_root": str(runtime_root),
        "plan_use_sha256": digest(use),
        "requested_artifact_sha256": digest(requested),
        "images": images,
        "state": state,
        "intent_summary_sha256": digest(summary),
    }


def prepare(path, expected_sha256, store, *, root=ROOT, runtime_root=artifacts.ROOT):
    """Caller holds/resumes the original intent lock. No Docker/PKI/volume reads."""
    snapshot = _snapshot(path, expected_sha256, store, runtime_root)
    original = plan.load_for_cleanup(path, expected_sha256)
    root = artifacts.pki.absolute(root)
    protected = [Path(original[key]) for key in ("source_path", "candidate_path")]
    protected += [path.parent, store.root, Path(snapshot["runtime_root"])]
    if any(root == parent or parent in root.parents for parent in protected):
        raise ActivationError("identity_cleanup_output_must_be_separate")
    root = artifacts.pki.private_directory(root, create=True)
    now, identifier = artifacts.pki.clock(), uuid4().hex
    value = {
        "format": FORMAT,
        "id": identifier,
        "created_at": now.isoformat(),
        "expires_at": (now + TTL).isoformat(),
        "tool_commit": plan.tool_state(),
        "profile": PROFILE,
        "snapshot": snapshot,
    }
    value["scope_sha256"] = digest(value)
    folder = root / identifier
    folder.mkdir(mode=0o700)
    artifacts.pki.sync(root)
    _write(folder / "plan.json", artifacts._encode(value))
    return {
        "plan_path": str(folder / "plan.json"),
        "plan_sha256": digest(value),
        "scope_sha256": value["scope_sha256"],
        "cleanup_executed": False,
        "normal_operation_permitted": False,
    }


def load(folder, expected_sha256):
    _hash(expected_sha256)
    artifacts.pki.private_directory(folder)
    value = metadata.document(artifacts.pki.read(folder / "plan.json", modes=(0o600,)))
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or digest(value) != expected_sha256
        or value["format"] != FORMAT
        or _identifier(value["id"]) != folder.name
        or digest(value["profile"]) != digest(PROFILE)
        or value["scope_sha256"]
        != digest({key: item for key, item in value.items() if key != "scope_sha256"})
        or value["tool_commit"] != plan.tool_state()
    ):
        raise ActivationError("identity_cleanup_policy_unconfirmed")
    created, expires = (
        plan.datetime.fromisoformat(value[key]) for key in ("created_at", "expires_at")
    )
    if (
        created.utcoffset() != timedelta(0)
        or expires.utcoffset() != timedelta(0)
        or expires - created != TTL
        or not created <= artifacts.pki.clock() < expires
    ):
        raise ActivationError("identity_cleanup_policy_expired")
    return value


class _Native:
    def __init__(self, folder, expected, policy, store, *, docker=None, ownership_docker=None):
        self.folder, self.expected, self.policy, self.store = folder, expected, policy, store
        self.docker, self.owner = docker, ownership_docker
        self.started = artifacts.pki.clock()
        self.expires = min(
            self.started + timedelta(seconds=120), plan.datetime.fromisoformat(policy["expires_at"])
        )
        self.deadline = time.monotonic() + (self.expires - self.started).total_seconds()

    def remaining(self):
        state, summary = self.store.review(), self.store.summary()
        snap = self.policy["snapshot"]
        now = artifacts.pki.clock()
        if (
            load(self.folder, self.expected) != self.policy
            or summary["id"] != snap["operation_id"]
            or summary["begin_sha256"] != snap["begin_sha256"]
            or state["header"] != snap["state"]["header"]
            or set(state["resources"]) != set(snap["state"]["resources"])
            or any(
                item["resource_id"] is not None
                and state["resources"][role]["resource_id"] != item["resource_id"]
                for role, item in snap["state"]["resources"].items()
            )
            or not self.started <= now < self.expires
        ):
            raise ActivationError("identity_cleanup_scope_or_budget_changed")
        left = min(self.deadline - time.monotonic(), (self.expires - now).total_seconds())
        if left <= 0:
            raise ActivationError("identity_cleanup_budget_exhausted")
        return min(20, left)

    def _scope(self, operation, expected, role):
        snap = self.policy["snapshot"]
        if (operation, expected) != (snap["operation_id"], snap["plan_sha256"]) or role not in snap[
            "state"
        ]["resources"]:
            raise ActivationError("identity_cleanup_resource_outside_scope")

    def query(self, kind, operation, expected, role, known_id=None):
        self._scope(operation, expected, role)
        args = ownership.command(kind, operation, expected, role, known_id)
        limit = self.remaining()
        result = (
            self.owner.query(kind, operation, expected, role, known_id)
            if self.owner is not None
            else metadata._execute(args, timeout=limit)
        )
        self.remaining()
        return result

    def effect(self, kind, operation, expected, role, known_id):
        self._scope(operation, expected, role)
        state = self.store.review()["resources"][role]
        if state["state"] != "REMOVAL_REQUESTED" or state["resource_id"] != known_id:
            raise ActivationError("identity_cleanup_removal_fence_required")
        requested = metadata.document(
            artifacts.pki.read(self.folder / "requested.json", modes=(0o600,))
        )
        if requested != {
            "plan_sha256": self.expected,
            "scope_sha256": self.policy["scope_sha256"],
            "operation_id": operation,
            "begin_sha256": self.policy["snapshot"]["begin_sha256"],
            "expires_at": self.expires.isoformat(),
        }:
            raise ActivationError("identity_cleanup_policy_use_fence_required")
        args = closure.command(kind, operation, expected, role, known_id)
        limit = self.remaining()
        if self.docker is not None:
            self.docker.effect(kind, operation, expected, role, known_id)
        else:
            metadata._execute(args, timeout=limit)


def execute(
    folder,
    expected_sha256,
    authorized_scope_sha256,
    store,
    *,
    confirm_owned_cleanup=False,
    docker=None,
    ownership_docker=None,
):
    """Fresh cleanup-only approval, not renewal of the original assay300s window."""
    if confirm_owned_cleanup is not True:
        raise ActivationError("identity_cleanup_explicit_confirmation_required")
    _hash(authorized_scope_sha256)
    value = load(folder, expected_sha256)
    if value["scope_sha256"] != authorized_scope_sha256:
        raise ActivationError("identity_cleanup_authorized_scope_mismatch")
    snap = value["snapshot"]
    if digest(
        _snapshot(Path(snap["plan_path"]), snap["plan_sha256"], store, Path(snap["runtime_root"]))
    ) != digest(snap):
        raise ActivationError("identity_cleanup_original_inputs_changed")
    native = _Native(
        folder, expected_sha256, value, store, docker=docker, ownership_docker=ownership_docker
    )
    native.remaining()
    _write(
        folder / "requested.json",
        artifacts._encode(
            {
                "plan_sha256": expected_sha256,
                "scope_sha256": authorized_scope_sha256,
                "operation_id": snap["operation_id"],
                "begin_sha256": snap["begin_sha256"],
                "expires_at": native.expires.isoformat(),
            }
        ),
    )
    result, interrupted, failed = None, None, None
    try:
        result = closure.cleanup(store, snap["images"], docker=native, ownership_docker=native)
        native.remaining()
    except ERRORS:
        failed = "identity_cleanup_unconfirmed"
    except BaseException as error:
        interrupted, failed = error, "identity_cleanup_interrupted"
    verified = (
        failed is None
        and result is not None
        and result["managed_resources_absence_verified"] is True
        and result["operation_closed"] is True
    )
    receipt = {
        "format": "aegis-identity-cleanup-receipt/1",
        "operation_id": snap["operation_id"],
        "begin_sha256": snap["begin_sha256"],
        "original_plan_sha256": snap["plan_sha256"],
        "cleanup_plan_sha256": expected_sha256,
        "cleanup_scope_sha256": authorized_scope_sha256,
        "status": "identity_owned_cleanup_verified_and_closed"
        if verified
        else "identity_owned_cleanup_unconfirmed",
        "error": failed,
        "cleanup": result,
        "managed_resources_absence_verified": verified,
        "expires_at": native.expires.isoformat(),
        "assay_resumed": False,
        "pki_activated": False,
        "volumes_removed": False,
        "normal_operation_permitted": False,
    }
    try:
        _write(folder / "receipt.json", artifacts._encode(receipt))
    except (ValueError, OSError):
        raise ActivationError("identity_cleanup_receipt_publication_unconfirmed") from None
    if interrupted is not None:
        raise interrupted
    return receipt


def prepare_from_original(
    path, expected_sha256, operation_id, begin_sha256, *, intents_root=None, runtime_root=None
):
    """Resume the exact original lock/history only to prepare a separate policy."""
    _identifier(operation_id)
    _hash(begin_sha256)
    _hash(expected_sha256)
    with ActivationIntents(DEFAULT_ROOT if intents_root is None else intents_root) as store:
        store.resume(operation_id, begin_sha256)
        return prepare(
            path,
            expected_sha256,
            store,
            root=ROOT,
            runtime_root=artifacts.ROOT if runtime_root is None else runtime_root,
        )


def run_from_ids(
    identifier,
    expected_sha256,
    authorized_scope_sha256,
    *,
    confirm_owned_cleanup=False,
    intents_root=None,
    docker=None,
    ownership_docker=None,
):
    if confirm_owned_cleanup is not True:
        raise ActivationError("identity_cleanup_explicit_confirmation_required")
    folder = ROOT / _identifier(identifier)
    value = load(folder, expected_sha256)
    if _hash(authorized_scope_sha256) != value["scope_sha256"]:
        raise ActivationError("identity_cleanup_authorized_scope_mismatch")
    snap = value["snapshot"]
    with ActivationIntents(DEFAULT_ROOT if intents_root is None else intents_root) as store:
        store.resume(_identifier(snap["operation_id"]), _hash(snap["begin_sha256"]))
        return execute(
            folder,
            expected_sha256,
            authorized_scope_sha256,
            store,
            confirm_owned_cleanup=True,
            docker=docker,
            ownership_docker=ownership_docker,
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("plan")
    for name in ("original-plan-id", "original-plan-sha256", "operation-id", "begin-sha256"):
        prepare_parser.add_argument("--" + name, required=True)
    run_parser = sub.add_parser("run")
    for name in ("cleanup-plan-id", "expected-sha256", "authorized-scope-sha256"):
        run_parser.add_argument("--" + name, required=True)
    run_parser.add_argument("--confirm-owned-cleanup", required=True, action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            path = (
                plan.ROOT
                / ".local/pki-activation-plans"
                / _identifier(args.original_plan_id)
                / "plan.json"
            )
            result = prepare_from_original(
                path, args.original_plan_sha256, args.operation_id, args.begin_sha256
            )
            print(json.dumps(result, sort_keys=True))
            return 0  # Policy preparation only, no cleanup or runtime assertion.
        result = run_from_ids(
            args.cleanup_plan_id,
            args.expected_sha256,
            args.authorized_scope_sha256,
            confirm_owned_cleanup=args.confirm_owned_cleanup,
        )
        print(
            json.dumps({"receipt": result, "receipt_body_sha256": digest(result)}, sort_keys=True)
        )
        return 0 if result["managed_resources_absence_verified"] is True else 1
    except ERRORS:
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error": "identity_owned_cleanup_unconfirmed",
                    "assay_resumed": False,
                    "normal_operation_permitted": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
