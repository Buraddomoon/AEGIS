"""Prepare/recheck a metadata-only original-volume diagnostic plan; never run it."""

import argparse
import json
import subprocess
from datetime import datetime, timedelta
from uuid import uuid4

import build_review_runner as image_build
import runner_activation_image_source as source
import runner_activation_metadata as metadata
import runner_pki as pki
from aegis.domain.validation import digest
from runner_activation_intents import _hash, _identifier
from runner_activation_metadata import ActivationError

ROOT = source.ROOT
OUTPUT = ROOT / ".local/runner-diagnostic-plans"
TTL = timedelta(hours=24)
FORMAT = "aegis-runner-diagnostic-plan/1"
FLAGS = {
    "authorization_verified": False,
    "lab_started": False,
    "database_contents_verified": False,
    "journal_contents_verified": False,
    "pki_activated": False,
    "normal_operation_permitted": False,
}


def profile():
    return {
        "id": "linux-original-volume-diagnostic/1",
        "project": metadata.PROJECT,
        "roles": [
            "db",
            "database-review-before",
            "journal-before",
            "journal-after",
            "database-review-after",
        ],
        "maximum_seconds": 300,
        "maximum_simultaneous_containers": 2,
        "database_volume": metadata.PROJECT + "_postgres-data",
        "database_volume_access": "read-write-postgresql-operational-metadata",
        "sql_access": "fixed-read-only-proof-reader",
        "journal_volume": metadata.PROJECT + "_journal",
        "journal_volume_access": "read-only",
        "published_ports": [],
        "docker_network": "none-or-owned-database-namespace",
        "marker_permitted": False,
        "worker_permitted": False,
        "wazuh_permitted": False,
        "migration_permitted": False,
        "credential_or_grant_changes_permitted": False,
        "pki_or_binding_changes_permitted": False,
        "volume_creation_or_removal_permitted": False,
        "executor_implemented": False,
    }


def _runner(inputs, images):
    if set(inputs) != {"build_id", "build_plan_sha256", "build_receipt_sha256"}:
        raise ActivationError("diagnostic_runner_build_inputs_invalid")
    folder = image_build.ROOT / _identifier(inputs["build_id"])
    _hash(inputs["build_plan_sha256"])
    _hash(inputs["build_receipt_sha256"])
    verified = image_build.review(folder, inputs["build_plan_sha256"])
    if (
        verified["receipt_sha256"] != inputs["build_receipt_sha256"]
        or verified["native_image_id"] != images["runner"]
        or verified["local_build_inputs_verified"] is not True
    ):
        raise ActivationError("diagnostic_runner_image_mismatch")
    return image_build.verify(folder, inputs["build_plan_sha256"])


def _current_source(repo, build_plan):
    commit = source._state(repo)
    files = source._collect(repo, commit)
    package = {
        name.removeprefix(source.PACKAGE): record
        for name, record in source._manifest(files).items()
        if name.startswith(source.PACKAGE)
    }
    if package != build_plan["expected_check"]["package_files"]:
        raise ActivationError("diagnostic_runner_source_outdated")
    for name, sealed in (
        ("requirements.lock", "runtime.lock"),
        ("pyproject.toml", "pyproject.toml"),
    ):
        if source._manifest({sealed: files[name]})[sealed] != build_plan["context"][sealed]:
            raise ActivationError("diagnostic_runner_dependencies_outdated")
    return commit


def snapshot(images, build_inputs, *, repo=ROOT, docker=None):
    """Only public certificates, committed code and native metadata; no secrets/SQL/mounts."""
    if not isinstance(images, dict) or set(images) != set(metadata.IMAGES):
        raise ActivationError("diagnostic_explicit_images_required")
    images = dict(images)
    for value in images.values():
        metadata.image_id(value)
    if len(set(images.values())) != len(metadata.IMAGES):
        raise ActivationError("diagnostic_distinct_images_required")
    reviewed = _runner(build_inputs, images)
    commit = _current_source(repo, reviewed)
    origin = repo / ".local/linux-lab"
    public, _validity = pki.inventory(origin, current=False)
    if public["connection"]["url"] != "https://172.30.88.2:8443":
        raise ActivationError("diagnostic_integrated_linux_identity_required")
    before = metadata.metadata(images, docker=docker)
    after = metadata.metadata(images, docker=docker)
    final_public, _validity = pki.inventory(origin, current=False)
    if (
        digest(before) != digest(after)
        or digest(final_public) != digest(public)
        or source._state(repo) != commit
    ):
        raise ActivationError("diagnostic_inputs_changed_during_review")
    return {
        "tool_commit": commit,
        "public_source_sha256": digest(public),
        "identity": {name: public["connection"][name] for name in pki.IDS},
        "old_descriptor_sha256": public["descriptor_sha256"],
        "runner_build": dict(build_inputs),
        "runner_source_sha256": reviewed["source_sha256"],
        "metadata": before,
    }


def scope(snapshot):
    return {
        "format": "aegis-runner-diagnostic-scope/1",
        "profile": profile(),
        "tool_commit": snapshot["tool_commit"],
        "identity": snapshot["identity"],
        "old_descriptor_sha256": snapshot["old_descriptor_sha256"],
        "runner_build": snapshot["runner_build"],
        "inventory_sha256": digest(snapshot["metadata"]),
        "public_source_sha256": snapshot["public_source_sha256"],
    }


def prepare(images, build_inputs, *, repo=ROOT, output=OUTPUT, docker=None):
    current = snapshot(images, build_inputs, repo=repo, docker=docker)
    created = pki.clock()
    scope_doc = scope(current)
    artifact = {
        "format": FORMAT,
        "id": uuid4().hex,
        "created_at": created.isoformat(),
        "expires_at": (created + TTL).isoformat(),
        "status": "diagnostic_plan_requires_specific_authorization_and_executor",
        "scope": scope_doc,
        "scope_sha256": digest(scope_doc),
        "snapshot": current,
        **FLAGS,
    }
    root = pki.private_directory(output, create=True)
    folder = pki.private_directory(root / artifact["id"], create=True)
    image_build._write(
        folder / "plan.json", json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
    )
    return {
        "format": FORMAT,
        "plan_id": artifact["id"],
        "plan_sha256": digest(artifact),
        "scope_sha256": artifact["scope_sha256"],
        "expires_at": artifact["expires_at"],
        "status": artifact["status"],
        **FLAGS,
    }


def load(folder, expected_sha256):
    _hash(expected_sha256)
    _identifier(folder.name)
    artifact = image_build._json(folder / "plan.json")
    if digest(artifact) != expected_sha256:
        raise ActivationError("diagnostic_plan_integrity_mismatch")
    if (
        set(artifact)
        != {
            "format",
            "id",
            "created_at",
            "expires_at",
            "status",
            "scope",
            "scope_sha256",
            "snapshot",
            *FLAGS,
        }
        or artifact.get("format") != FORMAT
        or artifact.get("id") != folder.name
        or artifact.get("status") != "diagnostic_plan_requires_specific_authorization_and_executor"
        or any(artifact.get(key) is not False for key in FLAGS)
        or digest(artifact["scope"]) != artifact["scope_sha256"]
        or digest(artifact["scope"]) != digest(scope(artifact["snapshot"]))
    ):
        raise ActivationError("diagnostic_plan_policy_mismatch")
    created, expires = (
        datetime.fromisoformat(artifact[key]) for key in ("created_at", "expires_at")
    )
    if (
        created.utcoffset() != timedelta(0)
        or expires.utcoffset() != timedelta(0)
        or expires - created != TTL
        or not created <= pki.clock() < expires
    ):
        raise ActivationError("diagnostic_plan_expired_or_invalid_time")
    return artifact


def recheck(folder, expected_sha256, *, repo=ROOT, docker=None):
    artifact = load(folder, expected_sha256)
    original = artifact["snapshot"]
    images = {key: original["metadata"]["images"][key]["id"] for key in metadata.IMAGES}
    current = snapshot(images, original["runner_build"], repo=repo, docker=docker)
    if digest(current) != digest(original) or load(folder, expected_sha256) != artifact:
        raise ActivationError("diagnostic_plan_drift")
    return {
        "format": FORMAT,
        "plan_id": artifact["id"],
        "plan_sha256": expected_sha256,
        "scope_sha256": artifact["scope_sha256"],
        "status": "diagnostic_plan_revalidated_not_authorized",
        **FLAGS,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    for role in metadata.IMAGES:
        create.add_argument("--" + role + "-image", required=True)
    for key in ("build-id", "build-plan-sha256", "build-receipt-sha256"):
        create.add_argument("--" + key, required=True)
    check = commands.add_parser("recheck")
    check.add_argument("--plan-id", required=True)
    check.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            report = prepare(
                {role: getattr(args, role + "_image") for role in metadata.IMAGES},
                {
                    key: getattr(args, key)
                    for key in ("build_id", "build_plan_sha256", "build_receipt_sha256")
                },
            )
        else:
            report = recheck(OUTPUT / _identifier(args.plan_id), args.expected_sha256)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        print(json.dumps({"status": "rejected", "code": "diagnostic_plan_unconfirmed", **FLAGS}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
