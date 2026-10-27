"""Plan/recheck Linux PKI activation prerequisites; never activate or start a lab."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import runner_pki as pki
from aegis.domain.validation import digest
from runner_activation_metadata import (
    IMAGES,
    PROJECT,
    ActivationError,
    document,
    image_id,
    metadata,
)

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "aegis-runner-activation-plan/1"
COMPOSE = ("docker-compose.yml", "labs/linux/compose.yml", "labs/linux/platform.yml")
TTL = timedelta(minutes=15)
FLAGS = {
    "activation_performed": False,
    "authorization_granted": False,
    "lab_started": False,
    "database_verified": False,
    "journal_verified": False,
    "runtime_mounts_verified": False,
    "network_isolation_verified": False,
    "image_provenance_verified": False,
    "normal_operation_permitted": False,
}
PENDING = [
    "specific_human_authorization",
    "image_provenance_review",
    "linux_database_binding_review",
    "original_journal_continuity",
    "runtime_mounts_and_isolation",
    "coordinated_mutual_tls",
    "explicit_revoked_binding_registration",
    "verified_resource_closure",
]


def profile():
    return {
        "id": "linux-integrated-pki/1",
        "project": PROJECT,
        "api_origin": "http://localhost:18785",
        "runner_url": "https://172.30.88.2:8443",
        "compose_files": list(COMPOSE),
        "worker_must_remain_stopped": True,
        "marker_permitted": False,
        "wazuh_permitted": False,
        "executor_implemented": False,
    }


def mounts(candidate):
    controller = {
        "/run/secrets/controller_server_ca": str(candidate / "server-ca.crt"),
        "/run/secrets/controller_client_cert": str(candidate / "runner-client.crt"),
        "/run/secrets/controller_client_key": str(candidate / "runner-client.key"),
        "/run/secrets/controller_connection": str(candidate / "connection.json"),
    }
    return {
        "runner": {
            "/state": PROJECT + "_journal",
            "/run/secrets/runner_server_key": str(candidate / "runner-server.key"),
            "/run/secrets/runner_server_cert": str(candidate / "runner-server.crt"),
            "/run/secrets/runner_client_ca": str(candidate / "client-ca.crt"),
        },
        "api": dict(controller),
        "worker": dict(controller),
        "db": {"/var/lib/postgresql/data": PROJECT + "_postgres-data"},
    }


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ActivationError("reviewed_sha256_required")
    return value


def snapshot(source, candidate, manifest_sha256, images, *, docker=None, inventory_reader=None):
    sha256(manifest_sha256)
    source, candidate = pki.private_directory(source), pki.private_directory(candidate)
    verified = pki.verify(source, candidate, manifest_sha256)
    manifest = document(pki.read(candidate / "rotation.json", modes=(0o600,)))
    if digest(manifest) != manifest_sha256:
        raise ActivationError("pki_manifest_changed")
    if manifest["candidate"]["connection"]["url"] != profile()["runner_url"]:
        raise ActivationError("linux_integrated_profile_required")
    files = {
        name: hashlib.sha256(pki.read(ROOT / name, maximum=262144)).hexdigest() for name in COMPOSE
    }
    # Internal adapter for the same immutable plan during an owned operation.
    # The public plan/recheck commands always use the quiescent inventory.
    observed = (
        metadata(images, docker=docker) if inventory_reader is None else inventory_reader(images)
    )
    # Recheck after the daemon queries too. Snapshots still are not a global lock.
    if pki.verify(source, candidate, manifest_sha256) != verified or files != {
        name: hashlib.sha256(pki.read(ROOT / name, maximum=262144)).hexdigest() for name in COMPOSE
    }:
        raise ActivationError("inputs_changed_during_review")
    return {
        "source_path": str(source),
        "candidate_path": str(candidate),
        "pki": {
            "manifest_sha256": manifest_sha256,
            "source_inventory_sha256": digest(manifest["source"]),
            "old_descriptor_sha256": manifest["source"]["descriptor_sha256"],
            "new_descriptor_sha256": verified["descriptor_sha256"],
            "identities": {name: manifest["candidate"]["connection"][name] for name in pki.IDS},
        },
        "compose_sha256": files,
        "expected_mount_sources": mounts(candidate),
        "metadata": observed,
    }


def plan(source, candidate, manifest_sha256, images, output_root, *, docker=None):
    # Validate images before any filesystem/daemon access, never resolve tags.
    if set(images) != set(IMAGES):
        raise ActivationError("four_explicit_images_required")
    for value in images.values():
        image_id(value)
    reviewed = snapshot(source, candidate, manifest_sha256, images, docker=docker)
    output_root = pki.absolute(output_root)
    if any(
        output_root == Path(reviewed[name]) or Path(reviewed[name]) in output_root.parents
        for name in ("source_path", "candidate_path")
    ):
        raise ActivationError("output_must_be_separate_from_pki")
    root = pki.private_directory(output_root, create=True)
    identifier = uuid4().hex
    created = pki.clock()
    artifact = {
        "format": FORMAT,
        "id": identifier,
        "created_at": created.isoformat(),
        "expires_at": (created + TTL).isoformat(),
        "profile": profile(),
        "status": "metadata_plan_requires_authorized_runtime_review",
        "pending_gates": list(PENDING),
        **FLAGS,
        **reviewed,
    }
    folder = root / identifier
    folder.mkdir(mode=0o700)
    fd = os.open(folder / "plan.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(artifact, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    pki.sync(folder)
    pki.sync(root)
    return {
        "format": FORMAT,
        "id": identifier,
        "plan_path": str(folder / "plan.json"),
        "plan_sha256": digest(artifact),
        "status": artifact["status"],
        "expires_at": artifact["expires_at"],
        **FLAGS,
    }


def load_plan(path, expected_sha256):
    """Read a pinned, unexpired plan; does not grant authorization or query Docker."""
    sha256(expected_sha256)
    path = pki.absolute(path)
    if path.name != "plan.json":
        raise ActivationError("plan_filename_required")
    pki.private_directory(path.parent)
    artifact = document(pki.read(path, modes=(0o600,)))
    if not isinstance(artifact, dict) or digest(artifact) != expected_sha256:
        raise ActivationError("plan_integrity_mismatch")
    if (
        set(artifact)
        != {
            "format",
            "id",
            "created_at",
            "expires_at",
            "profile",
            "status",
            "pending_gates",
            "source_path",
            "candidate_path",
            "pki",
            "compose_sha256",
            "expected_mount_sources",
            "metadata",
            *FLAGS,
        }
        or artifact["format"] != FORMAT
        or artifact["id"] != path.parent.name
        or UUID(hex=artifact["id"]).hex != artifact["id"]
        or digest(artifact["profile"]) != digest(profile())
        or artifact["status"] != "metadata_plan_requires_authorized_runtime_review"
        or artifact["pending_gates"] != PENDING
        or any(artifact[name] is not False for name in FLAGS)
    ):
        raise ActivationError("plan_policy_mismatch")
    created = datetime.fromisoformat(artifact["created_at"])
    expires = datetime.fromisoformat(artifact["expires_at"])
    if (
        created.utcoffset() != timedelta(0)
        or expires.utcoffset() != timedelta(0)
        or expires - created != TTL
        or not created <= pki.clock() < expires
    ):
        raise ActivationError("plan_expired_or_invalid_time")
    return artifact


def recheck(path, expected_sha256, *, docker=None):
    artifact = load_plan(path, expected_sha256)
    created = datetime.fromisoformat(artifact["created_at"])
    expires = datetime.fromisoformat(artifact["expires_at"])
    images = {role: artifact["metadata"]["images"][role]["id"] for role in IMAGES}
    current = snapshot(
        Path(artifact["source_path"]),
        Path(artifact["candidate_path"]),
        artifact["pki"]["manifest_sha256"],
        images,
        docker=docker,
    )
    if any(digest(artifact[name]) != digest(value) for name, value in current.items()):
        raise ActivationError("activation_plan_drift")
    checked_at = pki.clock()
    if not created <= checked_at < expires:
        raise ActivationError("plan_expired_or_invalid_time")
    return {
        "format": FORMAT,
        "id": artifact["id"],
        "plan_sha256": expected_sha256,
        "status": "metadata_plan_revalidated_not_activated",
        "checked_at": checked_at.isoformat(),
        "pending_gates": list(PENDING),
        **FLAGS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("plan")
    prepare.add_argument("--source", type=Path, required=True)
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--manifest-sha256", required=True)
    prepare.add_argument("--output-root", type=Path, default=ROOT / ".local/pki-activation-plans")
    for role in IMAGES:
        prepare.add_argument("--" + role + "-image", required=True)
    check = commands.add_parser("recheck")
    check.add_argument("--plan", type=Path, required=True)
    check.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            result = plan(
                args.source,
                args.candidate,
                args.manifest_sha256,
                {role: getattr(args, role + "_image") for role in IMAGES},
                args.output_root,
            )
        else:
            result = recheck(args.plan, args.expected_sha256)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except ActivationError as error:
        print(json.dumps({"status": "rejected", "code": str(error), **FLAGS}))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        # PKI/files/daemon can contain sensitive data. No traceback or dynamic text.
        print(
            json.dumps(
                {"status": "rejected", "code": "activation_plan_prerequisite_failed", **FLAGS}
            )
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
