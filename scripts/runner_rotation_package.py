"""Prepare/review a separate native-rotation scope; no lifecycle or implicit migration."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import runner_activation as base
import runner_activation_identity_image as image
import runner_postgres_origin as postgres
from aegis import schemas
from aegis.domain.validation import digest
from build_review_runner import _write
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_intents import _hash
from runner_activation_metadata import ActivationError

ROOT = base.ROOT / ".local/pki-rotation-packages"
FORMAT = "aegis-native-rotation-package/1"
PROFILE = {
    "id": "linux-native-pki-rotation/1",
    "executor_implemented": True,
    "project": "aegis-linux-lab",
    "schema_required": "b7f3c2d91a06",
    "postgres_network_ip": "192.168.253.4",
    "runner_network_ip": "192.168.253.2",
    "network_internal": True,
    "network_gateway_mode": "isolated",
    "administration": "fixed_helpers_in_database_network_namespace",
    "normal_runner_starts": 2,
    "runner_start_roles_distinct": True,
    "previous_server_trust_control_required": True,
    "worker_started": False,
    "api_started": False,
    "marker_permitted": False,
    "wazuh_permitted": False,
    "migrate_permitted": False,
    "seed_permitted": False,
    "normal_operation_permitted": False,
}


def backup_evidence(value, expected_sha256, artifact):
    _hash(expected_sha256)
    fields = {
        "format",
        "source_volume_sha256",
        "source_schema",
        "clone_schema",
        "backup_sha256",
        "restored_inventory_sha256",
        "upgraded_old_inventory_sha256",
        "clone_restore_verified",
        "old_rows_preserved",
        "grants_verified",
        "original_modified",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or digest(value) != expected_sha256
        or value["format"] != "aegis-linux-schema-clone-evidence/1"
        or value["source_volume_sha256"] != digest(artifact["metadata"]["volumes"]["postgres-data"])
        or value["source_schema"] != "a0d9c7e21b45"
        or value["clone_schema"] != PROFILE["schema_required"]
        or any(
            value[k] is not True
            for k in ("clone_restore_verified", "old_rows_preserved", "grants_verified")
        )
        or value["original_modified"] is not False
        or value["restored_inventory_sha256"] != value["upgraded_old_inventory_sha256"]
    ):
        raise ActivationError("rotation_clone_evidence_unconfirmed")
    for key in ("backup_sha256", "restored_inventory_sha256", "upgraded_old_inventory_sha256"):
        _hash(value[key])


def prepare(
    path,
    expected_sha256,
    build_inputs,
    postgres_origin,
    clone_evidence,
    clone_sha256,
    actor_id,
    registration,
    *,
    output=ROOT,
    docker=None,
):
    artifact = base.load_plan(path, expected_sha256)
    base.recheck(path, expected_sha256, docker=docker)
    image.review(
        build_inputs, artifact["metadata"]["images"]["runner"]["id"], artifact["tool_commit"]
    )
    postgres.review(artifact["metadata"]["images"]["postgres"]["id"], postgres_origin)
    backup_evidence(clone_evidence, clone_sha256, artifact)
    if str(UUID(actor_id)) != actor_id:
        raise ActivationError("rotation_administrator_id_invalid")
    data = schemas.LinuxRegistration.model_validate(registration).model_dump(mode="json")
    item = {
        "format": FORMAT,
        "id": uuid4().hex,
        "profile": PROFILE,
        "base_plan_path": str(base.pki.absolute(path)),
        "base_plan_sha256": expected_sha256,
        "expires_at": artifact["expires_at"],
        "build_inputs": build_inputs,
        "postgres_origin": postgres_origin,
        "clone_evidence": clone_evidence,
        "clone_evidence_sha256": clone_sha256,
        "actor_id": actor_id,
        "registration": data,
    }
    folder = base.pki.private_directory(output, create=True) / item["id"]
    folder.mkdir(mode=0o700)
    _write(folder / "package.json", json.dumps(item, sort_keys=True).encode())
    return {
        "package_path": str(folder / "package.json"),
        "package_sha256": digest(item),
        "status": "native_rotation_scope_requires_specific_authorization",
    }


def load(path, expected, *, current=True):
    _hash(expected)
    path = base.pki.absolute(path)
    base.pki.private_directory(path.parent)
    value = base.document(base.pki.read(path, modes=(0o600,), maximum=4 * 1024**2))
    if (
        not isinstance(value, dict)
        or digest(value) != expected
        or set(value)
        != {
            "format",
            "id",
            "profile",
            "base_plan_path",
            "base_plan_sha256",
            "expires_at",
            "build_inputs",
            "postgres_origin",
            "clone_evidence",
            "clone_evidence_sha256",
            "actor_id",
            "registration",
        }
        or value["format"] != FORMAT
        or digest(value["profile"]) != digest(PROFILE)
        or UUID(hex=value["id"]).hex != value["id"]
        or path.parent.name != value["id"]
        or path.name != "package.json"
    ):
        raise ActivationError("rotation_package_integrity_or_profile_invalid")
    loader = base.load_plan if current else base.load_for_cleanup
    artifact = loader(Path(value["base_plan_path"]), value["base_plan_sha256"])
    backup_evidence(value["clone_evidence"], value["clone_evidence_sha256"], artifact)
    if value["expires_at"] != artifact["expires_at"]:
        raise ActivationError("rotation_package_deadline_changed")
    schemas.LinuxRegistration.model_validate(value["registration"])
    if str(UUID(value["actor_id"])) != value["actor_id"]:
        raise ActivationError("rotation_administrator_id_invalid")
    return value, artifact


class NativeConfirmation(ConfirmedPlan):
    """Base metadata scope plus separately approved native package, both immutable."""

    def __init__(self, package_path, package_sha256, authorized_package_sha256, store):
        if authorized_package_sha256 != package_sha256:
            raise ActivationError("rotation_specific_package_authorization_required")
        package, artifact = load(package_path, package_sha256)
        self.package_path, self.package_sha256, self.package = package_path, package_sha256, package
        origin = datetime.fromisoformat(store.events[0]["at"])
        super().__init__(
            Path(package["base_plan_path"]),
            package["base_plan_sha256"],
            store,
            artifact["scope_sha256"],
            min(
                origin + timedelta(seconds=230), datetime.fromisoformat(package["expires_at"])
            ).isoformat(),
        )

    def _guard(self):
        state = super()._guard()
        package, artifact = load(self.package_path, self.package_sha256)
        if package != self.package or artifact != self.artifact:
            raise ActivationError("rotation_package_changed")
        scope = state.get("rotation_scope")
        if scope is not None and scope != {
            "package_sha256": self.package_sha256,
            "expires_at": self.expires.isoformat(),
        }:
            raise ActivationError("rotation_original_authorization_changed")
        return state
