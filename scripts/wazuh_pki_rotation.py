"""Prepare/recheck a private Wazuh PKI change procedure. Never execute lifecycle commands."""

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from uuid import UUID, uuid4

import wazuh_pki as pki
from aegis.domain.validation import digest

FORMAT = "aegis-wazuh-pki-rotation/2"
SECRET_FILES = {
    "wazuh_ca": "root-ca.pem",
    "indexer_cert": "indexer.pem",
    "indexer_key": "indexer-key.pem",
    "filebeat_cert": "filebeat.pem",
    "filebeat_key": "filebeat-key.pem",
}
PROTECTED = (
    "lab.env",
    "client.keys",
    "indexer-passwords.json",
    "internal_users.yml",
    "collection.json",
    "runner/connection.json",
    "runner/server-ca.crt",
    "runner/client-ca.crt",
    "runner/runner-server.crt",
    "runner/runner-client.crt",
)
BASE_COMPOSE = (
    "docker-compose.yml",
    "labs/linux/compose.yml",
    "labs/linux/platform.yml",
    "labs/wazuh/compose.yml",
    "labs/wazuh/network.yml",
)
# Ordered, bounded manual procedure, not a catalog of commands accepted from users.
STEPS = (
    "quiesce_collectors_agent_manager",
    "stop_indexer",
    "confirm_all_consumers_stopped",
    "recreate_indexer_with_candidate",
    "verify_indexer_tls_identity",
    "recreate_manager_with_candidate",
    "verify_filebeat_tls",
    "start_agent_without_enrollment",
    "verify_agent_identity_acl_and_collector",
    "stop_candidate_consumers",
    "confirm_no_candidate_consumers",
    "retain_evidence_and_volumes",
)
ROLLBACK_STEPS = (
    "stop_candidate_consumers",
    "confirm_no_candidate_consumers",
    "select_original_compose",
    "verify_original_configuration_restored_stopped",
    "retain_evidence_and_volumes",
)


def overlay(candidate: Path) -> dict:
    # Change all consumers' shared CA and both pairs together; never a CA bundle/fallback.
    # Compose secrets are mounted as individual RO files; the CA private key is absent.
    return {
        "secrets": {
            name: {"file": str(candidate / "pki" / file)} for name, file in SECRET_FILES.items()
        }
    }


def validate_rendered(original: dict, changed: dict, candidate: Path):
    """Compare captured Compose JSON in memory, never print its credential values."""
    expected = copy.deepcopy(original)
    for name, filename in SECRET_FILES.items():
        expected["secrets"][name]["file"] = str(candidate / "pki" / filename)
    if changed != expected:
        raise pki.fs.PKIError("rotation_compose_changes_outside_five_secret_files")
    for name, service in changed["services"].items():
        if name != "api" and service.get("ports"):
            raise pki.fs.PKIError("rotation_published_service_port")
    ports = changed["services"]["api"].get("ports", [])
    if (
        len(ports) != 1
        or ports[0].get("host_ip") != "127.0.0.1"
        or str(ports[0].get("published")) != "18786"
    ):
        raise pki.fs.PKIError("rotation_published_api_port")
    if any(Path(secret["file"]).name == "ca-key.pem" for secret in changed["secrets"].values()):
        raise pki.fs.PKIError("rotation_private_ca_mount")


def snapshot(source: Path) -> dict:
    source = pki.fs.private_directory(source)
    protected = {
        name: pki.fs.read(
            source / name,
            modes=(0o600,) if name in {"lab.env", "indexer-passwords.json"} else (0o444, 0o600),
        )
        for name in PROTECTED
    }
    lines = protected["lab.env"].decode().splitlines()
    if any("=" not in line for line in lines):
        raise pki.fs.PKIError("invalid_rotation_source_environment")
    pairs = [line.split("=", 1) for line in lines]
    environment = dict(pairs)
    expected = {
        "AEGIS_WAZUH_CONFIG_DIR": str(source),
        "AEGIS_LAB_CONFIG_DIR": str(source / "runner"),
        "WAZUH_URL": "https://wazuh.indexer:9200",
        "WAZUH_ALLOWED_IP": pki.inventory(source)["profile"]["indexer_ip"],
        **{
            f"AEGIS_WAZUH_{name.upper()}_IMAGE": value
            for name, value in pki.profile()["images"]["images"].items()
        },
    }
    if len(environment) != len(pairs) or any(
        environment.get(name) != value for name, value in expected.items()
    ):
        raise pki.fs.PKIError("rotation_source_environment_identity_mismatch")
    return {
        "repository": {
            name: hashlib.sha256(pki.fs.read(pki.ROOT / name)).hexdigest()
            for name in (
                *BASE_COMPOSE,
                "scripts/wazuh_pki.py",
                "scripts/wazuh_pki_rotation.py",
                "scripts/runner_pki.py",
            )
        },
        "protected": {
            name: hashlib.sha256(content).hexdigest() for name, content in protected.items()
        },
    }


def prepare(source: Path, candidate: Path, candidate_sha256: str, output_root: Path) -> dict:
    source, candidate = pki.fs.absolute(source), pki.fs.absolute(candidate)
    checked = pki.verify(source, candidate, candidate_sha256)
    if checked["native_blockers"]:
        raise pki.fs.PKIError("legacy_candidate_cannot_enter_current_rotation")
    output_root = pki.separate(candidate, pki.separate(source, output_root))
    before = snapshot(source)
    output_root = pki.fs.private_directory(output_root, create=True)
    directory = output_root / uuid4().hex
    directory.mkdir(mode=0o700)
    document = overlay(candidate)
    pki.write_json(directory / "compose.pki.json", document)
    record = {
        "format": FORMAT,
        "id": directory.name,
        "source": str(source),
        "candidate": str(candidate),
        "candidate_sha256": candidate_sha256,
        "source_inventory_sha256": digest(pki.inventory(source)),
        "snapshot": before,
        "overlay_sha256": digest(document),
        "steps": list(STEPS),
        "rollback_steps": list(ROLLBACK_STEPS),
        "native_blockers": checked["native_blockers"],
        "activation_performed": False,
    }
    # Publish only after repeat verification; a partial directory cannot be used.
    pki.verify(source, candidate, candidate_sha256)
    if snapshot(source) != before:
        raise pki.fs.PKIError("rotation_inputs_changed_during_preparation")
    pki.write_json(directory / "plan.json", record)
    pki.fs.sync(output_root)
    return {
        "plan_path": str(directory),
        "plan_sha256": digest(record),
        "status": "procedure_prepared_not_authorized",
        "native_blockers": record["native_blockers"],
        "activation_performed": False,
    }


def recheck(directory: Path, expected_sha256: str) -> dict:
    directory = pki.fs.private_directory(directory)
    if set(os.listdir(directory)) != {"plan.json", "compose.pki.json"}:
        raise pki.fs.PKIError("unexpected_rotation_plan_artifacts")
    plan = json.loads(pki.fs.read(directory / "plan.json", modes=(0o600,)))
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest(plan) != expected_sha256:
        raise pki.fs.PKIError("rotation_plan_integrity_mismatch")
    if (
        set(plan)
        != {
            "format",
            "id",
            "source",
            "candidate",
            "candidate_sha256",
            "source_inventory_sha256",
            "snapshot",
            "overlay_sha256",
            "steps",
            "rollback_steps",
            "native_blockers",
            "activation_performed",
        }
        or plan["format"] != FORMAT
        or plan["id"] != directory.name
        or UUID(hex=plan["id"]).hex != plan["id"]
        or plan["activation_performed"] is not False
        or plan["steps"] != list(STEPS)
        or plan["rollback_steps"] != list(ROLLBACK_STEPS)
        or plan["native_blockers"] != []
    ):
        raise pki.fs.PKIError("invalid_rotation_plan")
    source, candidate = Path(plan["source"]), Path(plan["candidate"])
    pki.separate(source, directory)
    pki.separate(candidate, directory)
    if pki.verify(source, candidate, plan["candidate_sha256"])["native_blockers"]:
        raise pki.fs.PKIError("legacy_candidate_cannot_enter_current_rotation")
    if (
        digest(pki.inventory(source)) != plan["source_inventory_sha256"]
        or snapshot(source) != plan["snapshot"]
    ):
        raise pki.fs.PKIError("rotation_inputs_drift")
    document = json.loads(pki.fs.read(directory / "compose.pki.json", modes=(0o600,)))
    if document != overlay(candidate) or digest(document) != plan["overlay_sha256"]:
        raise pki.fs.PKIError("rotation_overlay_drift")
    return {
        "status": "offline_procedure_verified_authorization_required",
        "plan_sha256": expected_sha256,
        "native_blockers": [],
        "activation_performed": False,
        "normal_operation_permitted": False,
    }


class ProcedureJournal:
    """Offline journal of the manual procedure. This class cannot execute a step.

    An INTENT precedes each external operation; ambiguous/unconfirmed steps stay
    pending across reloads. This is bookkeeping, never runtime proof/authorization.
    No native CLI exposes these transitions while #149/#57 remain blocked.
    """

    def __init__(self, directory: Path, plan_sha256: str):
        if not re.fullmatch(r"[a-f0-9]{64}", plan_sha256):
            raise pki.fs.PKIError("invalid_rotation_plan_hash")
        self.directory = pki.fs.private_directory(directory)
        self.plan_sha256 = plan_sha256

    def events(self) -> list[dict]:
        names = sorted(os.listdir(self.directory))
        if len(names) > 128 or names != [f"{index:04d}.json" for index in range(len(names))]:
            raise pki.fs.PKIError("rotation_journal_partial_or_unexpected")
        events, previous = [], self.plan_sha256
        for name in names:
            event = json.loads(pki.fs.read(self.directory / name, modes=(0o600,)))
            if (
                set(event) != {"previous", "plan_sha256", "kind", "step", "proof_sha256"}
                or event["previous"] != previous
                or event["plan_sha256"] != self.plan_sha256
            ):
                raise pki.fs.PKIError("rotation_journal_integrity_mismatch")
            self._validate(events, event)
            events.append(event)
            previous = digest(event)
        return events

    def _validate(self, events: list[dict], event: dict):
        if event["kind"] not in {"INTENT", "CONFIRMED", "ROLLBACK"}:
            raise pki.fs.PKIError("invalid_rotation_transition")
        if event["kind"] == "ROLLBACK":
            if event["step"] != "rollback" or any(item["kind"] == "ROLLBACK" for item in events):
                raise pki.fs.PKIError("rollback_replay_refused")
            # A pending effect requires explicit reconciliation proof before rollback.
            if not re.fullmatch(r"[a-f0-9]{64}", event["proof_sha256"] or ""):
                raise pki.fs.PKIError("rollback_reconciliation_proof_required")
            return
        rollback = next((i for i, item in enumerate(events) if item["kind"] == "ROLLBACK"), None)
        active = events if rollback is None else events[rollback + 1 :]
        steps = STEPS if rollback is None else ROLLBACK_STEPS
        confirmed = sum(item["kind"] == "CONFIRMED" for item in active)
        if confirmed >= len(steps) or event["step"] != steps[confirmed]:
            raise pki.fs.PKIError("rotation_step_out_of_order_or_replayed")
        pending = bool(active and active[-1]["kind"] == "INTENT")
        if event["kind"] == "INTENT":
            if pending or event["proof_sha256"] is not None:
                raise pki.fs.PKIError("rotation_pending_effect_no_retry")
        elif not pending or not re.fullmatch(r"[a-f0-9]{64}", event["proof_sha256"] or ""):
            raise pki.fs.PKIError("rotation_confirmation_proof_required")

    def append(self, kind: str, step: str, proof_sha256: str | None = None):
        events = self.events()
        event = {
            "previous": digest(events[-1]) if events else self.plan_sha256,
            "plan_sha256": self.plan_sha256,
            "kind": kind,
            "step": step,
            "proof_sha256": proof_sha256,
        }
        self._validate(events, event)
        # O_EXCL prevents concurrent writers/replay. A crash/partial write blocks
        # future use; never delete/rewrite an event to make the sequence pass.
        pki.write_json(self.directory / f"{len(events):04d}.json", event)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_command = commands.add_parser("prepare")
    prepare_command.add_argument("--source", type=Path, required=True)
    prepare_command.add_argument("--candidate", type=Path, required=True)
    prepare_command.add_argument("--candidate-sha256", required=True)
    prepare_command.add_argument("--output-root", type=Path, default=Path(".local/wazuh-pki-plans"))
    check_command = commands.add_parser("recheck")
    check_command.add_argument("--plan", type=Path, required=True)
    check_command.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        result = (
            prepare(args.source, args.candidate, args.candidate_sha256, args.output_root)
            if args.command == "prepare"
            else recheck(args.plan, args.expected_sha256)
        )
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error": "Plano de troca recusado; preservar evidências e origem. Nenhum serviço iniciado.",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
