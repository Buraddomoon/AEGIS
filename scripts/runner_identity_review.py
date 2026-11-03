"""Read saved identity artifacts only; no Docker, lease renewal, PKI or native inspection."""

import argparse
import json

import runner_activation_identity_client_gates as client
import runner_activation_identity_gates as server
import runner_activation_network_lifecycle as network
import runner_identity_artifacts as artifacts
from aegis.domain.validation import digest
from aegis.lab_runner import identity_probe as probe
from runner_activation_intents import _hash, _identifier
from runner_activation_metadata import ActivationError

FLAGS = frozenset(
    {
        "marker_executed",
        "worker_started",
        "database_started",
        "journal_opened",
        "wazuh_started",
        "pki_activated",
        "binding_changed",
        "old_client_rejection_verified",
        "volumes_removed",
        "normal_operation_permitted",
    }
)
FIELDS = frozenset(
    {
        "format",
        "operation_id",
        "begin_sha256",
        "plan_sha256",
        "scope_sha256",
        "plan_use_sha256",
        "status",
        "error",
        "failure_phase",
        "stages",
        "artifacts",
        "artifact_inventory_verified",
        "intent_summary_sha256",
        "cleanup",
        "tls_controls_status",
        "tls_controls_verified",
        "managed_resources_absence_verified",
        "effect_expires_at",
        "cleanup_expires_at",
        *FLAGS,
    }
)


def _gates(records, anchor):
    for name, item in records.items():
        if not name.endswith("-gate"):
            continue
        role, phase, _ = name.split("-")
        bundle = item["body"]
        if set(bundle) != {"gate", "review", "evidence"}:
            raise ActivationError("identity_saved_gate_bundle_invalid")
        gate, facts, evidence = (bundle[key] for key in ("gate", "review", "evidence"))
        fields = {
            "before_sha256": "plan_before",
            "after_sha256": "plan_after",
            **(
                {"subnet_review_sha256": "subnet"}
                if role == "network"
                else {
                    "sealed_image_sha256": "image_inputs",
                    "image_profile_sha256": "image_profile",
                    "network_sha256": "network",
                    **(
                        {"runtime_sha256": "runtime"}
                        if role == "server"
                        else {
                            "server_runtime_sha256": "server_runtime",
                            "client_runtime_sha256": "client_runtime",
                        }
                    ),
                }
            ),
        }
        expected_checks = {
            "network": network.CHECKS,
            "server": server.CHECKS,
            "client": client.CHECKS,
        }[role]
        if (
            gate["format"]
            != {
                "network": "aegis-rotation-network-gate/1",
                "server": "aegis-identity-server-gate/1",
                "client": "aegis-identity-client-gate/1",
            }[role]
            or gate["phase"] != phase
            or gate["operation_id"] != anchor["operation_id"]
            or gate["plan_sha256"] != anchor["plan_sha256"]
            or gate["scope_sha256"] != anchor["scope_sha256"]
            or set(gate["checks"]) != expected_checks
            or any(value is not True for value in gate["checks"].values())
            or evidence["gate_sha256"] != digest(gate)
            or any(
                evidence[key] != (digest(facts[field]) if facts[field] is not None else None)
                for key, field in fields.items()
            )
        ):
            raise ActivationError("identity_saved_gate_facts_mismatch")
        if role == "client" and (
            evidence["request_context_sha256"] != facts["request_context_sha256"]
            or gate["request_context_sha256"] != facts["request_context_sha256"]
        ):
            raise ActivationError("identity_saved_gate_request_mismatch")


def _receipt(records, anchor, expected_sha256):
    result = records["receipt"]["body"]
    if (
        set(result) != FIELDS
        or result["format"] != "aegis-identity-assay-receipt/1"
        or digest(result) != expected_sha256
        or any(result[key] != value for key, value in anchor.items())
        or result["artifact_inventory_verified"] is not True
        or not isinstance(result["stages"], dict)
        or not set(result["stages"]) <= {"network", "server", "client"}
        or type(result["tls_controls_verified"]) is not bool
        or type(result["managed_resources_absence_verified"]) is not bool
        or any(result[key] is not False for key in FLAGS)
        or result["artifacts"]
        != {name: digest(item) for name, item in records.items() if name != "receipt"}
    ):
        raise ActivationError("identity_saved_receipt_mismatch")
    _hash(result["plan_use_sha256"])
    _hash(result["intent_summary_sha256"])
    for role, expected in result["stages"].items():
        if records[role + "-lifecycle"]["body_sha256"] != expected:
            raise ActivationError("identity_saved_stage_mismatch")
    _gates(records, anchor)
    wire = None
    if "client-request" in records:
        body = records["client-request"]["body"]
        context = probe.decode(
            json.dumps(body["request"]).encode(), body["context_sha256"], current=False
        )
        if (
            any(context[key] != anchor[key] for key in ("plan_sha256", "scope_sha256"))
            or context["operation_id"] != anchor["operation_id"]
        ):
            raise ActivationError("identity_saved_request_anchor_mismatch")
        if "client-lifecycle" in records:
            reported = records["client-lifecycle"]["body"]["result"]
            if reported is not None:
                wire = probe.decode_result(
                    json.dumps(reported).encode(), context, body["context_sha256"]
                )
    cleanup = result["cleanup"]
    closed = (
        isinstance(cleanup, dict)
        and cleanup["managed_resources_absence_verified"] is True
        and cleanup["operation_closed"] is True
    )
    if "cleanup" not in records or (cleanup is not None and records["cleanup"]["body"] != cleanup):
        raise ActivationError("identity_saved_cleanup_mismatch")
    concluded = result["error"] is None and wire is not None and closed
    verified = concluded and wire["status"] == "identity_tls_controls_verified"
    expected_status = (
        "identity_assay_verified_and_closed"
        if verified
        else "identity_assay_inconclusive_and_closed"
        if concluded
        else "identity_assay_failed_and_closed"
        if closed
        else "identity_assay_cleanup_unconfirmed"
    )
    if (
        result["status"] != expected_status
        or result["tls_controls_verified"] is not verified
        or result["managed_resources_absence_verified"] is not closed
        or (concluded and set(records) != artifacts.NAMES)
        or (concluded and result["tls_controls_status"] != wire["status"])
    ):
        raise ActivationError("identity_saved_classification_mismatch")
    return result


def review(
    operation_id,
    begin_sha256,
    plan_sha256,
    scope_sha256,
    receipt_body_sha256,
    *,
    root=artifacts.ROOT,
):
    """Pins must come from an independently retained record, not the files being read.

    Does not open plan/intent/PKI or obtain Docker metadata. Historical integrity
    cannot establish current runtime absence, TLS origin or permission to resume.
    """
    anchor = {
        "operation_id": _identifier(operation_id),
        "begin_sha256": _hash(begin_sha256),
        "plan_sha256": _hash(plan_sha256),
        "scope_sha256": _hash(scope_sha256),
    }
    _hash(receipt_body_sha256)
    try:
        root = artifacts.pki.private_directory(root)
        folder = artifacts.pki.private_directory(root / operation_id)
        info = folder.stat()
        names = sorted(p.name for p in folder.iterdir())
        if not names or any(
            name not in {key + ".json" for key in artifacts.NAMES} for name in names
        ):
            raise ActivationError("identity_saved_inventory_invalid")
        raw = {
            name: artifacts.pki.read(folder / name, modes=(0o600,), maximum=artifacts.MAX_BYTES)
            for name in names
        }
        records = {
            name[:-5]: artifacts.decode_record(content, name[:-5], anchor)
            for name, content in raw.items()
        }
        result = _receipt(records, anchor, receipt_body_sha256)
        artifacts.pki.private_directory(root)
        after = artifacts.pki.private_directory(folder).stat()
        if (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino) or names != sorted(
            p.name for p in folder.iterdir()
        ):
            raise ActivationError("identity_saved_directory_changed")
        for name, content in raw.items():
            if (
                artifacts.pki.read(folder / name, modes=(0o600,), maximum=artifacts.MAX_BYTES)
                != content
            ):
                raise ActivationError("identity_saved_record_changed")
    except (ValueError, OSError, TypeError, KeyError, AttributeError, RecursionError):
        raise ActivationError("identity_saved_artifacts_unconfirmed") from None
    return {
        "format": "aegis-identity-saved-review/1",
        **anchor,
        "receipt_body_sha256": receipt_body_sha256,
        "status": "saved_identity_artifacts_verified_not_runtime_rechecked",
        "recorded_assay_status": result["status"],
        "recorded_tls_controls_verified": result["tls_controls_verified"],
        "records_reviewed": len(records),
        "native_runtime_rechecked": False,
        "plan_use_file_rechecked": False,
        "normal_operation_permitted": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "operation-id",
        "begin-sha256",
        "plan-sha256",
        "scope-sha256",
        "receipt-body-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = review(
            args.operation_id,
            args.begin_sha256,
            args.plan_sha256,
            args.scope_sha256,
            args.receipt_body_sha256,
        )
    except (ValueError, OSError):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error": "identity_saved_artifacts_unconfirmed",
                    "native_runtime_rechecked": False,
                    "normal_operation_permitted": False,
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0  # Saved integrity only, not a passed assay or current native state.


if __name__ == "__main__":
    raise SystemExit(main())
