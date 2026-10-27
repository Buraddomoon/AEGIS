"""Bind fixed probe output to persisted proofs and compare full logical inventories."""

from aegis.domain.validation import digest
from aegis.lab_runner.continuity import MAX_EVENTS, MAX_JOBS, ContinuityError
from aegis.lab_runner.journal_probe import FLAGS
from aegis.lab_runner.persisted_review import expected_proofs
from runner_activation_intents import _hash
from runner_activation_metadata import ActivationError, document

SNAPSHOT_FLAGS = (
    "source_modified",
    "volume_binding_verified",
    "database_binding_verified",
    "activation_permitted",
    "normal_operation_permitted",
)
COUNTS = (
    "jobs_reviewed",
    "events_reviewed",
    "expected_proofs_matched",
    "additional_jobs_reviewed",
    "implicit_restart_histories",
)


def decode(raw, bundle, expected_sha256):
    """Output is a statement by the pinned image, not a signature or mount proof."""
    try:
        identity, proofs = expected_proofs(bundle, expected_sha256)
        item = document(raw)
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "format",
                "status",
                "proof_bundle_sha256",
                "old_descriptor_sha256",
                "snapshot",
                *FLAGS,
            }
            or item["format"] != "aegis-runner-journal-probe/1"
            or item["status"] != "journal_snapshot_consistent_not_activated"
            or item["proof_bundle_sha256"] != expected_sha256
            or item["old_descriptor_sha256"] != bundle["old_descriptor_sha256"]
            or any(item[key] is not False for key in FLAGS)
        ):
            raise ActivationError("journal_probe_result_context_mismatch")
        snapshot = item["snapshot"]
        if (
            not isinstance(snapshot, dict)
            or set(snapshot)
            != {
                "format",
                "status",
                "identity_sha256",
                "inventory_sha256",
                *COUNTS,
                *SNAPSHOT_FLAGS,
            }
            or snapshot["format"] != "aegis-runner-journal-review/1"
            or snapshot["status"] != "snapshot_consistent_with_supplied_proofs"
            or snapshot["identity_sha256"] != digest(identity.model_dump(mode="json"))
            or any(snapshot[key] is not False for key in SNAPSHOT_FLAGS)
            or any(type(snapshot[key]) is not int for key in COUNTS)
        ):
            raise ActivationError("journal_probe_snapshot_context_mismatch")
        _hash(snapshot["inventory_sha256"])
        if (
            not len(proofs) <= snapshot["jobs_reviewed"] <= MAX_JOBS
            or not 3 * snapshot["jobs_reviewed"] <= snapshot["events_reviewed"] <= MAX_EVENTS
            or snapshot["expected_proofs_matched"] != len(proofs)
            or snapshot["additional_jobs_reviewed"] != snapshot["jobs_reviewed"] - len(proofs)
            or not 0 <= snapshot["implicit_restart_histories"] <= snapshot["jobs_reviewed"]
        ):
            raise ActivationError("journal_probe_snapshot_counts_mismatch")
        return item
    except ActivationError:
        raise
    except (ContinuityError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ActivationError("journal_probe_result_invalid") from None


def compare(before_raw, after_raw, bundle, expected_sha256):
    before = decode(before_raw, bundle, expected_sha256)
    after = decode(after_raw, bundle, expected_sha256)
    if digest(before) != digest(after):
        raise ActivationError("journal_probe_continuity_changed")
    return {
        "format": "aegis-journal-probe-comparison/1",
        "status": "supplied_probe_inventories_unchanged",
        "proof_bundle_sha256": expected_sha256,
        "snapshot_sha256": digest(before["snapshot"]),
        "inventory_sha256": before["snapshot"]["inventory_sha256"],
        **{key: before["snapshot"][key] for key in COUNTS},
        "logical_inventories_match": True,
        "runtime_binding_verified": False,
        "image_provenance_verified": False,
        "authorization_verified": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
