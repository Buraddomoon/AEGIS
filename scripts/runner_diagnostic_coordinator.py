"""Internal one-use original-volume diagnostic; native invocation needs specific authorization."""

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta

import runner_activation_cleanup as closure
import runner_diagnostic_gates as gates
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError
from runner_activation_probe_result import compare as compare_journal


@dataclass(frozen=True)
class Adapters:
    """Trusted internal native/test adapters, never commands or JSON from an API."""

    server: object = None
    reader: object = None
    reader_runtime: object = None
    journal: object = None
    journal_runtime: object = None
    cleanup: object = None


def compare_proofs(before, after):
    """Compare reviewed binding/proofs; only the explicit review timestamp is volatile."""
    left, right = json.loads(json.dumps(before)), json.loads(json.dumps(after))
    gates.expected_proofs(left, digest(left))
    gates.expected_proofs(right, digest(right))
    volatile = []
    if "reviewed_at" in left["review"] or "reviewed_at" in right["review"]:
        for item in (left, right):
            stamp = datetime.fromisoformat(item["review"].pop("reviewed_at"))
            if stamp.utcoffset() != timedelta(0):
                raise ActivationError("diagnostic_proof_review_timestamp_invalid")
        volatile = ["review.reviewed_at"]
    if digest(left) != digest(right):
        raise ActivationError("diagnostic_persisted_proofs_changed")
    return {
        "format": "aegis-diagnostic-proof-comparison/1",
        "status": "reviewed_binding_and_proofs_unchanged",
        "before_bundle_sha256": digest(before),
        "after_bundle_sha256": digest(after),
        "comparison_sha256": digest(left),
        "ignored_volatile_fields": volatile,
        "proofs_reviewed": len(left["proofs"]),
        "full_database_contents_compared": False,
    }


def execute(context, password, *, adapters=None):
    """Only a complete authorized host coordinator may invoke this with native adapters.

    Writes one-use intent before the first effect, never retries a role, and always
    closes owned resources. This module alone is not permission to open Lab volumes.
    """
    if not isinstance(context, gates.DiagnosticGates):
        raise ActivationError("diagnostic_trusted_context_required")
    adapters = adapters or Adapters()
    if not isinstance(adapters, Adapters):
        raise ActivationError("diagnostic_trusted_adapters_required")
    context._guard()
    store, images = context.store, context.images
    if store.review()["resources"]:
        raise ActivationError("diagnostic_new_operation_required_no_replay")
    # Validate private input before recording intent or starting PostgreSQL.
    gates.captures.request(context.identity, context.descriptor, password)
    writer = gates.facts.plan.image_build._write
    writer(
        context.folder / "diagnostic-requested.json",
        json.dumps(
            {
                "plan_sha256": context.plan_sha256,
                "scope_sha256": context.scope,
                "operation_id": store.summary()["id"],
                "begin_sha256": store.summary()["begin_sha256"],
            },
            sort_keys=True,
        ).encode(),
    )
    stages, comparison, journal_comparison = {}, None, None
    failed, interrupted, cleanup = None, None, None
    runtime_folder = None

    def record(role, report):
        stages[role] = report
        writer(
            runtime_folder / (role + "-lifecycle.json"), json.dumps(report, sort_keys=True).encode()
        )
        if role == "db":
            complete = report["database_retained_running"] is True
        else:
            complete = report["probe_result_verified"] is True and report["probe_removed"] is True
        if not complete:
            raise ActivationError("diagnostic_stage_unconfirmed")
        context._guard()
        return report["result"] if role != "db" else report

    def read(role):
        report = gates.reader.execute_reader(
            store,
            images,
            role,
            context.identity,
            context.descriptor,
            password,
            before_effect=context.before_reader,
            lifecycle=adapters.reader,
            runtime_docker=adapters.reader_runtime,
            ownership_docker=context.ownership_docker,
            cleanup_docker=adapters.cleanup,
            capture_root=context.capture_root,
        )
        capture = record(role, report)
        return gates.captures.load(
            store,
            role,
            capture["proof_bundle_sha256"],
            context.identity,
            context.descriptor,
            root=context.capture_root,
        )

    try:
        runtime_folder = gates.facts.plan.pki.private_directory(context.policy_root, create=True)
        runtime_folder = gates.facts.plan.pki.private_directory(
            runtime_folder / store.summary()["id"], create=True
        )
        gates.database.server.policy.prepare(store, root=context.policy_root)
        record(
            "db",
            gates.server.start_server(
                store,
                images,
                before_effect=context.before_server,
                policy_root=context.policy_root,
                lifecycle=adapters.server,
                runtime_docker=context.runtime_docker,
                ownership_docker=context.ownership_docker,
                cleanup_docker=adapters.cleanup,
            ),
        )
        before = read("database-review-before")
        context.use_capture("database-review-before", digest(before))
        journal_results = []
        for role in ("journal-before", "journal-after"):
            context._guard()
            report = gates.journal.execute_probe(
                store,
                images,
                role,
                before,
                digest(before),
                before_effect=context.before_journal,
                lifecycle=adapters.journal,
                runtime_docker=adapters.journal_runtime,
                ownership_docker=context.ownership_docker,
                cleanup_docker=adapters.cleanup,
            )
            journal_results.append(record(role, report))
        journal_comparison = compare_journal(
            *(json.dumps(item).encode() for item in journal_results), before, digest(before)
        )
        after = read("database-review-after")
        comparison = compare_proofs(before, after)
        context._guard()
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        failed = "diagnostic_execution_unconfirmed"
    except BaseException as error:
        interrupted = error
        failed = "diagnostic_interrupted"
    finally:
        # Expired approval/budget never blocks cleanup; native driver only targets
        # this locked intent's IDs, leaving parents when a dependent is uncertain.
        try:
            cleanup = closure.cleanup(
                store, images, docker=adapters.cleanup, ownership_docker=context.ownership_docker
            )
        except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError):
            cleanup = None
    complete = (
        cleanup is not None
        and cleanup["managed_resources_absence_verified"] is True
        and cleanup["operation_closed"] is True
    )
    verified = (
        failed is None and comparison is not None and journal_comparison is not None and complete
    )
    try:
        start_requested = "start" in store.review()["resources"].get("db", {})
    except (ValueError, OSError):
        start_requested = None
    result = {
        "format": "aegis-original-volume-diagnostic/1",
        "operation_id": store.summary()["id"],
        "plan_sha256": context.plan_sha256,
        "scope_sha256": context.scope,
        "status": "diagnostic_verified_and_closed"
        if verified
        else "diagnostic_failed_and_closed"
        if complete
        else "diagnostic_cleanup_unconfirmed",
        "error": failed,
        "stages": {role: digest(item) for role, item in stages.items()},
        "computed_gate_evidence": context.evidence,
        "persisted_comparison": comparison,
        "journal_comparison": journal_comparison,
        "cleanup": cleanup,
        "diagnostic_verified": verified,
        "database_start_requested": start_requested,
        "managed_resources_absence_verified": complete,
        "marker_executed": False,
        "worker_started": False,
        "pki_activated": False,
        "binding_changed": False,
        "volumes_removed": False,
        "normal_operation_permitted": False,
    }
    if runtime_folder is not None:
        writer(
            runtime_folder / "diagnostic-receipt.json", json.dumps(result, sort_keys=True).encode()
        )
    if interrupted is not None:
        raise interrupted
    return result
