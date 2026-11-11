"""Internal SQL/journal continuity coordinator; never starts a lab or repairs history.

The host executor must prove physical mounts/ownership and hold its durable
one-use intent before invoking this component. A fixture is not that proof.
"""

from dataclasses import dataclass
from pathlib import Path

from aegis.domain.validation import digest
from aegis.lab_runner import continuity, persisted_review
from aegis.lab_runner.protocol import RunnerIdentity


@dataclass(frozen=True)
class ContinuityReview:
    """In-process result, deliberately not deserializable from API or saved JSON."""

    identity: RunnerIdentity
    old_descriptor_sha256: str
    environment_version: int
    before_bundle_sha256: str
    after_bundle_sha256: str
    stable_bundle_sha256: str
    inventory_sha256: str
    proofs_examined: int


def stable_sha256(bundle: dict) -> str:
    """Only the review timestamp may vary; compare full immutable proof bodies."""
    value = {**bundle, "review": {k: v for k, v in bundle["review"].items() if k != "reviewed_at"}}
    return digest(value)


def unchanged(before: dict, after: dict) -> bool:
    return stable_sha256(before) == stable_sha256(after)


def collect(engine, state_directory: Path, identity: RunnerIdentity, old_descriptor_sha256: str):
    """Two independent read-only SQL snapshots surrounding two journal reviews.

    Locks and WAL-aware scratch copies are supplied by the existing reviewers.
    No Runner/Journal writer, remote job, database fallback or repair is used.
    Caller must recheck the result under the laboratory lock before binding.
    """
    before = persisted_review.collect(engine, identity, old_descriptor_sha256)
    _, proofs = persisted_review.expected_proofs(before, digest(before))
    first = continuity.review(state_directory, identity, proofs)
    second = continuity.review(state_directory, identity, proofs)
    after = persisted_review.collect(engine, identity, old_descriptor_sha256)
    if first != second or not unchanged(before, after):
        raise continuity.ContinuityError("activation_continuity_changed")
    return ContinuityReview(
        identity=identity,
        old_descriptor_sha256=old_descriptor_sha256,
        environment_version=before["environment_version"],
        before_bundle_sha256=digest(before),
        after_bundle_sha256=digest(after),
        stable_bundle_sha256=stable_sha256(before),
        inventory_sha256=first["inventory_sha256"],
        proofs_examined=len(proofs),
    )


def require_current(db, lab, reviewed: ContinuityReview):
    """Repeat the complete persisted predicate while caller owns the lab lock.

    The descriptor remains the old one until the reviewed registration commits.
    Never rewrite scopes, cleanup records or approvals to match new trust.
    """
    from sqlalchemy import select

    from aegis import binding_review
    from aegis.models import Asset, CampaignRun, LinuxLabBinding, RunnerCleanup, RunnerDispatch
    from aegis.models import TestExecution as Execution

    if not isinstance(reviewed, ContinuityReview):
        raise continuity.ContinuityError("activation_in_process_review_required")
    binding = db.get(LinuxLabBinding, lab.id)
    asset = db.get(Asset, str(reviewed.identity.asset_id))
    if (
        lab.id != str(reviewed.identity.laboratory_id)
        or lab.environment_version != reviewed.environment_version
        or not binding
        or binding.runner_id != str(reviewed.identity.runner_id)
        or binding.configuration_hash != reviewed.old_descriptor_sha256
        or not asset
        or asset.laboratory_id != lab.id
        or asset.synthetic
        or asset.platform != "Linux"
        or asset.external_id != str(reviewed.identity.asset_id)
    ):
        raise continuity.ContinuityError("activation_original_binding_changed")
    binding_review.require_review(db, lab)
    rows = (
        db.execute(
            select(RunnerCleanup.content)
            .select_from(CampaignRun)
            .join(Execution, Execution.run_id == CampaignRun.id)
            .join(RunnerDispatch, RunnerDispatch.execution_id == Execution.id)
            .join(RunnerCleanup, RunnerCleanup.execution_id == Execution.id)
            .where(CampaignRun.laboratory_id == lab.id)
            .order_by(Execution.id)
            .limit(binding_review.HISTORY_LIMIT + 1)
        )
        .scalars()
        .all()
    )
    # Rebuild the exact original bundle in the locked transaction. The regular
    # collector intentionally owns its RR snapshot and cannot reuse this session.
    from aegis.lab_runner.persisted_review import expected_proofs

    review = binding_review.review(db, lab)
    bundle = {
        "format": "aegis-persisted-journal-proofs/1",
        "identity": reviewed.identity.model_dump(mode="json"),
        "old_descriptor_sha256": binding.configuration_hash,
        "laboratory_id": lab.id,
        "environment_version": lab.environment_version,
        "review": review,
        "proofs": list(rows),
        "proofs_sha256": digest(list(rows)),
        "status": "persisted_proofs_require_original_journal_review",
        "database_volume_binding_verified": False,
        "journal_verified": False,
        "activation_permitted": False,
        "normal_operation_permitted": False,
    }
    expected_proofs(bundle, digest(bundle))
    if stable_sha256(bundle) != reviewed.stable_bundle_sha256:
        raise continuity.ContinuityError("activation_persisted_history_changed")
    return bundle
