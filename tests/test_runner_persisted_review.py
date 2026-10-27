"""Real disposable PostgreSQL schemas and temporary journals; never a real lab."""

import copy
from uuid import UUID, uuid4

import pytest
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.lab_runner import continuity, persisted_review
from aegis.lab_runner.journal import Journal
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.models import AuditEvent, Laboratory, LinuxLabBinding
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from test_binding_review import binding_lab as binding_lab
from test_binding_review import history


def arguments(binding_lab):
    _, descriptor = binding_lab
    identity = RunnerIdentity(
        **{key: descriptor[key] for key in ("runner_id", "laboratory_id", "asset_id")}
    )
    return identity, digest(descriptor)


def collect(binding_lab, pg_engine):
    return persisted_review.collect(pg_engine, *arguments(binding_lab))


def test_read_only_proofs_match_temporary_original_journal(
    binding_lab, pg_engine, tmp_path, monkeypatch
):
    _, descriptor = binding_lab
    history(descriptor)
    original = persisted_review.binding_review.review

    def read_only(db, lab):
        assert db.scalar(text("SHOW transaction_read_only")) == "on"
        assert db.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        assert db.scalar(text("SHOW statement_timeout")) == "15s"
        return original(db, lab)

    monkeypatch.setattr(persisted_review.binding_review, "review", read_only)
    with session_factory()() as db:
        before = db.scalar(select(func.count()).select_from(AuditEvent))
        version = db.get(Laboratory, descriptor["laboratory_id"]).environment_version
    bundle = collect(binding_lab, pg_engine)
    identity, expected = persisted_review.expected_proofs(bundle, digest(bundle))
    assert bundle["status"] == "persisted_proofs_require_original_journal_review"
    assert len(expected) == 1
    assert all(
        bundle[key] is False
        for key in (
            "database_volume_binding_verified",
            "journal_verified",
            "activation_permitted",
            "normal_operation_permitted",
        )
    )
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    writer = Journal(root)
    with writer.connection() as db:
        db.execute(
            "INSERT INTO metadata VALUES ('identity',?)",
            (digest(identity.model_dump(mode="json")),),
        )
        for view in expected.values():
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(view.spec.job_id),
                    view.spec.model_dump_json(),
                    view.spec_hash,
                    str(view.generation),
                    view.state,
                    view.cleanup_state,
                    view.reason,
                    None,
                    None,
                ),
            )
            for action in ("PREPARED", "CANCELLED", "CLEANED"):
                writer.event(db, view.spec.job_id, action)
    writer.close()
    assert continuity.review(root, identity, expected)["expected_proofs_matched"] == 1
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == before
        assert db.get(Laboratory, descriptor["laboratory_id"]).environment_version == version
        assert not db.get(Laboratory, descriptor["laboratory_id"]).authorized


def test_db_cannot_write_even_if_review_implementation_regresses(
    binding_lab, pg_engine, monkeypatch
):
    _, descriptor = binding_lab
    history(descriptor)

    def write(db, lab):
        db.execute(text("UPDATE laboratories SET authorized=true WHERE id=:id"), {"id": lab.id})
        pytest.fail("PostgreSQL must reject the write")

    monkeypatch.setattr(persisted_review.binding_review, "review", write)
    with pytest.raises(DBAPIError) as error:
        collect(binding_lab, pg_engine)
    assert error.value.orig.sqlstate == "25006"
    with session_factory()() as db:
        assert not db.get(Laboratory, descriptor["laboratory_id"]).authorized


@pytest.mark.parametrize(
    "problem",
    [
        "missing_lab",
        "old_hash",
        "runner",
        "asset",
        "revocation",
        "reservation",
        "pending",
        "no_cleanup",
        "empty",
        "limit",
    ],
)
def test_original_binding_and_complete_resolved_history_are_required(
    binding_lab, pg_engine, monkeypatch, problem
):
    _, descriptor = binding_lab
    identity, old_hash = arguments(binding_lab)
    if problem != "empty":
        history(
            descriptor,
            parent="PENDING_APPROVAL" if problem == "pending" else "COMPLETED",
            cleaned=problem != "no_cleanup",
        )
    if problem == "missing_lab":
        identity = identity.model_copy(update={"laboratory_id": uuid4()})
    elif problem == "old_hash":
        old_hash = "0" * 64
    elif problem == "runner":
        identity = identity.model_copy(update={"runner_id": uuid4()})
    elif problem == "asset":
        identity = identity.model_copy(update={"asset_id": uuid4()})
    elif problem in {"revocation", "reservation"}:
        with session_factory()() as db:
            lab = db.get(Laboratory, descriptor["laboratory_id"])
            if problem == "revocation":
                lab.authorized = True
            else:
                lab.active_run_id = str(uuid4())
            db.commit()
    elif problem == "limit":
        monkeypatch.setattr(persisted_review.binding_review, "HISTORY_LIMIT", 0)
    with pytest.raises(continuity.ContinuityError):
        persisted_review.collect(pg_engine, identity, old_hash)


def test_old_configuration_binding_cannot_change_between_plan_and_snapshot(binding_lab, pg_engine):
    _, descriptor = binding_lab
    history(descriptor)
    with session_factory()() as db:
        db.get(LinuxLabBinding, descriptor["laboratory_id"]).configuration_hash = "f" * 64
        db.commit()
    with pytest.raises(continuity.ContinuityError, match="original_binding_mismatch"):
        collect(binding_lab, pg_engine)


@pytest.fixture
def bundle(journal):
    root, identity, expected = journal
    proofs = [value.model_dump(mode="json") for value in expected.values()]
    return {
        "format": "aegis-persisted-journal-proofs/1",
        "identity": identity.model_dump(mode="json"),
        "old_descriptor_sha256": "a" * 64,
        "laboratory_id": str(identity.laboratory_id),
        "environment_version": 2,
        "status": "persisted_proofs_require_original_journal_review",
        "review": {
            "format": "aegis-linux-binding-review/1",
            "laboratory_id": str(identity.laboratory_id),
            "environment_version": 2,
            "status": "persisted_prerequisites_satisfied",
            "blockers": [],
            "dispatch_history_complete": True,
            "nonterminal_runs": 0,
            "nonterminal_tests": 0,
            "unconfirmed_cleanup_count": 0,
            "dispatches_examined": 1,
            "runner_contacted": False,
            "journal_verified": False,
            "activation_permitted": False,
            "normal_operation_permitted": False,
        },
        "proofs": proofs,
        "proofs_sha256": digest(proofs),
        "database_volume_binding_verified": False,
        "journal_verified": False,
        "activation_permitted": False,
        "normal_operation_permitted": False,
    }


# Reuse temporary SQLite fixture; it doesn't request PostgreSQL or a runner.
from test_runner_journal_continuity import journal as journal  # noqa: E402


def test_independently_hashed_bundle_roundtrips(bundle):
    identity, expected = persisted_review.expected_proofs(bundle, digest(bundle))
    assert isinstance(identity.laboratory_id, UUID) and len(expected) == 1


@pytest.mark.parametrize(
    "problem",
    [
        "hash",
        "format",
        "flag",
        "flag_type",
        "lab",
        "version",
        "blocker",
        "incomplete",
        "pending",
        "count",
        "duplicate",
        "proof_hash",
        "proof_identity",
        "proof_cleanup",
        "unknown",
        "descriptor",
    ],
)
def test_edited_or_contradictory_bundle_cannot_be_used_as_expectation(bundle, problem):
    original_hash = digest(bundle)
    value = copy.deepcopy(bundle)
    if problem == "hash":
        value["environment_version"] = 3
    elif problem == "format":
        value["format"] = "unknown/1"
    elif problem == "flag":
        value["journal_verified"] = True
    elif problem == "flag_type":
        value["activation_permitted"] = 0
    elif problem == "lab":
        value["laboratory_id"] = str(uuid4())
    elif problem == "version":
        value["environment_version"] = True
    elif problem == "blocker":
        value["review"]["blockers"] = ["unconfirmed_cleanup"]
    elif problem == "incomplete":
        value["review"]["dispatch_history_complete"] = False
    elif problem == "pending":
        value["review"]["nonterminal_tests"] = 1
    elif problem == "count":
        value["review"]["dispatches_examined"] = 2
    elif problem == "duplicate":
        value["proofs"] *= 2
        value["proofs_sha256"] = digest(value["proofs"])
        value["review"]["dispatches_examined"] = 2
    elif problem == "proof_hash":
        value["proofs_sha256"] = "0" * 64
    elif problem == "proof_identity":
        value["proofs"][0]["spec"]["runner_id"] = str(uuid4())
        value["proofs_sha256"] = digest(value["proofs"])
    elif problem == "proof_cleanup":
        value["proofs"][0]["cleanup_state"] = "PENDING"
        value["proofs_sha256"] = digest(value["proofs"])
    elif problem == "descriptor":
        value["old_descriptor_sha256"] = "not-a-hash"
    else:
        value["unexpected"] = "field"
    with pytest.raises(continuity.ContinuityError):
        persisted_review.expected_proofs(
            value, original_hash if problem == "hash" else digest(value)
        )
