"""Internal core: actual disposable SQL/SQLite, offline PKI, fixture TLS/runtime."""

import copy
import json
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from aegis import linux_labs, schemas
from aegis.db import session_factory
from aegis.domain.validation import digest
from aegis.lab_runner.journal import Journal
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.models import Laboratory, LinuxLabBinding, User
from sqlalchemy import select
from test_binding_review import REGISTRATION, history
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_rotation_coordinator as rotation  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def world(admin, material, code, pg_engine, tmp_path, monkeypatch):
    prepared, _ = prepare(material, tmp_path)
    manifest = json.loads((material[1] / "rotation.json").read_bytes())

    def descriptor(which):
        item = manifest[which]
        return rotation.plan.pki.descriptor(item["connection"], item["certificates"])

    old, new = descriptor("source"), descriptor("candidate")
    active = {"descriptor": old}
    monkeypatch.setattr(linux_labs, "descriptor", lambda: copy.deepcopy(active["descriptor"]))
    response = admin.post("/api/v1/labs/linux/register", json=REGISTRATION)
    assert response.status_code == 201, response.text
    history(old)
    identity = RunnerIdentity(**{key: old[key] for key in rotation.plan.pki.IDS})
    bundle = rotation.review.persisted_review.collect(pg_engine, identity, digest(old))
    _, proofs = rotation.review.persisted_review.expected_proofs(bundle, digest(bundle))
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    writer = Journal(root)
    with writer.connection() as db:
        db.execute(
            "INSERT INTO metadata VALUES ('identity',?)",
            (digest(identity.model_dump(mode="json")),),
        )
        for proof in proofs.values():
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(proof.spec.job_id),
                    proof.spec.model_dump_json(),
                    proof.spec_hash,
                    str(proof.generation),
                    proof.state,
                    proof.cleanup_state,
                    proof.reason,
                    None,
                    None,
                ),
            )
            for action in ("PREPARED", "CANCELLED", "CLEANED"):
                writer.event(db, proof.spec.job_id, action)
    writer.close()
    with session_factory()() as db:
        actor = db.scalar(select(User).where(User.username == "administrator")).id
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        c = rotation.ConfirmedPlan(
            Path(prepared["plan_path"]),
            prepared["plan_sha256"],
            store,
            prepared["scope_sha256"],
            (rotation.plan.pki.clock() + timedelta(seconds=290)).isoformat(),
        )
        value = SimpleNamespace(
            c=c,
            scene=None,
            effects=[],
            calls=0,
            old=old,
            new=new,
            identity=identity,
            engine=pg_engine,
        )

        def verify(context):
            value.effects.append("fixture_runtime_review")
            if value.scene == "runtime":
                raise ValueError("private-sensitive-sentinel")

        def open_runtime(context):
            value.effects.append("fixture_prepare")
            assert (context.path.parent / "rotation-requested.json").exists()
            if value.scene == "prepare":
                raise ValueError("private-sensitive-sentinel")
            active["descriptor"] = new
            return rotation.PreparedRuntime(
                pg_engine, root, actor, schemas.LinuxRegistration(**REGISTRATION), verify
            )

        def preflight():
            value.calls += 1
            value.effects.append("fixture_identity")
            if value.scene == "interrupt":
                raise KeyboardInterrupt
            if value.scene == "identity" or value.scene == "preflight" and value.calls == 2:
                raise ValueError("private-sensitive-sentinel")
            if value.scene == "expired":
                c.deadline = 0
            if value.scene == "drift":
                history(old)
            return identity

        def cleanup(context):
            value.effects.append("fixture_cleanup")
            if value.scene == "cleanup":
                raise ValueError("private-sensitive-sentinel")
            if value.scene != "forged_cleanup":
                store.append(
                    "closed", {"evidence_sha256": digest({"fixture": "no resources created"})}
                )
            return {"managed_resources_absence_verified": True, "operation_closed": True}

        monkeypatch.setattr(
            linux_labs, "client", lambda: SimpleNamespace(preflight=preflight, close=lambda: None)
        )
        value.adapters = rotation.Adapters(open_runtime, cleanup)
        yield value


def test_complete_internal_rotation_preserves_proofs_and_registers_revoked_binding(world):
    before = rotation.review.persisted_review.collect(
        world.engine, world.identity, digest(world.old)
    )
    result = rotation.execute(world.c, adapters=world.adapters)
    assert result["status"] == "internal_rotation_reviewed_and_closed", result
    assert result["binding_commit_state"] == "committed_revoked"
    assert result["new_preflight_success"] and world.calls == 2
    assert result["managed_resources_absence_verified"]
    assert not any(
        result[key]
        for key in (
            "native_runtime_verified",
            "activation_verified",
            "marker_executed",
            "worker_started",
            "normal_operation_permitted",
        )
    )
    with session_factory()() as db:
        lab = db.get(Laboratory, str(world.identity.laboratory_id))
        assert not lab.authorized and lab.environment_version == before["environment_version"] + 1
        assert db.get(LinuxLabBinding, lab.id).configuration_hash == digest(world.new)
        assert linux_labs.verified(db, lab)
    after = rotation.review.persisted_review.collect(
        world.engine, world.identity, digest(world.new)
    )
    assert after["proofs"] == before["proofs"]
    with pytest.raises(rotation.ActivationError):
        rotation.execute(world.c, adapters=world.adapters)
    assert world.effects[-1] == "fixture_cleanup"


@pytest.mark.parametrize(
    "scene",
    [
        "prepare",
        "runtime",
        "identity",
        "preflight",
        "expired",
        "drift",
        "cleanup",
        "forged_cleanup",
        "interrupt",
    ],
)
def test_failure_closes_owned_resources_without_replay_or_automatic_rollback(world, scene):
    world.scene = scene
    if scene == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            rotation.execute(world.c, adapters=world.adapters)
        result = json.loads((world.c.path.parent / "rotation-receipt.json").read_bytes())
    else:
        result = rotation.execute(world.c, adapters=world.adapters)
    assert result["status"] != "internal_rotation_reviewed_and_closed"
    assert world.effects[-1] == "fixture_cleanup"
    assert "private-sensitive-sentinel" not in json.dumps(result)
    assert result["managed_resources_absence_verified"] is (
        scene not in {"cleanup", "forged_cleanup"}
    )
    with session_factory()() as db:
        lab = db.get(Laboratory, str(world.identity.laboratory_id))
        assert not lab.authorized
        expected = world.new if scene in {"preflight", "cleanup", "forged_cleanup"} else world.old
        assert db.get(LinuxLabBinding, lab.id).configuration_hash == digest(expected)


def test_ambiguous_commit_retains_new_revoked_binding_and_never_retries(world, monkeypatch):
    original = linux_labs.register

    def ambiguous(*args, **kwargs):
        original(*args, **kwargs)
        raise ValueError("private-sensitive-sentinel")

    monkeypatch.setattr(linux_labs, "register", ambiguous)
    result = rotation.execute(world.c, adapters=world.adapters)
    assert result["binding_commit_state"] == "unconfirmed"
    assert result["status"] == "rotation_failed_and_closed"
    with session_factory()() as db:
        lab = db.get(Laboratory, str(world.identity.laboratory_id))
        assert not lab.authorized
        assert db.get(LinuxLabBinding, lab.id).configuration_hash == digest(world.new)


def test_partial_request_fence_blocks_before_preparation(world):
    (world.c.path.parent / "rotation-requested.json").write_bytes(b"partial")
    with pytest.raises(FileExistsError):
        rotation.execute(world.c, adapters=world.adapters)
    assert world.effects == []


def test_a0_cannot_be_used_by_the_current_administrative_rotation(world):
    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    command.downgrade(config, "a0d9c7e21b45")
    try:
        result = rotation.execute(world.c, adapters=world.adapters)
        assert result["status"] == "rotation_failed_and_closed"
        assert world.calls == 0 and result["binding_commit_state"] == "not_requested"
    finally:
        command.upgrade(config, "head")
