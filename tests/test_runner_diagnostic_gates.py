"""Compute gates using native fixtures, real private captures and temporary Git/PKI."""

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from aegis.lab_runner.network_profile import LEGACY_LINUX_IP
from test_build_review_runner import prepared as prepared
from test_runner_activation_database_inspection import Docker as Database
from test_runner_activation_image_source import repository as repository
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_diagnostic_plan import diagnostic as diagnostic
from test_runner_diagnostic_recheck import World
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_diagnostic_gates as gates  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def public_identity(monkeypatch, bundle):
    original = gates.facts.plan.pki.initialize

    def initialize(path, **kwargs):
        kwargs.setdefault("server_ip", LEGACY_LINUX_IP)
        kwargs["identifiers"] = {key: bundle["identity"][key] for key in gates.facts.plan.pki.IDS}
        return original(path, **kwargs)

    monkeypatch.setattr(gates.facts.plan.pki, "initialize", initialize)


@pytest.fixture
def material(public_identity, diagnostic):
    return diagnostic


def setup(material, store, tmp_path, role, phase):
    folder, report, selected, _, options = material
    store.begin(report["plan_id"], report["plan_sha256"], report["scope_sha256"])
    world = World(store, options["docker"], selected, role, phase)
    root = tmp_path / "runtime"
    gates.database.server.policy.prepare(store, root=root)
    spec = gates.server.server.recipe(store, selected["postgres"], policy_root=root)
    runtime = Database(spec, "running" if role != "db" or phase == "running" else "created")
    runtime.item.update(
        id=world.owners["db"].details["id"],
        image=selected["postgres"],
        image_reference=selected["postgres"],
    )
    runtime.image["id"] = selected["postgres"]
    context = gates.DiagnosticGates(
        folder,
        report["plan_sha256"],
        store,
        report["scope_sha256"],
        (gates.facts.plan.pki.clock() + timedelta(seconds=290)).isoformat(),
        repo=options["repo"],
        policy_root=root,
        capture_root=root,
        docker=options["docker"],
        ownership_docker=world,
        runtime_docker=runtime,
    )
    return context, world, runtime, spec


def test_reconstructing_diagnostic_gates_cannot_renew_original_operation_budget(
    material, tmp_path, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, _, _, _ = setup(material, store, tmp_path, "db", "create")
        later = context.started_at + timedelta(seconds=120)
        monkeypatch.setattr(gates.facts.plan.pki, "clock", lambda: later)
        with pytest.raises(gates.ActivationError, match="authorization_interval_invalid"):
            gates.DiagnosticGates(
                context.folder,
                context.plan_sha256,
                store,
                context.scope,
                (later + timedelta(seconds=290)).isoformat(),
            )


def test_diagnostic_clock_rollback_blocks_effects(material, tmp_path, monkeypatch):
    with ActivationIntents(tmp_path / "intents") as store:
        context, _, _, spec = setup(material, store, tmp_path, "db", "create")
        monkeypatch.setattr(
            gates.facts.plan.pki, "clock", lambda: context.confirmed_at - timedelta(seconds=1)
        )
        with pytest.raises(gates.ActivationError, match="scope_or_budget_unconfirmed"):
            context.before_server("create", spec)


@pytest.mark.parametrize("phase", ["create", "start", "ready"])
def test_server_gate_derives_facts_and_policy_and_checks_physical_runtime(
    material, tmp_path, phase
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, _, _, spec = setup(
            material, store, tmp_path, "db", "running" if phase == "ready" else phase
        )
        gate = context.before_server(phase, spec)
        assert set(gate["checks"]) == gates.server.CHECKS
        assert all(value is True for value in gate["checks"].values())
        assert gate["scope_sha256"] == store.review()["header"]["scope_sha256"]
        assert context.evidence[-1]["phase"] == phase
        assert store.review()["resources"]["db"]["state"] != "ABSENT"


@pytest.mark.parametrize("role", ["database-review-before", "database-review-after"])
@pytest.mark.parametrize("phase", ["create", "start"])
def test_reader_gate_proves_database_mount_isolation_and_auth_policy(
    material, tmp_path, role, phase
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, _, _, _ = setup(material, store, tmp_path, role, phase)
        spec = gates.reader.runtime.recipe(
            store,
            role,
            context.images["runner"],
            gates.digest(gates.captures.context(context.identity, context.descriptor)),
        )
        gate = context.before_reader(phase, spec)
        assert set(gate["checks"]) == gates.reader.CHECKS
        assert gate["checks"]["database_runtime_isolated"] is True
        assert gate["database_resource_id"] == store.review()["resources"]["db"]["resource_id"]
        assert "persisted_history_verified" not in gate["checks"]


def pin_capture(context, world, bundle):
    store = context.store
    bundle = json.loads(json.dumps(bundle))
    bundle["old_descriptor_sha256"] = context.descriptor
    role = "database-review-before"
    store.request(role)
    store.append("observed", {"role": role, "resource_id": "a" * 64})
    store.append(
        "database_review_start_requested",
        {
            "role": role,
            "recipe_sha256": "1" * 64,
            "gates_sha256": "2" * 64,
            "request_context_sha256": gates.digest(
                gates.captures.context(context.identity, context.descriptor)
            ),
        },
    )
    captured = gates.captures.capture(
        store,
        role,
        json.dumps(bundle).encode(),
        context.identity,
        context.descriptor,
        root=context.capture_root,
    )
    store.append("removal_requested", {"role": role})
    store.append("absence_recorded", {"role": role, "evidence_sha256": "3" * 64})
    owner = Owner(store.summary()["id"], role, present=False)
    world.owners[role] = owner
    context.use_capture(role, captured["proof_bundle_sha256"])
    return bundle


@pytest.mark.parametrize("role", ["journal-before", "journal-after"])
@pytest.mark.parametrize("phase", ["create", "start"])
def test_journal_gate_requires_real_private_capture_decoder_and_removed_reader(
    material, tmp_path, bundle, role, phase
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, world, _, _ = setup(material, store, tmp_path, role, phase)
        pin_capture(context, world, bundle)
        spec = gates.journal.runtime.recipe(
            store.summary()["id"],
            context.plan_sha256,
            role,
            context.images["runner"],
            context.proof_sha256,
        )
        gate = context.before_journal(phase, spec)
        assert set(gate["checks"]) == gates.journal.CHECKS
        assert gate["checks"]["persisted_history_verified"] is True
        assert gate["proof_bundle_sha256"] == context.proof_sha256
        with pytest.raises(ValueError, match="already_pinned"):
            context.use_capture("database-review-before", context.proof_sha256)


@pytest.mark.parametrize(
    "scene", ["mount", "network", "policy", "recipe", "consumer", "source", "budget"]
)
def test_computed_gate_fails_on_physical_or_context_drift(material, tmp_path, scene, monkeypatch):
    with ActivationIntents(tmp_path / "intents") as store:
        context, world, runtime, _ = setup(
            material, store, tmp_path, "database-review-before", "create"
        )
        spec = gates.reader.runtime.recipe(
            store,
            "database-review-before",
            context.images["runner"],
            gates.digest(gates.captures.context(context.identity, context.descriptor)),
        )
        if scene == "mount":
            runtime.item["mounts"][0]["name"] = "foreign-volume"
        elif scene == "network":
            runtime.item["host"]["NetworkMode"] = "host"
        elif scene == "policy":
            path = (
                context.policy_root / store.summary()["id"] / gates.database.server.policy.FILENAME
            )
            path.chmod(0o600)
            path.write_text("host all all all trust\n")
        elif scene == "recipe":
            spec["arguments"] = ["arbitrary"]
        elif scene == "consumer":
            world.docker.responses["consumers", "journal"] = ("f" * 64 + "\n").encode()
        elif scene == "source":
            (context.repo / "pyproject.toml").write_text("changed")
        else:
            context.deadline = 0
        with pytest.raises(ValueError):
            context.before_reader("create", spec)
        assert not context.evidence
        assert store.review()["resources"]["database-review-before"]["state"] == "REQUESTED"


@pytest.mark.parametrize("scene", ["scope", "expired", "too_long", "naive"])
def test_operator_confirmation_cannot_use_another_scope_or_an_unbounded_interval(
    material, tmp_path, scene
):
    folder, report, _, _, options = material
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(report["plan_id"], report["plan_sha256"], report["scope_sha256"])
        expires = gates.facts.plan.pki.clock() + timedelta(
            seconds=-1 if scene == "expired" else 301 if scene == "too_long" else 290
        )
        stamp = (
            expires.replace(tzinfo=None).isoformat() if scene == "naive" else expires.isoformat()
        )
        with pytest.raises(ValueError):
            gates.DiagnosticGates(
                folder,
                report["plan_sha256"],
                store,
                "f" * 64 if scene == "scope" else report["scope_sha256"],
                stamp,
                repo=options["repo"],
            )
