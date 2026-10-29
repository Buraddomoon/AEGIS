"""Full internal coordinator over native fixtures and real private SQLite/proof decoding."""

import contextlib
import io
import json
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from aegis.lab_runner import journal_probe
from test_build_review_runner import prepared as prepared
from test_runner_activation_database_inspection import Docker as DatabaseRuntime
from test_runner_activation_database_runtime import projection as reader_projection
from test_runner_activation_image_source import repository as repository
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_activation_probe_runtime import projection as journal_projection
from test_runner_diagnostic_gates import material as material
from test_runner_diagnostic_gates import public_identity as public_identity
from test_runner_diagnostic_plan import diagnostic as diagnostic
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_diagnostic_coordinator as coordinator  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402

gates = coordinator.gates


class World:
    def __init__(self, material, store, bundle, journal_root, monkeypatch, scene=None):
        self.material, self.store, self.bundle, self.journal_root = (
            material,
            store,
            bundle,
            journal_root,
        )
        self.monkeypatch, self.scene, self.objects, self.effects = monkeypatch, scene, {}, []
        self.counter = 0
        folder, report, images, _, options = material
        self.meta, self.images, self.repo = options["docker"], images, options["repo"]
        self.bundle = json.loads(json.dumps(bundle))
        artifact = gates.facts.plan.load(folder, report["plan_sha256"])
        self.bundle["old_descriptor_sha256"] = artifact["snapshot"]["old_descriptor_sha256"]

    def refresh(self):
        def ids(roles):
            return b"".join(
                (obj["id"] + "\n").encode() for role, obj in self.objects.items() if role in roles
            )

        self.meta.responses["containers", None] = ids(set(self.objects))
        self.meta.responses["consumers", "postgres-data"] = ids({"db"})
        self.meta.responses["consumers", "journal"] = ids({"journal-before", "journal-after"})

    def query(self, kind, operation, plan, role, known_id=None):
        obj = self.objects.get(role)
        owner = Owner(operation, role, present=obj is not None)
        owner.details["plan"] = plan
        if obj:
            owner.named = owner.labelled = owner.known = (obj["id"] + "\n").encode()
            owner.details.update(
                id=obj["id"], image=obj["spec"]["image"], running=obj["phase"] == "running"
            )
        return owner.query(kind, operation, plan, role, known_id)

    def create(self, spec):
        role = spec["role"]
        assert self.store.review()["resources"][role]["state"] == "REQUESTED"
        self.counter += 1
        obj = {"id": f"{self.counter:064x}", "phase": "created", "spec": spec}
        self.objects[role] = obj
        self.effects.append(("create", role))
        self.refresh()
        return obj["id"]

    def server_create(self, store, image, *, policy_root):
        gates.server.command("create", store, image, policy_root=policy_root)
        return self.create(gates.server.server.recipe(store, image, policy_root=policy_root))

    def server_start(self, store, image, known_id, *, policy_root):
        gates.server.command("start", store, image, known_id=known_id, policy_root=policy_root)
        self.effects.append(("start", "db"))
        if self.scene == "server_failed":
            raise ValueError("private-sensitive-sentinel")
        self.objects["db"]["phase"] = "running"
        self.refresh()

    def ready(self, store, image, known_id, *, policy_root, timeout):
        gates.server.command("ready", store, image, known_id=known_id, policy_root=policy_root)
        return True

    def reader_create(self, store, role, image, context_sha):
        gates.reader.command("create", store, role, image, context_sha)
        return self.create(gates.reader.runtime.recipe(store, role, image, context_sha))

    def reader_start(self, store, role, image, context_sha, known_id, payload):
        gates.reader.command("start", store, role, image, context_sha, known_id)
        gates.reader.decode(payload, context_sha)
        self.effects.append(("start", role))
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        self.objects[role]["phase"] = "exited"
        if self.scene == "reader_bad":
            return b'{"invalid":"private-sensitive-sentinel"}'
        result = json.loads(json.dumps(self.bundle))
        if role.endswith("after") and self.scene == "proofs_changed":
            result["environment_version"] += 1
            result["review"]["environment_version"] += 1
        if self.scene == "budget":
            self.context.deadline = 0
        return json.dumps(result).encode()

    def journal_create(self, operation, plan, role, image, proof_sha):
        gates.journal.command("create", operation, plan, role, image, proof_sha)
        return self.create(gates.journal.runtime.recipe(operation, plan, role, image, proof_sha))

    def journal_start(self, operation, plan, role, image, proof_sha, known_id, payload):
        gates.journal.command("start", operation, plan, role, image, proof_sha, known_id)
        self.effects.append(("start", role))
        self.objects[role]["phase"] = "exited"
        with self.monkeypatch.context() as patch:
            patch.setattr(journal_probe, "STATE_DIRECTORY", self.journal_root)
            patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert journal_probe.main(["--expected-sha256", proof_sha]) == 0
        result = json.loads(output.getvalue())
        if role.endswith("after") and self.scene == "journal_changed":
            result["snapshot"]["inventory_sha256"] = "0" * 64
        return json.dumps(result).encode()

    def effect(self, kind, operation, plan, role, known_id):
        coordinator.closure.command(kind, operation, plan, role, known_id)
        assert self.objects[role]["id"] == known_id
        self.effects.append((kind, role))
        if self.scene == "cleanup_failed" and role == "database-review-before":
            raise ValueError("private-sensitive-sentinel")
        if kind == "stop":
            self.objects[role]["phase"] = "exited"
        else:
            del self.objects[role]
        self.refresh()

    def database_runtime(self, kind, image, *, spec=None, known_id=None):
        # Native profile inspection only; root/state volumes are fixture metadata.
        if spec is None:
            spec = gates.server.server.recipe(
                self.store, image, policy_root=self.context.policy_root
            )
        runtime = DatabaseRuntime(spec, "created")
        runtime.image["id"] = image
        if kind == "image":
            return json.dumps(runtime.image).encode()
        obj = self.objects["db"]
        runtime = DatabaseRuntime(spec, obj["phase"])
        runtime.item.update(id=obj["id"], image=image, image_reference=image)
        return json.dumps(runtime.item).encode()

    def reader_runtime(self, kind, store, role, image, context_sha, known_id=None):
        spec = gates.reader.runtime.recipe(store, role, image, context_sha)
        obj = self.objects.get(role)
        if kind == "image":
            return json.dumps(
                {
                    "id": image,
                    "user": "10001:10001",
                    "volumes": None,
                    "exposed_ports": None,
                    "environment": [
                        {"key": key, "valid": True} for key in gates.journal.runtime.ENV_FIXED
                    ],
                }
            ).encode()
        item = reader_projection(spec, obj["phase"])
        item.update(id=obj["id"], image=image, image_reference=image, arguments=spec["arguments"])
        return json.dumps(item).encode()

    def journal_runtime(self, kind, operation, plan, role, image, proof_sha, known_id=None):
        spec = gates.journal.runtime.recipe(operation, plan, role, image, proof_sha)
        obj = self.objects.get(role)
        if kind == "image":
            return json.dumps(
                {
                    "id": image,
                    "user": "10001:10001",
                    "volumes": None,
                    "environment": [
                        {"key": key, "valid": True} for key in gates.journal.runtime.ENV_FIXED
                    ],
                }
            ).encode()
        item = journal_projection(spec, obj["phase"])
        item.update(id=obj["id"], image=image, image_reference=image, arguments=spec["arguments"])
        return json.dumps(item).encode()

    def adapters(self):
        return coordinator.Adapters(
            server=SimpleNamespace(
                create=self.server_create, start=self.server_start, ready=self.ready
            ),
            reader=SimpleNamespace(create=self.reader_create, start=self.reader_start),
            reader_runtime=SimpleNamespace(query=self.reader_runtime),
            journal=SimpleNamespace(create=self.journal_create, start=self.journal_start),
            journal_runtime=SimpleNamespace(query=self.journal_runtime),
            cleanup=self,
        )


def setup(material, store, bundle, journal, tmp_path, monkeypatch, scene=None):
    folder, report, _, _, options = material
    store.begin(report["plan_id"], report["plan_sha256"], report["scope_sha256"])
    world = World(material, store, bundle, journal[0], monkeypatch, scene)
    context = gates.DiagnosticGates(
        folder,
        report["plan_sha256"],
        store,
        report["scope_sha256"],
        (gates.facts.plan.pki.clock() + timedelta(seconds=290)).isoformat(),
        repo=options["repo"],
        policy_root=tmp_path / "runtime",
        capture_root=tmp_path / "runtime",
        docker=world.meta,
        ownership_docker=world,
        runtime_docker=SimpleNamespace(query=world.database_runtime),
    )
    world.context = context
    return context, world


def test_complete_internal_diagnostic_runs_once_with_real_decoders_and_verified_closure(
    material, tmp_path, bundle, journal, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, world = setup(material, store, bundle, journal, tmp_path, monkeypatch)
        report = coordinator.execute(
            context, "private-sensitive-sentinel", adapters=world.adapters()
        )
        assert report["status"] == "diagnostic_verified_and_closed", report
        assert report["diagnostic_verified"] and report["managed_resources_absence_verified"]
        assert not world.objects and store.review()["closed"]
        assert [
            role for kind, role in world.effects if kind == "start"
        ] == gates.facts.plan.profile()["roles"]
        assert not any(
            report[key]
            for key in (
                "marker_executed",
                "worker_started",
                "pki_activated",
                "binding_changed",
                "volumes_removed",
                "normal_operation_permitted",
            )
        )
        assert "private-sensitive-sentinel" not in json.dumps(report)
        with pytest.raises(ValueError):
            coordinator.execute(context, "private-sensitive-sentinel", adapters=world.adapters())


@pytest.mark.parametrize(
    "scene",
    [
        "server_failed",
        "reader_bad",
        "proofs_changed",
        "journal_changed",
        "budget",
        "cleanup_failed",
        "interrupt",
    ],
)
def test_failures_never_claim_success_and_cleanup_retains_ambiguous_dependents(
    material, tmp_path, bundle, journal, monkeypatch, scene
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, world = setup(material, store, bundle, journal, tmp_path, monkeypatch, scene)
        if scene == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                coordinator.execute(
                    context, "private-sensitive-sentinel", adapters=world.adapters()
                )
            path = context.policy_root / store.summary()["id"] / "diagnostic-receipt.json"
            report = json.loads(path.read_bytes())
        else:
            report = coordinator.execute(
                context, "private-sensitive-sentinel", adapters=world.adapters()
            )
        assert not report["diagnostic_verified"]
        assert "private-sensitive-sentinel" not in json.dumps(report)
        if scene == "cleanup_failed":
            assert report["status"] == "diagnostic_cleanup_unconfirmed"
            assert "db" in world.objects and not store.review()["closed"]
            assert ("stop", "db") not in world.effects
        else:
            assert report["status"] == "diagnostic_failed_and_closed"
            assert not world.objects and store.review()["closed"]


def test_policy_preparation_failure_closes_empty_intent_without_database_start(
    material, tmp_path, bundle, journal, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, world = setup(material, store, bundle, journal, tmp_path, monkeypatch)

        def failed(*args, **kwargs):
            raise OSError("private-sensitive-sentinel")

        monkeypatch.setattr(gates.database.server.policy, "prepare", failed)
        result = coordinator.execute(
            context, "private-sensitive-sentinel", adapters=world.adapters()
        )
        assert result["status"] == "diagnostic_failed_and_closed"
        assert result["database_start_requested"] is False
        assert not world.effects and store.review()["closed"]


def test_existing_one_use_request_refuses_a_new_operation_before_effects(
    material, tmp_path, bundle, journal, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        context, world = setup(material, store, bundle, journal, tmp_path, monkeypatch)
        gates.facts.plan.image_build._write(context.folder / "diagnostic-requested.json", b"{}")
        with pytest.raises(FileExistsError):
            coordinator.execute(context, "private-sensitive-sentinel", adapters=world.adapters())
        assert not world.effects
        coordinator.closure.cleanup(store, world.images, docker=world, ownership_docker=world)
        assert store.review()["closed"]


@pytest.mark.parametrize("scene", ["timestamps", "changed", "missing", "naive", "counter"])
def test_proof_comparison_ignores_only_valid_volatile_review_timestamps(bundle, scene):
    before, after = json.loads(json.dumps(bundle)), json.loads(json.dumps(bundle))
    before["review"]["reviewed_at"] = "2026-10-29T12:00:00+00:00"
    after["review"]["reviewed_at"] = "2026-10-29T12:00:01+00:00"
    if scene == "changed":
        after["environment_version"] += 1
        after["review"]["environment_version"] += 1
    elif scene == "missing":
        after["review"].pop("reviewed_at")
    elif scene == "naive":
        after["review"]["reviewed_at"] = "2026-10-29T12:00:01"
    elif scene == "counter":
        after["review"]["dispatches_examined"] = 0
    if scene == "timestamps":
        result = coordinator.compare_proofs(before, after)
        assert result["ignored_volatile_fields"] == ["review.reviewed_at"]
        assert not result["full_database_contents_compared"]
    else:
        with pytest.raises((ValueError, KeyError)):
            coordinator.compare_proofs(before, after)
