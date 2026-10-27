"""Fixed probe orchestration with real temporary journals and fixture Docker only."""

import contextlib
import io
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import journal_probe
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_cleanup as closure  # noqa: E402
import runner_activation_probe_lifecycle as life  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402
from test_runner_activation_metadata import images  # noqa: E402
from test_runner_activation_ownership import FakeDocker as Owner  # noqa: E402
from test_runner_activation_probe_runtime import OBJECT  # noqa: E402
from test_runner_activation_probe_runtime import Docker as Runtime  # noqa: E402


class World:
    def __init__(self, store, bundle, root, monkeypatch, scene=None):
        self.store, self.bundle, self.root, self.monkeypatch = store, bundle, root, monkeypatch
        self.scene, self.owner, self.effects = scene, None, []
        self.operation = store.summary()["id"]
        self.spec = life.runtime.recipe(
            self.operation, "a" * 64, "journal-before", images()["runner"], digest(bundle)
        )
        self.runtime = Runtime(self.spec)
        self.runtime.image["id"] = images()["runner"]
        self.runtime.item["image"] = self.runtime.item["image_reference"] = images()["runner"]
        self.runtime.item["arguments"][-1] = digest(bundle)
        self.gate_calls = []

    def query(self, kind, *args):
        if kind in {"image", "container"}:
            return self.runtime.query(kind, *args)
        if self.owner is None:
            assert kind != "inspect"
            return b""
        return self.owner.query(kind, *args)

    def create_object(self):
        self.owner = Owner(self.operation, "journal-before")
        self.owner.details["image"] = images()["runner"]

    def gate(self, phase, spec):
        self.gate_calls.append(phase)
        assert spec == self.spec
        now = datetime.now(UTC)
        item = {
            "format": "aegis-journal-probe-gate/1",
            "phase": phase,
            "operation_id": self.operation,
            "plan_sha256": "a" * 64,
            "scope_sha256": "b" * 64,
            "recipe_sha256": digest(spec),
            "proof_bundle_sha256": digest(self.bundle),
            "old_descriptor_sha256": self.bundle["old_descriptor_sha256"],
            "identity_sha256": digest(self.bundle["identity"]),
            "checked_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=20)).isoformat(),
            "checks": dict.fromkeys(life.CHECKS, True),
        }
        if self.scene == "deny_" + phase:
            item["checks"]["specific_authorization_verified"] = False
        if self.scene == "stale_" + phase:
            item["checked_at"] = (now - timedelta(seconds=11)).isoformat()
        if self.scene == "future_" + phase:
            item["checked_at"] = (now + timedelta(seconds=1)).isoformat()
        if self.scene == "wrong_context_" + phase:
            item["scope_sha256"] = "f" * 64
        if self.scene == "missing_check_" + phase:
            item["checks"].pop("image_provenance_verified")
        if self.scene == "integer_check_" + phase:
            item["checks"]["worker_stopped"] = 1
        if self.scene == "runtime_changed" and phase == "start":
            self.runtime.item["host"]["Privileged"] = True
        if self.scene == "collision" and phase == "create":
            self.create_object()
        return item

    def create(self, *args):
        assert self.store.review()["resources"]["journal-before"]["state"] == "REQUESTED"
        records = [json.loads(path.read_bytes()) for path in self.store.folder.glob("*.json")]
        assert any(event["kind"] == "create_requested" for event in records)
        self.effects.append("create")
        if self.scene == "create_failed_before":
            raise life.ActivationError("private-sensitive-sentinel")
        self.create_object()
        if self.scene == "create_failed_after":
            raise life.ActivationError("private-sensitive-sentinel")
        return "f" * 64 if self.scene == "wrong_returned_id" else OBJECT

    def start(self, operation, plan, role, image, proof_sha, object_id, payload):
        item = self.store.review()["resources"][role]
        assert item["state"] == "START_REQUESTED" and item["resource_id"] == object_id == OBJECT
        assert item["start"]["recipe_sha256"] == digest(self.spec)
        assert item["start"]["proof_bundle_sha256"] == proof_sha
        records = [json.loads(path.read_bytes()) for path in self.store.folder.glob("*.json")]
        assert any(event["kind"] == "probe_start_requested" for event in records)
        assert digest(json.loads(payload)) == proof_sha == digest(self.bundle)
        self.effects.append("start")
        if self.scene == "start_ambiguous":
            self.owner.details["running"] = True
            raise life.ActivationError("private-sensitive-sentinel")
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        self.runtime.item["status"] = "exited"
        if self.scene == "bad_output":
            return b"private-sensitive-sentinel"
        if self.scene == "exit_failed":
            self.runtime.item["exit_code"] = 2
        with self.monkeypatch.context() as patch:
            patch.setattr(journal_probe, "STATE_DIRECTORY", self.root)
            patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert journal_probe.main(["--expected-sha256", proof_sha]) == 0
            return output.getvalue().encode()

    def effect(self, kind, operation, plan, role, known_id):
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        closure.command(kind, operation, plan, role, known_id)
        self.effects.append(kind)
        if self.scene == "cleanup_failed":
            raise life.ActivationError("private-sensitive-sentinel")
        if kind == "stop":
            self.owner.details["running"] = False
        else:
            self.owner = None


def invoke(store, world, bundle, **kwargs):
    return life.execute_probe(
        store,
        images(),
        "journal-before",
        bundle,
        digest(bundle),
        before_effect=world.gate,
        lifecycle=world,
        runtime_docker=world,
        ownership_docker=world,
        cleanup_docker=world,
        **kwargs,
    )


def test_complete_probe_flow_persists_intents_verifies_real_sqlite_result_and_cleans_without_closing_parent(
    tmp_path, journal, bundle, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, bundle, journal[0], monkeypatch)
        result = invoke(store, world, bundle)
        assert result["status"] == "probe_completed_and_removed"
        assert result["probe_removed"] and result["probe_result_verified"]
        assert result["result"]["snapshot"]["expected_proofs_matched"] == 1
        assert (
            result["authorization_verified"]
            is result["activation_verified"]
            is result["normal_operation_permitted"]
            is False
        )
        assert world.effects == ["create", "start", "remove"] and world.gate_calls == [
            "create",
            "start",
        ]
        assert store.review()["resources"]["journal-before"]["state"] == "ABSENT"
        assert not store.review()["closed"]
        assert bundle["proofs"][0]["spec"]["marker"] not in json.dumps(result)
        store.request("runner")


@pytest.mark.parametrize("phase", ["create", "start"])
@pytest.mark.parametrize(
    "scene", ["deny", "stale", "future", "wrong_context", "missing_check", "integer_check"]
)
def test_missing_stale_or_wrong_scope_gate_never_performs_corresponding_effect(
    tmp_path, journal, bundle, monkeypatch, phase, scene
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, bundle, journal[0], monkeypatch, scene + "_" + phase)
        result = invoke(store, world, bundle)
        assert result["status"] == "probe_execution_unconfirmed" and result["probe_removed"]
        assert "start" not in world.effects
        assert ("create" in world.effects) is (phase == "start")
        assert not result["probe_result_verified"] and not store.review()["closed"]


@pytest.mark.parametrize(
    "scene",
    [
        "create_failed_before",
        "create_failed_after",
        "wrong_returned_id",
        "start_ambiguous",
        "bad_output",
        "exit_failed",
        "runtime_changed",
    ],
)
def test_create_start_and_result_ambiguity_is_never_replayed_and_is_cleaned_if_owned(
    tmp_path, journal, bundle, monkeypatch, scene
):
    with ActivationIntents(tmp_path / "intents") as store:
        origin = store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, bundle, journal[0], monkeypatch, scene)
        result = invoke(store, world, bundle)
        assert result["status"] == "probe_execution_unconfirmed" and result["probe_removed"]
        assert not result["probe_result_verified"]
        assert world.effects.count("start") <= 1 and world.effects.count("create") == 1
        assert "private-sensitive-sentinel" not in json.dumps(result)
        previous = list(world.effects)
        with pytest.raises(life.ActivationError, match="no_replay"):
            invoke(store, world, bundle)
        assert world.effects == previous
    with ActivationIntents(tmp_path / "intents") as store:
        store.resume(origin["id"], origin["begin_sha256"])
        world.store = store
        with pytest.raises(life.ActivationError, match="no_replay"):
            invoke(store, world, bundle)
        assert world.effects == previous


def test_cleanup_failure_never_publishes_success_and_preserves_open_intent(
    tmp_path, journal, bundle, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, bundle, journal[0], monkeypatch, "cleanup_failed")
        result = invoke(store, world, bundle)
        assert result["status"] == "probe_cleanup_unconfirmed"
        assert result["probe_result_verified"] and not result["probe_removed"]
        assert store.review()["resources"]["journal-before"]["state"] == "REMOVAL_REQUESTED"
        assert not store.review()["closed"] and world.owner is not None


def test_keyboard_interrupt_runs_owned_cleanup_and_is_not_swallowed(
    tmp_path, journal, bundle, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, bundle, journal[0], monkeypatch, "interrupt")
        with pytest.raises(KeyboardInterrupt):
            invoke(store, world, bundle)
        assert world.effects == ["create", "start", "remove"]
        assert not store.review()["closed"]


@pytest.mark.parametrize("scene", ["prior", "collision"])
def test_preexisting_or_racing_resource_is_never_adopted_or_removed_before_create_attempt(
    tmp_path, journal, bundle, monkeypatch, scene
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, bundle, journal[0], monkeypatch, scene)
        if scene == "prior":
            world.create_object()
            with pytest.raises(life.ActivationError, match="prior_resource_present"):
                invoke(store, world, bundle)
            assert store.review()["resources"] == {}
        else:
            result = invoke(store, world, bundle)
            assert result["status"] == "probe_cleanup_unconfirmed"
            assert store.review()["resources"]["journal-before"]["state"] == "CONFLICT"
            later = closure.cleanup(store, images(), docker=world, ownership_docker=world)
            assert later["status"] == "cleanup_incomplete" and not store.review()["closed"]
        assert world.owner is not None and world.effects == []


@pytest.mark.parametrize("kind", ["exec", "run", "stop", "rm", "network", "volume"])
def test_lifecycle_command_catalog_accepts_no_arbitrary_effect_or_non_probe(kind):
    with pytest.raises(life.ActivationError, match="command_not_allowed"):
        life.command(kind, uuid4().hex, "a" * 64, "journal-before", images()["runner"], "b" * 64)
    with pytest.raises(life.ActivationError):
        life.command("start", uuid4().hex, "a" * 64, "runner", images()["runner"], "b" * 64, OBJECT)


def test_concrete_driver_uses_fixed_arguments_only_and_stdin_not_environment_or_argv(monkeypatch):
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return (OBJECT + "\n").encode() if args[1] == "create" else b"reply"

    monkeypatch.setattr(life, "_execute", execute)
    driver = life.ProbeDocker()
    operation = uuid4().hex
    assert (
        driver.create(operation, "a" * 64, "journal-before", images()["runner"], "b" * 64) == OBJECT
    )
    assert (
        driver.start(
            operation,
            "a" * 64,
            "journal-before",
            images()["runner"],
            "b" * 64,
            OBJECT,
            b"private-sensitive-sentinel",
        )
        == b"reply"
    )
    assert calls[1] == (
        ("container", "start", "--attach", "--interactive", OBJECT),
        {"payload": b"private-sensitive-sentinel", "timeout": 20},
    )
    assert all("private-sensitive-sentinel" not in str(args) for args, _ in calls)


def test_import_is_inert_and_does_not_load_application_configuration():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('No external effects permitted')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('No secrets permitted')
sys.addaudithook(guard)
import runner_activation_probe_lifecycle
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
assert 'aegis.lab_runner.engine' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
