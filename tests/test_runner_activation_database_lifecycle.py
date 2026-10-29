"""SQL reader orchestration with private temp files and fixture Docker only."""

import contextlib
import copy
import io
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner import persisted_probe as probe
from aegis.lab_runner.protocol import RunnerIdentity
from test_runner_activation_database_runtime import DATABASE, READER
from test_runner_activation_database_runtime import Docker as Runtime
from test_runner_activation_database_runtime import store as store
from test_runner_activation_metadata import images
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_journal_continuity import journal as journal
from test_runner_persisted_review import bundle as bundle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_cleanup as cleanup  # noqa: E402
import runner_activation_database_lifecycle as life  # noqa: E402

SECRET = "private-sensitive-sentinel"
ROLE = "database-review-before"


class World:
    def __init__(self, store, bundle, monkeypatch, role=ROLE, scene=None):
        self.store, self.bundle, self.monkeypatch, self.role = store, bundle, monkeypatch, role
        self.scene, self.owner, self.effects, self.gates = scene, None, [], []
        self.operation = store.summary()["id"]
        self.identity = RunnerIdentity.model_validate(bundle["identity"])
        self.context_sha256 = digest(
            life.results.context(self.identity, bundle["old_descriptor_sha256"])
        )
        self.spec = life.runtime.recipe(store, role, images()["runner"], self.context_sha256)
        self.runtime = Runtime(store, role)
        self.runtime.image["id"] = images()["runner"]
        self.runtime.item["image"] = self.runtime.item["image_reference"] = images()["runner"]
        self.runtime.item["arguments"] = self.spec["arguments"]
        self.db = self.runtime.owners["db"]
        self.db.details["image"] = images()["postgres"]

    def query(self, kind, *args):
        if kind in {"image", "container"}:
            return self.runtime.query(kind, *args)
        if args[2] == "db":
            return self.db.query(kind, *args)
        if self.owner is None:
            assert kind != "inspect"
            return b""
        return self.owner.query(kind, *args)

    def gate(self, phase, spec):
        self.gates.append(phase)
        assert spec == self.spec
        now = datetime.now(UTC)
        item = {
            "format": "aegis-database-reader-gate/1",
            "phase": phase,
            "operation_id": self.operation,
            "plan_sha256": "a" * 64,
            "scope_sha256": "f" * 64,
            "recipe_sha256": digest(spec),
            "request_context_sha256": self.context_sha256,
            "old_descriptor_sha256": self.bundle["old_descriptor_sha256"],
            "identity_sha256": digest(self.bundle["identity"]),
            "database_resource_id": DATABASE,
            "checked_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=20)).isoformat(),
            "checks": dict.fromkeys(life.CHECKS, True),
        }
        if self.scene == "deny_" + phase:
            item["checks"]["specific_authorization_verified"] = False
        elif self.scene == "stale_" + phase:
            item["checked_at"] = (now - timedelta(seconds=11)).isoformat()
        elif self.scene == "future_" + phase:
            item["checked_at"] = (now + timedelta(seconds=1)).isoformat()
        elif self.scene == "wrong_context_" + phase:
            item["request_context_sha256"] = "f" * 64
        elif self.scene == "wrong_db_" + phase:
            item["database_resource_id"] = "f" * 64
        elif self.scene == "missing_check_" + phase:
            item["checks"].pop("database_runtime_isolated")
        elif self.scene == "integer_check_" + phase:
            item["checks"]["worker_stopped"] = 1
        elif self.scene == "collision" and phase == "create":
            self.create_object()
        elif self.scene == "runtime_changed" and phase == "start":
            self.runtime.item["host"]["Privileged"] = True
        return item

    def create_object(self):
        self.owner = Owner(self.operation, self.role)
        self.owner.details["image"] = images()["runner"]

    def create(self, store, role, image, context_sha256):
        assert life.command("create", store, role, image, context_sha256)[:2] == (
            "container",
            "create",
        )
        assert (
            json.loads(sorted(store.folder.glob("*.json"))[-1].read_bytes())["kind"]
            == "create_requested"
        )
        self.effects.append("create")
        if self.scene == "create_failed_before":
            raise life.ActivationError(SECRET)
        self.create_object()
        if self.scene == "create_failed_after":
            raise life.ActivationError(SECRET)
        return "f" * 64 if self.scene == "wrong_id" else READER

    def start(self, store, role, image, context_sha256, object_id, payload):
        assert life.command("start", store, role, image, context_sha256, object_id) == (
            "container",
            "start",
            "--attach",
            "--interactive",
            READER,
        )
        assert (
            json.loads(sorted(store.folder.glob("*.json"))[-1].read_bytes())["kind"]
            == "database_review_start_requested"
        )
        assert probe.decode(payload, context_sha256)[2] == SECRET
        self.effects.append("start")
        if self.scene == "start_ambiguous":
            self.owner.details["running"] = True
            raise life.ActivationError(SECRET)
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        self.runtime.item["status"] = "exited"
        if self.scene == "bad_output":
            return SECRET.encode()
        if self.scene == "exit_failed":
            self.runtime.item["exit_code"] = 2
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding="utf-8")

        class Engine:
            def dispose(self):
                pass

        engine = Engine()

        def collect(actual_engine, identity, descriptor, *, verify):
            assert actual_engine is engine and identity == self.identity
            assert descriptor == self.bundle["old_descriptor_sha256"]
            assert verify is probe._require_fixed_database
            return copy.deepcopy(self.bundle)

        with self.monkeypatch.context() as patch:
            patch.setattr(probe, "_require_probe_process", lambda: None)
            patch.setattr(
                probe, "_open_engine", lambda password: engine if password == SECRET else None
            )
            patch.setattr(probe, "collect", collect)
            patch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
            with contextlib.redirect_stdout(stdout):
                assert probe.main(["--context-sha256", context_sha256]) == 0
            stdout.flush()
            return output.getvalue()

    def effect(self, kind, operation, plan, role, known_id):
        assert role == self.role and known_id == READER
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        cleanup.command(kind, operation, plan, role, known_id)
        self.effects.append(kind)
        if self.scene == "cleanup_failed":
            raise life.ActivationError(SECRET)
        if kind == "stop":
            self.owner.details["running"] = False
        else:
            self.owner = None


def invoke(store, world, tmp_path):
    return life.execute_reader(
        store,
        images(),
        world.role,
        world.identity,
        world.bundle["old_descriptor_sha256"],
        SECRET,
        before_effect=world.gate,
        lifecycle=world,
        runtime_docker=world,
        ownership_docker=world,
        cleanup_docker=world,
        capture_root=tmp_path / "capture",
    )


@pytest.mark.parametrize("role", [ROLE, "database-review-after"])
def test_reader_flow_uses_private_transport_captures_proofs_removes_only_reader_and_keeps_parent(
    store, bundle, tmp_path, monkeypatch, role
):
    world = World(store, bundle, monkeypatch, role)
    result = invoke(store, world, tmp_path)
    assert result["status"] == "probe_completed_and_removed"
    assert result["result"]["proof_bundle_sha256"] == digest(bundle)
    assert result["result"]["capture_verified"] and result["probe_removed"]
    assert result["probe_result_verified"] and not store.review()["closed"]
    assert store.review()["resources"]["db"]["state"] == "OBSERVED"
    assert world.effects == ["create", "start", "remove"]
    assert world.gates == ["create", "start"]
    assert SECRET not in json.dumps(result)
    assert bundle["proofs"][0]["spec"]["marker"] not in json.dumps(result)
    assert SECRET not in b"".join(path.read_bytes() for path in store.folder.iterdir()).decode()
    with pytest.raises(life.ActivationError, match="no_replay"):
        invoke(store, world, tmp_path)


@pytest.mark.parametrize("phase", ["create", "start"])
@pytest.mark.parametrize(
    "scene",
    ["deny", "stale", "future", "wrong_context", "wrong_db", "missing_check", "integer_check"],
)
def test_missing_or_stale_gates_prevent_effect_and_leave_no_private_capture(
    store, bundle, tmp_path, monkeypatch, phase, scene
):
    world = World(store, bundle, monkeypatch, scene=scene + "_" + phase)
    result = invoke(store, world, tmp_path)
    assert result["status"] == "probe_execution_unconfirmed" and result["probe_removed"]
    assert "start" not in world.effects
    assert ("create" in world.effects) is (phase == "start")
    assert not (tmp_path / "capture").exists()
    assert store.review()["resources"]["db"]["state"] == "OBSERVED"


@pytest.mark.parametrize(
    "scene",
    [
        "create_failed_before",
        "create_failed_after",
        "wrong_id",
        "start_ambiguous",
        "bad_output",
        "exit_failed",
        "runtime_changed",
    ],
)
def test_ambiguous_effect_or_invalid_result_cleans_only_owned_reader_without_replaying(
    store, bundle, tmp_path, monkeypatch, scene
):
    world = World(store, bundle, monkeypatch, scene=scene)
    result = invoke(store, world, tmp_path)
    assert result["status"] == "probe_execution_unconfirmed" and result["probe_removed"]
    assert not result["probe_result_verified"]
    assert SECRET not in json.dumps(result)
    assert store.review()["resources"]["db"]["state"] == "OBSERVED"
    assert not (tmp_path / "capture").exists()


def test_cleanup_failure_retains_parent_and_does_not_turn_capture_into_success(
    store, bundle, tmp_path, monkeypatch
):
    world = World(store, bundle, monkeypatch, scene="cleanup_failed")
    result = invoke(store, world, tmp_path)
    assert result["status"] == "probe_cleanup_unconfirmed"
    assert result["probe_result_verified"] and not result["probe_removed"]
    assert result["result"]["capture_verified"] and result["activation_verified"] is False
    with pytest.raises(life.ActivationError, match="dependencies_retained"):
        store.append("removal_requested", {"role": "db"})


def test_collision_is_quarantined_without_adopting_foreign_resource(
    store, bundle, tmp_path, monkeypatch
):
    world = World(store, bundle, monkeypatch, scene="collision")
    result = invoke(store, world, tmp_path)
    assert result["status"] == "probe_cleanup_unconfirmed" and world.effects == []
    assert store.review()["resources"][ROLE]["state"] == "CONFLICT"
    assert store.review()["resources"]["db"]["state"] == "OBSERVED"


def test_interrupt_cleans_reader_and_propagates_without_repeating_start(
    store, bundle, tmp_path, monkeypatch
):
    world = World(store, bundle, monkeypatch, scene="interrupt")
    with pytest.raises(KeyboardInterrupt):
        invoke(store, world, tmp_path)
    assert world.effects == ["create", "start", "remove"]
    assert store.review()["resources"][ROLE]["state"] == "ABSENT"


def test_capture_failure_preserves_output_and_still_cleans_reader(
    store, bundle, tmp_path, monkeypatch
):
    world = World(store, bundle, monkeypatch)
    folder = tmp_path / "capture" / store.summary()["id"]
    folder.mkdir(parents=True, mode=0o700)
    folder.parent.chmod(0o700)
    file = folder / (ROLE + "-proofs.json")
    file.write_bytes(b"prior-private-evidence")
    result = invoke(store, world, tmp_path)
    assert result["status"] == "probe_execution_unconfirmed" and result["probe_removed"]
    assert file.read_bytes() == b"prior-private-evidence"


def test_concrete_driver_pins_stdin_and_output_budget_without_echoing_password(
    store, bundle, monkeypatch
):
    identity = RunnerIdentity.model_validate(bundle["identity"])
    payload, context_sha = life.results.request(identity, bundle["old_descriptor_sha256"], SECRET)
    spec = life.runtime.recipe(store, ROLE, images()["runner"], context_sha)
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return (READER + "\n").encode() if args[1] == "create" else b"private-reply"

    monkeypatch.setattr(life, "_execute", execute)
    driver = life.DatabaseProbeDocker()
    with pytest.raises(life.ActivationError, match="create_outcome_unconfirmed"):
        driver.create(store, ROLE, images()["runner"], context_sha)
    assert calls == []
    store.request(ROLE)
    assert driver.create(store, ROLE, images()["runner"], context_sha) == READER
    store.append("observed", {"role": ROLE, "resource_id": READER})
    with pytest.raises(life.ActivationError, match="start_outcome_unconfirmed"):
        driver.start(store, ROLE, images()["runner"], context_sha, READER, payload)
    store.append(
        "database_review_start_requested",
        {
            "role": ROLE,
            "recipe_sha256": digest(spec),
            "gates_sha256": "f" * 64,
            "request_context_sha256": context_sha,
        },
    )
    assert (
        driver.start(store, ROLE, images()["runner"], context_sha, READER, payload)
        == b"private-reply"
    )
    callback = calls[-1][1].pop("failure_decoder")
    assert callable(callback)
    assert calls[-1] == (
        ("container", "start", "--attach", "--interactive", READER),
        {"payload": payload, "timeout": 20, "output_limit": 4 * 1024**2},
    )
    assert all(SECRET not in str(args) for args, _ in calls)


@pytest.mark.parametrize("exit_failed", [False, True])
def test_driver_retains_only_a_context_bound_static_rejection(
    store, bundle, monkeypatch, exit_failed
):
    identity = RunnerIdentity.model_validate(bundle["identity"])
    payload, context_sha = life.results.request(identity, bundle["old_descriptor_sha256"], SECRET)
    spec = life.runtime.recipe(store, ROLE, images()["runner"], context_sha)
    store.request(ROLE)
    store.append("observed", {"role": ROLE, "resource_id": READER})
    store.append(
        "database_review_start_requested",
        {
            "role": ROLE,
            "recipe_sha256": digest(spec),
            "gates_sha256": "f" * 64,
            "request_context_sha256": context_sha,
        },
    )
    report = {
        "format": probe.FAILURE_FORMAT,
        "status": "rejected",
        "code": "persisted_probe_rejected",
        "context_sha256": context_sha,
        "failure_phase": "collect",
        "failure_reason": "persisted_probe_schema_unsupported",
        **probe.FLAGS,
    }

    def execute(*_args, **kwargs):
        raw = json.dumps(report).encode()
        if exit_failed:
            kwargs["failure_decoder"](raw)
            pytest.fail("Nonzero rejection must raise")
        return raw

    monkeypatch.setattr(life, "_execute", execute)
    with pytest.raises(life.ActivationError, match="^persisted_probe_schema_unsupported$"):
        life.DatabaseProbeDocker().start(
            store, ROLE, images()["runner"], context_sha, READER, payload
        )


@pytest.mark.parametrize("code", ["persisted_probe_schema_unsupported", SECRET])
def test_lifecycle_records_static_rejection_or_hides_unknown_reason(
    store, bundle, monkeypatch, tmp_path, code
):
    world = World(store, bundle, monkeypatch)

    def start(*_args):
        raise life.ActivationError(code)

    world.start = start
    result = invoke(store, world, tmp_path)
    assert result["failure_phase"] == "start"
    assert result["failure_code"] == (code if code in probe.FAILURE_REASONS else None)
    assert result["probe_removed"] and not result["probe_result_verified"]
    assert SECRET not in json.dumps(result)


def test_fresh_import_does_not_access_network_process_or_secrets():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('effect forbidden')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('secret forbidden')
sys.addaudithook(guard)
import runner_activation_database_lifecycle
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
