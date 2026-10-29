"""Startup/readiness lifecycle with temporary policy/intents and fixture daemon."""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from aegis.domain.validation import digest
from test_runner_activation_database_inspection import OBJECT
from test_runner_activation_database_inspection import Docker as Runtime
from test_runner_activation_database_server import prepared as prepared
from test_runner_activation_metadata import images
from test_runner_activation_ownership import FakeDocker as Owner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_database_server_lifecycle as life  # noqa: E402

SECRET = "private-sensitive-sentinel"


class World:
    def __init__(self, prepared, monkeypatch, scene=None):
        self.store, self.root = prepared
        self.scene, self.owner, self.effects, self.gates = scene, None, [], []
        self.operation = self.store.summary()["id"]
        self.spec = life.server.recipe(self.store, images()["postgres"], policy_root=self.root)
        self.runtime = Runtime(self.spec, "created")
        self.runtime.image["id"] = images()["postgres"]
        self.runtime.item["image"] = self.runtime.item["image_reference"] = images()["postgres"]
        self.clock = 0.0
        monkeypatch.setattr(
            life, "time", SimpleNamespace(monotonic=lambda: self.clock, sleep=self.advance)
        )

    def advance(self, seconds):
        self.clock += seconds

    def query(self, kind, *args, **kwargs):
        if kind in {"image", "container"}:
            return self.runtime.query(kind, *args, **kwargs)
        if self.owner is None:
            assert kind != "inspect"
            return b""
        return self.owner.query(kind, *args)

    def gate(self, phase, spec):
        self.gates.append(phase)
        assert spec == self.spec
        now = datetime.now(UTC)
        item = {
            "format": "aegis-database-server-gate/1",
            "phase": phase,
            "operation_id": self.operation,
            "resource_id": None if phase == "create" else OBJECT,
            "plan_sha256": "a" * 64,
            "scope_sha256": "b" * 64,
            "recipe_sha256": digest(spec),
            "policy_sha256": spec["policy_sha256"],
            "volume": life.server.VOLUME,
            "checked_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=20)).isoformat(),
            "checks": dict.fromkeys(life.CHECKS, True),
        }
        if self.scene == "deny_" + phase:
            item["checks"]["specific_authorization_verified"] = False
        elif self.scene == "stale_" + phase:
            item["checked_at"] = (now - timedelta(seconds=11)).isoformat()
        elif self.scene == "wrong_context_" + phase:
            item["scope_sha256"] = "f" * 64
        elif self.scene == "integer_" + phase:
            item["checks"]["worker_stopped"] = 1
        elif self.scene == "collision" and phase == "create":
            self.create_object()
        elif self.scene == "runtime_changed" and phase == "start":
            self.runtime.item["host"]["Privileged"] = True
        elif self.scene == "gate_deadline" and phase == "ready":
            self.clock += 16
        return item

    def create_object(self):
        self.owner = Owner(self.operation, "db")
        self.owner.details.update(id=OBJECT, image=images()["postgres"])
        self.owner.named = self.owner.labelled = self.owner.known = (OBJECT + "\n").encode()

    def create(self, store, image, *, policy_root):
        assert life.command("create", store, image, policy_root=policy_root)[:2] == (
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
        return "f" * 64 if self.scene == "wrong_id" else OBJECT

    def start(self, store, image, object_id, *, policy_root):
        assert life.command("start", store, image, policy_root=policy_root, known_id=object_id) == (
            "container",
            "start",
            OBJECT,
        )
        assert (
            json.loads(sorted(store.folder.glob("*.json"))[-1].read_bytes())["kind"]
            == "database_start_requested"
        )
        self.effects.append("start")
        if self.scene == "start_ambiguous":
            self.owner.details["running"] = True
            raise life.ActivationError(SECRET)
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        self.owner.details["running"] = True
        self.runtime.item.update(status="running", running=True)

    def ready(self, store, image, object_id, *, policy_root, timeout):
        args = life.command("ready", store, image, policy_root=policy_root, known_id=object_id)
        assert args[:6] == (
            "container",
            "exec",
            "--user",
            "70:70",
            OBJECT,
            "/usr/local/bin/pg_isready",
        )
        assert 0 < timeout <= 2
        self.effects.append("ready")
        if self.scene == "readiness_deadline":
            self.clock += 16
        if self.scene == "readiness_unavailable" or self.scene == "cleanup_failed":
            return False
        if self.scene == "ready_integer":
            return 1
        if self.scene == "ready_retry":
            return self.effects.count("ready") >= 3
        return True

    def effect(self, kind, operation, plan, role, known_id):
        assert role == "db" and known_id == OBJECT
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        self.effects.append(kind)
        if self.scene == "cleanup_failed":
            raise life.ActivationError(SECRET)
        if kind == "stop":
            self.owner.details["running"] = False
        else:
            self.owner = None


def invoke(world):
    return life.start_server(
        world.store,
        images(),
        before_effect=world.gate,
        policy_root=world.root,
        lifecycle=world,
        runtime_docker=world,
        ownership_docker=world,
        cleanup_docker=world,
    )


def test_confirmed_start_retains_database_parent_for_reader_and_never_proves_authentication(
    prepared, monkeypatch
):
    world = World(prepared, monkeypatch)
    result = invoke(world)
    assert result["status"] == "database_running_and_ready_not_activated"
    assert result["database_retained_running"] and result["connection_readiness_verified"]
    assert result["cleanup"] is None and not result["database_absence_verified"]
    assert result["database_volume_readonly"] is False and result["volumes_removed"] is False
    assert all(
        result[key] is False
        for key in (
            "authentication_verified",
            "database_identity_verified",
            "image_provenance_verified",
            "authorization_verified",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    assert world.effects == ["create", "start", "ready"]
    assert world.gates == ["create", "start", "ready"]
    state = world.store.review()
    assert not state["closed"] and state["resources"]["db"]["state"] == "OBSERVED"
    assert "start" in state["resources"]["db"]
    assert SECRET not in json.dumps(result)
    with pytest.raises(life.ActivationError, match="no_replay"):
        invoke(world)
    cleanup = life.owned.cleanup_owned_probe(
        world.store, images(), "db", True, cleanup_docker=world, ownership_docker=world
    )
    assert cleanup["selected_resources_absence_verified"]
    assert world.effects[-2:] == ["stop", "remove"]


@pytest.mark.parametrize("phase", ["create", "start", "ready"])
@pytest.mark.parametrize("scene", ["deny", "stale", "wrong_context", "integer"])
def test_each_fresh_scoped_gate_is_required_before_its_effect(prepared, monkeypatch, phase, scene):
    world = World(prepared, monkeypatch, scene + "_" + phase)
    result = invoke(world)
    assert result["status"] == "database_failed_and_absence_verified"
    assert result["database_absence_verified"] and not result["connection_readiness_verified"]
    assert ("create" in world.effects) is (phase != "create")
    assert ("start" in world.effects) is (phase == "ready")
    assert "ready" not in world.effects


@pytest.mark.parametrize(
    "scene",
    [
        "create_failed_before",
        "create_failed_after",
        "wrong_id",
        "start_ambiguous",
        "runtime_changed",
        "readiness_unavailable",
        "ready_integer",
        "readiness_deadline",
        "gate_deadline",
    ],
)
def test_unknown_outcome_failed_runtime_or_readiness_never_restarts_database(
    prepared, monkeypatch, scene
):
    world = World(prepared, monkeypatch, scene)
    result = invoke(world)
    assert result["status"] == "database_failed_and_absence_verified"
    assert world.effects.count("start") <= 1 and world.effects.count("create") == 1
    assert result["database_absence_verified"] and not result["database_retained_running"]
    assert result["readiness_attempts"] <= 8
    assert SECRET not in json.dumps(result)
    assert world.store.review()["resources"]["db"]["state"] == "ABSENT"


def test_only_fixed_readiness_checks_can_repeat_and_budget_does_not_reset(prepared, monkeypatch):
    world = World(prepared, monkeypatch, "ready_retry")
    result = invoke(world)
    assert result["database_retained_running"] and result["readiness_attempts"] == 3
    assert world.effects == ["create", "start", "ready", "ready", "ready"]
    assert result["authentication_verified"] is False


@pytest.mark.parametrize("code", ["docker_query_failed", "database_server_mount_mismatch", SECRET])
def test_failed_created_inspection_records_only_static_reason_and_never_starts(
    prepared, monkeypatch, code
):
    world = World(prepared, monkeypatch)
    original_query = world.query

    def query(kind, *args, **kwargs):
        if kind == "container":
            raise life.ActivationError(code)
        return original_query(kind, *args, **kwargs)

    world.query = query
    result = invoke(world)
    assert result["failure_phase"] == "inspect_created"
    assert result["failure_code"] == (code if code in life.FAILURE_CODES else None)
    assert result["error"] == "database_server_startup_unconfirmed"
    assert result["database_absence_verified"]
    assert world.effects == ["create", "remove"]
    assert SECRET not in json.dumps(result)


def test_foreign_collision_before_create_is_quarantined_without_delete(prepared, monkeypatch):
    world = World(prepared, monkeypatch, "collision")
    result = invoke(world)
    assert result["status"] == "database_cleanup_unconfirmed" and world.effects == []
    assert world.store.review()["resources"]["db"]["state"] == "CONFLICT"


def test_interrupt_propagates_after_cleanup_of_owned_server(prepared, monkeypatch):
    world = World(prepared, monkeypatch, "interrupt")
    with pytest.raises(KeyboardInterrupt):
        invoke(world)
    assert world.effects == ["create", "start", "remove"]
    assert world.store.review()["resources"]["db"]["state"] == "ABSENT"


def test_failed_cleanup_keeps_owned_id_and_never_reports_started_or_removed(prepared, monkeypatch):
    world = World(prepared, monkeypatch, "cleanup_failed")
    result = invoke(world)
    assert result["status"] == "database_cleanup_unconfirmed"
    assert not result["database_absence_verified"] and not result["database_retained_running"]
    assert world.store.review()["resources"]["db"]["resource_id"] == OBJECT
    assert not world.store.review()["closed"]


def test_concrete_driver_has_only_exact_owned_create_start_and_health_process(
    prepared, monkeypatch
):
    store, root = prepared
    image = images()["postgres"]
    spec = life.server.recipe(store, image, policy_root=root)
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return b"" if args[1] == "exec" else (OBJECT + "\n").encode()

    monkeypatch.setattr(life, "_execute", execute)
    driver = life.DatabaseServerDocker()
    store.request("db")
    assert driver.create(store, image, policy_root=root) == OBJECT
    store.append("observed", {"role": "db", "resource_id": OBJECT})
    with pytest.raises(life.ActivationError):
        driver.start(store, image, OBJECT, policy_root=root)
    store.append(
        "database_start_requested",
        {
            "role": "db",
            "recipe_sha256": digest(spec),
            "gates_sha256": "e" * 64,
            "policy_sha256": spec["policy_sha256"],
        },
    )
    driver.start(store, image, OBJECT, policy_root=root)
    store.append("database_runtime_observed", {"role": "db", "runtime_evidence_sha256": "f" * 64})
    assert driver.ready(store, image, OBJECT, policy_root=root, timeout=1.5)
    assert calls[1] == (("container", "start", OBJECT), {})
    assert calls[2] == (
        (
            "container",
            "exec",
            "--user",
            "70:70",
            OBJECT,
            "/usr/local/bin/pg_isready",
            "--quiet",
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
            "--username",
            "aegis_app",
            "--dbname",
            "aegis",
            "--timeout",
            "1",
        ),
        {"timeout": 1.5},
    )
    for kind in ("exec", "run", "stop", "remove"):
        with pytest.raises(life.ActivationError):
            life.command(kind, store, image, policy_root=root, known_id=OBJECT)


def test_import_has_no_database_daemon_network_or_secret_effect():
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
import runner_activation_database_server_lifecycle
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
