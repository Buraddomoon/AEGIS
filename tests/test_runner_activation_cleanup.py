"""Real temporary ownership journals and fixture-only daemon effects."""

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_cleanup as cleanup  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402
from test_runner_activation_metadata import images  # noqa: E402
from test_runner_activation_ownership import FakeDocker  # noqa: E402

# The API/DB profile and identity-only client cannot coexist. The latter has
# dedicated dependency/cleanup tests in test_runner_identity_client_intents.
ORIGINAL_ORDER = tuple(role for role in cleanup.ORDER if role != "identity-client")


class World:
    def __init__(self, store, roles, *, running=False, absent=False):
        self.store = store
        self.effects = []
        self.fail = None
        self.apply_on_error = False
        self.mutate_before_effect = None
        self.id = store.summary()["id"]
        self.objects = {}
        # Namespace-sharing readers can only be requested after a known DB ID.
        requested = sorted(roles, key=lambda role: role != "db")
        for role in requested:
            index = list(roles).index(role)
            store.request(role)
            obj = FakeDocker(self.id, role, present=not absent)
            self.objects[role] = obj
            identifier = f"{index + 1:064x}"
            obj.named = obj.labelled = obj.known = b"" if absent else (identifier + "\n").encode()
            obj.details["id"] = identifier
            if role in cleanup.IMAGE_ROLE:
                obj.details.update(image=images()[cleanup.IMAGE_ROLE[role]], running=running)
            if not absent:
                store.append("observed", {"role": role, "resource_id": identifier})

    def query(self, kind, operation, plan, role, known_id=None):
        return self.objects[role].query(kind, operation, plan, role, known_id)

    def effect(self, kind, operation, plan, role, known_id):
        # Verify ordering against bytes that are actually durable on disk.
        records = [
            json.loads(path.read_bytes()) for path in sorted(self.store.folder.glob("*.json"))
        ]
        assert any(
            event["kind"] == "removal_requested" and event["data"]["role"] == role
            for event in records
        )
        assert self.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        args = cleanup.command(kind, operation, plan, role, known_id)
        self.effects.append((role, kind, args))
        if self.fail != (role, kind) or self.apply_on_error:
            obj = self.objects[role]
            if kind == "stop":
                obj.details["running"] = False
            else:
                obj.named = obj.labelled = obj.known = b""
        if self.fail == (role, kind):
            raise cleanup.ActivationError("private-sensitive-sentinel")


def begin(store):
    return store.begin(uuid4().hex, "a" * 64, "b" * 64)


def test_all_owned_resources_close_in_dependency_order_with_repeated_absence_checks(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ORIGINAL_ORDER, running=True)
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["status"] == "owned_resources_absence_verified"
        assert result["resources_reviewed"] == len(ORIGINAL_ORDER)
        assert result["managed_resources_absence_verified"]
        assert store.review()["closed"] and result["volumes_removed"] is False
        assert result["authorization_verified"] is result["normal_operation_permitted"] is False
        removed = [role for role, kind, _ in world.effects if kind == "remove"]
        assert removed == list(ORIGINAL_ORDER)
        assert all(
            args[-1] == f"{ORIGINAL_ORDER.index(role) + 1:064x}" for role, _, args in world.effects
        )
        assert all(
            flag not in args
            for _, _, args in world.effects
            for flag in ("--force", "--volumes", "prune", "down", "create", "start", "exec")
        )
        before = list(world.effects)
        assert cleanup.cleanup(store, images(), docker=world, ownership_docker=world)[
            "managed_resources_absence_verified"
        ]
        assert world.effects == before


@pytest.mark.parametrize("failure", ["stop", "remove"])
def test_unconfirmed_api_cleanup_retains_database_cache_runner_and_all_networks(tmp_path, failure):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ORIGINAL_ORDER, running=True)
        world.fail = ("api", failure)
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["status"] == "cleanup_incomplete" and not store.review()["closed"]
        assert set(result["blockers"]) == {
            "api",
            "db",
            "redis",
            "runner",
            "network-ingress",
            "network-backend",
            "network-isolated",
        }
        assert not any(
            role in {"db", "redis", "runner"} or role.startswith("network-")
            for role, _, _ in world.effects
        )
        assert {role for role, kind, _ in world.effects if kind == "remove"} >= {
            "journal-before",
            "journal-after",
        }
        assert "private-sensitive-sentinel" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["stop", "remove"])
def test_ambiguous_command_failure_requires_fresh_daemon_confirmation_never_error_as_absence(
    tmp_path, kind
):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["journal-before"], running=True)
        world.fail, world.apply_on_error = ("journal-before", kind), True
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["status"] == "owned_resources_absence_verified"
        assert result["command_errors_reconciled"] == [{"role": "journal-before", "effect": kind}]
        assert [effect for _, effect, _ in world.effects] == ["stop", "remove"]


def test_fresh_resume_only_cleans_after_start_ambiguity_and_does_not_need_valid_plan_or_pki(
    tmp_path,
):
    root = tmp_path / "intents"
    with ActivationIntents(root) as store:
        origin = begin(store)
        world = World(store, ["journal-before"], running=True)
        store.append(
            "probe_start_requested",
            {
                "role": "journal-before",
                "recipe_sha256": "1" * 64,
                "gates_sha256": "2" * 64,
                "proof_bundle_sha256": "3" * 64,
            },
        )
    with ActivationIntents(root) as store:
        store.resume(origin["id"], origin["begin_sha256"])
        world.store = store
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["managed_resources_absence_verified"] and store.review()["closed"]
        assert all(effect in {"stop", "remove"} for _, effect, _ in world.effects)


def test_ambiguous_create_without_returned_id_is_discovered_recorded_and_cleaned(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, [])
        store.request("journal-before")
        obj = FakeDocker(world.id, "journal-before")
        obj.details["image"] = images()["runner"]
        world.objects["journal-before"] = obj
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["managed_resources_absence_verified"]
        assert [event["kind"] for event in store.events] == [
            "begin",
            "create_requested",
            "removal_requested",
            "observed",
            "absence_recorded",
            "closed",
        ]


def test_create_intent_without_actual_object_records_absence_without_any_effect(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["journal-before"], absent=True)
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["managed_resources_absence_verified"] and world.effects == []


@pytest.mark.parametrize("scene", ["image", "owner", "name", "id", "member"])
def test_foreign_ambiguous_or_nonempty_resource_is_retained(tmp_path, scene):
    role = "network-isolated" if scene == "member" else "journal-before"
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, [role])
        obj = world.objects[role]
        if scene == "member":
            obj.details["member_count"] = 1
        elif scene == "image":
            obj.details["image"] = "sha256:" + "f" * 64
        elif scene == "owner":
            obj.labelled = b""
        elif scene == "name":
            obj.details["name"] = "/foreign"
        else:
            obj.details["id"] = "f" * 64
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["status"] == "cleanup_incomplete" and world.effects == []
        assert not store.review()["closed"]


def test_resource_changed_at_second_observation_is_never_removed(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["journal-before"])
        original = world.query
        calls = 0

        def changed(*args):
            nonlocal calls
            calls += 1
            if calls == 8:
                world.objects["journal-before"].details["image"] = "sha256:" + "f" * 64
            return original(*args)

        world.query = changed
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert result["status"] == "cleanup_incomplete" and world.effects == []


def test_final_absence_pass_refuses_resource_that_reappears_after_first_absence(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["journal-before"])
        original = world.query
        empty_queries = 0

        def reappear(*args):
            nonlocal empty_queries
            if not world.objects["journal-before"].named:
                empty_queries += 1
                if empty_queries == 7:
                    obj = world.objects["journal-before"]
                    obj.named = obj.labelled = obj.known = ("f" * 64 + "\n").encode()
            return original(*args)

        world.query = reappear
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert not result["managed_resources_absence_verified"] and not store.review()["closed"]
        assert len(world.effects) == 1


@pytest.mark.parametrize("scene", ["memory", "disk", "lock", "fsync"])
def test_changed_or_unconfirmed_journal_cannot_perform_external_effect(
    tmp_path, monkeypatch, scene
):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["journal-before"])
        if scene == "memory":
            store.state["resources"]["journal-before"]["resource_id"] = "f" * 64
        elif scene == "disk":
            (store.folder / "0001.json").write_bytes(b"invalid")
        elif scene == "lock":
            (store.root / "operation.lock").chmod(0o644)
        else:

            def fail(path):
                raise OSError("private-sensitive-sentinel")

            monkeypatch.setattr(sys.modules["runner_pki"], "sync", fail)
        if scene == "fsync":
            result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
            assert result["status"] == "cleanup_incomplete" and store.poisoned
        else:
            with pytest.raises(ValueError):
                cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert world.effects == []


@pytest.mark.parametrize("kind", ["create", "start", "exec", "prune", "volume", "down", "kill"])
def test_cleanup_catalog_cannot_create_start_execute_or_delete_volume(kind):
    with pytest.raises(cleanup.ActivationError, match="command_not_allowed"):
        cleanup.command(kind, uuid4().hex, "a" * 64, "runner", "b" * 64)
    with pytest.raises(cleanup.ActivationError):
        cleanup.command("remove", uuid4().hex, "a" * 64, "worker", "b" * 64)
    with pytest.raises(cleanup.ActivationError):
        cleanup.command("remove", uuid4().hex, "a" * 64, "runner", "arbitrary-name")


def test_concrete_driver_compiles_only_fixed_command_and_redacts_os_error(monkeypatch):
    calls = []
    monkeypatch.setattr(cleanup, "_execute", lambda args: calls.append(args))
    cleanup.CleanupDocker().effect("stop", uuid4().hex, "a" * 64, "runner", "b" * 64)
    assert calls == [("container", "stop", "--signal", "SIGTERM", "--timeout", "5", "b" * 64)]

    def fail(*args):
        raise OSError("private-sensitive-sentinel")

    monkeypatch.setattr(cleanup, "_execute", fail)
    with pytest.raises(cleanup.ActivationError, match="command_failed"):
        cleanup.CleanupDocker().effect("remove", uuid4().hex, "a" * 64, "runner", "b" * 64)


def test_import_has_no_side_effect_or_cli():
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
import runner_activation_cleanup
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_selected_probe_cleanup_retains_other_owned_resources_and_keeps_operation_open(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["db", "journal-before"], running=True)
        result = cleanup.cleanup(
            store,
            images(),
            roles={"journal-before"},
            close_operation=False,
            docker=world,
            ownership_docker=world,
        )
        assert (
            result["selected_resources_absence_verified"]
            and not result["managed_resources_absence_verified"]
        )
        assert result["status"] == "selected_owned_resources_absence_verified"
        assert not result["operation_closed"] and not store.review()["closed"]
        assert all(role == "journal-before" for role, _, _ in world.effects)
        store.request("runner")


def test_single_probe_cleanup_can_leave_a_durable_open_operation_for_later_stages(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["journal-before"])
        result = cleanup.cleanup(
            store,
            images(),
            roles={"journal-before"},
            close_operation=False,
            docker=world,
            ownership_docker=world,
        )
        assert result["managed_resources_absence_verified"] and not result["operation_closed"]
        assert not store.review()["closed"]
        store.request("runner")


@pytest.mark.parametrize(
    "roles,close", [({"worker"}, False), ({"runner"}, False), ({"journal-before"}, True), (None, 1)]
)
def test_invalid_selection_or_premature_whole_operation_close_causes_no_effect(
    tmp_path, roles, close
):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, ["db", "journal-before"])
        with pytest.raises(cleanup.ActivationError, match="selection_or_closure"):
            cleanup.cleanup(
                store,
                images(),
                roles=roles,
                close_operation=close,
                docker=world,
                ownership_docker=world,
            )
        assert world.effects == []


@pytest.mark.parametrize("role", ["database-review-before", "database-review-after"])
@pytest.mark.parametrize("failure", ["stop", "remove"])
def test_uncertain_database_reader_retains_its_namespace_and_networks(tmp_path, role, failure):
    with ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        world = World(store, [role, "db", "network-backend"], running=True)
        world.fail = (role, failure)
        result = cleanup.cleanup(store, images(), docker=world, ownership_docker=world)
        assert set(result["blockers"]) == {role, "db", "network-backend"}
        assert not result["managed_resources_absence_verified"]
        assert all(effect_role == role for effect_role, _, _ in world.effects)
        assert not store.review()["closed"]
