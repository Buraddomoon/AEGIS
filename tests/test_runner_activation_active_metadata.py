"""Owned active-project metadata against fixture daemon; no real lab or volume."""

import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_active_metadata as active  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402
from test_runner_activation_metadata import FakeDocker as MetadataDocker  # noqa: E402
from test_runner_activation_metadata import images  # noqa: E402
from test_runner_activation_ownership import FakeDocker as Owner  # noqa: E402


class World:
    def __init__(self, store, role="journal-before", phase="create"):
        self.store, self.role, self.phase = store, role, phase
        self.meta, self.owners = MetadataDocker(), {}
        self.expected = active.metadata.inventory(images(), docker=self.meta)
        self.meta.calls.clear()
        operation = store.summary()["id"]
        keys = ("db", "network-backend", role) if role != "db" else ("network-backend", "db")
        for index, key in enumerate(keys):
            store.request(key)
            exists = key != role or phase in {"start", "running"}
            obj = Owner(operation, key, present=exists)
            obj.details["plan"] = store.review()["header"]["plan_sha256"]
            self.owners[key] = obj
            identifier = f"{index + 1:064x}"
            obj.details["id"] = identifier
            obj.named = obj.labelled = obj.known = (identifier + "\n").encode() if exists else b""
            if key in active.IMAGE_ROLE:
                obj.details["image"] = images()[active.IMAGE_ROLE[key]]
                obj.details["running"] = key == "db" and (key != role or phase == "running")
            if exists:
                store.append("observed", {"role": key, "resource_id": identifier})
        if role == "db" and phase == "running":
            store.append(
                "database_start_requested",
                {
                    "role": "db",
                    "recipe_sha256": "1" * 64,
                    "gates_sha256": "2" * 64,
                    "policy_sha256": "3" * 64,
                },
            )
            store.append(
                "database_runtime_observed", {"role": "db", "runtime_evidence_sha256": "4" * 64}
            )
        self.meta.responses["containers", None] = self.ids(
            *(key for key, obj in self.owners.items() if key in active.IMAGE_ROLE and obj.named)
        )
        self.meta.responses["networks", None] = self.ids("network-backend")
        self.meta.responses["network_name", "backend"] = self.ids("network-backend")
        self.meta.responses["consumers", "journal"] = (
            self.ids(role)
            if phase == "start" and role in {"journal-before", "journal-after"}
            else b""
        )
        self.meta.responses["consumers", "postgres-data"] = (
            self.ids("db") if self.owners["db"].named else b""
        )

    def ids(self, *roles):
        return "".join(self.owners[key].details["id"] + "\n" for key in roles).encode()

    def query(self, kind, operation, plan, role, known_id=None):
        return self.owners[role].query(kind, operation, plan, role, known_id)

    def review(self):
        return active.review(
            self.store,
            images(),
            self.expected,
            self.role,
            self.phase,
            docker=self.meta,
            ownership_docker=self,
        )


@pytest.mark.parametrize("role", sorted(active.PROBE_ROLES))
@pytest.mark.parametrize("phase", ["create", "start"])
def test_owned_inventory_allows_only_durable_exact_project_and_volume_members(
    role, phase, tmp_path
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, role, phase)
        before = store.summary()
        result = world.review()
        assert result["status"] == "owned_metadata_snapshot_consistent"
        assert result["inventory"] == world.expected and result["resources_reviewed"] == 3
        assert result["journal_consumer_set_verified"] and result["project_membership_verified"]
        assert (
            result["database_binding_verified"]
            is result["network_isolation_verified"]
            is result["normal_operation_permitted"]
            is False
        )
        assert store.summary() == before
        assert len(world.meta.calls) == 28
        assert all(
            call[0] in {"info", "image", "volume", "ps", "network"}
            for call in [active.metadata.command(kind, value) for kind, value in world.meta.calls]
        )


@pytest.mark.parametrize(
    "scene",
    [
        "foreign_container",
        "foreign_network",
        "unlabelled_reserved_network",
        "foreign_journal_consumer",
        "foreign_postgres_consumer",
        "duplicate_ids",
    ],
)
def test_foreign_or_ambiguous_project_and_volume_users_block_without_any_effect(tmp_path, scene):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store)
        foreign = ("f" * 64 + "\n").encode()
        if scene == "foreign_container":
            world.meta.responses["containers", None] += foreign
        elif scene == "foreign_network":
            world.meta.responses["networks", None] += foreign
        elif scene == "unlabelled_reserved_network":
            world.meta.responses["network_name", "isolated"] = foreign
        elif scene == "foreign_journal_consumer":
            world.meta.responses["consumers", "journal"] = foreign
        elif scene == "foreign_postgres_consumer":
            world.meta.responses["consumers", "postgres-data"] = foreign
        else:
            world.meta.responses["containers", None] *= 2
        before = store.summary()
        with pytest.raises(active.ActivationError):
            world.review()
        assert store.summary() == before


@pytest.mark.parametrize(
    "scene",
    ["daemon", "volume", "image", "owner", "renamed", "missing", "running_probe", "appeared_probe"],
)
def test_inventory_and_owned_resource_drift_are_not_accepted(tmp_path, scene):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, phase="start" if scene == "running_probe" else "create")
        if scene == "daemon":
            world.meta.responses["daemon", None]["id"] = "f" * 64
        elif scene == "volume":
            world.meta.responses["volume", "journal"]["created_at"] = "2026-10-27T00:00:00Z"
        elif scene == "image":
            world.owners["db"].details["image"] = "sha256:" + "f" * 64
        elif scene == "owner":
            world.owners["db"].details["plan"] = "f" * 64
        elif scene == "renamed":
            world.owners["db"].details["name"] = "/foreign"
        elif scene == "missing":
            obj = world.owners["db"]
            obj.named = obj.labelled = obj.known = b""
        elif scene == "running_probe":
            world.owners[world.role].details["running"] = True
        else:
            obj = world.owners[world.role]
            obj.named = obj.labelled = obj.known = world.ids(world.role)
        with pytest.raises(active.ActivationError):
            world.review()


@pytest.mark.parametrize(
    "scene", ["closing", "conflict", "pending_other", "runner_exists", "wrong_phase"]
)
def test_unresolved_or_incompatible_intents_block_before_daemon_queries(tmp_path, scene):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store)
        if scene == "closing":
            store.append("removal_requested", {"role": "db"})
        elif scene == "conflict":
            store.append("ownership_conflict", {"role": world.role, "evidence_sha256": "f" * 64})
        elif scene == "pending_other":
            store.request("redis")
        elif scene == "runner_exists":
            store.request("runner")
            store.append("observed", {"role": "runner", "resource_id": "f" * 64})
        else:
            world.phase = "start"
        with pytest.raises(active.ActivationError, match="unresolved_or_incompatible"):
            world.review()
        assert world.meta.calls == []


def test_repeat_snapshots_and_durable_state_detect_mutation_between_queries(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store)
        original = world.meta.query
        count = 0

        def changed(kind, value=None):
            nonlocal count
            raw = original(kind, value)
            if (kind, value) == ("consumers", "postgres-data"):
                count += 1
                if count == 1:
                    world.owners["db"].details["running"] = False
            return raw

        world.meta.query = changed
        with pytest.raises(active.ActivationError, match="changed_during_review"):
            world.review()


def test_expected_inventory_hash_is_pinned_before_untrusted_queries(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store)
        original = world.meta.query

        def changed(kind, value=None):
            if kind == "daemon":
                world.expected["daemon"]["id"] = "f" * 64
                world.meta.responses["daemon", None]["id"] = "f" * 64
            return original(kind, value)

        world.meta.query = changed
        with pytest.raises(active.ActivationError, match="inventory_drift"):
            world.review()


def test_one_shared_deadline_limits_queries_and_default_executor_receives_remaining_budget(
    monkeypatch,
):
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return b""

    monkeypatch.setattr(active.metadata, "_execute", execute)
    bounded = active._Budget(None, False, time.monotonic() + 1)
    assert bounded.query("containers") == b""
    assert 0 < calls[0][1]["timeout"] <= 1 and calls[0][0][0] == "ps"
    with pytest.raises(active.ActivationError, match="time_limit"):
        active._Budget(None, True, time.monotonic() - 1).query(
            "name", uuid4().hex, "a" * 64, "journal-before"
        )
    assert len(calls) == 1


def test_slow_query_cannot_publish_after_deadline(tmp_path, monkeypatch):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store)
        now = [100.0]
        monkeypatch.setattr(active.time, "monotonic", lambda: now[0])
        original = world.meta.query

        def delayed(*args):
            value = original(*args)
            now[0] += 21
            return value

        world.meta.query = delayed
        with pytest.raises(active.ActivationError, match="time_limit"):
            world.review()
        assert len(world.meta.calls) == 1


def test_final_durable_review_and_initial_review_are_included_in_absolute_deadline(
    tmp_path, monkeypatch
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store)
        now = [100.0]
        monkeypatch.setattr(active.time, "monotonic", lambda: now[0])
        original = store.review
        count = 0

        def slow_final():
            nonlocal count
            value = original()
            count += 1
            if count == 2:
                now[0] += 21
            return value

        monkeypatch.setattr(store, "review", slow_final)
        with pytest.raises(active.ActivationError, match="time_limit"):
            world.review()
        assert count == 2

        def slow_initial():
            value = original()
            now[0] += 21
            return value

        monkeypatch.setattr(store, "review", slow_initial)
        world.meta.calls.clear()
        with pytest.raises(active.ActivationError, match="time_limit"):
            world.review()
        assert world.meta.calls == []


@pytest.mark.parametrize("role", sorted(active.PROBE_ROLES))
@pytest.mark.parametrize("phase", ["create", "start"])
def test_another_unfinished_probe_blocks_all_phases_before_daemon_queries(tmp_path, role, phase):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, role, phase)
        other = next(key for key in sorted(active.PROBE_ROLES) if key != role)
        store.request(other)
        store.append("observed", {"role": other, "resource_id": "f" * 64})
        with pytest.raises(active.ActivationError, match="unresolved_or_incompatible"):
            world.review()
        assert world.meta.calls == []


@pytest.mark.parametrize("phase", ["create", "start", "running"])
def test_database_phase_pins_empty_then_owned_volume_consumers_without_claiming_journal_content(
    tmp_path, phase
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        world = World(store, "db", phase)
        result = world.review()
        assert result["status"] == "owned_metadata_snapshot_consistent"
        assert result["resources_reviewed"] == 2
        assert result["role"] == "db" and result["phase"] == phase
        assert result["journal_contents_verified"] is result["database_binding_verified"] is False
        assert result["authorization_verified"] is False
        assert world.meta.responses["consumers", "journal"] == b""
        assert bool(world.meta.responses["consumers", "postgres-data"]) is (phase != "create")


@pytest.mark.parametrize(
    "scene", ["missing_start", "not_running", "journal_consumer", "foreign_db_consumer"]
)
def test_database_startup_and_running_gates_refuse_ambiguous_or_unconfirmed_context(
    tmp_path, scene
):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        phase = "start" if scene == "missing_start" else "running"
        world = World(store, "db", phase)
        if scene == "missing_start":
            world.phase = "running"
        elif scene == "not_running":
            world.owners["db"].details["running"] = False
        elif scene == "journal_consumer":
            world.meta.responses["consumers", "journal"] = ("f" * 64 + "\n").encode()
        else:
            world.meta.responses["consumers", "postgres-data"] += ("f" * 64 + "\n").encode()
        with pytest.raises(active.ActivationError):
            world.review()


@pytest.mark.parametrize(
    "role,phase",
    [
        ("journal-before", "running"),
        ("database-review-before", "running"),
        ("api", "create"),
        ("worker", "running"),
    ],
)
def test_running_database_phase_does_not_widen_other_resource_profiles(tmp_path, role, phase):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        with pytest.raises(active.ActivationError, match="probe_context_required"):
            active.review(store, images(), {}, role, phase)
