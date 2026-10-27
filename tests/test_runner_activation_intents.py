"""Ownership records in private temporary directories; no daemon or lab effects."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_intents as intents  # noqa: E402


def begin(store):
    return store.begin(uuid4().hex, "a" * 64, "b" * 64)


def absent(store, role):
    store.append("removal_requested", {"role": role})
    return store.append("absence_recorded", {"role": role, "evidence_sha256": "c" * 64})


def test_intent_is_durable_before_caller_can_create_and_summary_never_authorizes(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        requested = store.request("runner")
        record = json.loads((store.folder / "0001.json").read_bytes())
        expected = intents.resource(origin["id"], "a" * 64, "runner")
        assert record["data"] == expected
        assert expected["labels"]["io.aegis.activation-id"] == origin["id"]
        assert expected["name"].startswith("aegis-linux-lab-activation-")
        assert requested["resources"]["runner"] == {"state": "REQUESTED", "resource_id": None}
        store.append("observed", {"role": "runner", "resource_id": "d" * 64})
        absent(store, "runner")
        final = store.append("closed", {"evidence_sha256": "e" * 64})
        assert final["status"] == "absence_recorded_not_runtime_verified"
        assert all(final[key] is False for key in intents.FLAGS)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        for file in store.folder.iterdir():
            assert stat.S_IMODE(file.stat().st_mode) == 0o600
        with pytest.raises(intents.ActivationError, match="already_closed"):
            store.request("db")
    with intents.ActivationIntents(root) as next_store:
        assert begin(next_store)["id"] != origin["id"]


def test_ambiguous_create_is_reconciled_by_original_name_without_replay(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request("db")
    with intents.ActivationIntents(root) as store:
        with pytest.raises(intents.ActivationError, match="prior_operation_unresolved"):
            begin(store)
        state = store.resume(origin["id"], origin["begin_sha256"])
        assert state["resources"]["db"] == {"state": "REQUESTED", "resource_id": None}
        with pytest.raises(intents.ActivationError, match="duplicate_or_foreign"):
            store.request("db")
        # An ambiguous create may have created nothing, but absence still needs
        # exact-name/label reconciliation and a separately hashed observation.
        absent(store, "db")
        store.append("closed", {"evidence_sha256": "f" * 64})


@pytest.mark.parametrize(
    "role",
    [
        "worker",
        "migrate",
        "controller",
        "journal",
        "postgres-data",
        "wazuh",
        "../../other",
        "foreign-container",
    ],
)
def test_non_allowlisted_resources_cannot_acquire_ownership(tmp_path, role):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        with pytest.raises(intents.ActivationError, match="not_allowed"):
            store.request(role)
        assert len(store.events) == 1


@pytest.mark.parametrize("role", ["db", "redis", "runner", "network-isolated"])
def test_uncertain_api_retains_dependencies_and_networks(tmp_path, role):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        store.request(role)
        store.request("api")
        with pytest.raises(intents.ActivationError, match="dependencies_retained"):
            absent(store, role)
        assert store.state["resources"][role]["state"] == "REQUESTED"
        absent(store, "api")
        absent(store, role)


def test_no_remove_absence_or_closure_without_known_ownership_and_order(tmp_path):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        for event in ("observed", "removal_requested", "absence_recorded"):
            with pytest.raises(intents.ActivationError, match="ownership_required"):
                store.append(event, {"role": "db"})
        store.request("db")
        with pytest.raises(intents.ActivationError, match="absence_requires_removal"):
            store.append("absence_recorded", {"role": "db", "evidence_sha256": "c" * 64})
        with pytest.raises(intents.ActivationError, match="unresolved_resources"):
            store.append("closed", {"evidence_sha256": "e" * 64})


def test_same_object_id_cannot_be_claimed_by_two_resources(tmp_path):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        for role in ("runner", "api"):
            store.request(role)
        store.append("observed", {"role": "runner", "resource_id": "d" * 64})
        with pytest.raises(intents.ActivationError, match="id_reused"):
            store.append("observed", {"role": "api", "resource_id": "d" * 64})


def test_exclusive_cooperative_lock_does_not_steal_active_operation(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        begin(store)
        with pytest.raises(intents.ActivationError, match="operation_busy"):
            intents.ActivationIntents(root)
        store.request("db")


@pytest.mark.parametrize(
    "problem",
    [
        "gap",
        "extra",
        "truncated",
        "chain",
        "unknown_kind",
        "foreign_role",
        "public",
        "symlink",
        "hardlink",
        "directory",
    ],
)
def test_partial_tampered_or_unsafe_history_blocks_new_operation_and_resume(tmp_path, problem):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request("runner")
        folder = store.folder
    path = folder / "0001.json"
    if problem == "gap":
        path.rename(folder / "0002.json")
    elif problem == "extra":
        (folder / "unknown").touch()
    elif problem == "truncated":
        path.write_bytes(b'{"format":')
    elif problem in {"chain", "unknown_kind", "foreign_role"}:
        event = json.loads(path.read_bytes())
        if problem == "chain":
            event["previous_sha256"] = "0" * 64
        elif problem == "unknown_kind":
            event["kind"] = "execute"
        else:
            event["data"]["name"] = "foreign-container"
        path.write_text(json.dumps(event))
    elif problem == "public":
        path.chmod(0o644)
    elif problem == "symlink":
        path.rename(tmp_path / "outside")
        path.symlink_to(tmp_path / "outside")
    elif problem == "hardlink":
        os.link(path, tmp_path / "outside")
    else:
        folder.chmod(0o755)
    with intents.ActivationIntents(root) as store:
        with pytest.raises((intents.ActivationError, intents.pki.PKIError, ValueError)):
            begin(store)
        with pytest.raises((intents.ActivationError, intents.pki.PKIError, ValueError)):
            store.resume(origin["id"], origin["begin_sha256"])
    assert folder.exists()


def test_wrong_origin_hash_and_unknown_operation_cannot_resume(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
    with intents.ActivationIntents(root) as store:
        with pytest.raises(intents.ActivationError, match="origin_integrity_mismatch"):
            store.resume(origin["id"], "0" * 64)
        with pytest.raises(intents.ActivationError, match="resume_not_exclusive"):
            store.resume(uuid4().hex, origin["begin_sha256"])


def test_write_failure_poisoning_requires_explicit_fresh_resume(tmp_path, monkeypatch):
    root = tmp_path / "intents"
    original = intents.pki.sync
    with intents.ActivationIntents(root) as store:
        origin = begin(store)

        def fail(path):
            if path == store.folder:
                raise OSError("private-sensitive-sentinel")
            original(path)

        monkeypatch.setattr(intents.pki, "sync", fail)
        with pytest.raises(OSError):
            store.request("runner")
        assert (store.folder / "0001.json").exists()
        with pytest.raises(intents.ActivationError, match="not_writable"):
            store.request("api")
    monkeypatch.setattr(intents.pki, "sync", original)
    with intents.ActivationIntents(root) as store:
        store.resume(origin["id"], origin["begin_sha256"])
        assert store.state["resources"]["runner"]["state"] == "REQUESTED"
        absent(store, "runner")


def test_empty_partial_directory_blocks_without_removing_it(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root):
        partial = root / uuid4().hex
        partial.mkdir(mode=0o700)
    with intents.ActivationIntents(root) as store:
        with pytest.raises(intents.ActivationError, match="partial_or_unexpected"):
            begin(store)
    assert partial.exists() and list(partial.iterdir()) == []


def test_replaced_lock_path_cannot_be_used_to_append(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        begin(store)
        (root / "operation.lock").rename(root / "old-lock")
        (root / "operation.lock").touch(mode=0o600)
        with pytest.raises(intents.ActivationError, match="lock_or_directory_changed"):
            store.request("runner")


def test_repeated_close_or_reopen_resource_never_replays_creation(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request("runner")
        absent(store, "runner")
        with pytest.raises(intents.ActivationError, match="duplicate_or_foreign"):
            store.request("runner")
        store.append("closed", {"evidence_sha256": "e" * 64})
    with intents.ActivationIntents(root) as store:
        assert (
            store.resume(origin["id"], origin["begin_sha256"])["status"]
            == "absence_recorded_not_runtime_verified"
        )
        with pytest.raises(intents.ActivationError, match="already_closed"):
            store.request("runner")


def test_crash_after_removal_intent_can_record_discovered_id_without_resetting_state(tmp_path):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request("db")
        store.append("removal_requested", {"role": "db"})
    with intents.ActivationIntents(root) as store:
        store.resume(origin["id"], origin["begin_sha256"])
        store.append("observed", {"role": "db", "resource_id": "d" * 64})
        assert store.state["resources"]["db"]["state"] == "REMOVAL_REQUESTED"
        store.append("absence_recorded", {"role": "db", "evidence_sha256": "e" * 64})
        store.append("closed", {"evidence_sha256": "f" * 64})


@pytest.mark.parametrize("dependency", ["db", "redis", "runner", "network-isolated"])
@pytest.mark.parametrize("resume", [False, True])
def test_no_new_api_intent_during_or_after_dependency_removal(tmp_path, dependency, resume):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request(dependency)
        store.append("removal_requested", {"role": dependency})
        if not resume:
            with pytest.raises(intents.ActivationError, match="dependency_is_closing"):
                store.request("api")
        store.append("absence_recorded", {"role": dependency, "evidence_sha256": "e" * 64})
        if not resume:
            with pytest.raises(intents.ActivationError, match="dependency_is_closing"):
                store.request("api")
    if resume:
        with intents.ActivationIntents(root) as store:
            store.resume(origin["id"], origin["begin_sha256"])
            with pytest.raises(intents.ActivationError, match="dependency_is_closing"):
                store.request("api")


def test_mutated_memory_cannot_override_persisted_dependency_state(tmp_path):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        store.request("api")
        store.state["resources"]["api"]["state"] = "ABSENT"
        with pytest.raises(intents.ActivationError, match="history_changed"):
            store.append("closed", {"evidence_sha256": "e" * 64})


@pytest.mark.parametrize("dependency", ["db", "redis", "runner", "network-backend"])
def test_resumed_pending_removal_cannot_gain_new_dependent(tmp_path, dependency):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request(dependency)
        store.append("removal_requested", {"role": dependency})
    with intents.ActivationIntents(root) as store:
        store.resume(origin["id"], origin["begin_sha256"])
        with pytest.raises(intents.ActivationError, match="dependency_is_closing"):
            store.request("api")
        store.append("absence_recorded", {"role": dependency, "evidence_sha256": "e" * 64})


@pytest.mark.parametrize("problem", ["permissions", "hardlink", "contents", "symlink"])
def test_unsafe_lock_cannot_start_or_append_operation(tmp_path, problem):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        begin(store)
        lock = root / "operation.lock"
        if problem == "permissions":
            lock.chmod(0o644)
        elif problem == "hardlink":
            os.link(lock, tmp_path / "link")
        elif problem == "contents":
            lock.write_bytes(b"unknown")
        else:
            lock.rename(tmp_path / "original")
            lock.symlink_to(tmp_path / "original")
        with pytest.raises(intents.ActivationError, match="lock_or_directory_changed"):
            store.request("runner")
    with pytest.raises((intents.ActivationError, OSError)):
        intents.ActivationIntents(root)


def test_event_budget_blocks_before_creating_an_extra_file(tmp_path, monkeypatch):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        monkeypatch.setattr(intents, "MAX_EVENTS", 1)
        with pytest.raises(intents.ActivationError, match="session_or_limit_invalid"):
            store.request("runner")
        assert sorted(path.name for path in store.folder.iterdir()) == ["0000.json"]


def test_import_cannot_contact_daemon_services_or_read_secrets():
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
import runner_activation_intents
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


def start_payload(role="journal-before"):
    return {
        "role": role,
        "recipe_sha256": "1" * 64,
        "gates_sha256": "2" * 64,
        "proof_bundle_sha256": "3" * 64,
    }


@pytest.mark.parametrize("resume", [False, True])
def test_probe_start_intent_is_durable_and_never_replayed_even_after_resume(tmp_path, resume):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request("journal-before")
        store.append("observed", {"role": "journal-before", "resource_id": "d" * 64})
        store.append("probe_start_requested", start_payload())
        record = json.loads((store.folder / "0003.json").read_bytes())
        assert record["data"] == start_payload()
        if not resume:
            with pytest.raises(intents.ActivationError, match="already_requested"):
                store.append("probe_start_requested", start_payload())
            absent(store, "journal-before")
    if resume:
        with intents.ActivationIntents(root) as store:
            store.resume(origin["id"], origin["begin_sha256"])
            item = store.state["resources"]["journal-before"]
            assert item["state"] == "START_REQUESTED" and item["start"]["recipe_sha256"] == "1" * 64
            with pytest.raises(intents.ActivationError, match="already_requested"):
                store.append("probe_start_requested", start_payload())
            absent(store, "journal-before")


@pytest.mark.parametrize("role", ["runner", "api", "db", "redis", "network-isolated"])
def test_start_intent_never_authorizes_non_probe_role(tmp_path, role):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        store.request(role)
        store.append("observed", {"role": role, "resource_id": "d" * 64})
        with pytest.raises(intents.ActivationError, match="probe_start_invalid"):
            store.append("probe_start_requested", start_payload(role))


@pytest.mark.parametrize("scene", ["not_observed", "closing", "recipe", "gates", "proof", "extra"])
def test_missing_id_closing_resource_or_unpinned_start_is_rejected(tmp_path, scene):
    with intents.ActivationIntents(tmp_path / "intents") as store:
        begin(store)
        store.request("journal-before")
        if scene != "not_observed":
            store.append("observed", {"role": "journal-before", "resource_id": "d" * 64})
        if scene == "closing":
            store.append("removal_requested", {"role": "journal-before"})
        payload = start_payload()
        key = {
            "recipe": "recipe_sha256",
            "gates": "gates_sha256",
            "proof": "proof_bundle_sha256",
        }.get(scene)
        if key:
            payload[key] = "not-a-hash"
        if scene == "extra":
            payload["command"] = "arbitrary"
        with pytest.raises(intents.ActivationError):
            store.append("probe_start_requested", payload)
        assert all(event["kind"] != "probe_start_requested" for event in store.events)


@pytest.mark.parametrize("role", ["db", "runner", "network-isolated", "journal-before"])
def test_conflicted_ownership_cannot_be_adopted_removed_replayed_or_closed_after_resume(
    tmp_path, role
):
    root = tmp_path / "intents"
    with intents.ActivationIntents(root) as store:
        origin = begin(store)
        store.request(role)
        store.append("ownership_conflict", {"role": role, "evidence_sha256": "f" * 64})
    with intents.ActivationIntents(root) as store:
        store.resume(origin["id"], origin["begin_sha256"])
        assert store.review()["resources"][role]["state"] == "CONFLICT"
        for kind, data in [
            ("observed", {"role": role, "resource_id": "d" * 64}),
            ("removal_requested", {"role": role}),
            ("probe_start_requested", start_payload(role)),
            ("closed", {"evidence_sha256": "e" * 64}),
        ]:
            with pytest.raises(intents.ActivationError):
                store.append(kind, data)
        if role != "journal-before":
            with pytest.raises(intents.ActivationError, match="dependency_is_closing"):
                store.request("api")
