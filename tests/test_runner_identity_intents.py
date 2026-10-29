"""Durable identity-only start fences; no daemon or runner process."""

import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from aegis.domain.validation import digest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runner_activation_intents import ActivationError, ActivationIntents  # noqa: E402

NETWORK, RUNNER = "c" * 64, "d" * 64


def start():
    return {
        "role": "runner",
        "recipe_sha256": "1" * 64,
        "gates_sha256": "2" * 64,
        "pki_manifest_sha256": "3" * 64,
        "network_resource_id": NETWORK,
        "mode": "identity-only",
    }


def observed():
    return {"role": "runner", "runtime_evidence_sha256": "4" * 64}


@pytest.fixture
def store(tmp_path):
    with ActivationIntents(tmp_path / "intents") as value:
        value.begin(uuid4().hex, "a" * 64, "b" * 64)
        value.request("network-isolated")
        value.append("observed", {"role": "network-isolated", "resource_id": NETWORK})
        value.request("runner")
        value.append("observed", {"role": "runner", "resource_id": RUNNER})
        yield value


def test_start_and_configuration_observation_are_distinct_durable_fences(store):
    event = store.append("identity_start_requested", start())
    assert store.review()["resources"]["runner"]["state"] == "START_REQUESTED"
    assert "runtime_evidence_sha256" not in store.review()["resources"]["runner"]
    persisted = json.loads(sorted(store.folder.glob("*.json"))[-1].read_bytes())
    assert persisted["kind"] == "identity_start_requested"
    assert event["event_sha256"] == digest(persisted)
    store.append("identity_runtime_observed", observed())
    item = store.review()["resources"]["runner"]
    assert item["state"] == "OBSERVED" and item["start"]["mode"] == "identity-only"
    assert item["runtime_evidence_sha256"] == "4" * 64
    assert all(
        store.summary()[field] is False
        for field in (
            "authorization_verified",
            "activation_verified",
            "daemon_absence_verified",
            "normal_operation_permitted",
        )
    )


@pytest.mark.parametrize("scene", ["mode", "wrong_network", "hash", "extra", "role"])
def test_arbitrary_profiles_unpinned_hashes_and_other_roles_are_rejected_before_write(store, scene):
    data = start()
    if scene == "mode":
        data["mode"] = "execution"
    elif scene == "wrong_network":
        data["network_resource_id"] = "f" * 64
    elif scene == "hash":
        data["pki_manifest_sha256"] = "unreviewed"
    elif scene == "extra":
        data["command"] = "unreviewed"
    else:
        data["role"] = "network-isolated"
    before = store.summary()
    with pytest.raises(ActivationError):
        store.append("identity_start_requested", data)
    assert store.summary() == before


@pytest.mark.parametrize("role", ["db", "redis", "api", "journal-before", "network-backend"])
def test_identity_surface_does_not_start_alongside_other_pending_or_active_roles(store, role):
    store.request(role)
    with pytest.raises(ActivationError, match="identity_start_invalid"):
        store.append("identity_start_requested", start())
    assert store.review()["resources"]["runner"]["state"] == "OBSERVED"


@pytest.mark.parametrize("has_runtime", [False, True])
def test_start_is_not_repeatable_even_after_successful_configuration_observation(
    store, has_runtime
):
    store.append("identity_start_requested", start())
    if has_runtime:
        store.append("identity_runtime_observed", observed())
    with pytest.raises(ActivationError, match="already_requested"):
        store.append("identity_start_requested", start())
    if has_runtime:
        with pytest.raises(ActivationError, match="observation_invalid"):
            store.append("identity_runtime_observed", observed())


def test_runtime_cannot_precede_start_intent_or_substitute_for_other_profiles(store):
    with pytest.raises(ActivationError, match="observation_invalid"):
        store.append("identity_runtime_observed", observed())
    with pytest.raises(ActivationError, match="database_runtime_observation_invalid"):
        store.append("database_runtime_observed", observed())


def test_restarted_host_resumes_only_reconciliation_and_cleanup_without_replaying_start(tmp_path):
    root = tmp_path / "intents"
    with ActivationIntents(root) as value:
        value.begin(uuid4().hex, "a" * 64, "b" * 64)
        value.request("network-isolated")
        value.append("observed", {"role": "network-isolated", "resource_id": NETWORK})
        value.request("runner")
        value.append("observed", {"role": "runner", "resource_id": RUNNER})
        value.append("identity_start_requested", start())
        summary = value.summary()
    with ActivationIntents(root) as resumed:
        resumed.resume(summary["id"], summary["begin_sha256"])
        with pytest.raises(ActivationError, match="already_requested"):
            resumed.append("identity_start_requested", start())
        with pytest.raises(ActivationError, match="dependencies_retained"):
            resumed.append("removal_requested", {"role": "network-isolated"})
        for role in ("runner", "network-isolated"):
            resumed.append("removal_requested", {"role": role})
            resumed.append("absence_recorded", {"role": role, "evidence_sha256": "5" * 64})
        resumed.append("closed", {"evidence_sha256": "6" * 64})
        assert resumed.review()["closed"]
