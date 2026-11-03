"""Persistence boundary tests; actual network facts and explicit server/client gate fixtures."""

import copy
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_network_gates import code as code
from test_runner_activation_network_gates import context as context
from test_runner_activation_network_gates import material as material

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_recorded_gates as recorded  # noqa: E402


@pytest.fixture
def prepared(context, tmp_path):
    c, world = context
    with recorded.IdentityArtifacts(c, root=tmp_path / "records") as records:
        yield c, world, records


def test_network_admission_is_returned_only_after_real_facts_have_been_flushed(prepared):
    c, world, records = prepared
    world.store.request(recorded.network.network.ROLE)
    result = recorded.before_network_create(
        c, records, "create", recorded.network.network.recipe(world.store)
    )
    item = records.read("network-create-gate")["body"]
    assert item["gate"] == result
    for key, fact in (
        ("before_sha256", "plan_before"),
        ("after_sha256", "plan_after"),
        ("subnet_review_sha256", "subnet"),
    ):
        assert item["evidence"][key] == recorded.digest(item["review"][fact])
    c._last_review["plan_before"].clear()
    assert records.read("network-create-gate")["body"] == item
    assert world.effects == []


def test_expiry_during_disk_io_retains_facts_but_refuses_admission(prepared, monkeypatch):
    c, world, records = prepared
    write = records.write

    def expired(*args):
        result = write(*args)
        monkeypatch.setattr(recorded.network.plan.pki, "clock", lambda: c.expires)
        return result

    monkeypatch.setattr(records, "write", expired)
    world.store.request(recorded.network.network.ROLE)
    with pytest.raises(recorded.ActivationError, match="scope_or_budget_unconfirmed"):
        recorded.before_network_create(
            c, records, "create", recorded.network.network.recipe(world.store)
        )
    assert records.read("network-create-gate")["body"]["gate"]["phase"] == "create"
    assert world.effects == []


@pytest.mark.parametrize("scene", ["write_failed", "intent_changed", "stale"])
def test_persistence_does_not_turn_failure_or_old_facts_into_admission(
    prepared, monkeypatch, scene
):
    c, world, records = prepared
    now = recorded.network.plan.pki.clock()
    gate = {"checked_at": now.isoformat(), "expires_at": (now + timedelta(seconds=20)).isoformat()}
    write = records.write

    def changed(*args):
        result = write(*args)
        if scene == "write_failed":
            raise OSError("private-sensitive-sentinel")
        if scene == "intent_changed":
            c.store.request("redis")
        if scene == "stale":
            monkeypatch.setattr(
                recorded.network.plan.pki, "clock", lambda: now + timedelta(seconds=11)
            )
        return result

    monkeypatch.setattr(records, "write", changed)
    with pytest.raises((OSError, recorded.ActivationError)):
        recorded._persist(
            records, c, "server-start-gate", gate, {}, {"gate_sha256": recorded.digest(gate)}
        )
    assert "server-start-gate" in records.inventory()
    assert world.effects == []


@pytest.mark.parametrize("role", ["server", "client"])
def test_recorded_wrappers_never_accept_saved_gate_instead_of_calling_computed_provider(
    prepared, monkeypatch, role
):
    c, world, records = prepared
    base = (
        recorded.server.IdentityGates if role == "server" else recorded.client.IdentityClientGates
    )
    cls = recorded.RecordedServerGates if role == "server" else recorded.RecordedClientGates
    calls = []

    def init(self, confirmation, *args, **kwargs):
        self.confirmation = confirmation
        self.evidence = []

    def review(self, phase, spec):
        calls.append((phase, spec))
        now = recorded.network.plan.pki.clock()
        result = {
            "checked_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=20)).isoformat(),
        }
        self._last_gate = copy.deepcopy(result)
        self._last_review = {"explicit_fixture_boundary": True}
        self.evidence.append({"gate_sha256": recorded.digest(result)})
        return result

    monkeypatch.setattr(base, "__init__", init)
    monkeypatch.setattr(base, "review", review)
    value = cls(c, {}, records) if role == "server" else cls(c, {}, b"fixture", "a" * 64, records)
    result = value.review("create", {"closed_recipe_fixture": True})
    assert calls == [("create", {"closed_recipe_fixture": True})]
    assert records.read(role + "-create-gate")["body"]["gate"] == result
    assert world.effects == []
    if role == "client":
        # The second write cannot replace the first proof, even if the fixture
        # provider returns another positive gate; the cached admission is revoked.
        with pytest.raises(FileExistsError):
            value.review("create", {})
        assert value._last_gate is None and value._last_review is None


def test_other_confirmation_or_plain_saved_dict_cannot_supply_artifacts(prepared):
    c, _, records = prepared
    for value in ({"confirmation": c}, None):
        with pytest.raises(recorded.ActivationError, match="same_confirmation_required"):
            recorded.RecordedServerGates(c, {}, value)
    other = copy.copy(c)
    with pytest.raises(recorded.ActivationError, match="same_confirmation_required"):
        recorded.RecordedServerGates(other, {}, records)
