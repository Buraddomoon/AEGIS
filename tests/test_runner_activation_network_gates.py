"""Real temporary Git/PKI and read-only daemon fixtures; no native network lifecycle."""

import copy
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_image_source import git
from test_runner_activation_metadata import FakeDocker, images
from test_runner_activation_network_lifecycle import World
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare
from test_runner_activation_subnet_review import Docker as SubnetDocker
from test_runner_activation_subnet_review import Routes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_network_gates as gates  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def context(material, code, tmp_path):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store)
        value = gates.NetworkGates(
            Path(prepared["plan_path"]),
            prepared["plan_sha256"],
            store,
            prepared["scope_sha256"],
            (gates.plan.pki.clock() + timedelta(seconds=290)).isoformat(),
            docker=FakeDocker(),
            ownership_docker=world,
            subnet_docker=SubnetDocker(),
            routes=Routes(),
        )
        yield value, world


def invoke(context):
    value, world = context
    world.store.request(gates.network.ROLE)
    return value.before_create("create", gates.network.recipe(world.store))


def test_gate_composes_actual_pki_plan_ownership_and_two_fresh_subnet_snapshots(context):
    value, world = context
    result = invoke(context)
    assert set(result["checks"]) == gates.lifecycle.CHECKS
    assert all(check is True for check in result["checks"].values())
    assert result["scope_sha256"] == value.artifact["scope_sha256"]
    assert value.routes.calls == 2 and len(value.subnet_docker.calls) == 6
    assert value.evidence[0]["gate_sha256"] == gates.digest(result)
    encoded = json.dumps([result, value.evidence])
    assert "private-sensitive-sentinel" not in encoded
    assert "192.0.2.0" not in encoded and "198.51.100.1" not in encoded
    assert world.effects == []
    assert world.store.review()["resources"][gates.network.ROLE]["state"] == "REQUESTED"
    assert value.artifact["activation_performed"] is False
    assert value.artifact["profile"]["executor_implemented"] is False


def test_computed_gate_is_consumed_by_single_create_fixture_and_never_replays(context):
    value, world = context
    create = world.create

    def matching_create(store):
        known_id = create(store)
        world.owner.details["plan"] = value.plan_sha256
        return known_id

    world.create = matching_create
    result = gates.lifecycle.create_network(
        world.store,
        images(),
        before_effect=value.before_create,
        lifecycle=world,
        runtime_docker=world.runtime,
        ownership_docker=world,
        cleanup_docker=world,
    )
    assert result["status"] == "empty_owned_network_created_and_retained"
    assert world.effects == ["create"] and len(value.evidence) == 1
    with pytest.raises(gates.ActivationError, match="no_replay"):
        gates.lifecycle.create_network(world.store, images(), before_effect=value.before_create)


@pytest.mark.parametrize("source", ["docker", "route"])
def test_live_overlap_denies_gate_without_create_even_after_an_older_clear_review(context, source):
    value, world = context
    gates.subnet.review(docker=value.subnet_docker, routes=value.routes)
    if source == "docker":
        value.subnet_docker.item["config"] = [{"Subnet": gates.network.SUBNET}]
    else:
        value.routes.items.append({"dst": "172.30.88.2/32", "table": 101})
    with pytest.raises(gates.ActivationError, match="overlap_observed"):
        invoke(context)
    assert value.evidence == [] and world.effects == []


@pytest.mark.parametrize("scene", ["foreign_worker", "journal_consumer", "network_collision"])
def test_unowned_resources_block_before_route_observation(context, scene):
    value, world = context
    kind, name = {
        "foreign_worker": ("containers", None),
        "journal_consumer": ("consumers", "journal"),
        "network_collision": ("network_name", "isolated"),
    }[scene]
    value.docker.responses[kind, name] = ("f" * 64 + "\n").encode()
    with pytest.raises(gates.ActivationError):
        invoke(context)
    assert value.routes.calls == 0 and value.evidence == [] and world.effects == []


@pytest.mark.parametrize("scene", ["scope", "intent", "utc", "expired", "too_long"])
def test_specific_scope_and_bounded_utc_confirmation_are_required_before_metadata(context, scene):
    value, world = context
    now = gates.plan.pki.clock()
    expires = now + timedelta(seconds=290)
    scope = value.scope
    if scene == "scope":
        scope = "f" * 64
    elif scene == "intent":
        value.store.append("closed", {"evidence_sha256": "f" * 64})
    elif scene == "utc":
        expires = expires.replace(tzinfo=None)
    elif scene == "expired":
        expires = now - timedelta(seconds=1)
    elif scene == "too_long":
        expires = now + timedelta(seconds=301)
    with pytest.raises(gates.ActivationError, match="(scope_or_budget|interval_invalid)"):
        gates.NetworkGates(value.path, value.plan_sha256, value.store, scope, expires.isoformat())
    assert value.docker.calls == [] and world.effects == []


@pytest.mark.parametrize("phase", ["created", "start", "running", "ready"])
def test_no_other_lifecycle_phase_is_enabled(context, phase):
    value, _world = context
    with pytest.raises(gates.ActivationError, match="create_only"):
        value.before_create(phase, {})
    assert value.docker.calls == [] and value.routes.calls == 0


@pytest.mark.parametrize("field", ["subnet", "name", "labels", "options"])
def test_recipe_substitution_cannot_expand_confirmed_scope(context, field):
    value, world = context
    spec = copy.deepcopy(gates.network.recipe(world.store))
    spec[field] = "private-sensitive-sentinel"
    with pytest.raises(gates.ActivationError, match="recipe_mismatch") as caught:
        value.before_create("create", spec)
    assert "private-sensitive-sentinel" not in str(caught.value)
    assert value.docker.calls == [] and value.routes.calls == 0


@pytest.mark.parametrize("scene", ["authorization", "plan", "clock_rollback", "monotonic"])
def test_expiration_or_clock_changes_during_reading_never_publish_gate(context, monkeypatch, scene):
    value, world = context
    original = value.routes.query

    def change(**kwargs):
        raw = original(**kwargs)
        if scene == "monotonic":
            monkeypatch.setattr(gates.time, "monotonic", lambda: value.deadline + 1)
        else:
            when = {
                "authorization": value.expires,
                "plan": gates.datetime.fromisoformat(value.artifact["expires_at"]),
                "clock_rollback": value.confirmed_at - timedelta(seconds=1),
            }[scene]
            monkeypatch.setattr(gates.plan.pki, "clock", lambda: when)
        return raw

    value.routes.query = change
    with pytest.raises(gates.ActivationError):
        invoke(context)
    assert value.evidence == [] and world.effects == []


@pytest.mark.parametrize("scene", ["source", "ownership", "metadata", "aged_observation"])
def test_second_plan_review_catches_changes_during_subnet_io(context, code, monkeypatch, scene):
    value, world = context
    original = value.routes.query
    changed = False
    initial = gates.plan.pki.clock()

    def change(**kwargs):
        nonlocal changed
        raw = original(**kwargs)
        if not changed:
            changed = True
            if scene == "source":
                (code / "executor.py").write_text("# changed during read-only preflight\n")
                git(code, "add", "executor.py")
                git(code, "commit", "-m", "fixture: change executor during preflight")
            elif scene == "ownership":
                world.store.request("redis")
            elif scene == "metadata":
                value.docker.responses["daemon", None]["id"] = "f" * 64
            else:
                monkeypatch.setattr(
                    gates.plan.pki, "clock", lambda: initial + timedelta(seconds=11)
                )
        return raw

    value.routes.query = change
    with pytest.raises(gates.ActivationError):
        invoke(context)
    assert value.evidence == [] and world.effects == []


def test_import_has_no_connections_processes_or_secret_reads():
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
import runner_activation_network_gates
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
