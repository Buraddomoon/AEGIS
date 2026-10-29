"""Rotation network fixtures and optional existing Demo metadata; never create networks."""

import copy
import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from test_runner_activation_ownership import OBJECT
from test_runner_activation_ownership import FakeDocker as Owner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_isolated_network as network  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def store(tmp_path):
    with ActivationIntents(tmp_path / "intents") as value:
        value.begin(uuid4().hex, "a" * 64, "b" * 64)
        yield value


def projection(spec):
    return {
        "id": OBJECT,
        "name": spec["name"],
        "driver": "bridge",
        "scope": "local",
        "internal": True,
        "ipv4": True,
        "ipv6": False,
        "attachable": False,
        "ingress": False,
        "config_only": False,
        "config_from": {"Network": ""},
        "containers": {},
        "options": dict(network.OPTIONS),
        "labels": spec["labels"],
        "label_count": 5,
        "ipam": {
            "Driver": "default",
            "Options": None,
            "Config": [{"Subnet": network.SUBNET, "Gateway": network.GATEWAY}],
        },
    }


class Docker:
    def __init__(self, store):
        self.item = projection(network.recipe(store))
        self.calls = []

    def query(self, store, known_id):
        self.calls.append(network.command(store, known_id))
        return json.dumps(self.item).encode()


def owned(store):
    store.request(network.ROLE)
    store.append("observed", {"role": network.ROLE, "resource_id": OBJECT})
    return Docker(store), Owner(store.summary()["id"], network.ROLE)


def test_compiler_requires_new_intent_and_has_no_configurable_network_surface(store):
    with pytest.raises(network.ActivationError, match="create_intent_required"):
        network.create_arguments(store)
    store.request(network.ROLE)
    args = network.create_arguments(store)
    assert args[:2] == ("network", "create")
    for option, value in (
        ("--driver", "bridge"),
        ("--scope", "local"),
        ("--subnet", "172.30.88.0/29"),
        ("--gateway", "172.30.88.1"),
        ("--ipam-driver", "default"),
    ):
        assert args[args.index(option) + 1] == value
    assert {
        "--internal",
        "--ipv4=true",
        "--ipv6=false",
        "--attachable=false",
        "--ingress=false",
        "--config-only=false",
    } <= set(args)
    labels = [args[i + 1] for i, word in enumerate(args) if word == "--label"]
    assert len(labels) == 5 and args[-1] == "aegis-linux-lab_isolated"
    assert not {"connect", "disconnect", "rm", "prune", "--config-from", "--ip-range"} & set(args)
    store.append("observed", {"role": network.ROLE, "resource_id": OBJECT})
    with pytest.raises(network.ActivationError, match="create_intent_required"):
        network.create_arguments(store)


def test_review_confirms_only_empty_owned_configuration_without_permission_or_reachability(store):
    docker, owner = owned(store)
    before = store.review()
    result = network.review(store, OBJECT, docker=docker, ownership_docker=owner)
    assert result["configured_internal_bridge_verified"]
    assert result["configured_gateway_mode_isolated_verified"] and result["members_absent_verified"]
    assert all(
        result[key] is False
        for key in (
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    assert store.review() == before and len(owner.calls) == 14
    assert len(docker.calls) == 1 and docker.calls[0][:2] == ("network", "inspect")
    assert "Config.Env" not in docker.calls[0][3]


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "c" * 64),
        ("name", "other"),
        ("driver", "overlay"),
        ("scope", "swarm"),
        ("internal", False),
        ("internal", 1),
        ("ipv4", None),
        ("ipv6", True),
        ("attachable", True),
        ("ingress", True),
        ("config_only", True),
        ("config_from", {"Network": "other"}),
        ("options", {}),
        ("options", {"com.docker.network.bridge.gateway_mode_ipv4": "nat"}),
        ("containers", {"c" * 64: {"Name": "foreign"}}),
        ("label_count", 6),
        ("labels", {}),
        ("label_count", 5.0),
    ],
)
def test_drift_unreviewed_driver_or_member_blocks_without_echo(store, field, value):
    docker, owner = owned(store)
    docker.item[field] = value
    with pytest.raises(network.ActivationError, match="configuration_mismatch"):
        network.review(store, OBJECT, docker=docker, ownership_docker=owner)


@pytest.mark.parametrize(
    "scene",
    [
        "driver",
        "options",
        "extra",
        "multiple",
        "subnet",
        "gateway",
        "range",
        "aux",
        "config_extra",
        "missing",
    ],
)
def test_ipam_cannot_broaden_subnet_addressing_or_load_external_configuration(store, scene):
    docker, owner = owned(store)
    ipam = docker.item["ipam"]
    config = ipam["Config"][0]
    if scene == "driver":
        ipam["Driver"] = "external"
    elif scene == "options":
        ipam["Options"] = {"plugin": "private-sensitive-sentinel"}
    elif scene == "extra":
        ipam["Other"] = "private-sensitive-sentinel"
    elif scene == "multiple":
        ipam["Config"].append(copy.deepcopy(config))
    elif scene == "subnet":
        config["Subnet"] = "0.0.0.0/0"
    elif scene == "gateway":
        config["Gateway"] = "172.30.88.2"
    elif scene == "range":
        config["IPRange"] = "172.30.88.0/30"
    elif scene == "aux":
        config["AuxiliaryAddresses"] = {"other": "172.30.88.3"}
    elif scene == "config_extra":
        config["Other"] = True
    else:
        del config["Gateway"]
    with pytest.raises(network.ActivationError, match="ipam_mismatch") as caught:
        network.review(store, OBJECT, docker=docker, ownership_docker=owner)
    assert "private-sensitive-sentinel" not in str(caught.value)


@pytest.mark.parametrize("scene", ["absent", "members", "wrong_id"])
def test_ownership_and_empty_network_are_required_before_runtime_query(store, scene):
    docker, owner = owned(store)
    if scene == "absent":
        owner.named = owner.labelled = owner.known = b""
    elif scene == "members":
        owner.details["member_count"] = 1
    with pytest.raises(network.ActivationError):
        network.review(
            store,
            "c" * 64 if scene == "wrong_id" else OBJECT,
            docker=docker,
            ownership_docker=owner,
        )
    assert docker.calls == []


def test_concrete_adapter_cannot_issue_creation_and_never_echoes_daemon_errors(store, monkeypatch):
    owned(store)
    calls = []

    def execute(args):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args, stderr=b"private-sensitive-sentinel")

    monkeypatch.setattr(network, "_execute", execute)
    with pytest.raises(network.ActivationError, match="query_failed") as caught:
        network.NetworkDocker().query(store, OBJECT)
    assert calls[0][:2] == ("network", "inspect")
    assert "private-sensitive-sentinel" not in str(caught.value)


@pytest.mark.parametrize("scene", ["member", "intent"])
def test_review_rechecks_ownership_and_durable_state_after_daemon_query(store, scene):
    docker, owner = owned(store)
    original_query = docker.query

    def query(*args):
        raw = original_query(*args)
        if scene == "member":
            owner.details["member_count"] = 1
        else:
            store.request("journal-before")
        return raw

    docker.query = query
    with pytest.raises(network.ActivationError, match="changed_during_review"):
        network.review(store, OBJECT, docker=docker, ownership_docker=owner)


@pytest.mark.parametrize(
    "module", ["runner_activation_isolated_network", "runner_activation_network_lifecycle"]
)
def test_fresh_import_has_no_network_process_or_secret_effect(module):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect','socket.getaddrinfo','subprocess.Popen','os.system'}:
        raise AssertionError('effect forbidden')
    if event == 'open' and isinstance(args[0],str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('secret forbidden')
sys.addaudithook(guard)
import importlib
importlib.import_module(sys.argv[1])
assert 'aegis.config' not in sys.modules
""",
            module,
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_projection_on_existing_demo_network_only_when_available():
    if not Path("/usr/bin/docker").is_file() or not Path("/var/run/docker.sock").exists():
        pytest.skip("Optional existing Demo network metadata; no resources created")
    try:
        raw = network._execute(
            (
                "network",
                "ls",
                "--no-trunc",
                "--quiet",
                "--filter",
                "label=com.docker.compose.project=aegis",
                "--filter",
                "name=^aegis_backend$",
            )
        )
    except network.ActivationError:
        pytest.skip("Daemon unavailable; no resources created")
    ids = raw.decode("ascii").splitlines()
    if not ids:
        pytest.skip("Existing Demo network absent; no resources created")
    assert len(ids) == 1
    known_id = network.identifier(ids[0])
    item = network.document(
        network._execute(("network", "inspect", "--format", network.FORMAT, known_id))
    )
    assert item["id"] == known_id and item["driver"] == "bridge"
    assert type(item["ipv4"]) is bool and isinstance(item["ipam"], dict)
    assert set(item["labels"]) == set(network.LABELS.values())
    # Demo metadata is not validated/adopted as an owned rotation network.
