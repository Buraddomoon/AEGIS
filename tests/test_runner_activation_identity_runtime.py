"""Pure identity-container compilation with temporary plans; no Docker RPC or secret reads."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_runtime as runtime  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402

NETWORK = "c" * 64


@pytest.fixture
def context(material, code, tmp_path):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        store.request(runtime.network.ROLE)
        store.append("observed", {"role": runtime.network.ROLE, "resource_id": NETWORK})
        yield store, Path(prepared["plan_path"]), prepared["plan_sha256"]


def test_recipe_only_mounts_three_candidate_files_without_journal_or_execution_capabilities(
    context,
):
    store, path, expected_sha = context
    before = store.summary()
    spec = runtime.recipe(store, path, expected_sha)
    assert spec["identity"]["tests"] == [] and spec["ipv4_address"] == "172.30.88.2"
    assert spec["network_resource_id"] == NETWORK
    assert spec["environment"]["AEGIS_RUNNER_IDENTITY_ONLY"] == "true"
    assert len(spec["mount_sources"]) == 3
    assert set(spec["mount_sources"]) == set(runtime.SECRETS)
    assert spec["arguments"] == ["-I", "-B", "-m", "aegis.lab_runner.server"]
    assert spec["host"]["ReadonlyRootfs"] and spec["host"]["CapDrop"] == ["ALL"]
    assert spec["host"]["PortBindings"] is True  # Projected emptiness predicate.
    assert spec["stdin_open"] is False and spec["user"] == "10001:10001"
    assert "journal" not in json.dumps(spec) and "/state" not in json.dumps(spec)
    assert store.summary() == before


def test_compiler_uses_owned_network_id_fixed_ip_and_readonly_leaf_mounts_without_rpc(context):
    store, path, expected_sha = context
    with pytest.raises(runtime.ActivationError, match="new_runner_intent_required"):
        runtime.create_arguments(store, path, expected_sha)
    store.request("runner")
    args = runtime.create_arguments(store, path, expected_sha)
    assert args[:2] == ("container", "create")
    assert args[args.index("--network") + 1] == NETWORK
    assert args[args.index("--ip") + 1] == "172.30.88.2"
    assert args[args.index("--pull") + 1] == "never"
    mounts = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
    assert len(mounts) == 3 and all(value.startswith("type=bind,") for value in mounts)
    assert all(value.endswith(",readonly,bind-propagation=rprivate") for value in mounts)
    assert not {
        "--publish",
        "--publish-all",
        "--interactive",
        "--tty",
        "--volume",
        "--privileged",
        "--env-file",
        "--device",
        "--volumes-from",
        "--network-alias",
    } & set(args)
    assert "client-ca.key" not in " ".join(args) and "server-ca.key" not in " ".join(args)
    assert "journal" not in " ".join(args) and "/state" not in " ".join(args)
    assert args[-5].startswith("sha256:")
    assert args[-4:] == ("-I", "-B", "-m", "aegis.lab_runner.server")
    assert store.review()["resources"]["runner"] == {"state": "REQUESTED", "resource_id": None}


@pytest.mark.parametrize("scene", ["missing", "requested", "removing", "absent"])
def test_network_must_be_observed_owned_and_not_under_cleanup(context, monkeypatch, scene):
    store, path, expected_sha = context
    state = copy.deepcopy(store.review())
    if scene == "missing":
        state["resources"].pop(runtime.network.ROLE)
    else:
        state["resources"][runtime.network.ROLE]["state"] = {
            "requested": "REQUESTED",
            "removing": "REMOVAL_REQUESTED",
            "absent": "ABSENT",
        }[scene]
    monkeypatch.setattr(store, "review", lambda: state)
    with pytest.raises(runtime.ActivationError, match="owned_network_required"):
        runtime.recipe(store, path, expected_sha)


def test_wrong_plan_hash_or_expired_plan_cannot_compile_create(context, monkeypatch):
    store, path, expected_sha = context
    with pytest.raises(runtime.ActivationError, match="integrity_mismatch"):
        runtime.recipe(store, path, "0" * 64)
    artifact = runtime.plan.load_plan(path, expected_sha)
    expiry = runtime.plan.datetime.fromisoformat(artifact["expires_at"])
    monkeypatch.setattr(runtime.plan.pki, "clock", lambda: expiry)
    with pytest.raises(runtime.ActivationError, match="expired_or_invalid_time"):
        runtime.recipe(store, path, expected_sha)


@pytest.mark.parametrize("scene", ["scope", "id", "hash"])
def test_intent_from_another_review_cannot_supply_network_ownership(context, monkeypatch, scene):
    store, path, expected_sha = context
    state = copy.deepcopy(store.review())
    field = {"scope": "scope_sha256", "id": "plan_id", "hash": "plan_sha256"}[scene]
    state["header"][field] = "f" * (32 if scene == "id" else 64)
    monkeypatch.setattr(store, "review", lambda: state)
    with pytest.raises(runtime.ActivationError, match="owned_network_required"):
        runtime.recipe(store, path, expected_sha)


@pytest.mark.parametrize("scene", ["comma", "newline", "wrong_source"])
def test_unreviewed_secret_sources_or_mount_csv_injection_are_refused(context, monkeypatch, scene):
    store, path, expected_sha = context
    artifact = runtime.plan.load_plan(path, expected_sha)
    if scene == "wrong_source":
        artifact["expected_mount_sources"]["runner"]["/run/secrets/runner_server_key"] = (
            "/elsewhere"
        )
    else:
        artifact["candidate_path"] += ",readonly=false" if scene == "comma" else "\ninvalid"
    monkeypatch.setattr(runtime.plan, "load_plan", lambda *a: artifact)
    with pytest.raises(runtime.ActivationError, match="(mount_path_invalid|sources_mismatch)"):
        runtime.recipe(store, path, expected_sha)


def test_compiler_cannot_reuse_observed_runner_or_modify_the_intent(context):
    store, path, expected_sha = context
    store.request("runner")
    store.append("observed", {"role": "runner", "resource_id": "d" * 64})
    before = store.summary()
    with pytest.raises(runtime.ActivationError, match="new_runner_intent_required"):
        runtime.create_arguments(store, path, expected_sha)
    assert store.summary() == before


def test_import_does_not_read_secrets_or_connect():
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
import runner_activation_identity_runtime
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
