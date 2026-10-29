"""Pinned PKI/plans plus fixture daemon while resources are owned; no lab effects."""

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from test_runner_activation_active_metadata import World
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation as activation  # noqa: E402
import runner_activation_active_plan as active_plan  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


def review(prepared, store, world):
    return active_plan.recheck(
        Path(prepared["plan_path"]),
        prepared["plan_sha256"],
        store,
        world.role,
        world.phase,
        docker=world.meta,
        ownership_docker=world,
    )


@pytest.mark.parametrize(
    "role,phase",
    [
        (role, phase)
        for role in sorted(active_plan.active.PROBE_ROLES)
        for phase in ("create", "start")
    ]
    + [("db", phase) for phase in ("create", "start", "running")]
    + [("network-isolated", phase) for phase in ("create", "created")],
)
def test_same_pinned_plan_can_be_rechecked_only_under_exact_durable_operation(
    material, code, tmp_path, role, phase
):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store, role, phase)
        result = review(prepared, store, world)
        assert result["status"] == "active_plan_revalidated_not_activated"
        assert (
            result["plan_sha256"] == prepared["plan_sha256"]
            and result["scope_sha256"] == prepared["scope_sha256"]
        )
        assert result["owned_metadata"]["journal_consumer_set_verified"]
        assert all(result[key] is False for key in activation.FLAGS)
        assert not store.review()["closed"]


def test_normal_public_recheck_still_refuses_active_project_even_when_owned(
    material, code, tmp_path
):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store)
        with pytest.raises(activation.ActivationError, match="not_quiescent"):
            activation.recheck(
                Path(prepared["plan_path"]), prepared["plan_sha256"], docker=world.meta
            )
        assert review(prepared, store, world)["status"] == "active_plan_revalidated_not_activated"


@pytest.mark.parametrize("mismatch", ["id", "hash", "scope"])
def test_other_plan_or_unpinned_intent_is_refused_before_runtime(
    material, code, tmp_path, monkeypatch, mismatch
):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(
            uuid4().hex if mismatch == "id" else prepared["id"],
            "f" * 64 if mismatch == "hash" else prepared["plan_sha256"],
            "f" * 64 if mismatch == "scope" else prepared["scope_sha256"],
        )
        monkeypatch.setattr(
            activation, "snapshot", lambda *a, **k: pytest.fail("No runtime query permitted")
        )
        with pytest.raises(activation.ActivationError, match="intent_mismatch"):
            active_plan.recheck(
                Path(prepared["plan_path"]),
                prepared["plan_sha256"],
                store,
                "journal-before",
                "create",
            )


def test_wrong_hash_and_expired_plan_fail_before_pki_or_daemon(
    material, code, tmp_path, monkeypatch
):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        monkeypatch.setattr(
            activation, "snapshot", lambda *a, **k: pytest.fail("No runtime query permitted")
        )
        with pytest.raises(activation.ActivationError, match="integrity_mismatch"):
            active_plan.recheck(
                Path(prepared["plan_path"]), "0" * 64, store, "journal-before", "create"
            )
        expired = datetime.fromisoformat(prepared["expires_at"])
        monkeypatch.setattr(activation.pki, "clock", lambda: expired)
        with pytest.raises(activation.ActivationError, match="expired_or_invalid_time"):
            active_plan.recheck(
                Path(prepared["plan_path"]),
                prepared["plan_sha256"],
                store,
                "journal-before",
                "create",
            )


def test_compose_drift_cannot_be_accepted_by_the_active_path(material, code, tmp_path):
    prepared, _ = prepare(material, tmp_path)
    (code / activation.COMPOSE[-1]).write_text("altered")
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store)
        # The clean-main guard now refuses the changed tracked Compose before
        # even reading PKI/metadata, rather than reaching the later hash compare.
        with pytest.raises(activation.ActivationError, match="executor_source_unreviewed"):
            review(prepared, store, world)


def test_expiration_during_daemon_queries_cannot_publish_success(
    material, code, tmp_path, monkeypatch
):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store)
        original = world.meta.query
        expired = datetime.fromisoformat(prepared["expires_at"]) + timedelta(seconds=1)

        def expire(*args):
            value = original(*args)
            monkeypatch.setattr(activation.pki, "clock", lambda: expired)
            return value

        world.meta.query = expire
        with pytest.raises(activation.ActivationError, match="expired_during_review"):
            review(prepared, store, world)


def test_expiration_during_last_durable_review_cannot_publish_success(
    material, code, tmp_path, monkeypatch
):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store)
        original = store.review
        count = 0
        expired = datetime.fromisoformat(prepared["expires_at"]) + timedelta(seconds=1)

        def expire():
            nonlocal count
            value = original()
            count += 1
            if count == 4:
                monkeypatch.setattr(activation.pki, "clock", lambda: expired)
            return value

        monkeypatch.setattr(store, "review", expire)
        with pytest.raises(activation.ActivationError, match="expired_during_review"):
            review(prepared, store, world)


def test_changed_ownership_after_metadata_is_not_accepted(material, code, tmp_path, monkeypatch):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        world = World(store)
        original = store.review
        count = 0

        def change():
            nonlocal count
            count += 1
            if count == 4:
                store.request("redis")
            return original()

        monkeypatch.setattr(store, "review", change)
        with pytest.raises(activation.ActivationError, match="ownership_changed"):
            review(prepared, store, world)


def test_public_profile_remains_non_operational_and_no_new_cli_apply_exists(
    material, code, tmp_path
):
    prepared, _ = prepare(material, tmp_path)
    artifact = activation.load_plan(Path(prepared["plan_path"]), prepared["plan_sha256"])
    assert artifact["profile"]["executor_implemented"] is False
    assert all(artifact[key] is False for key in activation.FLAGS)
    assert json.loads(Path(prepared["plan_path"]).read_bytes()) == artifact


def test_active_plan_import_does_not_read_secrets_or_connect():
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
import runner_activation_active_plan
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
