"""Offline PKI + read-only daemon fixtures; no lab/bank/journal access."""

import copy
import json
import os
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_image_source import git
from test_runner_activation_metadata import FakeDocker, images

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation as activation  # noqa: E402
import runner_pki as pki  # noqa: E402


@pytest.fixture(scope="module")
def material(tmp_path_factory):
    root = tmp_path_factory.mktemp("activation-pki")
    source = pki.initialize(root / "source")
    result = pki.prepare(source, pki.inspect(source)["inventory_sha256"], root / "candidates")
    return source, Path(result["candidate_path"]), result["manifest_sha256"]


@pytest.fixture
def code(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    for name in activation.COMPOSE:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((activation.ROOT / name).read_bytes())
    # Never parse .env, even when it contains sensitive/invalid configuration.
    (root / ".env").write_text("private-sensitive-sentinel")
    (root / ".gitignore").write_text(".env\n")
    git(root, "init", "-b", "main")
    git(root, "add", ".gitignore", *activation.COMPOSE)
    git(root, "commit", "-m", "fixture: pin synthetic executor inputs")
    monkeypatch.setattr(activation, "ROOT", root)
    return root


def prepare(material, tmp_path):
    docker = FakeDocker()
    result = activation.plan(*material, images(), tmp_path / "plans", docker=docker)
    return result, docker


def rewrite(path, change):
    record = json.loads(path.read_bytes())
    change(record)
    path.write_text(json.dumps(record))
    return activation.digest(record)


def test_clean_commit_changed_during_metadata_is_rejected_before_plan_publication(
    material, code, tmp_path
):
    docker = FakeDocker()
    original, changed = docker.query, [False]

    def query(kind, value=None):
        raw = original(kind, value)
        if kind == "daemon" and not changed[0]:
            changed[0] = True
            (code / "executor.py").write_text("# changed during fixture metadata IO\n")
            git(code, "add", "executor.py")
            git(code, "commit", "-m", "fixture: change source during review")
        return raw

    docker.query = query
    with pytest.raises(activation.ActivationError, match="inputs_changed_during_review"):
        activation.plan(*material, images(), tmp_path / "plans", docker=docker)
    assert not (tmp_path / "plans").exists()


def test_scope_pins_exact_clean_main_commit_and_ignores_untracked_secret_configuration(
    material, code, tmp_path
):
    prepared, docker = prepare(material, tmp_path)
    path = Path(prepared["plan_path"])
    artifact = activation.load_plan(path, prepared["plan_sha256"])
    assert artifact["tool_commit"] == git(code, "rev-parse", "HEAD").decode().strip()
    assert artifact["scope_sha256"] == prepared["scope_sha256"] == activation.scope_digest(artifact)
    (code / ".env").write_text("different-private-sensitive-sentinel")
    assert (
        activation.recheck(path, prepared["plan_sha256"], docker=docker)["scope_sha256"]
        == prepared["scope_sha256"]
    )


def test_dirty_executor_source_blocks_plan_before_pki_or_daemon_reads(
    material, code, tmp_path, monkeypatch
):
    (code / "executor.py").write_text("# unreviewed fixture change\n")
    docker = FakeDocker()
    monkeypatch.setattr(
        activation.pki, "verify", lambda *a: pytest.fail("PKI not permitted before source review")
    )
    with pytest.raises(activation.ActivationError, match="executor_source_unreviewed"):
        activation.plan(*material, images(), tmp_path / "plans", docker=docker)
    assert docker.calls == []


def test_new_clean_commit_invalidates_old_plan_without_rewriting_it(material, code, tmp_path):
    prepared, docker = prepare(material, tmp_path)
    path = Path(prepared["plan_path"])
    before = path.read_bytes()
    (code / "executor.py").write_text("# changed fixture source\n")
    git(code, "add", "executor.py")
    git(code, "commit", "-m", "fixture: change reviewed tool version")
    with pytest.raises(activation.ActivationError, match="activation_plan_drift"):
        activation.recheck(path, prepared["plan_sha256"], docker=docker)
    assert path.read_bytes() == before


@pytest.mark.parametrize("scene", ["legacy", "scope"])
def test_recomputed_outer_hash_cannot_upgrade_legacy_plan_or_replace_scope(
    material, code, tmp_path, scene
):
    prepared, _ = prepare(material, tmp_path)
    path = Path(prepared["plan_path"])
    expected = rewrite(
        path,
        lambda doc: doc.update(
            {"format": "aegis-runner-activation-plan/1"}
            if scene == "legacy"
            else {"scope_sha256": "0" * 64}
        ),
    )
    with pytest.raises(activation.ActivationError, match="policy_mismatch"):
        activation.load_plan(path, expected)


def test_same_inputs_in_another_plan_have_a_distinct_nonce_bound_scope(material, code, tmp_path):
    first, _ = prepare(material, tmp_path)
    second, _ = prepare(material, tmp_path)
    assert first["id"] != second["id"] and first["scope_sha256"] != second["scope_sha256"]


def test_partial_snapshot_cannot_silently_omit_executor_pin(material, code, tmp_path, monkeypatch):
    prepared, docker = prepare(material, tmp_path)
    path = Path(prepared["plan_path"])
    artifact = activation.load_plan(path, prepared["plan_sha256"])
    current = {key: artifact[key] for key in activation.SNAPSHOT_FIELDS if key != "tool_commit"}
    monkeypatch.setattr(activation, "snapshot", lambda *a, **kw: current)
    with pytest.raises(activation.ActivationError, match="activation_plan_drift"):
        activation.recheck(path, prepared["plan_sha256"], docker=docker)


def test_plan_and_recheck_pin_inputs_preserve_source_and_never_claim_activation(
    material, code, tmp_path, monkeypatch
):
    source, candidate, _ = material
    before = {
        str(path): (path.read_bytes(), path.stat().st_mtime_ns)
        for folder in (source, candidate)
        for path in folder.iterdir()
    }
    read = pki.read

    def restricted(path, **kwargs):
        if path.parent == source:
            assert path.name in pki.PUBLIC
        assert path.name != ".env"
        return read(path, **kwargs)

    monkeypatch.setattr(pki, "read", restricted)
    result, docker = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    record = json.loads(path.read_bytes())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert activation.digest(record) == result["plan_sha256"]
    assert record["profile"] == activation.profile()
    assert record["expected_mount_sources"]["runner"]["/state"] == "aegis-linux-lab_journal"
    assert record["expected_mount_sources"]["api"]["/run/secrets/controller_client_key"] == str(
        candidate / "runner-client.key"
    )
    checked = activation.recheck(path, result["plan_sha256"], docker=docker)
    assert checked["status"] == "metadata_plan_revalidated_not_activated"
    assert checked["pending_gates"] == activation.PENDING
    assert all(
        document[field] is False
        for document in (record, result, checked)
        for field in activation.FLAGS
    )
    assert all(
        document[field] is False
        for document in (record["profile"],)
        for field in ("executor_implemented", "marker_permitted", "wazuh_permitted")
    )
    assert before == {
        str(path): (path.read_bytes(), path.stat().st_mtime_ns)
        for folder in (source, candidate)
        for path in folder.iterdir()
    }
    assert b"private-sensitive-sentinel" not in path.read_bytes()


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "unsupported/2"),
        ("activation_performed", True),
        ("authorization_granted", True),
        ("normal_operation_permitted", 0),
        ("status", "ready"),
        ("pending_gates", []),
        ("profile", {"executor_implemented": True}),
        ("id", "0" * 32),
    ],
)
def test_policy_cannot_be_replaced_even_with_recomputed_hash(
    material, code, tmp_path, monkeypatch, field, value
):
    result, docker = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    expected = rewrite(path, lambda record: record.update({field: value}))
    docker.calls.clear()
    monkeypatch.setattr(
        activation, "snapshot", lambda *a, **kw: pytest.fail("policy must fail first")
    )
    with pytest.raises(activation.ActivationError, match="policy_mismatch"):
        activation.recheck(path, expected, docker=docker)
    assert not docker.calls


def test_profile_boolean_type_is_not_interchangeable_with_integer(material, code, tmp_path):
    result, docker = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    expected = rewrite(path, lambda record: record["profile"].update({"marker_permitted": 0}))
    with pytest.raises(activation.ActivationError, match="policy_mismatch"):
        activation.recheck(path, expected, docker=docker)


def test_hash_mismatch_fails_before_pkior_docker(material, code, tmp_path, monkeypatch):
    result, docker = prepare(material, tmp_path)
    monkeypatch.setattr(
        activation, "snapshot", lambda *a, **kw: pytest.fail("hash must fail first")
    )
    with pytest.raises(activation.ActivationError, match="integrity_mismatch"):
        activation.recheck(Path(result["plan_path"]), "0" * 64, docker=docker)


@pytest.mark.parametrize("change", ["compose", "daemon", "volume", "pending", "image"])
def test_inputs_drift_or_new_consumer_cannot_revalidate(material, code, tmp_path, change):
    result, docker = prepare(material, tmp_path)
    if change == "compose":
        with (code / "labs/linux/platform.yml").open("a") as output:
            output.write("\n# changed after review\n")
    elif change == "daemon":
        docker.responses["daemon", None]["id"] = "22345678-1234-1234-1234-123456789012"
    elif change == "volume":
        docker.responses["volume", "journal"]["created_at"] = "2026-10-22T12:00:00Z"
    elif change == "pending":
        docker.responses["consumers", "postgres-data"] = b"new-stopped-container"
    else:
        docker.responses["image", images()["runner"]]["user"] = "root"
    with pytest.raises(activation.ActivationError):
        activation.recheck(Path(result["plan_path"]), result["plan_sha256"], docker=docker)


@pytest.mark.parametrize(
    "age", [timedelta(minutes=15), timedelta(minutes=20), timedelta(seconds=-1)]
)
def test_expired_or_future_plan_is_rejected_before_reading_runtime(
    material, code, tmp_path, monkeypatch, age
):
    result, docker = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    record = json.loads(path.read_bytes())
    instant = activation.datetime.fromisoformat(record["created_at"]) + age
    monkeypatch.setattr(pki, "clock", lambda: instant)
    monkeypatch.setattr(
        activation, "snapshot", lambda *a, **kw: pytest.fail("time must fail first")
    )
    with pytest.raises(activation.ActivationError, match="expired_or_invalid_time"):
        activation.recheck(path, result["plan_sha256"], docker=docker)


def test_expiration_during_recheck_does_not_produce_success(material, code, tmp_path, monkeypatch):
    result, docker = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    record = json.loads(path.read_bytes())
    instant = activation.datetime.fromisoformat(record["created_at"])
    times = iter([instant + timedelta(seconds=1), instant + activation.TTL])
    monkeypatch.setattr(pki, "clock", lambda: next(times))
    current = {name: record[name] for name in activation.SNAPSHOT_FIELDS}
    monkeypatch.setattr(activation, "snapshot", lambda *a, **kw: copy.deepcopy(current))
    with pytest.raises(activation.ActivationError, match="expired_or_invalid_time"):
        activation.recheck(path, result["plan_sha256"], docker=docker)


def test_changed_input_during_snapshot_cannot_publish(material, code, tmp_path):
    docker = FakeDocker()
    query = docker.query

    def changed(kind, value=None):
        if kind == "daemon":
            with (code / "docker-compose.yml").open("a") as stream:
                stream.write("\n# drift\n")
        return query(kind, value)

    docker.query = changed
    with pytest.raises(activation.ActivationError, match="inputs_changed_during_review"):
        activation.plan(*material, images(), tmp_path / "plans", docker=docker)
    assert not (tmp_path / "plans").exists()


def test_bad_manifest_rejected_before_docker_or_output(material, code, tmp_path):
    docker = FakeDocker()
    with pytest.raises(pki.PKIError):
        activation.plan(
            material[0], material[1], "0" * 64, images(), tmp_path / "plans", docker=docker
        )
    assert not docker.calls and not (tmp_path / "plans").exists()


def test_wazuh_candidate_cannot_enter_linux_profile(tmp_path, code):
    source = pki.initialize(tmp_path / "wazuh-source", server_ip="172.30.89.2")
    result = pki.prepare(source, pki.inspect(source)["inventory_sha256"], tmp_path / "candidates")
    docker = FakeDocker()
    with pytest.raises(activation.ActivationError, match="linux_integrated_profile_required"):
        activation.plan(
            source,
            Path(result["candidate_path"]),
            result["manifest_sha256"],
            images(),
            tmp_path / "plans",
            docker=docker,
        )
    assert not docker.calls and not (tmp_path / "plans").exists()


@pytest.mark.parametrize("location", [0, 1])
def test_plan_output_cannot_change_pki_source_or_candidate(material, code, location):
    with pytest.raises(activation.ActivationError, match="output_must_be_separate"):
        activation.plan(*material, images(), material[location] / "plans", docker=FakeDocker())
    assert not (material[location] / "plans").exists()


@pytest.mark.parametrize(
    "problem", ["symlink", "hardlink", "public_file", "public_folder", "fifo", "excessive"]
)
def test_unsafe_plan_file_is_refused(material, code, tmp_path, problem):
    result, docker = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    if problem == "symlink":
        renamed = path.with_name("original.json")
        path.rename(renamed)
        path.symlink_to(renamed)
    elif problem == "hardlink":
        os.link(path, path.with_name("linked.json"))
    elif problem == "public_file":
        path.chmod(0o644)
    elif problem == "public_folder":
        path.parent.chmod(0o755)
    elif problem == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(b"x" * 65537)
    with pytest.raises((pki.PKIError, OSError, activation.ActivationError)):
        activation.recheck(path, result["plan_sha256"], docker=docker)


def test_failed_durability_retains_private_artifact_without_success(
    material, code, tmp_path, monkeypatch
):
    original = pki.sync

    def fail_publication(path):
        if path.parent.name == "plans":
            raise OSError("private-sensitive-sentinel")
        original(path)

    monkeypatch.setattr(pki, "sync", fail_publication)
    with pytest.raises(OSError):
        activation.plan(*material, images(), tmp_path / "plans", docker=FakeDocker())
    retained = list((tmp_path / "plans").glob("*/plan.json"))
    assert len(retained) == 1 and stat.S_IMODE(retained[0].stat().st_mode) == 0o600
    assert all(json.loads(retained[0].read_bytes())[key] is False for key in activation.FLAGS)


def test_repeated_preparation_keeps_previous_plan_immutable(material, code, tmp_path):
    first, _ = prepare(material, tmp_path)
    path = Path(first["plan_path"])
    original = path.read_bytes(), path.stat().st_mtime_ns
    second, _ = prepare(material, tmp_path)
    assert first["id"] != second["id"]
    assert original == (path.read_bytes(), path.stat().st_mtime_ns)


def test_cli_redacts_invalid_input_and_exposes_no_apply(tmp_path):
    folder = tmp_path / ("1" * 32)
    folder.mkdir(mode=0o700)
    path = folder / "plan.json"
    path.write_text("private-sensitive-sentinel")
    path.chmod(0o600)
    result = subprocess.run(
        [
            sys.executable,
            "scripts/runner_activation.py",
            "recheck",
            "--plan",
            str(path),
            "--expected-sha256",
            "0" * 64,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    output = json.loads(result.stdout)
    assert output["status"] == "rejected" and not output["activation_performed"]
    assert "private-sensitive-sentinel" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    help_result = subprocess.run(
        [sys.executable, "scripts/runner_activation.py", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert help_result.returncode == 0 and "{plan,recheck}" in help_result.stdout
    assert "apply" not in help_result.stdout
