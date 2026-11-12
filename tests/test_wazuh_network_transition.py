"""Service-PKI profile transition in temporary files; no lab packages or startup."""

import json
import shutil
import sys
from pathlib import Path

import pytest
from aegis.lab_runner.wazuh_network_profile import INDEXER_IP, LEGACY_INDEXER_IP, RUNNER_IP

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_pki as pki  # noqa: E402
import wazuh_pki_rotation as rotation  # noqa: E402
from prepare_wazuh_lab import prepare as fresh_lab  # noqa: E402


@pytest.fixture(scope="module")
def transition(tmp_path_factory):
    root = tmp_path_factory.mktemp("wazuh-network-transition")
    source = fresh_lab(root / "source")
    shutil.rmtree(source / "pki")  # Only the newly created temporary fixture, never a real lab.
    pki.generate(source, indexer_ip=LEGACY_INDEXER_IP)
    env = source / "lab.env"
    env.write_text(
        env.read_text().replace(
            "WAZUH_ALLOWED_IP=" + INDEXER_IP, "WAZUH_ALLOWED_IP=" + LEGACY_INDEXER_IP
        )
    )
    (source / "internal_users.yml").write_text("_meta: {type: internalusers, config_version: 2}\n")
    (source / "internal_users.yml").chmod(0o444)
    before = {
        str(path.relative_to(source)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in source.rglob("*")
        if path.is_file()
    }
    prepared = pki.prepare(
        source,
        pki.inspect(source)["inventory_sha256"],
        root / "candidates",
        migrate_wazuh_network=True,
    )
    return source, Path(prepared["candidate_path"]), prepared["manifest_sha256"], before


def test_explicit_versioned_transition_keeps_source_and_binds_new_profile(transition):
    source, candidate, sha, before = transition
    original = pki.inspect(source)
    result = pki.verify(source, candidate, sha)
    manifest = json.loads((candidate / "rotation.json").read_text())
    assert manifest["format"] == pki.TRANSITION_FORMAT
    assert manifest["source"] == original["public"]
    assert manifest["source"]["profile"]["indexer_ip"] == LEGACY_INDEXER_IP
    assert manifest["candidate"]["profile"]["indexer_ip"] == INDEXER_IP
    assert (
        manifest["candidate"]["certificates"]["indexer.pem"]["san"]
        == "DNS:wazuh.indexer, IP Address:" + INDEXER_IP
    )
    assert result["native_blockers"] == []
    assert result["activation_performed"] is result["lab_started"] is False
    assert {
        str(path.relative_to(source)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in source.rglob("*")
        if path.is_file()
    } == before


def test_new_plan_accepts_explicit_service_transition_without_rewriting_original_env(
    transition, tmp_path
):
    source, candidate, sha, _ = transition
    prepared = rotation.prepare(source, candidate, sha, tmp_path / "plans")
    plan = Path(prepared["plan_path"])
    assert rotation.recheck(plan, prepared["plan_sha256"])["normal_operation_permitted"] is False
    assert "WAZUH_ALLOWED_IP=" + LEGACY_INDEXER_IP in (source / "lab.env").read_text()
    assert json.loads((plan / "plan.json").read_text())["format"] == rotation.FORMAT


def test_historical_candidate_is_readable_but_cannot_enter_current_rotation(transition, tmp_path):
    source = transition[0]
    prepared = pki.prepare(source, pki.inspect(source)["inventory_sha256"], tmp_path / "candidates")
    candidate = Path(prepared["candidate_path"])
    verified = pki.verify(source, candidate, prepared["manifest_sha256"])
    assert verified["format"] == pki.FORMAT
    assert verified["candidate"]["profile"]["indexer_ip"] == LEGACY_INDEXER_IP
    with pytest.raises(ValueError, match="legacy_candidate"):
        rotation.prepare(source, candidate, prepared["manifest_sha256"], tmp_path / "plans")
    assert not (tmp_path / "plans").exists()


@pytest.mark.parametrize("value", [1, "true", None])
def test_transition_requires_explicit_boolean(transition, tmp_path, value):
    source = transition[0]
    with pytest.raises(ValueError, match="explicit_legacy"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_wazuh_network=value,
        )
    assert not (tmp_path / "candidates").exists()


def test_current_profile_cannot_transition_again(transition, tmp_path):
    source = transition[1]
    with pytest.raises(ValueError, match="explicit_legacy"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_wazuh_network=True,
        )
    assert not (tmp_path / "candidates").exists()


def test_resealing_cannot_downgrade_transition_to_ordinary_renewal(transition, monkeypatch):
    source, candidate, _, _ = transition
    record = json.loads((candidate / "rotation.json").read_text())
    record["format"] = pki.FORMAT
    read = pki.fs.read
    monkeypatch.setattr(
        pki.fs,
        "read",
        lambda path, **kwargs: (
            json.dumps(record).encode()
            if path == candidate / "rotation.json"
            else read(path, **kwargs)
        ),
    )
    with pytest.raises(ValueError, match="profile_drift"):
        pki.verify(source, candidate, pki.digest(record))


def test_full_startup_gate_rejects_historical_service_san(transition, monkeypatch):
    import wazuh_lab

    monkeypatch.setattr(wazuh_lab, "PRIVATE", transition[0])
    with pytest.raises(ValueError, match="histórica"):
        wazuh_lab.certificates_gate()


def test_initializer_new_wazuh_runner_is_exact_and_keeps_other_profiles_closed(tmp_path):
    runner = pki.fs.initialize(tmp_path / "runner", server_ip=RUNNER_IP)
    assert (
        json.loads((runner / "connection.json").read_text())["url"]
        == "https://" + RUNNER_IP + ":8443"
    )
    for address in ("192.168.253.11", "192.168.253.18", "127.0.0.1"):
        with pytest.raises(ValueError):
            pki.fs.initialize(tmp_path / "unreviewed", server_ip=address)
    assert not (tmp_path / "unreviewed").exists()


def test_real_render_of_legacy_source_uses_new_network_and_candidate_without_editing_source(
    transition, tmp_path
):
    from test_wazuh_pki_rotation import render

    source, candidate, sha, before = transition
    prepared = rotation.prepare(source, candidate, sha, tmp_path / "plans")
    plan = Path(prepared["plan_path"])
    original, changed = render(source), render(source, plan / "compose.pki.json")
    rotation.validate_rendered(original, changed, candidate)
    for name in ("api", "worker"):
        assert changed["services"][name]["environment"]["WAZUH_ALLOWED_IP"] == INDEXER_IP
    assert {
        str(path.relative_to(source)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in source.rglob("*")
        if path.is_file()
    } == before
