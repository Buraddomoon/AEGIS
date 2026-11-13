"""Offline ADR0034 runner PKI; temporary files only, no native journal or Docker."""

import json
import sys
from pathlib import Path

import pytest
from aegis.lab_runner.network_profile import LEGACY_LINUX_IP, LINUX_RUNNER_IP
from aegis.lab_runner.wazuh_network_profile import LEGACY_RUNNER_IP, RUNNER_IP, RUNNER_URL

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_pki as pki


@pytest.fixture(scope="module")
def transition(tmp_path_factory):
    root = tmp_path_factory.mktemp("wazuh-runner-transition")
    source = pki.initialize(root / "source", server_ip=LEGACY_RUNNER_IP)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in source.iterdir()}
    prepared = pki.prepare(
        source,
        pki.inspect(source)["inventory_sha256"],
        root / "candidates",
        migrate_wazuh_network=True,
    )
    return source, Path(prepared["candidate_path"]), prepared["manifest_sha256"], before


def test_transition_keeps_identities_and_source_with_fixed_new_san_and_distinct_keys(transition):
    source, candidate, sha, before = transition
    manifest = json.loads((candidate / "rotation.json").read_bytes())
    old, new = manifest["source"], manifest["candidate"]
    assert manifest["format"] == pki.WAZUH_TRANSITION_FORMAT
    assert new["connection"] == {**old["connection"], "url": RUNNER_URL}
    assert b"IP Address:" + RUNNER_IP.encode() in pki.openssl(
        "x509",
        "-noout",
        "-ext",
        "subjectAltName",
        data=(candidate / "runner-server.crt").read_bytes(),
    )
    assert not {v["spki_sha256"] for v in old["certificates"].values()} & {
        v["spki_sha256"] for v in new["certificates"].values()
    }
    result = pki.verify(source, candidate, sha)
    assert result["format"] == pki.WAZUH_TRANSITION_FORMAT
    for field in (
        "activation_performed",
        "lab_started",
        "database_modified",
        "journal_opened",
        "normal_operation_permitted",
    ):
        assert result[field] is False
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in source.iterdir()} == before


@pytest.mark.parametrize("ip", [LEGACY_LINUX_IP, LINUX_RUNNER_IP, RUNNER_IP])
def test_wrong_source_cannot_enter_wazuh_transition(tmp_path, ip):
    source = pki.initialize(tmp_path / "source", server_ip=ip)
    with pytest.raises(pki.PKIError, match="legacy_wazuh_source_required"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_wazuh_network=True,
        )
    assert not (tmp_path / "candidates").exists()


@pytest.mark.parametrize("bad", [1, "true", None])
def test_transition_requires_explicit_boolean(transition, tmp_path, bad):
    source = transition[0]
    with pytest.raises(pki.PKIError, match="explicit_network_transition_required"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_wazuh_network=bad,
        )
    assert not (tmp_path / "candidates").exists()


def test_mutually_exclusive_profiles_rejected_before_generation(transition, tmp_path):
    source = transition[0]
    with pytest.raises(pki.PKIError, match="single_network_transition_required"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_linux_network=True,
            migrate_wazuh_network=True,
        )
    assert not (tmp_path / "candidates").exists()


@pytest.mark.parametrize("format", [pki.FORMAT, pki.TRANSITION_FORMAT])
def test_resealing_cannot_reinterpret_wazuh_transition_as_an_old_format(
    transition, monkeypatch, format
):
    source, candidate, _, _ = transition
    record = json.loads((candidate / "rotation.json").read_bytes())
    record["format"] = format
    read = pki.read
    monkeypatch.setattr(
        pki,
        "read",
        lambda path, **kwargs: (
            json.dumps(record).encode()
            if path == candidate / "rotation.json"
            else read(path, **kwargs)
        ),
    )
    with pytest.raises(
        pki.PKIError, match="candidate_identity_or_validity_mismatch|legacy_linux_source_required"
    ):
        pki.verify(source, candidate, pki.digest(record))


def test_cli_keeps_profiles_exclusive_without_touching_source(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "runner_pki.py",
            "prepare",
            "--source",
            "/not-opened",
            "--expected-sha256",
            "0" * 64,
            "--migrate-linux-network",
            "--migrate-wazuh-network",
        ],
    )
    monkeypatch.setattr(pki, "prepare", lambda *a, **k: pytest.fail("CLI must reject first"))
    with pytest.raises(SystemExit) as error:
        pki.main()
    assert error.value.code == 2


def test_ordinary_rotation_does_not_silently_migrate_wazuh_or_read_old_private_keys(
    transition, tmp_path, monkeypatch
):
    source = transition[0]
    read = pki.read

    def public_source_only(path, **kwargs):
        assert path.parent != source or path.name in pki.PUBLIC
        return read(path, **kwargs)

    monkeypatch.setattr(pki, "read", public_source_only)
    prepared = pki.prepare(source, pki.inspect(source)["inventory_sha256"], tmp_path / "candidates")
    candidate = Path(prepared["candidate_path"])
    assert pki.verify(source, candidate, prepared["manifest_sha256"])["format"] == pki.FORMAT
    assert (
        pki.inspect(candidate)["public"]["connection"]
        == pki.inspect(source)["public"]["connection"]
    )
