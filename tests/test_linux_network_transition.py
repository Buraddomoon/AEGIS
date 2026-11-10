"""Offline transition with temporary PKI only; never start Docker or a lab."""

import json
import sys
from pathlib import Path

import pytest
from aegis.lab_runner.network_profile import LEGACY_LINUX_IP, LINUX_RUNNER_IP, LINUX_URL

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_pki as pki


@pytest.fixture(scope="module")
def transition(tmp_path_factory):
    root = tmp_path_factory.mktemp("linux-network-transition")
    source = pki.initialize(root / "source", server_ip=LEGACY_LINUX_IP)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in source.iterdir()}
    prepared = pki.prepare(
        source,
        pki.inspect(source)["inventory_sha256"],
        root / "candidates",
        migrate_linux_network=True,
    )
    return source, Path(prepared["candidate_path"]), prepared["manifest_sha256"], before


def test_explicit_transition_preserves_identity_and_original_bytes_with_new_san(transition):
    source, candidate, sha, before = transition
    manifest = json.loads((candidate / "rotation.json").read_bytes())
    assert manifest["format"] == pki.TRANSITION_FORMAT
    old, new = manifest["source"], manifest["candidate"]
    assert new["connection"] == {**old["connection"], "url": LINUX_URL}
    assert pki.verify(source, candidate, sha)["format"] == pki.TRANSITION_FORMAT
    assert b"IP Address:" + LINUX_RUNNER_IP.encode() in pki.openssl(
        "x509",
        "-noout",
        "-ext",
        "subjectAltName",
        data=(candidate / "runner-server.crt").read_bytes(),
    )
    old_keys = {v["spki_sha256"] for v in old["certificates"].values()}
    assert not old_keys & {v["spki_sha256"] for v in new["certificates"].values()}
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in source.iterdir()} == before


def test_ordinary_rotation_keeps_old_endpoint_unless_transition_explicit(transition, tmp_path):
    source = transition[0]
    result = pki.prepare(source, pki.inspect(source)["inventory_sha256"], tmp_path / "candidates")
    candidate = Path(result["candidate_path"])
    assert (
        pki.inspect(candidate)["public"]["connection"]
        == pki.inspect(source)["public"]["connection"]
    )
    assert pki.verify(source, candidate, result["manifest_sha256"])["format"] == pki.FORMAT


@pytest.mark.parametrize("ip", [LINUX_RUNNER_IP, "172.30.89.2"])
def test_transition_refuses_nonlegacy_source_before_creating_output(tmp_path, ip):
    source = pki.initialize(tmp_path / "source", server_ip=ip)
    with pytest.raises(pki.PKIError, match="legacy_linux_source_required"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_linux_network=True,
        )
    assert not (tmp_path / "candidates").exists()


@pytest.mark.parametrize("bad", [1, "true", None])
def test_transition_option_is_strictly_boolean(transition, tmp_path, bad):
    source = transition[0]
    with pytest.raises(pki.PKIError, match="explicit_network_transition_required"):
        pki.prepare(
            source,
            pki.inspect(source)["inventory_sha256"],
            tmp_path / "candidates",
            migrate_linux_network=bad,
        )
    assert not (tmp_path / "candidates").exists()


def test_resealed_transition_cannot_be_downgraded_to_ordinary_rotation(transition, monkeypatch):
    source, candidate, _, _ = transition
    record = json.loads((candidate / "rotation.json").read_bytes())
    record["format"] = pki.FORMAT
    original = pki.read

    def read(path, **kwargs):
        return (
            json.dumps(record).encode()
            if path == candidate / "rotation.json"
            else original(path, **kwargs)
        )

    monkeypatch.setattr(pki, "read", read)
    with pytest.raises(pki.PKIError, match="candidate_identity_or_validity_mismatch"):
        pki.verify(source, candidate, pki.digest(record))


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.253.4", "192.168.253.2:8443"])
def test_initializer_rejects_unreviewed_targets_before_creating_files(tmp_path, ip):
    with pytest.raises(ValueError, match="perfis de laboratório revisados"):
        pki.initialize(tmp_path / "source", server_ip=ip)
    assert not (tmp_path / "source").exists()
