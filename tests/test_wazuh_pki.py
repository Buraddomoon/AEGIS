import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_pki as pki  # noqa: E402
from prepare_wazuh_lab import prepare as fresh_lab  # noqa: E402


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    return fresh_lab(tmp_path_factory.mktemp("wazuh-pki-source") / "source")


@pytest.fixture(scope="module")
def staged(source, tmp_path_factory):
    prepared = pki.prepare(
        source,
        pki.inspect(source)["inventory_sha256"],
        tmp_path_factory.mktemp("wazuh-candidates") / "candidates",
    )
    return Path(prepared["candidate_path"]), prepared["manifest_sha256"]


def copy_candidate(staged, tmp_path):
    target = tmp_path / staged[0].name
    shutil.copytree(staged[0], target)
    return target


def test_source_public_inventory_and_candidate_preserve_every_original_file(source, staged):
    before = {
        str(path.relative_to(source)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in source.rglob("*")
        if path.is_file()
    }
    public = pki.inspect(source)
    verified = pki.verify(source, *staged)
    assert public["source_private_keys_read"] is False
    assert all(public["valid_now"].values())
    assert verified["status"] == "offline_candidate_verified_not_activated"
    assert verified["lab_started"] is verified["activation_performed"] is False
    assert verified["native_blockers"] == [149]
    assert "not-x509" in public["public"]["profile"]["agent_transport"]
    assert {
        str(path.relative_to(source)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in source.rglob("*")
        if path.is_file()
    } == before
    assert not {item["spki_sha256"] for item in public["public"]["certificates"].values()} & {
        item["spki_sha256"] for item in verified["candidate"]["certificates"].values()
    }
    assert set(staged[0].iterdir()) == {staged[0] / "pki", staged[0] / "rotation.json"}
    assert stat.S_IMODE((staged[0] / "pki/ca-key.pem").stat().st_mode) == 0o600


def test_inventory_and_prepare_work_without_any_source_private_keys(source, tmp_path):
    public = tmp_path / "source"
    (public / "pki").mkdir(parents=True, mode=0o700)
    public.chmod(0o700)
    for name in pki.PUBLIC:
        shutil.copy2(source / "pki" / name, public / "pki" / name)
    inventory = pki.inspect(public)
    result = pki.prepare(public, inventory["inventory_sha256"], tmp_path / "candidates")
    assert (
        pki.verify(public, Path(result["candidate_path"]), result["manifest_sha256"])["lab_started"]
        is False
    )


def test_source_inventory_drift_rejected_before_writing(source, tmp_path):
    with pytest.raises(ValueError, match="source_inventory_drift"):
        pki.prepare(source, "0" * 64, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "relative", ["pki/indexer-key.pem", "pki/filebeat-key.pem", "pki/ca-key.pem"]
)
def test_mismatched_candidate_key_is_rejected(source, staged, tmp_path, relative):
    target = copy_candidate(staged, tmp_path)
    file = target / relative
    mode = stat.S_IMODE(file.stat().st_mode)
    file.chmod(0o600)
    file.write_bytes(
        (
            staged[0] / "pki/filebeat-key.pem"
            if "filebeat" not in relative
            else staged[0] / "pki/indexer-key.pem"
        ).read_bytes()
    )
    file.chmod(mode)
    with pytest.raises(ValueError, match="key_pair_mismatch"):
        pki.verify(source, target, staged[1])


@pytest.mark.parametrize(
    "kind", ["symlink", "hardlink", "fifo", "mode", "extra", "mixed-trust", "bundle", "manifest"]
)
def test_unsafe_or_changed_artifacts_fail_closed(source, staged, tmp_path, kind):
    target = copy_candidate(staged, tmp_path)
    file = target / "pki/indexer.pem"
    if kind == "mode":
        file.chmod(0o666)
    elif kind == "extra":
        (target / "pki/unreviewed.pem").write_text("unexpected")
    elif kind in {"symlink", "hardlink", "fifo"}:
        file.unlink()
        if kind == "symlink":
            file.symlink_to(staged[0] / "pki/indexer.pem")
        elif kind == "hardlink":
            sibling = tmp_path / "shared.pem"
            shutil.copy2(staged[0] / "pki/indexer.pem", sibling)
            os.link(sibling, file)
        else:
            os.mkfifo(file)
    elif kind == "manifest":
        (target / "rotation.json").write_text("{}")
    else:
        file = target / ("pki/root-ca.pem" if kind == "mixed-trust" else "pki/indexer.pem")
        file.chmod(0o600)
        file.write_bytes(
            (source / "pki/root-ca.pem").read_bytes()
            if kind == "mixed-trust"
            else file.read_bytes() * 2
        )
        file.chmod(0o444)
    with pytest.raises((OSError, ValueError)):
        pki.verify(source, target, staged[1])


def test_expired_source_can_be_inventoried_but_candidate_is_not_accepted(
    source, staged, monkeypatch
):
    monkeypatch.setattr(
        pki.fs,
        "clock",
        lambda: datetime.now(UTC) + timedelta(days=3),
    )
    assert not all(pki.inspect(source)["valid_now"].values())
    with pytest.raises(ValueError):
        pki.verify(source, *staged)


def test_candidate_short_remaining_lifetime_rejected(source, staged, monkeypatch):
    instant = pki.fs.clock() + timedelta(hours=25)
    monkeypatch.setattr(pki.fs, "clock", lambda: instant)
    with pytest.raises(ValueError, match="lifetime"):
        pki.verify(source, *staged)


def test_source_and_repository_drift_fail_closed(source, staged, tmp_path, monkeypatch):
    other = tmp_path / "source"
    shutil.copytree(source, other)
    certificate = other / "pki/indexer.pem"
    certificate.chmod(0o600)
    certificate.write_bytes((staged[0] / "pki/indexer.pem").read_bytes())
    certificate.chmod(0o444)
    with pytest.raises(ValueError):
        pki.verify(other, *staged)
    read = pki.fs.read
    monkeypatch.setattr(
        pki.fs,
        "read",
        lambda path, **kwargs: (
            read(path, **kwargs)
            + (b"\n" if path == pki.ROOT / "labs/wazuh/config/indexer.yml" else b"")
        ),
    )
    with pytest.raises(ValueError, match="unreviewed_wazuh_profile"):
        pki.inspect(source)


@pytest.mark.parametrize("location", ["source", "source/inside", "."])
def test_candidates_never_overlap_source(source, tmp_path, location):
    target_source = tmp_path / "source"
    shutil.copytree(source, target_source)
    with pytest.raises(ValueError, match="separate"):
        pki.prepare(
            target_source, pki.inspect(target_source)["inventory_sha256"], tmp_path / location
        )


@pytest.mark.parametrize(
    "name,role", [("indexer.pem", "filebeat.pem"), ("filebeat.pem", "indexer.pem")]
)
def test_wrong_dn_or_purpose_is_rejected(source, name, role):
    with pytest.raises(ValueError, match="dn_mismatch"):
        pki.certificate((source / "pki" / name).read_bytes(), role)


def test_cli_redacts_private_paths_and_bad_pem(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(pki.ROOT / "scripts/wazuh_pki.py"),
            "inspect",
            "--source",
            str(tmp_path / "private-path-should-not-leak"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert "private-path-should-not-leak" not in result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "rejected"


def test_new_process_inspection_never_opens_source_private_artifacts_or_network(source):
    program = """
import sys, pathlib, socket
sys.path.insert(0, "scripts")
import wazuh_pki as p
source = pathlib.Path(sys.argv[1])
allowed = {str(source / "pki" / name) for name in p.PUBLIC}
def audit(event, args):
    if event == "open" and isinstance(args[0], str) and args[0].startswith(str(source)) and args[0] not in allowed:
        raise RuntimeError("source-private-read")
    if event.startswith("socket."):
        raise RuntimeError("network-forbidden")
sys.addaudithook(audit)
assert p.inspect(source)["source_private_keys_read"] is False
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(source)], cwd=pki.ROOT, capture_output=True, timeout=15
    )
    assert result.returncode == 0, result.stderr


def test_actual_certificate_with_wrong_san_is_rejected(tmp_path):
    certificate = tmp_path / "wrong-san.pem"
    pki.fs.openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(tmp_path / "key.pem"),
        "-out",
        str(certificate),
        "-days",
        "2",
        "-subj",
        "/CN=wazuh.indexer/OU=AEGIS/O=AEGIS Lab",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext",
        "extendedKeyUsage=serverAuth,clientAuth",
        "-addext",
        "subjectAltName=DNS:unreviewed.example,IP:172.30.90.2",
    )
    with pytest.raises(ValueError, match="san_mismatch"):
        pki.certificate(certificate.read_bytes(), "indexer.pem")


def test_fsync_failure_never_publishes_completion_marker(source, tmp_path, monkeypatch):
    before = pki.inspect(source)["inventory_sha256"]

    def fail(path):
        raise OSError("fixture-fsync-failed")

    output = tmp_path / "candidates"
    output.mkdir(mode=0o700)
    monkeypatch.setattr(pki.fs, "sync", fail)
    with pytest.raises(OSError):
        pki.prepare(source, before, output)
    assert not list(output.glob("*/rotation.json"))
    assert pki.inspect(source)["inventory_sha256"] == before
