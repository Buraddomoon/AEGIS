"""Fixed HBA policy only in private temporary folders; no DB, network or Docker."""

import os
import stat
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_database_policy as policy  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


@pytest.fixture
def store(tmp_path):
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(uuid4().hex, "a" * 64, "b" * 64)
        yield store


def test_policy_is_exclusive_nonsecret_file_in_private_operation_folder_without_database_access(
    store, tmp_path
):
    root = tmp_path / "runtime"
    report = policy.prepare(store, root=root)
    path = Path(report["path"])
    assert path == root / store.summary()["id"] / policy.FILENAME
    assert path.read_bytes() == policy.CONTENT
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert stat.S_IMODE(path.parent.stat().st_mode) == stat.S_IMODE(root.stat().st_mode) == 0o700
    assert report["fixed_policy_verified"]
    assert all(
        report[key] is False
        for key in (
            "original_hba_modified",
            "database_credentials_changed",
            "runtime_mount_verified",
            "authentication_verified",
            "effects_authorized",
            "normal_operation_permitted",
        )
    )
    lines = [
        line.split() for line in policy.CONTENT.decode().splitlines() if not line.startswith("#")
    ]
    assert [line for line in lines if line[-1] != "reject"] == [
        ["host", "aegis", "aegis_app", "127.0.0.1/32", "scram-sha-256"],
    ]
    assert not any(
        word in {"trust", "peer", "include", "include_dir", "md5", "password"}
        for line in lines
        for word in line
    )
    before = path.read_bytes()
    with pytest.raises(policy.ActivationError, match="preparation_unconfirmed"):
        policy.prepare(store, root=root)
    assert path.read_bytes() == before
    assert len(list(store.folder.iterdir())) == 1


@pytest.mark.parametrize(
    "scene", ["mode", "edited", "symlink", "hardlink", "parent_mode", "parent_symlink", "missing"]
)
def test_verification_refuses_changed_or_unsafe_policy_without_repair(store, tmp_path, scene):
    root = tmp_path / "runtime"
    path = Path(policy.prepare(store, root=root)["path"])
    if scene == "mode":
        path.chmod(0o644)
    elif scene == "edited":
        path.chmod(0o600)
        path.write_bytes(b"host all all all trust\n")
        path.chmod(0o444)
    elif scene == "symlink":
        target = tmp_path / "external"
        path.rename(target)
        path.symlink_to(target)
    elif scene == "hardlink":
        os.link(path, tmp_path / "other-name")
    elif scene == "parent_mode":
        path.parent.chmod(0o755)
    elif scene == "parent_symlink":
        moved = tmp_path / "moved"
        path.parent.rename(moved)
        path.parent.symlink_to(moved)
    else:
        path.unlink()
    with pytest.raises((ValueError, OSError)):
        policy.verify(store, root=root)
    if scene == "edited":
        assert path.read_bytes() == b"host all all all trust\n"


def test_closed_operation_cannot_prepare_another_runtime_policy(store, tmp_path):
    store.append("closed", {"evidence_sha256": "f" * 64})
    with pytest.raises(policy.ActivationError, match="open_operation_required"):
        policy.prepare(store, root=tmp_path / "runtime")
    assert not (tmp_path / "runtime").exists()


def test_file_fsync_failure_does_not_remove_or_overwrite_uncertain_artifact(
    store, tmp_path, monkeypatch
):
    fsync = os.fsync

    def fail(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("private-sensitive-sentinel")
        return fsync(fd)

    monkeypatch.setattr(os, "fsync", fail)
    root = tmp_path / "runtime"
    with pytest.raises(policy.ActivationError, match="preparation_unconfirmed") as caught:
        policy.prepare(store, root=root)
    assert "private-sensitive-sentinel" not in str(caught.value)
    path = root / store.summary()["id"] / policy.FILENAME
    assert path.read_bytes() == policy.CONTENT


def test_import_never_reads_original_hba_or_connects():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('effect forbidden')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.conf')):
        raise AssertionError('configuration forbidden')
sys.addaudithook(guard)
import runner_activation_database_policy
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
