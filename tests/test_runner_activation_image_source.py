"""Disposable local Git main repositories and private source artifacts; no Docker."""

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from aegis.domain.validation import digest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_image_source as source  # noqa: E402


def git(repo, *args):
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "user.name=AEGIS fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=repo,
        env=source.GIT_ENV,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return result.stdout


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir(mode=0o700)
    git(repo, "init", "-b", "main")
    for name in source.REQUIRED:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Synthetic source fixture, not an executable build\n")
    (repo / ".gitignore").write_text(".env\nignored.key\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test: create synthetic source fixture")
    (repo / ".env").write_text("private-sensitive-sentinel")
    (repo / "ignored.key").write_text("private-sensitive-sentinel")
    return repo


def prepare(repository, tmp_path):
    return source.prepare(repo=repository, output_root=tmp_path / "output")


def test_committed_source_exports_only_allowlisted_blobs_with_deterministic_private_context(
    repository, tmp_path
):
    original = git(repository, "rev-parse", "HEAD").decode().strip()
    report = prepare(repository, tmp_path)
    folder = Path(report["folder"])
    document = source.verify(folder, report["source_sha256"])
    assert document["source_commit"] == original == report["source_commit"]
    assert set(document["files"]) == source.REQUIRED
    assert report["files_exported"] == len(source.REQUIRED)
    assert all(report[key] is False for key in source.FLAGS)
    assert (
        stat.S_IMODE(folder.stat().st_mode) == stat.S_IMODE(folder.parent.stat().st_mode) == 0o700
    )
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in folder.iterdir())
    raw = (folder / "context.tar").read_bytes()
    assert b"private-sensitive-sentinel" not in raw
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        assert set(archive.getnames()) == source.REQUIRED
        assert all(member.type == tarfile.REGTYPE for member in archive.getmembers())
    second = prepare(repository, tmp_path)
    assert Path(second["folder"]) != folder
    assert (Path(second["folder"]) / "context.tar").read_bytes() == raw
    assert second["source_sha256"] == report["source_sha256"]
    assert (repository / ".env").read_text() == "private-sensitive-sentinel"
    assert git(repository, "status", "--porcelain") == b""


@pytest.mark.parametrize("scene", ["dirty", "staged", "untracked", "detached"])
def test_dirty_or_unpinned_source_is_refused_without_building_or_overwriting(
    repository, tmp_path, scene
):
    if scene == "untracked":
        (repository / "untracked.py").write_text("# new\n")
    elif scene == "detached":
        git(repository, "checkout", "--detach")
    else:
        (repository / "requirements.lock").write_text("changed\n")
        if scene == "staged":
            git(repository, "add", "requirements.lock")
    with pytest.raises(source.ActivationError):
        prepare(repository, tmp_path)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("scene", ["symlink", "executable", "hidden", "missing"])
def test_unexpected_tracked_source_types_or_paths_never_enter_context(repository, tmp_path, scene):
    if scene == "missing":
        (repository / "requirements.lock").unlink()
        git(repository, "add", "-u")
    elif scene == "symlink":
        (repository / source.PACKAGE / "external.py").symlink_to(repository / ".env")
    elif scene == "executable":
        (repository / source.PACKAGE / "models.py").chmod(0o755)
    else:
        (repository / source.PACKAGE / ".env.py").write_text("private-sensitive-sentinel")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "test: incompatible source fixture")
    with pytest.raises(source.ActivationError):
        prepare(repository, tmp_path)
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "scene", ["wrong_hash", "manifest", "context", "symlink", "mode", "hardlink"]
)
def test_untrusted_or_changed_artifacts_cannot_be_verified(repository, tmp_path, scene):
    report = prepare(repository, tmp_path)
    folder = Path(report["folder"])
    expected = report["source_sha256"]
    file = folder / "context.tar"
    if scene == "wrong_hash":
        expected = "f" * 64
    elif scene == "manifest":
        (folder / "source.json").write_text("{}")
    elif scene == "context":
        file.write_bytes(b"private-sensitive-sentinel")
    elif scene == "mode":
        file.chmod(0o644)
    elif scene == "hardlink":
        os.link(file, tmp_path / "extra-link")
    else:
        target = tmp_path / "external-context"
        file.rename(target)
        file.symlink_to(target)
    with pytest.raises(source.ActivationError, match="verification_failed"):
        source.verify(folder, expected)


def test_oversized_source_blob_refused_before_reading_blob_data(repository, tmp_path, monkeypatch):
    original = source._git
    reads = []

    def query(repo, *args, **kwargs):
        if args[0] == "ls-tree":
            return b"100644 blob " + b"a" * 40 + b" 1048577\tapps/api/aegis/models.py\0"
        if args[0] == "cat-file":
            reads.append(args)
        return original(repo, *args, **kwargs)

    monkeypatch.setattr(source, "_git", query)
    with pytest.raises(source.ActivationError, match="tree_invalid"):
        prepare(repository, tmp_path)
    assert reads == []


def test_commit_change_during_export_never_publishes_success(repository, tmp_path, monkeypatch):
    original = source._state
    calls = 0

    def changed(repo):
        nonlocal calls
        calls += 1
        return original(repo) if calls == 1 else "f" * 40

    monkeypatch.setattr(source, "_state", changed)
    with pytest.raises(source.ActivationError, match="changed_during_export"):
        prepare(repository, tmp_path)
    assert not (tmp_path / "output").exists()


def test_fsync_failure_preserves_uncertain_artifact_without_success(
    repository, tmp_path, monkeypatch
):
    fsync = os.fsync

    def fail(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("private-sensitive-sentinel")
        return fsync(fd)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(source.ActivationError, match="export_unconfirmed") as caught:
        prepare(repository, tmp_path)
    assert "private-sensitive-sentinel" not in str(caught.value)
    assert list((tmp_path / "output").glob("*/context.tar"))


def test_archive_rejects_special_members_even_with_a_self_consistent_hash(repository, tmp_path):
    report = prepare(repository, tmp_path)
    folder = Path(report["folder"])
    document = source.verify(folder, report["source_sha256"])
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("apps/api/aegis/models.py")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../.env"
        archive.addfile(member)
    context = buffer.getvalue()
    (folder / "context.tar").write_bytes(context)
    document["context_sha256"] = hashlib.sha256(context).hexdigest()
    document["context_bytes"] = len(context)
    (folder / "source.json").write_text(json.dumps(document))
    with pytest.raises(source.ActivationError, match="verification_failed"):
        source.verify(folder, digest(document))


def test_import_never_invokes_git_docker_network_or_environment_configuration():
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
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('secret forbidden')
sys.addaudithook(guard)
import runner_activation_image_source
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_host_cli_prepares_and_verifies_only_fixed_root_without_build_effects(
    repository, tmp_path, monkeypatch, capsys
):
    original = source.prepare
    monkeypatch.setattr(
        source, "prepare", lambda: original(repo=repository, output_root=tmp_path / "output")
    )
    monkeypatch.setattr(source, "DEFAULT_OUTPUT", tmp_path / "output")
    assert source.main(["prepare"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert (
        source.main(
            [
                "verify",
                "--source-id",
                Path(report["folder"]).name,
                "--expected-sha256",
                report["source_sha256"],
            ]
        )
        == 0
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["source_sha256"] == report["source_sha256"]
    assert all(verified[key] is False for key in source.FLAGS)
    assert "private-sensitive-sentinel" not in json.dumps(verified)


@pytest.mark.parametrize("identifier", ["../external", "A" * 32, "not-a-uuid"])
def test_cli_rejects_free_artifact_paths_before_file_read(identifier, monkeypatch, capsys):
    monkeypatch.setattr(source, "verify", lambda *a: pytest.fail("No file read allowed"))
    assert source.main(["verify", "--source-id", identifier, "--expected-sha256", "a" * 64]) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "runner_source_operation_rejected"
