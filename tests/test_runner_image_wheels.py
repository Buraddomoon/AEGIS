"""Fixed pip cache contract and bounded local fixture children; no package downloads."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_runner_activation_image_source import git
from test_runner_activation_image_source import repository as repository

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_image_wheels as wheels  # noqa: E402

PAYLOAD = b"synthetic wheel fixture; no executable package"
HASH = hashlib.sha256(PAYLOAD).hexdigest()
RUNTIME = ("fiction-runtime==1.0 --hash=sha256:" + HASH + "\n").encode()
TOOLS = ("fiction-builder==2.0 --hash=sha256:" + HASH + "\n").encode()


def fake_download(folder):
    (folder / "download.log").write_bytes(b"synthetic downloader, never pip")
    (folder / "download.log").chmod(0o600)
    for name in ("fiction_runtime-1.0-py3-none-any.whl", "fiction_builder-2.0-py3-none-any.whl"):
        path = folder / "wheels" / name
        path.write_bytes(PAYLOAD)
        path.chmod(0o600)


def prepare(tmp_path, monkeypatch):
    monkeypatch.setattr(wheels, "download", fake_download)
    return wheels.prepare(RUNTIME, TOOLS, "a" * 64, root=tmp_path / "cache")


def test_cache_verifies_exact_locked_hashes_and_never_claims_package_install_or_image_build(
    tmp_path, monkeypatch
):
    report = prepare(tmp_path, monkeypatch)
    receipt = wheels.verify(Path(report["folder"]), report["receipt_sha256"])
    assert receipt["wheel_hashes_verified"] and report["wheels_verified"] == 2
    assert report["wheel_bytes"] == 2 * len(PAYLOAD)
    assert all(report[key] is False for key in wheels.FLAGS)
    assert all(item["sha256"] == HASH for item in receipt["wheels"].values())


@pytest.mark.parametrize(
    "scene",
    [
        "wrong_hash",
        "edited",
        "symlink",
        "hardlink",
        "mode",
        "extra_file",
        "extra_wheel",
        "lock_changed",
        "flag",
    ],
)
def test_altered_cache_or_extra_context_is_refused_without_repair(tmp_path, monkeypatch, scene):
    report = prepare(tmp_path, monkeypatch)
    folder, expected = Path(report["folder"]), report["receipt_sha256"]
    file = folder / "wheels" / "fiction_runtime-1.0-py3-none-any.whl"
    if scene == "wrong_hash":
        expected = "f" * 64
    elif scene == "edited":
        file.write_bytes(b"private-sensitive-sentinel")
    elif scene == "symlink":
        outside = tmp_path / "outside"
        file.rename(outside)
        file.symlink_to(outside)
    elif scene == "hardlink":
        os.link(file, tmp_path / "second-link")
    elif scene == "mode":
        file.chmod(0o644)
    elif scene == "extra_file":
        (folder / ".env").write_bytes(b"private-sensitive-sentinel")
    elif scene == "extra_wheel":
        (folder / "wheels" / "other.whl").write_bytes(PAYLOAD)
    elif scene == "lock_changed":
        (folder / "build.lock").write_bytes(RUNTIME)
    else:
        document = json.loads((folder / "receipt.json").read_bytes())
        document["packages_installed"] = True
        (folder / "receipt.json").write_text(json.dumps(document))
    with pytest.raises(wheels.ActivationError, match="verification_failed") as caught:
        wheels.verify(folder, expected)
    assert "private-sensitive-sentinel" not in str(caught.value)


def test_failed_download_preserves_partial_artifacts_without_receipt(tmp_path, monkeypatch):
    def fail(folder):
        fake_download(folder)
        raise OSError("private-sensitive-sentinel")

    monkeypatch.setattr(wheels, "download", fail)
    with pytest.raises(wheels.ActivationError, match="preparation_unconfirmed"):
        wheels.prepare(RUNTIME, TOOLS, "a" * 64, root=tmp_path / "cache")
    assert list((tmp_path / "cache").glob("*/plan.json"))
    assert not list((tmp_path / "cache").glob("*/receipt.json"))


def test_requirement_profiles_cannot_overlap_or_add_unhashed_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(wheels, "download", lambda *a: pytest.fail("No download allowed"))
    with pytest.raises(wheels.ActivationError, match="profiles_overlap"):
        wheels.prepare(RUNTIME, RUNTIME, "a" * 64, root=tmp_path / "cache")
    with pytest.raises(ValueError):
        wheels.prepare(
            b"--index-url https://untrusted.invalid", TOOLS, "a" * 64, root=tmp_path / "cache"
        )
    assert not (tmp_path / "cache").exists()


def test_pip_command_has_fixed_source_wheels_hashes_and_no_install(tmp_path):
    args = wheels.command(tmp_path)
    assert args[:4] == (sys.executable, "-I", "-m", "pip")
    assert "download" in args and "install" not in args
    assert args[args.index("--index-url") + 1] == "https://pypi.org/simple"
    assert all(
        flag in args
        for flag in (
            "--isolated",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--require-hashes",
            "--no-deps",
        )
    )
    assert args[args.index("--keyring-provider") + 1] == "disabled"
    assert wheels.ENV == {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "PIP_CONFIG_FILE": "/dev/null",
        "NETRC": "/dev/null",
    }


@pytest.mark.parametrize("scene", ["success", "nonzero", "overflow", "deadline"])
def test_downloader_bounds_a_real_local_child_and_reaps_it_without_network(
    tmp_path, monkeypatch, scene
):
    folder = tmp_path / "download"
    folder.mkdir(mode=0o700)
    code = "print('fixture output')"
    if scene == "nonzero":
        code += ";raise SystemExit(1)"
    elif scene == "overflow":
        code = "import os;os.write(1,b'x'*4096)"
    elif scene == "deadline":
        code = "import time;time.sleep(30)"
    monkeypatch.setattr(wheels, "command", lambda _: (sys.executable, "-I", "-B", "-c", code))
    processes = []
    original = subprocess.Popen

    def spawn(*args, **kwargs):
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["env"] == wheels.ENV and kwargs["umask"] == 0o077
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(wheels.subprocess, "Popen", spawn)
    if scene == "overflow":
        monkeypatch.setattr(wheels, "MAX_LOG", 1024)
    elif scene == "deadline":
        ticks = iter([0.0, 121.0])
        monkeypatch.setattr(wheels, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    if scene == "success":
        wheels.download(folder)
    else:
        with pytest.raises(wheels.ActivationError):
            wheels.download(folder)
    assert len(processes) == 1 and processes[0].poll() is not None
    assert processes[0].stdout.closed
    assert (folder / "download.log").stat().st_size <= wheels.MAX_LOG


def test_import_has_no_pip_subprocess_or_network_effect():
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
sys.addaudithook(guard)
import runner_image_wheels
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_host_cli_binds_verified_source_and_committed_tools_without_install_or_arbitrary_url(
    repository, tmp_path, monkeypatch, capsys
):
    repo = repository
    (repo / "requirements.lock").write_bytes(RUNTIME)
    (repo / "requirements-image-build.lock").write_bytes(TOOLS)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test: add synthetic pinned wheel inputs")
    exported = wheels.source.prepare(repo=repo, output_root=tmp_path / "sources")
    monkeypatch.setattr(wheels.source, "DEFAULT_OUTPUT", tmp_path / "sources")
    monkeypatch.setattr(wheels.source, "ROOT", repo)
    monkeypatch.setattr(wheels, "ROOT", tmp_path / "cache")
    monkeypatch.setattr(wheels, "download", fake_download)
    assert (
        wheels.main(
            [
                "prepare",
                "--source-id",
                Path(exported["folder"]).name,
                "--expected-sha256",
                exported["source_sha256"],
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["source_sha256"] == exported["source_sha256"]
    assert (
        wheels.main(
            [
                "verify",
                "--cache-id",
                Path(report["folder"]).name,
                "--expected-sha256",
                report["receipt_sha256"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["wheels_verified"] == 2
    assert (repo / ".env").read_text() == "private-sensitive-sentinel"


@pytest.mark.parametrize("identifier", ["../outside", "A" * 32, "invalid"])
def test_cli_rejects_free_paths_before_any_download(identifier, monkeypatch, capsys):
    monkeypatch.setattr(wheels, "download", lambda *a: pytest.fail("No download permitted"))
    assert wheels.main(["prepare", "--source-id", identifier, "--expected-sha256", "a" * 64]) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "wheel_cache_operation_rejected"
