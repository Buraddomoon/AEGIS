"""Installed-source checker against temporary package trees, never a real image."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_image_assert as image  # noqa: E402


@pytest.fixture
def package(tmp_path):
    root = tmp_path / "aegis"
    root.mkdir()
    content = b"# synthetic source fixture\n"
    (root / "__init__.py").write_bytes(content)
    expected = {
        "format": "aegis-runner-image-package/1",
        "source_sha256": "a" * 64,
        "source_commit": "b" * 40,
        "project_version": "0.2.0",
        "package_files": {
            "__init__.py": {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        },
    }
    runtime = b"some-runtime==1.2.3 --hash=sha256:" + b"c" * 64 + b"\n"
    tools = b"some-builder==4.5.6 --hash=sha256:" + b"d" * 64 + b"\n"
    versions = {"some-runtime": "1.2.3", "some-builder": "4.5.6", "aegis-purple": "0.2.0"}
    return root, expected, runtime, tools, versions


def check(package):
    root, expected, runtime, tools, versions = package
    return image.check(expected, root, runtime, tools, version=versions.__getitem__)


def test_installed_source_and_all_versions_are_verified_without_provenance_or_lab_claim(package):
    result = check(package)
    assert result["installed_source_verified"] and result["installed_versions_verified"]
    assert (
        result["package_files_verified"]
        == result["runtime_versions_verified"]
        == result["build_versions_verified"]
        == 1
    )
    assert (
        result["probe_imports_verified"]
        is result["image_provenance_verified"]
        is result["lab_started"]
        is result["effects_authorized"]
        is False
    )
    assert "package_files" not in result


@pytest.mark.parametrize(
    "scene",
    [
        "changed",
        "missing",
        "extra",
        "pyc",
        "symlink",
        "directory_symlink",
        "hardlink",
        "runtime_version",
        "build_version",
        "project_version",
        "overlap",
    ],
)
def test_stale_hidden_or_modified_installed_code_cannot_match_context(package, tmp_path, scene):
    root, _, _, _, versions = package
    if scene == "changed":
        (root / "__init__.py").write_text("private-sensitive-sentinel")
    elif scene == "missing":
        (root / "__init__.py").unlink()
    elif scene == "extra":
        (root / "stale.py").write_text("# stale code\n")
    elif scene == "pyc":
        (root / "stale.pyc").write_bytes(b"compiled-code")
    elif scene == "symlink":
        (root / "__init__.py").rename(tmp_path / "outside")
        (root / "__init__.py").symlink_to(tmp_path / "outside")
    elif scene == "directory_symlink":
        (root / "hidden").symlink_to(tmp_path)
    elif scene == "hardlink":
        os.link(root / "__init__.py", tmp_path / "second")
    elif scene == "runtime_version":
        versions["some-runtime"] = "0.0.0"
    elif scene == "build_version":
        versions["some-builder"] = "0.0.0"
    elif scene == "project_version":
        versions["aegis-purple"] = "0.1.0"
    else:
        root, expected, runtime, _, versions = package
        package = (root, expected, runtime, runtime, versions)
    with pytest.raises(image.ImageCheckError) as caught:
        check(package)
    assert "private-sensitive-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "content",
    [
        b"name>=1",
        b"--index-url https://untrusted.invalid",
        b"name==1 --hash=sha256:invalid",
        b"",
        b"x" * 65537,
    ],
)
def test_only_hashed_exact_requirement_lines_are_accepted(content):
    with pytest.raises(image.ImageCheckError):
        image.requirements(content)


def test_requirements_normalize_distribution_names_and_reject_duplicates():
    line = b"Some_Package==1.2.3 --hash=sha256:" + b"a" * 64 + b"\n"
    assert image.requirements(b"# reviewed lock\n" + line) == {"some-package": "1.2.3"}
    with pytest.raises(image.ImageCheckError):
        image.requirements(line + line)


@pytest.mark.parametrize(
    "scene", ["traversal", "absolute", "bool_size", "wrong_hash", "format", "flag"]
)
def test_expected_manifest_cannot_expand_package_scope(package, scene):
    _, expected, _, _, _ = package
    if scene == "traversal":
        expected["package_files"]["../outside.py"] = expected["package_files"].pop("__init__.py")
    elif scene == "absolute":
        expected["package_files"]["/outside.py"] = expected["package_files"].pop("__init__.py")
    elif scene == "bool_size":
        expected["package_files"]["__init__.py"]["bytes"] = True
    elif scene == "wrong_hash":
        expected["package_files"]["__init__.py"]["sha256"] = "invalid"
    elif scene == "format":
        expected["format"] = "unknown"
    else:
        expected["authorization_verified"] = True
    with pytest.raises(image.ImageCheckError):
        check(package)


def test_build_tool_lock_is_hashed_and_does_not_duplicate_runtime_profile():
    root = Path(__file__).resolve().parents[1]
    tools = image.requirements((root / "requirements-image-build.lock").read_bytes())
    runtime = image.requirements((root / "requirements.lock").read_bytes())
    assert tools == {"pip": "26.2.2", "setuptools": "84.2.1", "wheel": "0.48.0"}
    assert not set(tools) & set(runtime)


def test_main_rejects_before_any_probe_import_when_fixed_input_is_missing(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(image, "SOURCE", tmp_path / "private-sensitive-sentinel.json")
    monkeypatch.setattr(
        image.importlib, "import_module", lambda *a: pytest.fail("No imports allowed")
    )
    assert image.main() == 1
    result = capsys.readouterr().out
    assert json.loads(result)["code"] == "runner_image_build_check_rejected"
    assert "private-sensitive-sentinel" not in result


def test_script_import_is_stdlib_only_and_has_no_external_effect():
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
import runner_image_assert
assert 'aegis.config' not in sys.modules
assert 'aegis' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_actual_identity_entrypoint_imports_and_tls_version_guard_have_no_lab_side_effects(
    tmp_path,
):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            """
import sys
sys.path.insert(0, sys.argv[1])
def guard(event, args):
    if event in {'socket.connect', 'socket.bind', 'subprocess.Popen', 'os.system', 'os.mkdir'}:
        raise AssertionError('No lab effects allowed')
    if event == 'open' and isinstance(args[0], str):
        if args[0].endswith(('.key', '.env', '.sqlite')) or args[0].startswith(('/state/', '/work/')):
            raise AssertionError('No private state allowed')
sys.addaudithook(guard)
import runner_image_assert
runner_image_assert.probe_imports()
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
assert 'aegis.lab_runner.identity_probe' in sys.modules
assert 'aegis.lab_runner.rotation_probe' in sys.modules
assert 'aegis.lab_runner.server' in sys.modules
assert 'aegis.lab_runner.tls_peer' in sys.modules
""",
            str(root / "scripts"),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []


def test_unsupported_identity_transport_fails_build_check_without_printing_exception(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(image.os, "getuid", lambda: 10001)
    monkeypatch.setattr(image.os, "getgid", lambda: 10001)
    monkeypatch.setattr(image, "_read", lambda *a: b"{}")
    monkeypatch.setattr(image, "check", lambda *a: {"probe_imports_verified": False})

    class Transport:
        def require_compatibility(self):
            raise RuntimeError("private-sensitive-sentinel")

    monkeypatch.setattr(image.importlib, "import_module", lambda *a: Transport())
    assert image.main() == 1
    result = capsys.readouterr().out
    assert json.loads(result) == {"status": "rejected", "code": "runner_image_build_check_rejected"}
    assert "private-sensitive-sentinel" not in result
