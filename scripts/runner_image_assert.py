"""Stdlib build check of exact installed source/versions; no network or SQL."""

import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import stat
import sys
import sysconfig
from pathlib import Path, PurePosixPath

SOURCE = Path("/review/source.json")
RUNTIME_LOCK = Path("/review/runtime.lock")
BUILD_LOCK = Path("/review/build.lock")
MAX_FILES, MAX_FILE = 256, 1024**2


class ImageCheckError(ValueError):
    pass


def requirements(content):
    if type(content) is not bytes or len(content) > 65536:
        raise ImageCheckError("image_requirements_invalid")
    parsed = {}
    for line in content.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.!+_-]+) --hash=sha256:([a-f0-9]{64})", line
        )
        if match is None:
            raise ImageCheckError("image_requirements_invalid")
        name, version, _ = match.groups()
        name = re.sub(r"[-_.]+", "-", name).lower()
        if name in parsed:
            raise ImageCheckError("image_requirements_invalid")
        parsed[name] = version
    if not 1 <= len(parsed) <= MAX_FILES:
        raise ImageCheckError("image_requirements_invalid")
    return parsed


def source_files(root):
    if root.is_symlink() or not root.is_dir():
        raise ImageCheckError("image_package_invalid")
    files = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ImageCheckError("image_package_invalid")
        if path.is_dir():
            continue
        info = path.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or path.suffix != ".py"
            or info.st_size > MAX_FILE
            or len(files) >= MAX_FILES
        ):
            raise ImageCheckError("image_package_invalid")
        content = _read(path, MAX_FILE)
        if len(content) != info.st_size:
            raise ImageCheckError("image_package_invalid")
        files[path.relative_to(root).as_posix()] = {
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    return files


def check(expected, root, runtime_lock, build_lock, *, version=importlib.metadata.version):
    if (
        not isinstance(expected, dict)
        or set(expected)
        != {"format", "source_sha256", "source_commit", "project_version", "package_files"}
        or expected["format"] != "aegis-runner-image-package/1"
        or not isinstance(expected["source_sha256"], str)
        or not isinstance(expected["source_commit"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected["source_sha256"])
        or not re.fullmatch(r"[a-f0-9]{40}", expected["source_commit"])
        or not isinstance(expected["project_version"], str)
        or not isinstance(expected["package_files"], dict)
        or not 1 <= len(expected["package_files"]) <= MAX_FILES
    ):
        raise ImageCheckError("image_expected_source_invalid")
    for name, item in expected["package_files"].items():
        if not isinstance(name, str):
            raise ImageCheckError("image_expected_source_invalid")
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
            or path.suffix != ".py"
            or not isinstance(item, dict)
            or set(item) != {"bytes", "sha256"}
            or type(item["bytes"]) is not int
            or not 0 <= item["bytes"] <= MAX_FILE
            or not isinstance(item["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
        ):
            raise ImageCheckError("image_expected_source_invalid")
    if source_files(root) != expected["package_files"]:
        raise ImageCheckError("image_installed_source_mismatch")
    runtime, tools = requirements(runtime_lock), requirements(build_lock)
    if set(runtime) & set(tools):
        raise ImageCheckError("image_dependency_profiles_overlap")
    for name, wanted in {**runtime, **tools, "aegis-purple": expected["project_version"]}.items():
        if version(name) != wanted:
            raise ImageCheckError("image_installed_version_mismatch")
    return {
        "format": "aegis-runner-image-build-check/1",
        "source_sha256": expected["source_sha256"],
        "source_commit": expected["source_commit"],
        "package_files_verified": len(expected["package_files"]),
        "runtime_versions_verified": len(runtime),
        "build_versions_verified": len(tools),
        "installed_source_verified": True,
        "installed_versions_verified": True,
        "probe_imports_verified": False,
        "image_provenance_verified": False,
        "lab_started": False,
        "effects_authorized": False,
    }


def _read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ImageCheckError("image_input_invalid")
        content = stream.read(maximum + 1)
        if len(content) != info.st_size or len(content) > maximum:
            raise ImageCheckError("image_input_invalid")
        return content


def main():
    try:
        if sys.version_info[:2] != (3, 13) or os.getuid() != 10001 or os.getgid() != 10001:
            raise ImageCheckError("image_python_profile_invalid")
        expected = json.loads(_read(SOURCE, 256 * 1024))
        root = Path(sysconfig.get_path("purelib")) / "aegis"
        result = check(expected, root, _read(RUNTIME_LOCK, 65536), _read(BUILD_LOCK, 65536))
        for module in (
            "sqlalchemy",
            "psycopg",
            "aegis.lab_runner.journal_probe",
            "aegis.lab_runner.persisted_probe",
        ):
            importlib.import_module(module)
        if "aegis.config" in sys.modules or "aegis.models" in sys.modules:
            raise ImageCheckError("image_probe_import_side_effect")
        result["probe_imports_verified"] = True
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"status": "rejected", "code": "runner_image_build_check_rejected"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
