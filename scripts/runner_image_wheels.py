"""Private hash-locked wheel cache using fixed isolated pip download; no installs."""

import argparse
import hashlib
import io
import json
import os
import selectors
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from uuid import UUID, uuid4

import runner_activation_image_source as source
import runner_pki as pki
from aegis.domain.validation import digest
from packaging.utils import canonicalize_name, parse_wheel_filename
from runner_activation_metadata import ActivationError, _unique
from runner_image_assert import requirements

ROOT = Path(__file__).resolve().parents[1] / ".local/pki-image-wheels"
MAX_WHEEL, MAX_TOTAL, MAX_LOG = 32 * 1024**2, 128 * 1024**2, 4 * 1024**2
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PIP_CONFIG_FILE": "/dev/null", "NETRC": "/dev/null"}
FLAGS = {"packages_installed": False, "image_built": False, "effects_authorized": False}


def _locked(runtime, tools):
    profiles = [requirements(content) for content in (runtime, tools)]
    if set(profiles[0]) & set(profiles[1]):
        raise ActivationError("wheel_dependency_profiles_overlap")
    records = {}
    for content in (runtime, tools):
        for line in content.decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            name = canonicalize_name(line.split("==", 1)[0])
            records[name] = {
                "version": {**profiles[0], **profiles[1]}[name],
                "sha256": line.rsplit("sha256:", 1)[1],
            }
    if not 1 <= len(records) <= 128:
        raise ActivationError("wheel_requirement_limit")
    return records


def command(folder):
    return (
        sys.executable,
        "-I",
        "-m",
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-input",
        "--keyring-provider",
        "disabled",
        "download",
        "--only-binary=:all:",
        "--require-hashes",
        "--no-deps",
        "--index-url",
        "https://pypi.org/simple",
        "--timeout",
        "10",
        "--retries",
        "0",
        "--dest",
        str(folder / "wheels"),
        "-r",
        str(folder / "runtime.lock"),
        "-r",
        str(folder / "build.lock"),
    )


def _write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def download(folder):
    """Closed CLI, no pip/user config, bounded output/deadline and kill/reap."""
    fd = os.open(
        folder / "download.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "wb") as log:
        process = subprocess.Popen(
            command(folder),
            cwd=folder,
            env=ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            umask=0o077,
        )
        try:
            deadline, size = time.monotonic() + 120, 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ActivationError("wheel_download_deadline")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > MAX_LOG:
                            raise ActivationError("wheel_download_log_limit")
                        log.write(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise ActivationError("wheel_download_unconfirmed")
            log.flush()
            os.fsync(log.fileno())
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()


def inventory(folder, locked):
    wheel_folder = pki.private_directory(folder / "wheels")
    paths = list(wheel_folder.iterdir())
    if len(paths) != len(locked):
        raise ActivationError("wheel_cache_count_mismatch")
    records, total = {}, 0
    for path in paths:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or path.suffix != ".whl"
            or info.st_size > MAX_WHEEL
        ):
            raise ActivationError("wheel_cache_file_invalid")
        name, version, _, _ = parse_wheel_filename(path.name)
        if name not in locked or str(version) != locked[name]["version"] or name in records:
            raise ActivationError("wheel_cache_distribution_mismatch")
        total += info.st_size
        if total > MAX_TOTAL:
            raise ActivationError("wheel_cache_size_limit")
        content = pki.read(path, modes=(0o600,), maximum=MAX_WHEEL)
        sha = hashlib.sha256(content).hexdigest()
        if sha != locked[name]["sha256"]:
            raise ActivationError("wheel_cache_hash_mismatch")
        records[name] = {
            "filename": path.name,
            "version": str(version),
            "bytes": len(content),
            "sha256": sha,
        }
    return dict(sorted(records.items()))


def prepare(runtime, tools, source_sha256, *, root=ROOT):
    """Inputs come from a verified source snapshot/committed tool lock; no free URLs."""
    if (
        not isinstance(source_sha256, str)
        or len(source_sha256) != 64
        or any(char not in "0123456789abcdef" for char in source_sha256)
    ):
        raise ActivationError("wheel_source_hash_required")
    locked = _locked(runtime, tools)
    root = pki.private_directory(root, create=True)
    folder = root / uuid4().hex
    folder.mkdir(mode=0o700)
    (folder / "wheels").mkdir(mode=0o700)
    pki.sync(folder)
    pki.sync(root)
    _write(folder / "runtime.lock", runtime)
    _write(folder / "build.lock", tools)
    plan = {
        "format": "aegis-runner-wheel-plan/1",
        "source_sha256": source_sha256,
        "runtime_lock_sha256": hashlib.sha256(runtime).hexdigest(),
        "build_lock_sha256": hashlib.sha256(tools).hexdigest(),
        "locked": locked,
    }
    _write(folder / "plan.json", json.dumps(plan, sort_keys=True, separators=(",", ":")).encode())
    pki.sync(folder)
    try:
        download(folder)
        wheels = inventory(folder, locked)
        for path in (folder / "wheels").iterdir():
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        pki.sync(folder / "wheels")
        receipt = {
            "format": "aegis-runner-wheel-cache/1",
            "plan_sha256": digest(plan),
            "source_sha256": source_sha256,
            "wheels": wheels,
            "wheel_hashes_verified": True,
            **FLAGS,
        }
        _write(
            folder / "receipt.json",
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
        )
        pki.sync(folder)
        verify(folder, digest(receipt))
    except (ValueError, OSError, subprocess.SubprocessError):
        raise ActivationError("wheel_cache_preparation_unconfirmed") from None
    return {
        "status": "wheels_verified_not_installed",
        "folder": str(folder),
        "receipt_sha256": digest(receipt),
        "source_sha256": source_sha256,
        "wheels_verified": len(wheels),
        "wheel_bytes": sum(item["bytes"] for item in wheels.values()),
        **FLAGS,
    }


def verify(folder, expected_sha256):
    try:
        folder = pki.private_directory(folder)
        receipt = json.loads(
            pki.read(folder / "receipt.json", modes=(0o600,), maximum=256 * 1024),
            object_pairs_hook=_unique,
        )
        plan = json.loads(
            pki.read(folder / "plan.json", modes=(0o600,), maximum=256 * 1024),
            object_pairs_hook=_unique,
        )
        if (
            not isinstance(receipt, dict)
            or digest(receipt) != expected_sha256
            or set(receipt)
            != {"format", "plan_sha256", "source_sha256", "wheels", "wheel_hashes_verified", *FLAGS}
            or receipt["format"] != "aegis-runner-wheel-cache/1"
            or receipt["wheel_hashes_verified"] is not True
            or any(receipt[key] is not False for key in FLAGS)
            or receipt["plan_sha256"] != digest(plan)
            or receipt["source_sha256"] != plan["source_sha256"]
            or plan["format"] != "aegis-runner-wheel-plan/1"
            or set(folder.iterdir())
            != {
                folder / name
                for name in (
                    "wheels",
                    "runtime.lock",
                    "build.lock",
                    "plan.json",
                    "receipt.json",
                    "download.log",
                )
            }
        ):
            raise ActivationError("wheel_cache_receipt_invalid")
        runtime = pki.read(folder / "runtime.lock", modes=(0o600,), maximum=65536)
        tools = pki.read(folder / "build.lock", modes=(0o600,), maximum=65536)
        locked = _locked(runtime, tools)
        if (
            hashlib.sha256(runtime).hexdigest() != plan["runtime_lock_sha256"]
            or hashlib.sha256(tools).hexdigest() != plan["build_lock_sha256"]
            or locked != plan["locked"]
            or inventory(folder, locked) != receipt["wheels"]
        ):
            raise ActivationError("wheel_cache_changed")
        return receipt
    except (ValueError, OSError, TypeError, KeyError, AttributeError, RecursionError):
        raise ActivationError("wheel_cache_verification_failed") from None


def _identifier(value):
    if not isinstance(value, str) or UUID(hex=value).hex != value:
        raise ActivationError("wheel_artifact_identifier_invalid")
    return value


def from_source(source_id, expected_sha256):
    folder = source.DEFAULT_OUTPUT / _identifier(source_id)
    document = source.verify(folder, expected_sha256)
    tools_commit = source._state(source.ROOT)
    context = pki.read(folder / "context.tar", modes=(0o600,), maximum=source.MAX_CONTEXT)
    if hashlib.sha256(context).hexdigest() != document["context_sha256"]:
        raise ActivationError("wheel_source_changed")
    with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
        runtime = archive.extractfile("requirements.lock").read(65537)
    tools = source._git(source.ROOT, "show", "HEAD:requirements-image-build.lock", maximum=65536)
    result = prepare(runtime, tools, expected_sha256, root=ROOT)
    if source._state(source.ROOT) != tools_commit:
        raise ActivationError("wheel_tools_source_changed")
    return {**result, "build_tools_commit": tools_commit}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    create.add_argument("--source-id", required=True)
    create.add_argument("--expected-sha256", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--cache-id", required=True)
    check.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            report = from_source(args.source_id, args.expected_sha256)
        else:
            receipt = verify(ROOT / _identifier(args.cache_id), args.expected_sha256)
            report = {
                "status": "wheels_verified_not_installed",
                "receipt_sha256": args.expected_sha256,
                "source_sha256": receipt["source_sha256"],
                "wheels_verified": len(receipt["wheels"]),
                **FLAGS,
            }
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, KeyError, AttributeError, tarfile.TarError):
        print(json.dumps({"status": "rejected", "code": "wheel_cache_operation_rejected", **FLAGS}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
