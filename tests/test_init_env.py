"""First-install configuration checks use private temporary files only."""

import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/init_env.py"
spec = importlib.util.spec_from_file_location("init_env", SCRIPT)
assert spec and spec.loader
init_env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(init_env)


def private_file(path, content):
    path.write_text(content)
    path.chmod(0o600)
    return path


def test_creation_is_private_random_consistent_and_idempotent(tmp_path):
    path = tmp_path / ".env"
    init_env.initialize(path)
    content = path.read_text()
    values = dict(line.split("=", 1) for line in content.splitlines())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    secrets = [values[key] for key in init_env.REQUIRED_SECRETS]
    assert len(set(secrets)) == 3
    assert all(len(value) == 48 for value in secrets)
    assert f":{secrets[0]}@localhost:18782/" in values["DATABASE_URL"]
    assert f":{secrets[1]}@localhost:18783/0" in values["REDIS_URL"]
    before = path.stat()
    message = init_env.initialize(path)
    assert "preservado" in message
    assert path.read_text() == content
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert not any(secret in message for secret in secrets)


def test_historical_configuration_gets_only_missing_runtime_secret(tmp_path):
    content = "POSTGRES_PASSWORD=private-original\nREDIS_PASSWORD=redis-original"
    path = private_file(tmp_path / ".env", content)
    init_env.initialize(path)
    assert path.read_text().startswith(content + "\nAPP_DB_PASSWORD=")
    assert path.read_text().count("APP_DB_PASSWORD=") == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    init_env.initialize(path)
    assert path.read_text().count("APP_DB_PASSWORD=") == 1


@pytest.mark.parametrize(
    "problem", ["blank", "quoted_blank", "placeholder", "duplicate", "missing"]
)
def test_incomplete_existing_configuration_is_preserved_without_secret_echo(tmp_path, problem):
    content = init_env.configuration()
    if problem == "blank":
        content += "APP_DB_PASSWORD=\n"
    elif problem == "quoted_blank":
        content = content.replace("APP_DB_PASSWORD=", 'APP_DB_PASSWORD=""\n#')
    elif problem == "placeholder":
        content = "POSTGRES_PASSWORD=GENERATE\nREDIS_PASSWORD=secret-sentinel\n"
    elif problem == "duplicate":
        content += "POSTGRES_PASSWORD=secret-sentinel\n"
    else:
        content = "# missing required values\n"
    path = private_file(tmp_path / ".env", content)
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=tmp_path, capture_output=True, text=True
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "secret-sentinel" not in result.stdout + result.stderr
    assert path.read_text() == content


@pytest.mark.parametrize(
    "kind", ["public", "symlink", "hardlink", "fifo", "directory", "oversize", "invalid_utf8"]
)
def test_unsafe_files_are_refused_without_modification_or_blocking(tmp_path, kind):
    path = tmp_path / ".env"
    target = private_file(tmp_path / "original", init_env.configuration())
    original = target.read_bytes()
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    elif kind == "oversize":
        private_file(path, "#" * (init_env.MAX_BYTES + 1))
    elif kind == "invalid_utf8":
        path.write_bytes(b"\xffsecret-sentinel")
        path.chmod(0o600)
    else:
        private_file(path, init_env.configuration()).chmod(0o644)
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=tmp_path, capture_output=True, text=True, timeout=3
    )
    assert result.returncode == 1
    assert "secret-sentinel" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert target.read_bytes() == original
    if kind == "public":
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_concurrent_writer_is_refused_without_modification(tmp_path):
    import fcntl

    path = private_file(tmp_path / ".env", init_env.configuration())
    original = path.read_bytes()
    with path.open("r+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=tmp_path, capture_output=True, text=True, timeout=3
        )
    assert result.returncode == 1
    assert path.read_bytes() == original
