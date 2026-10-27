"""No lab starts: daemon fixtures and tiny local child processes only."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_metadata as metadata  # noqa: E402


def images():
    return {role: "sha256:" + str(i + 1) * 64 for i, role in enumerate(metadata.IMAGES)}


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.responses = {
            ("daemon", None): {
                "id": "12345678-1234-1234-1234-123456789012",
                "os": "linux",
                "architecture": "x86_64",
            }
        }
        for kind, values in (
            ("containers", (None,)),
            ("networks", (None,)),
            ("network_name", metadata.NETWORKS),
            ("consumers", metadata.VOLUMES),
        ):
            for value in values:
                self.responses[kind, value] = b""
        for name in metadata.VOLUMES:
            self.responses["volume", name] = {
                "name": metadata.PROJECT + "_" + name,
                "driver": "local",
                "scope": "local",
                "options": None,
                "created_at": "2026-10-21T12:00:00Z",
                "project": metadata.PROJECT,
                "volume": name,
            }
        for role, identifier in images().items():
            self.responses["image", identifier] = {
                "id": identifier,
                "os": "linux",
                "architecture": "amd64",
                "user": "10001:10001" if role in {"application", "runner"} else "",
            }

    def query(self, kind, value=None):
        metadata.command(kind, value)  # Fixtures cannot accidentally add a lifecycle query.
        self.calls.append((kind, value))
        result = self.responses[kind, value]
        return result if isinstance(result, bytes) else json.dumps(result).encode()


def test_metadata_normalizes_options_without_mutating_daemon_data():
    docker = FakeDocker()
    before = copy.deepcopy(docker.responses)
    result = metadata.metadata(images(), docker=docker)
    assert result["images"]["application"]["id"] == images()["application"]
    assert result["volumes"]["journal"]["options"] == {}
    assert docker.responses == before
    assert len(docker.calls) == 14
    assert {kind for kind, _ in docker.calls} == {
        "daemon",
        "containers",
        "networks",
        "network_name",
        "consumers",
        "volume",
        "image",
    }


@pytest.mark.parametrize("role", ["postgres", "redis", "application", "runner"])
def test_optional_config_user_is_root_only_for_db_or_cache(role):
    docker = FakeDocker()
    docker.responses["image", images()[role]]["user"] = None
    assert 'index .Config "User"' in metadata.IMAGE_FORMAT
    if role in {"postgres", "redis"}:
        result = metadata.metadata(images(), docker=docker)
        assert result["images"][role]["user"] == ""
    else:
        with pytest.raises(metadata.ActivationError, match="image_metadata_mismatch"):
            metadata.metadata(images(), docker=docker)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("start", None),
        ("exec", "runner"),
        ("volume", "arbitrary"),
        ("consumers", "other"),
        ("network_name", "host"),
        ("daemon", "tcp://external:2375"),
        ("containers", "other-project"),
        ("image", "postgres:17-alpine"),
        ("image", "--help"),
        ("image", "sha256:" + "A" * 64),
    ],
)
def test_queries_reject_arbitrary_operations_and_tags(kind, value, monkeypatch):
    monkeypatch.setattr(
        metadata, "_execute", lambda *args: pytest.fail("must reject before Docker")
    )
    with pytest.raises(metadata.ActivationError):
        metadata.ReadOnlyDocker().query(kind, value)


@pytest.mark.parametrize(
    "role,value",
    [
        ("application", "latest"),
        ("runner", images()["application"]),
        ("missing", None),
    ],
)
def test_all_four_distinct_explicit_image_ids_required(role, value):
    docker = FakeDocker()
    requested = images()
    if role == "missing":
        requested.pop("redis")
    else:
        requested[role] = value
    with pytest.raises(metadata.ActivationError):
        metadata.metadata(requested, docker=docker)
    assert not docker.calls


@pytest.mark.parametrize(
    "kind,value",
    [
        ("containers", None),
        ("networks", None),
        ("network_name", "backend"),
        ("network_name", "isolated"),
        ("consumers", "journal"),
        ("consumers", "postgres-data"),
    ],
)
def test_any_container_or_volume_consumer_even_stopped_blocks(kind, value):
    docker = FakeDocker()
    docker.responses[kind, value] = b"a" * 64 + b"\n"
    with pytest.raises(metadata.ActivationError, match="not_quiescent"):
        metadata.metadata(images(), docker=docker)


@pytest.mark.parametrize(
    "field,value",
    [
        ("project", "aegis"),
        ("volume", "other"),
        ("name", "aegis_journal"),
        ("driver", "nfs"),
        ("scope", "global"),
        ("options", {"device": "/host"}),
        ("created_at", "not-a-time"),
        ("created_at", "2026-10-21T00:00:00"),
    ],
)
def test_mislabeled_or_external_volume_is_refused(field, value):
    docker = FakeDocker()
    docker.responses["volume", "journal"][field] = value
    with pytest.raises(metadata.ActivationError):
        metadata.metadata(images(), docker=docker)


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("daemon", "id", "private-sensitive-sentinel" + "\n"),
        ("daemon", "os", "windows"),
        ("daemon", "architecture", "mips64"),
        ("image", "architecture", "arm64"),
        ("image", "user", "root"),
        ("image", "id", "sha256:" + "0" * 64),
        ("image", "os", "windows"),
    ],
)
def test_wrong_daemon_or_image_is_refused(kind, field, value):
    docker = FakeDocker()
    key = (kind, None if kind == "daemon" else images()["application"])
    docker.responses[key][field] = value
    with pytest.raises(metadata.ActivationError) as error:
        metadata.metadata(images(), docker=docker)
    assert "private-sensitive-sentinel" not in str(error.value)


@pytest.mark.parametrize(
    "content",
    [
        b'{"id":"a","id":"b"}',
        b"not-json-private-sensitive-sentinel",
        b"x" * 65537,
    ],
)
def test_malformed_excessive_or_duplicate_json_is_refused(content):
    with pytest.raises(metadata.ActivationError) as error:
        metadata.document(content)
    assert "private-sensitive-sentinel" not in str(error.value)


def local_child(monkeypatch, code):
    original = subprocess.Popen
    processes = []

    def launch(arguments, **kwargs):
        assert arguments[:2] == ["/usr/bin/docker", "--config"]
        assert Path(arguments[2]).is_dir() and not list(Path(arguments[2]).iterdir())
        assert arguments[3:5] == ["--host", "unix:///var/run/docker.sock"]
        assert kwargs["env"] == metadata.ENV
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert "shell" not in kwargs
        process = original([sys.executable, "-c", code], **kwargs)
        processes.append((process, Path(arguments[2])))
        return process

    monkeypatch.setattr(metadata.subprocess, "Popen", launch)
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
    monkeypatch.setenv("DOCKER_CONFIG", "/sensitive/config")
    monkeypatch.setenv("HTTP_PROXY", "http://sensitive.invalid")
    return processes


def test_cli_transport_uses_local_daemon_and_discards_sensitive_stderr(monkeypatch):
    processes = local_child(
        monkeypatch, "import os; os.write(1,b'{}'); os.write(2,b'private-sentinel')"
    )
    assert metadata.ReadOnlyDocker().query("daemon") == b"{}"
    assert processes[0][0].returncode == 0
    assert not processes[0][1].exists()


@pytest.mark.parametrize(
    "code,expected",
    [
        ("import os; os.write(1,b'x'*1000000)", "response_too_large"),
        ("import os; os.write(2,b'private-sentinel'*100000)", "response_too_large"),
        ("import time; time.sleep(20)", "timed_out"),
        ("import os,time; os.close(1);os.close(2);time.sleep(20)", "query_failed"),
        ("import sys;sys.stderr.write('private-sentinel');sys.exit(1)", "query_failed"),
    ],
)
def test_children_are_killed_reaped_and_errors_redacted(monkeypatch, code, expected):
    monkeypatch.setattr(metadata, "TIMEOUT", 0.25)
    processes = local_child(monkeypatch, code)
    with pytest.raises(metadata.ActivationError, match=expected) as error:
        metadata.ReadOnlyDocker().query("daemon")
    assert "private-sentinel" not in str(error.value)
    assert processes[0][0].poll() is not None
    assert not processes[0][1].exists()
