import json
import runpy
import subprocess
from uuid import uuid4

import pytest

initialize = runpy.run_path("scripts/init_linux_lab.py")["initialize"]


def test_new_material_can_keep_explicit_identity_without_reusing_old_keys(tmp_path):
    original = initialize(tmp_path / "old")
    before = {p.name: p.read_bytes() for p in original.iterdir()}
    connection = json.loads(before["connection.json"])
    ids = {name: connection[name] for name in ("runner_id", "laboratory_id", "asset_id")}
    candidate = initialize(tmp_path / "candidate", identifiers=ids)
    after = json.loads((candidate / "connection.json").read_text())
    assert after == connection
    assert {p.name: p.read_bytes() for p in original.iterdir()} == before
    for name in ("server-ca.key", "client-ca.key", "runner-server.key", "runner-client.key"):
        assert (candidate / name).read_bytes() != before[name]
    assert all(ids[name] == connection[name] for name in ids)


@pytest.mark.parametrize("problem", ["missing", "extra", "invalid"])
def test_bad_identity_is_refused_before_creating_output(tmp_path, problem):
    ids = {name: str(uuid4()) for name in ("runner_id", "laboratory_id", "asset_id")}
    if problem == "missing":
        ids.pop("asset_id")
    if problem == "extra":
        ids["other"] = "value"
    if problem == "invalid":
        ids["runner_id"] = "not-a-uuid/command"
    with pytest.raises(ValueError):
        initialize(tmp_path / "candidate", identifiers=ids)
    assert not (tmp_path / "candidate").exists()


def test_openssl_generator_does_not_inherit_custom_configuration(monkeypatch):
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(subprocess, "run", execute)
    monkeypatch.setenv("OPENSSL_CONF", "/private/untrusted.cnf")
    monkeypatch.setenv("OPENSSL_MODULES", "/private/providers")
    runpy.run_path("scripts/init_linux_lab.py")["openssl"]("version")
    args, kwargs = calls[0]
    assert args == ["/usr/bin/openssl", "version"]
    assert kwargs["timeout"] == 10
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}
    assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
