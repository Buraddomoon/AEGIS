"""Package/authorization negatives only; never build/start/inspect a real Lab."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from aegis.lab_runner import atomic_policy


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path("scripts").resolve()))
    result = {}
    for name in ("atomic_assay", "atomic_assay_client", "atomic_assay_service"):
        spec = importlib.util.spec_from_file_location(name, f"scripts/{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result[name] = module
    return result


def plan():
    return {
        "id": uuid4().hex,
        "project": "aegis-atomic80-test",
        "identity": {key: str(uuid4()) for key in ("runner_id", "laboratory_id", "asset_id")},
        "images": {
            key: "sha256:" + "a" * 64 for key in ("application", "runner", "postgres", "redis")
        },
        "review": atomic_policy.review(),
    }


def test_recipe_has_new_named_volumes_internal_networks_and_no_owner_secrets_in_runtime(
    modules, tmp_path
):
    host = modules["atomic_assay"]
    value = plan()
    recipe = host.recipe(value, tmp_path)
    assert set(recipe["volumes"]) == {"database", "journal", "evidence"}
    assert all(v["name"].startswith(value["project"] + "_") for v in recipe["volumes"].values())
    assert all(n["internal"] and not n["enable_ipv6"] for n in recipe["networks"].values())
    assert not any(
        s.get("ports") or s.get("build") or s.get("privileged") or s.get("network_mode")
        for s in recipe["services"].values()
    )
    for name in ("api", "worker"):
        assert "owner_url" not in recipe["services"][name]["secrets"]
        assert "accounts" not in recipe["services"][name]["secrets"]
        assert recipe["services"][name]["cap_drop"] == ["ALL"]
    assert (
        recipe["services"]["runner"]["environment"]["AEGIS_RUNNER_TEST_ID"] == atomic_policy.TEST_ID
    )
    assert recipe["services"]["controller"]["volumes"] == ["evidence:/evidence"]
    assert not any("ca.key" in v["file"] for v in recipe["secrets"].values())


def test_catalog_asset_has_a_distinct_bounded_data_profile(modules):
    host = modules["atomic_assay"]
    content = host.committed_asset("HEAD", "fixtures/attack/enterprise.json")
    assert 1024**2 < len(content) <= 2 * 1024**2
    assert content == Path("fixtures/attack/enterprise.json").read_bytes()


def test_official_root_image_metadata_can_omit_config_user(modules, monkeypatch):
    host = modules["atomic_assay"]

    def query(*args, **kwargs):
        assert '(index .Config "User")' in args[3]
        assert ".Config.Env" not in args[3]
        return json.dumps(
            {
                "id": "sha256:" + "a" * 64,
                "descriptor": None,
                "user": None,
                "os": "linux",
                "architecture": "amd64",
            }
        ).encode()

    monkeypatch.setattr(host, "docker", query)
    assert host.image("sha256:" + "a" * 64)["user"] is None


@pytest.mark.parametrize("drift", [None, "asset", "runtime_copy"])
def test_fresh_asset_checker_runs_in_a_bounded_process_and_checks_runtime_copies(
    modules, tmp_path, drift
):
    host = modules["atomic_assay"]
    (tmp_path / "scripts").mkdir()
    (tmp_path / "runtime").mkdir()
    raw = b"# fixed helper\n"
    (tmp_path / "scripts/atomic_assay_service.py").write_bytes(raw)
    (tmp_path / "runtime/atomic_assay_service.py").write_bytes(raw)
    (tmp_path / "assets.json").write_text(
        json.dumps({"scripts/atomic_assay_service.py": hashlib.sha256(raw).hexdigest()})
    )
    if drift == "asset":
        (tmp_path / "scripts/atomic_assay_service.py").write_text("changed")
    elif drift == "runtime_copy":
        (tmp_path / "runtime/atomic_assay_service.py").write_text("changed")
    code = (
        host.asset_checker(uuid4().hex)
        .replace("'/assay/assets.json'", repr(str(tmp_path / "assets.json")))
        .replace("'/app'", repr(str(tmp_path)))
        .replace("'/assay'", repr(str(tmp_path / "runtime")))
    )
    hook = "import sys\ndef guard(event,args):\n if event in ('socket.connect','subprocess.Popen'): raise RuntimeError('forbidden side effect')\nsys.addaudithook(guard)\n"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", hook + code],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        timeout=15,
    )
    if drift:
        assert result.returncode != 0
    else:
        assert result.returncode == 0, result.stderr.decode()
        assert json.loads(result.stdout)["assets"] == 1


@pytest.mark.parametrize("problem", [None, "existing", "mismatch"])
def test_base_retention_is_exclusive_and_bound_to_an_immutable_id(
    modules, tmp_path, monkeypatch, problem
):
    host = modules["atomic_assay"]
    calls = []

    def execute(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("image", "ls"):
            return b"existing" if problem == "existing" else b""
        if args[:2] == ("image", "tag"):
            assert (tmp_path / "base-tag-intent.json").exists()
            return b""
        assert args[:2] == ("image", "inspect")
        return (host.BASE_IMAGE if problem != "mismatch" else "sha256:" + "0" * 64).encode()

    monkeypatch.setattr(host, "docker", execute)
    if problem:
        with pytest.raises(ValueError):
            host.retain_base(tmp_path)
    else:
        assert host.retain_base(tmp_path) == "aegis-atomic80-base:" + tmp_path.name
    if problem == "existing":
        assert not any(call[:2] == ("image", "tag") for call in calls)


@pytest.mark.parametrize(
    "header", [b"120000 blob " + b"a" * 40 + b" 10", b"100644 blob " + b"a" * 40 + b" 2097153"]
)
def test_invalid_catalog_asset_refused_before_content_read(modules, monkeypatch, header):
    host = modules["atomic_assay"]
    calls = []

    def query(*args, **kwargs):
        calls.append(args)
        assert "ls-tree" in args
        return header + b"\tfixtures/attack/enterprise.json\n"

    monkeypatch.setattr(host.source, "_git", query)
    with pytest.raises(ValueError, match="mode/size"):
        host.committed_asset("HEAD", "fixtures/attack/enterprise.json")
    assert len(calls) == 1


@pytest.mark.parametrize("problem", ["extra", "missing", "symlink", "hardlink", "mode", "fifo"])
def test_build_context_refuses_extras_links_special_files_and_missing_assets(
    modules, tmp_path, problem
):
    host = modules["atomic_assay"]
    folder = tmp_path / "context"
    folder.mkdir(mode=0o700)
    target = folder / "code.py"
    target.write_text("# reviewed\n")
    target.chmod(0o644)
    assert host.context_inventory(folder, {"code.py"})["code.py"]["bytes"] == 11
    if problem == "extra":
        (folder / ".env").write_text("never include")
    elif problem == "missing":
        target.unlink()
    elif problem == "mode":
        target.chmod(0o600)
    else:
        target.unlink()
        if problem == "symlink":
            target.symlink_to(tmp_path / "outside")
        elif problem == "hardlink":
            outside = tmp_path / "outside"
            outside.write_text("preserve")
            target.hardlink_to(outside)
        else:
            host.os.mkfifo(target)
    with pytest.raises(ValueError):
        host.context_inventory(folder, {"code.py"})


@pytest.mark.parametrize(
    "authority",
    [
        None,
        {"proposal_sha256": "wrong", "approved_by": "user", "one_attempt": True},
        {"proposal_sha256": "a" * 64, "approved_by": "automation", "one_attempt": True},
        {"proposal_sha256": "a" * 64, "approved_by": "user", "one_attempt": False},
    ],
)
def test_missing_or_wrong_human_authority_prevents_all_mutations(
    modules, tmp_path, monkeypatch, authority
):
    host = modules["atomic_assay"]
    monkeypatch.setattr(host, "verify", lambda *args: (tmp_path, plan()))
    monkeypatch.setattr(
        host,
        "docker",
        lambda *a, **kw: pytest.fail("No Docker mutation/query needed after failed authorization"),
    )
    if authority is not None:
        host.put(tmp_path / "authorization.json", authority)
    with pytest.raises((ValueError, OSError)):
        host.run(uuid4().hex, "a" * 64)
    assert not (tmp_path / "attempt.json").exists()


def test_consumed_attempt_is_not_reopened(modules, tmp_path, monkeypatch):
    host = modules["atomic_assay"]
    monkeypatch.setattr(host, "verify", lambda *args: (tmp_path, plan()))
    host.put(
        tmp_path / "authorization.json",
        {"proposal_sha256": "a" * 64, "approved_by": "user", "one_attempt": True},
    )
    host.put(tmp_path / "attempt.json", {"preserve": True})
    before = (tmp_path / "attempt.json").read_bytes()
    with pytest.raises(ValueError, match="consumed"):
        host.run(uuid4().hex, "a" * 64)
    assert (tmp_path / "attempt.json").read_bytes() == before


def test_controller_persists_scope_once_before_start(modules, tmp_path, monkeypatch):
    client = modules["atomic_assay_client"]
    monkeypatch.setattr(client, "EVIDENCE", tmp_path)
    client.save_intent({"run_id": "existing-run", "scope_hash": "a" * 64})
    path = tmp_path / "run.json"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        client.save_intent({"run_id": "another-run"})
    assert json.loads(path.read_text())["run_id"] == "existing-run"


def test_controller_expiration_blocks_registration_and_dispatch(modules):
    client = modules["atomic_assay_client"]
    value = plan()
    value["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    accounts = [
        {"username": role, "role": role, "password": "fixture-only"}
        for role in ("administrator", "operator")
    ]
    calls = []

    def reply(request):
        calls.append((request.method, request.url.path))
        if request.url.path.endswith("/auth/login"):
            return httpx.Response(200, json={"csrf_token": "fixture"})
        assert request.method == "GET"
        return httpx.Response(200, json={"total": 0})

    with httpx.Client(
        base_url="http://192.168.253.4:8080/api/v1", transport=httpx.MockTransport(reply)
    ) as remote:
        with pytest.raises(ValueError, match="expired"):
            client.assay(value, accounts, remote, persist=lambda x: pytest.fail("No run exists"))
    assert not any(method == "POST" and "login" not in path for method, path in calls)


@pytest.mark.parametrize(
    "drift",
    [
        None,
        "ports",
        "privileged",
        "image",
        "networks",
        "user",
        "readonly",
        "memory",
        "mount",
        "tmpfs",
    ],
)
def test_runner_runtime_drift_blocks_before_effect(modules, tmp_path, drift):
    host = modules["atomic_assay"]
    value = plan()
    item = {
        "image": value["images"]["runner"],
        "privileged": False,
        "ports": {},
        "project": value["project"],
        "service": "runner",
        "networks": {value["project"] + "_isolated": {"IPAddress": "192.168.253.2"}},
        "user": "10001:10001",
        "readonly": True,
        "cap_drop": ["ALL"],
        "security": ["no-new-privileges:true"],
        "pids": 64,
        "memory": 192 * 1024**2,
        "cpus": 1_000_000_000,
        "tmpfs": {"/work": "noexec,nosuid,nodev,uid=10001,gid=10001"},
        "mounts": [{"Type": "volume", "Name": value["project"] + "_journal"}],
    }
    if drift == "ports":
        item["ports"] = {"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8443"}]}
    elif drift == "privileged":
        item["privileged"] = True
    elif drift == "image":
        item["image"] = "mutable:tag"
    elif drift == "networks":
        item["networks"]["qasrc"] = {}
    elif drift == "user":
        item["user"] = "0"
    elif drift == "readonly":
        item["readonly"] = False
    elif drift == "memory":
        item["memory"] = 0
    elif drift == "mount":
        item["mounts"].append(
            {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/socket", "RW": True}
        )
    elif drift == "tmpfs":
        item["tmpfs"]["/work"] = "exec,suid"
    if drift:
        with pytest.raises(AssertionError):
            host.validate_runtime(item, "runner", value, tmp_path)
    else:
        host.validate_runtime(item, "runner", value, tmp_path)


@pytest.mark.parametrize(
    "uri",
    [
        "postgresql+psycopg://aegis:private@db:5432/aegis",
        "postgresql+psycopg://atomic_owner:private@original:5432/atomic_assay",
        "postgresql+psycopg://atomic_owner:private@db:5432/atomic_assay?options=anything",
    ],
)
def test_service_refuses_original_or_unreviewed_database_before_connecting(
    modules, tmp_path, monkeypatch, uri
):
    service = modules["atomic_assay_service"]
    monkeypatch.setattr(service, "SECRETS", tmp_path)
    (tmp_path / "owner_url").write_text(uri)
    with pytest.raises(ValueError, match="Fresh"):
        service.configure(owner=True)
