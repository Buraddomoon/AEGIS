"""Closed native package controls. No Docker, network, database or marker."""

import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


@pytest.fixture
def assay(monkeypatch):
    monkeypatch.syspath_prepend(str(Path("scripts").resolve()))
    spec = importlib.util.spec_from_file_location(
        "schedule104_test_module", "scripts/scheduling_assay.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if sys.platform == "win32":
        # Only the POSIX directory primitive is simulated here. Linux CI uses
        # real fsync; this Windows host still cannot execute a native attempt.
        monkeypatch.setattr(module, "sync_directory", lambda path: None)
    return module


def proposal():
    now = datetime(2026, 11, 24, 23, tzinfo=UTC)
    images = {
        name: {
            "id": "sha256:" + letter * 64,
            "entrypoint": ["python"] if name in {"application", "runner"} else [name],
            "cmd": [],
        }
        for name, letter in (
            ("application", "a"),
            ("runner", "b"),
            ("postgres", "c"),
            ("redis", "d"),
        )
    }
    return {
        "format": "aegis-scheduling104-native/1",
        "workflow_run": "12345678901",
        "approved_by": "Buraddomoon",
        "source_commit": "a" * 40,
        "prepared_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "project": "aegis-scheduling104-12345678901",
        "identity": {
            "runner_id": "11111111-1111-4111-8111-111111111111",
            "laboratory_id": "22222222-2222-4222-8222-222222222222",
            "asset_id": "33333333-3333-4333-8333-333333333333",
        },
        "occurrences": 2,
        "test_id": "linux-file-marker/v1",
        "definition_id": "linux-file-marker-v1",
        "max_concurrency": 1,
        "interval_seconds": 60,
        "max_duration_seconds": 30,
        "origin": "http://192.168.253.12:8080",
        "subnets": ["192.168.253.0/29", "192.168.253.8/29"],
        "original_volumes": [],
        "schema": "e2a71c9d064b",
        "expected_outcome": "INCONCLUSIVE",
        "host_disposal": "github_ephemeral_after_verified_cleanup",
        "images": images,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("occurrences", 3),
        ("test_id", "linux-shell-canary/v1"),
        ("interval_seconds", 1),
        ("max_duration_seconds", 300),
        ("max_concurrency", 2),
        ("origin", "http://example.com"),
        ("original_volumes", ["original"]),
        ("schema", "head"),
        ("expected_outcome", "DETECTED"),
        ("host_disposal", "retain_public_keys"),
        ("source_commit", "main"),
        ("project", "aegis-linux-lab"),
        ("workflow_run", "old-attempt"),
    ],
)
def test_package_scope_cannot_be_widened(assay, field, value):
    plan = proposal()
    assert assay.policy(plan) is plan
    plan[field] = value
    with pytest.raises(assay.Blocked):
        assay.policy(plan)


@pytest.mark.parametrize(
    "change", [None, "old", "expired", "actor", "hash", "effect_count", "host", "too_late"]
)
def test_only_later_specific_human_approval_matches(assay, change):
    plan = proposal()
    fingerprint = "f" * 64
    instant = datetime.fromisoformat(plan["prepared_at"]) + timedelta(minutes=2)
    comment = {
        "created_at": (instant - timedelta(seconds=1)).isoformat(),
        "user": {"login": plan["approved_by"]},
        "body": assay.approval_text(plan, fingerprint),
    }
    if change == "old":
        comment["created_at"] = (instant - timedelta(days=1)).isoformat()
    elif change == "expired":
        instant += timedelta(hours=1)
    elif change == "actor":
        comment["user"]["login"] = "another-account"
    elif change == "hash":
        comment["body"] = comment["body"].replace(fingerprint, "a" * 64)
    elif change == "effect_count":
        comment["body"] = comment["body"].replace("occurrences=2", "occurrences=3")
    elif change == "host":
        comment["body"] = comment["body"].replace(plan["workflow_run"], "98765432100")
    elif change == "too_late":
        instant = datetime.fromisoformat(plan["expires_at"]) - timedelta(minutes=4)
    assert assay.approved(comment, plan, fingerprint, instant) is (change is None)


def test_recipe_has_only_new_resources_minimal_roles_and_no_ports_or_socket(assay, tmp_path):
    plan = proposal()
    compiled = assay.recipe(tmp_path, plan)
    assert compiled["name"] == plan["project"]
    assert set(compiled["volumes"]) == {"database", "journal"}
    assert all(value["name"].startswith(plan["project"]) for value in compiled["volumes"].values())
    for name, service in compiled["services"].items():
        assert not service.get("ports") and not service.get("privileged")
        assert "docker.sock" not in json.dumps(service)
        if name not in {"admin", "db"}:
            assert "owner_url" not in service.get("secrets", [])
        if name in {"runner", "api", "worker"}:
            assert service["user"] == "10001:10001" and service["read_only"]
            assert service["cap_drop"] == ["ALL"]
        if name != "db":
            assert service["cpus"] == 1 and service["pids_limit"] == 64
    assert compiled["networks"]["isolated"]["internal"]
    assert compiled["networks"]["backend"]["internal"]
    assert compiled["services"]["redis"]["command"] == ["redis-server", "/run/secrets/redis_config"]


@pytest.mark.parametrize("overlap", [False, True])
def test_routes_and_existing_networks_block_overlap_without_mutation(assay, monkeypatch, overlap):
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("network", "ls"):
            return b"abc\n"
        return json.dumps(
            [
                {
                    "Id": "abc",
                    "Name": "third-party",
                    "IPAM": {
                        "Config": [{"Subnet": "192.168.253.0/24" if overlap else "172.17.0.0/16"}]
                    },
                }
            ]
        ).encode()

    monkeypatch.setattr(assay, "docker", docker)
    monkeypatch.setattr(
        assay, "command", lambda *a, **k: b'[{"dst":"default"},{"dst":"10.0.0.0/24"}]'
    )
    if overlap:
        with pytest.raises(assay.Blocked):
            assay.network_snapshot()
    else:
        assert assay.network_snapshot()["networks"] == [("abc", "third-party")]
    assert all(call[1] in {"ls", "inspect"} for call in calls)


def test_attempt_fence_is_exclusive_and_preserves_first_bytes(assay, tmp_path):
    path = tmp_path / "attempt.json"
    assay.write_new(path, {"effects": 2})
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        assay.write_new(path, {"effects": 4})
    assert path.read_bytes() == before


def test_browser_gets_home_without_workflow_tokens_proxies_or_loader_hooks(assay, monkeypatch):
    for name in ("GH_TOKEN", "HTTPS_PROXY", "LD_PRELOAD", "NODE_OPTIONS"):
        monkeypatch.setenv(name, "private-untrusted-value")
    values = assay.browser_environment()
    assert values["HOME"] and values["PATH"]
    assert not any(
        name in values for name in ("GH_TOKEN", "HTTPS_PROXY", "LD_PRELOAD", "NODE_OPTIONS")
    )


@pytest.mark.parametrize(
    "change", [None, "image", "memory", "uid", "networks", "command", "mount", "privileged"]
)
def test_native_runtime_is_independently_inspected(assay, tmp_path, monkeypatch, change):
    plan = proposal()
    compiled = assay.recipe(tmp_path, plan)
    monkeypatch.setattr(assay, "PUBLIC", tmp_path / "public")
    monkeypatch.setattr(assay, "compose", lambda folder, plan, *args, **kwargs: args[-1].encode())

    def docker(*args, **kwargs):
        service = args[-1]
        source = compiled["services"][service]
        kind = (
            "application"
            if service in {"api", "worker"}
            else "postgres"
            if service == "db"
            else service
        )
        result = {
            "id": service,
            "image": plan["images"][kind]["id"],
            "user": source.get("user", ""),
            "entrypoint": source.get("entrypoint", plan["images"][kind]["entrypoint"]),
            "cmd": source.get("command", plan["images"][kind]["cmd"]),
            "labels": {"com.docker.compose.project": plan["project"]},
            "memory": int(source["mem_limit"][:-1]) * 1024**2,
            "cpus": 1000000000,
            "pids": source["pids_limit"],
            "readonly": source.get("read_only", False),
            "privileged": False,
            "caps": source.get("cap_drop", []),
            "security": source.get("security_opt", []),
            "ports": {},
            "mounts": [],
            "networks": {plan["project"] + "_" + name: {} for name in source["networks"]},
        }
        if service == "api" and change:
            replacement = {
                "image": "sha256:" + "f" * 64,
                "memory": 1,
                "uid": "0:0",
                "networks": {"external": {}},
                "command": ["shell"],
                "mount": [{"Type": "bind", "Source": "/tmp/foreign", "RW": False}],
                "privileged": True,
            }[change]
            result[{"uid": "user", "command": "cmd", "mount": "mounts"}.get(change, change)] = (
                replacement
            )
        return json.dumps(result).encode()

    monkeypatch.setattr(assay, "docker", docker)
    if change:
        with pytest.raises(assay.Blocked):
            assay.runtime_check(tmp_path, plan)
    else:
        assay.runtime_check(tmp_path, plan)
        assert len(json.loads((assay.PUBLIC / "runtime.json").read_text())) == 5
