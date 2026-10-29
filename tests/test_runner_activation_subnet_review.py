"""Subnet preflight with fixtures/local children; never mutate routing or Docker."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_subnet_review as review  # noqa: E402

OBJECT = "a" * 64
SECRET = "private-sensitive-sentinel"


class Docker:
    def __init__(self):
        self.calls = []
        self.ids = (OBJECT + "\n").encode()
        self.item = {
            "id": OBJECT,
            "driver": "bridge",
            "scope": "local",
            "ipam_driver": "default",
            "config": [{"Subnet": "192.0.2.0/24"}],
        }

    def query(self, known_id=None, *, timeout):
        assert 0 < timeout <= 5
        self.calls.append(known_id)
        return self.ids if known_id is None else json.dumps(self.item).encode()


class Routes:
    def __init__(self):
        self.calls = 0
        self.items = [
            {"dst": "default", "gateway": "198.51.100.1"},
            {"dst": "127.0.0.0/8", "table": "local", "dev": "lo"},
        ]

    def query(self, *, timeout):
        assert 0 < timeout <= 5
        self.calls += 1
        return json.dumps(self.items).encode()


def test_two_stable_snapshots_have_no_overlap_and_return_only_counts_hashes_and_fixed_scope():
    docker, routes = Docker(), Routes()
    result = review.review(docker=docker, routes=routes)
    assert result["observed_ipv4_overlap_absent"] and result["networks_reviewed"] == 1
    assert result["routes_reviewed"] == 2 and result["default_routes_ignored"] == 1
    assert docker.calls == [None, OBJECT, None] * 2 and routes.calls == 2
    assert all(
        result[key] is False
        for key in (
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    encoded = json.dumps(result)
    assert "198.51.100.1" not in encoded and "127.0.0.0" not in encoded and OBJECT not in encoded


@pytest.mark.parametrize("destination", ["172.30.88.0/29", "172.30.88.2/32", "172.30.0.0/16"])
def test_any_matching_docker_subnet_or_host_route_blocks_without_echo(destination):
    docker = Docker()
    docker.item["config"][0]["Subnet"] = destination
    with pytest.raises(review.ActivationError, match="docker_overlap"):
        review.review(docker=docker, routes=Routes())
    routes = Routes()
    routes.items.append({"dst": destination, "table": 101, "gateway": SECRET})
    with pytest.raises(review.ActivationError, match="host_route_overlap") as caught:
        review.review(docker=Docker(), routes=routes)
    assert SECRET not in str(caught.value) and destination not in str(caught.value)


@pytest.mark.parametrize(
    "scene", ["plugin", "swarm", "empty", "invalid_cidr", "id", "oversize", "duplicate"]
)
def test_unreviewed_or_partial_network_metadata_cannot_be_called_available(scene):
    docker = Docker()
    if scene == "plugin":
        docker.item["ipam_driver"] = "external"
    elif scene == "swarm":
        docker.item["scope"] = "swarm"
    elif scene == "empty":
        docker.item["config"] = []
    elif scene == "invalid_cidr":
        docker.item["config"][0]["Subnet"] = SECRET
    elif scene == "id":
        docker.item["id"] = "b" * 64
    elif scene == "oversize":
        docker.ids = ((OBJECT + "\n") * 129).encode()
    else:
        docker.ids = ((OBJECT + "\n") * 2).encode()
    with pytest.raises(review.ActivationError) as caught:
        review.review(docker=docker, routes=Routes())
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "items",
    [
        [{}],
        [{"dst": "garbage"}],
        [{"dst": "::/0"}],
        [{"dst": "default", "table": True}],
        {"dst": "default"},
    ],
)
def test_malformed_routes_fail_closed(items):
    routes = Routes()
    routes.items = items
    with pytest.raises(review.ActivationError):
        review.review(docker=Docker(), routes=routes)


@pytest.mark.parametrize("driver", ["host", "null"])
def test_builtin_nonallocating_networks_and_ipv6_pools_do_not_broaden_ipv4_scope(driver):
    docker = Docker()
    docker.item.update(driver=driver, config=[])
    assert review.review(docker=docker, routes=Routes())["observed_ipv4_overlap_absent"]
    docker.item.update(driver="bridge", config=[{"Subnet": "2001:db8::/64"}])
    assert review.review(docker=docker, routes=Routes())["observed_ipv4_overlap_absent"]


def test_volatile_route_expiry_is_not_misrepresented_as_a_cidr_change():
    routes = Routes()
    original = routes.query

    def query(**kwargs):
        routes.items[0]["expires"] = 1000 - routes.calls
        return original(**kwargs)

    routes.query = query
    assert review.review(docker=Docker(), routes=routes)["observed_ipv4_overlap_absent"]


@pytest.mark.parametrize("scene", ["membership", "route", "deadline"])
def test_changes_or_budget_expiry_during_review_prevent_success(monkeypatch, scene):
    docker, routes = Docker(), Routes()
    original = docker.query
    clock = [0.0]
    monkeypatch.setattr(review, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def query(*args, **kwargs):
        raw = original(*args, **kwargs)
        if len(docker.calls) == 2:
            if scene == "membership":
                docker.ids = b""
            elif scene == "route":
                routes.items.append({"dst": "203.0.113.0/24"})
            else:
                clock[0] = 21
        return raw

    docker.query = query
    if scene == "route":
        original_routes = routes.query

        def changing_routes(**kwargs):
            raw = original_routes(**kwargs)
            routes.items.append({"dst": "192.0.2.0/24"})
            return raw

        routes.query = changing_routes
    with pytest.raises(review.ActivationError):
        review.review(docker=docker, routes=routes)


@pytest.mark.parametrize(
    "code,expected",
    [
        ("import time;time.sleep(10)", "timed_out"),
        ("import os,time;os.close(1);os.close(2);time.sleep(10)", "timed_out"),
        ("import os;os.write(1,b'x'*100000)", "too_large"),
        ("import os;os.write(2,b'x'*100000)", "too_large"),
        ("import sys;sys.stderr.write('private-sensitive-sentinel');sys.exit(1)", "unconfirmed"),
    ],
)
def test_route_reader_is_fixed_bounded_and_reaps_only_its_child(monkeypatch, code, expected):
    original, processes = subprocess.Popen, []

    def launch(args, **kwargs):
        assert tuple(args) == review.ROUTE_COMMAND and kwargs["env"] == review.metadata.ENV
        assert kwargs["stdin"] == subprocess.DEVNULL and "shell" not in kwargs
        process = original([sys.executable, "-c", code], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(review.subprocess, "Popen", launch)
    with pytest.raises(review.ActivationError, match=expected) as caught:
        review.RouteReader().query(timeout=0.1 if expected == "timed_out" else 2)
    assert processes[0].poll() is not None and SECRET not in str(caught.value)


def test_successful_route_reader_discards_stderr_and_has_no_docker_effect(monkeypatch):
    original = subprocess.Popen

    def launch(args, **kwargs):
        assert tuple(args) == review.ROUTE_COMMAND
        return original(
            [
                sys.executable,
                "-c",
                "import sys;sys.stderr.write('private-sensitive-sentinel');print('[]')",
            ],
            **kwargs,
        )

    monkeypatch.setattr(review.subprocess, "Popen", launch)
    assert review.RouteReader().query(timeout=2).strip() == b"[]"


def test_network_reader_queries_only_listing_and_projected_inspection(monkeypatch):
    calls = []
    monkeypatch.setattr(
        review.metadata,
        "_execute",
        lambda args, **kwargs: calls.append((args, kwargs)) or b"fixture",
    )
    reader = review.NetworkReader()
    reader.query(timeout=1)
    reader.query(OBJECT, timeout=1)
    assert calls[0] == (("network", "ls", "--quiet", "--no-trunc"), {"timeout": 1})
    assert calls[1][0][:2] == ("network", "inspect") and calls[1][0][-1] == OBJECT
    assert "Name" not in calls[1][0][3] and "Config.Env" not in calls[1][0][3]


def test_missing_route_tool_is_disconnected_without_fallback_or_error_details(monkeypatch):
    def missing(*_args, **_kwargs):
        raise OSError(SECRET)

    monkeypatch.setattr(review.subprocess, "Popen", missing)
    with pytest.raises(review.ActivationError, match="tool_unavailable") as caught:
        review.RouteReader().query(timeout=1)
    assert SECRET not in str(caught.value)
