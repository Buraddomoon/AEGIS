"""Read-only physical predicates and actual CLI formatting on a fake Unix daemon only."""

import copy
import json
import sys
from pathlib import Path

import pytest
from test_runner_activation_identity_client_runtime import CONTEXT
from test_runner_activation_identity_client_runtime import ready as ready
from test_runner_activation_identity_inspection import projection
from test_runner_activation_identity_runtime import code as code
from test_runner_activation_identity_runtime import context as context
from test_runner_activation_identity_runtime import material as material
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_mount_templates import render as render

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_client_inspection as inspection  # noqa: E402

CLIENT_ID = "e" * 64


def projected(spec, phase):
    value = projection(spec, phase)
    value.update(id=CLIENT_ID, stdin_open=True)
    value["endpoints"][0].update(ip=inspection.runtime.IP, configured_ip=inspection.runtime.IP)
    return value


@pytest.fixture
def spec(ready):
    return inspection.runtime.recipe(ready.store, ready.path, ready.sha, CONTEXT)


@pytest.mark.parametrize("phase", ["created", "exited"])
def test_closed_client_profile_accepts_only_successful_fixed_lifecycle_phases(spec, phase):
    inspection.validate(spec, projected(spec, phase), CLIENT_ID, phase)
    with pytest.raises(inspection.ActivationError, match="phase_invalid"):
        inspection.validate(spec, projected(spec, "running"), CLIENT_ID, "running")
    with pytest.raises(inspection.ActivationError):
        inspection.server.validate(spec, projected(spec, phase), CLIENT_ID, phase)


@pytest.mark.parametrize(
    "scene",
    [
        "stdin",
        "integer_stdin",
        "tty",
        "running",
        "exit",
        "argv",
        "volume",
        "port",
        "writable_key",
        "old_ca_source",
        "missing_old_ca",
        "old_key",
        "ip",
        "ipv6",
        "env",
    ],
)
def test_client_profile_rejects_shells_unsafe_mounts_networks_or_configuration(spec, scene):
    value = projected(spec, "exited")
    if scene == "stdin":
        value["stdin_open"] = False
    elif scene == "integer_stdin":
        value["stdin_open"] = 1
    elif scene in {"tty", "running"}:
        value[scene] = True
    elif scene == "exit":
        value["exit_code"] = 1
    elif scene == "argv":
        value["arguments"] = ["-c", "unreviewed"]
    elif scene == "volume":
        value["volumes"] = {"/state": {}}
    elif scene == "port":
        value["ports"] = {"8443/tcp": [{"HostPort": "8443"}]}
    elif scene == "writable_key":
        next(
            item
            for item in value["mounts"]
            if item["target"] == "/run/secrets/controller_client_key"
        )["writable"] = True
    elif scene in {"old_ca_source", "missing_old_ca", "old_key"}:
        entry = next(
            item for item in value["mounts"] if item["target"] == inspection.runtime.PREVIOUS_CA
        )
        if scene == "old_ca_source":
            entry["source_matches"] = False
        elif scene == "missing_old_ca":
            value["mounts"].remove(entry)
        else:
            value["mounts"].append({**entry, "target": "/run/secrets/previous_client_key"})
    elif scene in {"ip", "ipv6"}:
        value["endpoints"][0][scene] = "172.30.88.2" if scene == "ip" else "2001:db8::1"
    else:
        value["environment"].append({"key": "SSLKEYLOGFILE", "valid": True})
    with pytest.raises(inspection.ActivationError):
        inspection.validate(spec, value, CLIENT_ID, "exited")


def test_client_retains_fixed_configuration_when_operational_address_is_released(spec):
    value = projected(spec, "created")
    value["endpoints"][0].update(ip="", prefix=0, id="")
    inspection.validate(spec, value, CLIENT_ID, "created")
    value["status"] = "exited"
    inspection.validate(spec, value, CLIENT_ID, "exited")
    value["endpoints"][0]["configured_ip"] = "172.30.88.4"
    with pytest.raises(inspection.ActivationError, match="network_mismatch"):
        inspection.validate(spec, value, CLIENT_ID, "exited")


class World:
    def __init__(self, ready, phase):
        self.ready, self.calls = ready, 0
        store = ready.store
        store.request(inspection.runtime.ROLE)
        store.append("observed", {"role": inspection.runtime.ROLE, "resource_id": CLIENT_ID})
        self.spec = inspection.runtime.recipe(store, ready.path, ready.sha, CONTEXT)
        self.item = projected(self.spec, phase)
        if phase == "exited":
            store.append(
                "identity_client_start_requested",
                {
                    "role": inspection.runtime.ROLE,
                    "recipe_sha256": inspection.digest(self.spec),
                    "gates_sha256": "1" * 64,
                    "request_context_sha256": CONTEXT,
                    "runner_resource_id": self.spec["runner_resource_id"],
                    "network_resource_id": self.spec["network_resource_id"],
                },
            )
        self.owner = Owner(store.summary()["id"], inspection.runtime.ROLE)
        self.owner.details.update(
            id=CLIENT_ID, plan=ready.sha, image=self.spec["image"], running=False
        )
        self.owner.named = self.owner.labelled = self.owner.known = (CLIENT_ID + "\n").encode()

    def query(self, *args, **kwargs):
        if args[0] == "container":
            self.calls += 1
            return json.dumps(self.item).encode()
        return self.owner.query(*args)

    def review(self, phase):
        return inspection.review(
            self.ready.store,
            self.ready.path,
            self.ready.sha,
            CONTEXT,
            CLIENT_ID,
            phase,
            docker=self,
            ownership_docker=self,
        )


@pytest.mark.parametrize("phase", ["created", "exited"])
def test_runtime_review_binds_owned_id_and_configuration_without_inferring_tls(ready, phase):
    world = World(ready, phase)
    before = ready.store.summary()
    result = world.review(phase)
    assert (
        result["runtime_configuration_verified"] and result["original_volumes_not_mounted_verified"]
    )
    assert result["request_context_sha256"] == CONTEXT and world.calls == 1
    assert all(
        result[key] is False
        for key in (
            "tls_result_verified",
            "network_reachability_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    assert before == ready.store.summary()


@pytest.mark.parametrize("scene", ["owner", "intent", "deadline", "context", "missing_start"])
def test_drift_or_missing_start_fence_cannot_become_an_exited_client_review(
    ready, monkeypatch, scene
):
    world = World(ready, "created" if scene == "missing_start" else "exited")
    if scene == "owner":
        world.owner.details["image"] = "sha256:" + "f" * 64
    elif scene == "context":
        with pytest.raises(inspection.ActivationError, match="start_binding_mismatch"):
            inspection.review(ready.store, ready.path, ready.sha, "f" * 64, CLIENT_ID, "exited")
        assert world.calls == 0
        return
    elif scene != "missing_start":
        query = world.query

        def changed(*args, **kwargs):
            raw = query(*args, **kwargs)
            if args[0] == "container":
                if scene == "intent":
                    ready.store.request("redis")
                else:
                    when = inspection.time.monotonic() + 21
                    monkeypatch.setattr(inspection.time, "monotonic", lambda: when)
            return raw

        monkeypatch.setattr(world, "query", changed)
    with pytest.raises(inspection.ActivationError):
        world.review("exited")


def test_real_cli_mount_projection_covers_four_readonly_binds_and_redacts_host_paths(spec, render):
    raw = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": source,
                "Destination": target,
                "RW": False,
                "Propagation": "rprivate",
            }
            for target, source in spec["mount_sources"].items()
        ],
        "HostConfig": {
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": source,
                    "Target": target,
                    "ReadOnly": True,
                    "BindOptions": {"Propagation": "rprivate"},
                }
                for target, source in spec["mount_sources"].items()
            ]
        },
    }
    template = (
        '{"mounts":'
        + inspection.server._mounts(spec, effective=True)
        + ',"configured_mounts":'
        + inspection.server._mounts(spec, effective=False)
        + "}"
    )
    result = render(template, document=raw)
    assert len(result["mounts"]) == len(result["configured_mounts"]) == 4
    assert all(item["source_matches"] and not item["writable"] for item in result["mounts"])
    assert all(source not in json.dumps(result) for source in spec["mount_sources"].values())
    altered = copy.deepcopy(raw)
    altered["Mounts"][-1]["Source"] = "/foreign/previous-ca.crt"
    assert render(template, document=altered)["mounts"][-1]["source_matches"] is False
