import copy
import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def inspector(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("inspect_wazuh_lab")


@pytest.fixture
def snapshot(inspector):
    """Docker-shaped fixture, not runtime evidence of an actual Wazuh service."""
    containers, networks, volumes = [], [], []
    for name, attached in inspector.NETWORKS.items():
        host = {
            "Privileged": False,
            "CapAdd": None,
            "Devices": [],
            "DeviceRequests": None,
            "DeviceCgroupRules": None,
            "VolumesFrom": None,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "CgroupnsMode": "private",
            "NetworkMode": "none"
            if name == "observer"
            else inspector.PROJECT + "_" + sorted(attached)[0],
            "Memory": inspector.MEMORY[name] * inspector.MIB,
            "PidsLimit": 0,
            "NanoCpus": 0,
            "SecurityOpt": ["no-new-privileges:true"]
            if name in inspector.HARDENED | {"wazuh.manager", "wazuh.agent"}
            else None,
            "CapDrop": ["ALL"] if name in inspector.HARDENED else None,
            "ReadonlyRootfs": name in inspector.HARDENED - {"wazuh.indexer"},
            "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18786"}]}
            if name == "api"
            else {},
            "PublishAllPorts": False,
            "Tmpfs": {"/tmp": ""} if name in {"api", "worker"} else None,
        }
        if name in inspector.LIMITS:
            host["PidsLimit"], host["NanoCpus"] = inspector.LIMITS[name]
        containers.append(
            {
                "id": "fixture-" + name,
                "service": name,
                "project": inspector.PROJECT,
                "oneoff": "False",
                "status": "exited" if name == "migrate" else "running",
                "exit_code": 0,
                "restarting": False,
                "oom_killed": False,
                "health": "healthy",
                "user": "1000:0" if name == "wazuh.indexer" else "10001:10001",
                "host": host,
                "ports": host["PortBindings"],
                "networks": {
                    "none" if key == "none" else inspector.PROJECT + "_" + key: {
                        "IPAddress": inspector.ADDRESSES.get((name, key), "")
                    }
                    for key in attached
                },
                "mounts": [
                    {
                        "Destination": target,
                        "Type": spec[0],
                        "Name": spec[1] if spec[0] == "volume" else None,
                        "Source": spec[1],
                        "RW": spec[2],
                    }
                    for target, spec in inspector.expected_mounts(inspector.PRIVATE)[name].items()
                ],
                "image_reference": inspector.IMAGES[name.removeprefix("wazuh.")]
                if name.startswith("wazuh.")
                else "aegis-wazuh-runner:local"
                if name in {"runner", "observer"}
                else "aegis-wazuh-platform:local"
                if name in {"api", "worker", "migrate"}
                else {"db": "postgres:17-alpine", "redis": "redis:8-alpine"}[name],
            }
        )
    for name in ("backend", "ingress", "isolated", "telemetry"):
        networks.append(
            {
                "Name": inspector.PROJECT + "_" + name,
                "Driver": "bridge",
                "Internal": name != "ingress",
                "EnableIPv6": False,
                "Labels": {"com.docker.compose.project": inspector.PROJECT},
                "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                "IPAM": {
                    "Config": [
                        {"Subnet": "172.30.89.0/29" if name == "isolated" else "172.30.90.0/29"}
                    ]
                },
                "Containers": {
                    item["id"]: {}
                    for item in containers
                    if item["status"] == "running" and name in inspector.NETWORKS[item["service"]]
                },
            }
        )
    for name in sorted(
        {
            spec[1]
            for service in inspector.expected_mounts(inspector.PRIVATE).values()
            for spec in service.values()
            if spec[0] == "volume"
        }
    ):
        volumes.append(
            {
                "Name": name,
                "Driver": "local",
                "Scope": "local",
                "Labels": {"com.docker.compose.project": inspector.PROJECT},
                "Options": {
                    "type": "tmpfs",
                    "device": "tmpfs",
                    "o": "size=1m,uid=10001,gid=10001,mode=0700,noexec,nosuid,nodev",
                }
                if name.endswith("_workspace")
                else None,
            }
        )
    return containers, networks, volumes


def service(snapshot, name):
    return next(item for item in snapshot[0] if item["service"] == name)


def test_reviewed_snapshot_and_missing_stack_are_distinct(inspector, snapshot):
    assert all(inspector.validate(*snapshot).values())
    assert not all(inspector.validate([], [], []).values())


@pytest.mark.parametrize(
    "change", ["extra-service", "duplicate-service", "other-project", "oneoff"]
)
def test_project_boundaries_fail_closed(inspector, snapshot, change):
    item = copy.deepcopy(snapshot[0][0])
    if change == "extra-service":
        item["service"] = "unreviewed"
    elif change == "other-project":
        item["project"] = "aegis"
    elif change == "oneoff":
        item["oneoff"] = "True"
    snapshot[0].append(item)
    assert not all(inspector.validate(*snapshot).values())


@pytest.mark.parametrize(
    ("name", "field", "value"),
    [
        ("runner", "Privileged", True),
        ("runner", "CapAdd", ["SYS_ADMIN"]),
        ("observer", "NetworkMode", "host"),
        ("worker", "PidMode", "host"),
        ("wazuh.agent", "IpcMode", "host"),
        ("wazuh.manager", "UTSMode", "host"),
        ("wazuh.indexer", "CgroupnsMode", "host"),
        ("api", "ReadonlyRootfs", False),
        ("runner", "Memory", 0),
        ("runner", "PidsLimit", 0),
        ("wazuh.manager", "NanoCpus", 0),
        ("observer", "Devices", [{"PathOnHost": "/dev/sda"}]),
        ("wazuh.manager", "DeviceCgroupRules", ["a *:* rwm"]),
        ("db", "SecurityOpt", ["seccomp:unconfined"]),
        ("runner", "CapDrop", []),
        ("runner", "Tmpfs", {"/work": "size=1m"}),
    ],
)
def test_host_escape_and_unbounded_resources_are_rejected(inspector, snapshot, name, field, value):
    service(snapshot, name)["host"][field] = value
    assert not all(inspector.validate(*snapshot).values())


@pytest.mark.parametrize("location", ["host", "runtime"])
def test_port_exposure_is_checked_in_requested_and_effective_state(inspector, snapshot, location):
    item = service(snapshot, "api")
    # Break shared fixture references, so only one side is changed.
    if location == "host":
        item["host"]["PortBindings"] = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18786"}]}
    else:
        item["ports"] = {"8080/tcp": [{"HostIp": "::", "HostPort": "18786"}]}
    assert not inspector.validate(*snapshot)["api.ports"]


@pytest.mark.parametrize(
    "change", ["socket", "workspace-rw", "other-volume", "ingest-key", "host-path"]
)
def test_mounts_cannot_expand_reviewed_scope(inspector, snapshot, change):
    item = service(snapshot, "observer")
    if change == "workspace-rw":
        next(m for m in item["mounts"] if m["Destination"] == "/work")["RW"] = True
    elif change == "other-volume":
        item["mounts"][0]["Name"] = "aegis-linux-lab_workspace"
    elif change == "socket":
        item["mounts"].append(
            {
                "Destination": "/var/run/docker.sock",
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "RW": False,
            }
        )
    else:
        item = service(snapshot, "api")
        item["mounts"][0]["Source"] = (
            str(inspector.PRIVATE / "pki/filebeat-key.pem")
            if change == "ingest-key"
            else "/etc/passwd"
        )
    assert not all(inspector.validate(*snapshot).values())


@pytest.mark.parametrize(
    "change",
    [
        "runner-to-siem",
        "foreign-member",
        "gateway",
        "address",
        "ipv6",
        "workspace-disk",
        "remote-volume",
    ],
)
def test_network_and_storage_isolation_are_not_inferred_from_container_labels(
    inspector, snapshot, change
):
    if change == "runner-to-siem":
        service(snapshot, "runner")["networks"][inspector.PROJECT + "_telemetry"] = {}
    elif change == "foreign-member":
        snapshot[1][2]["Containers"]["foreign-container"] = {}
    elif change == "gateway":
        snapshot[1][2]["Options"] = {}
    elif change == "ipv6":
        snapshot[1][2]["EnableIPv6"] = True
    elif change == "address":
        service(snapshot, "wazuh.agent")["networks"][inspector.PROJECT + "_telemetry"][
            "IPAddress"
        ] = "172.30.90.7"
    elif change == "workspace-disk":
        next(v for v in snapshot[2] if v["Name"].endswith("_workspace"))["Options"] = None
    else:
        snapshot[2][0]["Options"] = {
            "type": "nfs",
            "device": "external:/share",
            "o": "addr=192.0.2.1",
        }
    assert not all(inspector.validate(*snapshot).values())


@pytest.mark.parametrize(
    "change", ["unhealthy", "failed-migration", "wrong-user", "unpinned-image", "missing-agent"]
)
def test_process_presence_alone_does_not_pass(inspector, snapshot, change):
    if change == "unhealthy":
        service(snapshot, "observer")["health"] = "starting"
    elif change == "failed-migration":
        service(snapshot, "migrate")["exit_code"] = 1
    elif change == "wrong-user":
        service(snapshot, "runner")["user"] = "0:0"
    elif change == "unpinned-image":
        service(snapshot, "wazuh.indexer")["image_reference"] = "wazuh/wazuh-indexer:4.14.9"
    else:
        snapshot[0].remove(service(snapshot, "wazuh.agent"))
    assert not all(inspector.validate(*snapshot).values())


def test_collector_only_reads_exact_project_and_uses_safe_projections(
    inspector, snapshot, monkeypatch
):
    calls = []
    by_kind = dict(zip(("container", "network", "volume"), snapshot, strict=True))

    def execute(command, **kwargs):
        calls.append(command)
        assert command[: len(inspector.DOCKER)] == inspector.DOCKER
        assert kwargs == {"capture_output": True, "text": True, "timeout": 10}
        arguments = command[len(inspector.DOCKER) :]
        if arguments[0] == "inspect":
            kind = arguments[arguments.index("--type") + 1]
            return SimpleNamespace(stdout="\n".join(json.dumps(item) for item in by_kind[kind]))
        assert arguments[0] in {"ps", "network", "volume"}
        assert arguments[-2:] == ["--filter", "label=com.docker.compose.project=aegis-wazuh-lab"]
        kind = "container" if arguments[0] == "ps" else arguments[0]
        return SimpleNamespace(
            stdout="\n".join("fixture-" + str(i) for i in range(len(by_kind[kind])))
        )

    monkeypatch.setattr(inspector, "execute", execute)
    assert inspector.collect() == snapshot
    assert len(calls) == 6
    for command in calls:
        assert not set(command).intersection(
            {"exec", "up", "run", "pull", "build", "stop", "down", "rm"}
        )
    assert ".Config.Env" not in inspector.CONTAINER_FORMAT
    assert "{{json .Config}}" not in inspector.CONTAINER_FORMAT
    assert "{{json .HostConfig}}" not in inspector.CONTAINER_FORMAT


@pytest.mark.parametrize("listing", ["", "--host=external", "\n".join(["a"] * 17)])
def test_bad_inventory_never_reaches_inspect(inspector, monkeypatch, listing):
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout=listing)

    monkeypatch.setattr(inspector, "execute", execute)
    with pytest.raises(ValueError):
        inspector.collect()
    assert len(calls) == 1 and "inspect" not in calls[0]


def test_truncated_daemon_snapshot_is_not_accepted(inspector, monkeypatch):
    monkeypatch.setattr(
        inspector,
        "execute",
        lambda command, **kwargs: SimpleNamespace(
            stdout="{}\n" if "inspect" in command else "a\nb\n",
        ),
    )
    with pytest.raises(ValueError, match="incompleto"):
        inspector.collect()


def test_cli_reports_only_checks_and_never_raw_daemon_failure(
    inspector, snapshot, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "argv", ["inspect_wazuh_lab.py"])
    monkeypatch.setattr(inspector, "collect", lambda: snapshot)
    assert inspector.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["isolation_verified"] and output["inspection_completed"]
    assert "fixture-" not in json.dumps(output) and str(inspector.PRIVATE) not in json.dumps(output)
    service(snapshot, "api")["host"]["ReadonlyRootfs"] = False
    assert inspector.main() == 1
    assert not json.loads(capsys.readouterr().out)["isolation_verified"]

    def fail():
        raise subprocess.CalledProcessError(1, ["sensitive-command"], stderr="private-value")

    monkeypatch.setattr(inspector, "collect", fail)
    assert inspector.main() == 1
    output = capsys.readouterr().out
    assert not json.loads(output)["inspection_completed"]
    assert "private-value" not in output and "sensitive-command" not in output


def test_unknown_volume_names_do_not_escape_as_output_keys(inspector, snapshot):
    snapshot[2].append({"Name": "unexpected-sensitive-value"})
    checks = inspector.validate(*snapshot)
    assert not checks["volume_inventory"]
    assert "unexpected-sensitive-value" not in json.dumps(checks)


@pytest.mark.parametrize(
    ("kind", "label", "format_name"),
    [
        ("container", "com.docker.compose.service=worker", "CONTAINER_FORMAT"),
        ("container", "com.docker.compose.service=db", "CONTAINER_FORMAT"),
        ("network", "com.docker.compose.network=backend", "NETWORK_FORMAT"),
        ("volume", "com.docker.compose.volume=postgres-data", "VOLUME_FORMAT"),
    ],
)
def test_projection_against_existing_demo_objects_only_if_present(
    inspector, kind, label, format_name
):
    """Read-only regression: Go lookup of absent Health/Tmpfs must not crash.

    CI without the existing Demo skips this optional check; no container, network
    or volume is ever created. These are not Wazuh runtime acceptance tests.
    """
    if not shutil.which("docker"):
        pytest.skip("Docker CLI unavailable; no installation/startup in tests.")
    listing = ["ps", "--all", "--quiet"] if kind == "container" else [kind, "ls", "--quiet"]
    try:
        identifiers = inspector.execute(
            [
                *inspector.DOCKER,
                *listing,
                "--filter",
                "label=com.docker.compose.project=aegis",
                "--filter",
                "label=" + label,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        pytest.skip("Local Docker unavailable; do not start daemon/services.")
    if len(identifiers) != 1:
        pytest.skip("Existing own Demo object unavailable; do not create one.")
    output = inspector.execute(
        [
            *inspector.DOCKER,
            "inspect",
            "--type",
            kind,
            "--format",
            getattr(inspector, format_name),
            identifiers[0],
        ],
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    item = json.loads(output)
    if kind == "container":
        assert "Env" not in item and "Env" not in item.get("host", {})
        assert "DeviceCgroupRules" in item["host"]
        if label.endswith("=worker"):
            assert item["health"] == ""
        else:
            assert item["host"]["Tmpfs"] is None
    else:
        assert item["Labels"]["com.docker.compose.project"] == "aegis"
