"""Cold archive/ownership/cleanup failures; fake daemon, never original volumes."""

import copy
import json
import shutil
import sys
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from aegis.operations import lab_backup as snapshot
from test_binding_review import binding_lab as binding_lab  # noqa: F401
from test_lab_backup import prepared as prepared  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import lab_recovery_runtime as runtime  # noqa: E402
import lab_recovery_transport as transport  # noqa: E402

IMAGE = "sha256:" + "d" * 64


def projection(spec, identifier, operation):
    return {
        "id": identifier,
        "name": "/" + spec["name"],
        "image": spec["image"],
        "labels": {
            runtime.LABEL: operation.identifier,
            "io.aegis.lab-recovery-plan": operation.plan_hash,
        },
        "user": spec["user"],
        "entrypoint": [spec["entrypoint"]],
        "args": spec["arguments"],
        "state": "created",
        "exit": 0,
        "networks": {
            "none": {"IPAddress": "", "GlobalIPv6Address": "", "Gateway": "", "IPv6Gateway": ""}
        },
        "mounts": [
            {
                "Destination": m["target"],
                "Type": m["type"],
                "Source": m["source"],
                "Name": m["source"],
                "RW": not m["readonly"],
            }
            for m in spec["mounts"]
        ],
        "host": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": spec["memory"],
            "MemorySwap": spec["memory"],
            "NanoCpus": runtime.CPU_NANOSECONDS,
            "BlkioDeviceReadBps": [
                {"Path": runtime.IO_DEVICE, "Rate": runtime.IO_BYTES_PER_SECOND}
            ],
            "BlkioDeviceWriteBps": [
                {"Path": runtime.IO_DEVICE, "Rate": runtime.IO_BYTES_PER_SECOND}
            ],
            "PidsLimit": 64,
            "RestartPolicy": {"Name": "no"},
            "AutoRemove": False,
            "PortBindings": {},
            "PublishAllPorts": False,
            "Devices": [],
            "DeviceRequests": None,
            "VolumesFrom": None,
            "Links": None,
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "LogConfig": {"Type": "none"},
            "Tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=64m",
                **(
                    {runtime.DATA: "rw,noexec,nosuid,nodev,size=1m"}
                    if not any(m["target"] == runtime.DATA for m in spec["mounts"])
                    else {}
                ),
            },
            "Mounts": [
                {
                    "Type": m["type"],
                    "Source": m["source"],
                    "Target": m["target"],
                    "ReadOnly": m["readonly"],
                    "VolumeOptions": {"NoCopy": True},
                    "BindOptions": {"Propagation": "rprivate"},
                }
                for m in spec["mounts"]
            ],
        },
    }


class Daemon:
    def __init__(self, operation):
        self.operation, self.objects, self.calls = operation, {}, []
        self.mode = None

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[0] == "ps":
            name = args[args.index("--filter") + 1].removeprefix("name=^/").removesuffix("$")
            return (
                (self.objects[name]["id"] + " " + name + "\n").encode()
                if name in self.objects
                else b""
            )
        if args[0] == "create":
            assert self.operation.events[-1]["kind"] == "create_requested"
            spec = self.operation.events[-1]["data"]["recipe"]
            if self.mode == "lost_absent":
                raise snapshot.SnapshotError("fixture_lost_create_response")
            identifier = f"{len(self.objects) + 1:064x}"
            self.objects[spec["name"]] = projection(spec, identifier, self.operation)
            if self.mode == "lost_created":
                raise snapshot.SnapshotError("fixture_lost_create_response")
            return identifier.encode()
        item = next((v for k, v in self.objects.items() if args[-1] in (k, v["id"])), None)
        if args[0] == "inspect":
            return json.dumps(item).encode()
        if args[0] == "start":
            assert self.operation.events[-1]["kind"] == "start_requested"
            item["state"] = "exited" if "-a" in args else "running"
            return b""
        if args[0] == "stop":
            item["state"] = "exited"
            return b""
        if args[0] == "rm":
            if self.mode == "cleanup_failed":
                raise snapshot.SnapshotError("fixture_cleanup_failed")
            assert "--force" not in args and "-v" not in args
            del self.objects[item["name"].removeprefix("/")]
            return b""
        if args[0] == "exec":
            return b""
        pytest.fail("Unexpected native command")


@pytest.fixture
def owned(tmp_path, monkeypatch):
    operation = runtime.Operation(tmp_path / "operation", "a" * 64)
    daemon = Daemon(operation)
    monkeypatch.setattr(transport, "run", daemon)
    yield operation, daemon
    daemon.mode = None
    try:
        runtime.Operation.load_cleanup(operation.folder, digest(operation.events[0])).cleanup()
    except (ValueError, OSError):
        if operation.workspace is not None and operation.workspace.exists():
            shutil.rmtree(operation.workspace)  # Mock-only resources, no real containers.


def test_durable_requests_and_loaded_cleanup_never_repeat_an_effect(owned):
    operation, daemon = owned
    identifier = operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [])
    operation.start("fixture")
    operation.execute("fixture", "/usr/bin/true", [])
    loaded = runtime.Operation.load_cleanup(operation.folder, digest(operation.events[0]))
    assert loaded.resources["fixture"]["id"] == identifier
    with pytest.raises(snapshot.SnapshotError, match="deadline"):
        loaded.start("fixture")
    loaded.cleanup()
    assert not daemon.objects
    assert sum(args[0] == "create" for args in daemon.calls) == 1
    assert sum(args[0] == "start" for args in daemon.calls) == 1
    # Loading after cleanup validates the entire chain, including immutable recipes.
    runtime.Operation.load_cleanup(operation.folder, digest(operation.events[0]))


@pytest.mark.parametrize("mode", ["lost_absent", "lost_created"])
def test_ambiguous_create_is_not_retried_and_absence_is_not_cleanup_proof(owned, mode):
    operation, daemon = owned
    daemon.mode = mode
    with pytest.raises(snapshot.SnapshotError, match="lost_create"):
        operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [])
    with pytest.raises(snapshot.SnapshotError, match="replay"):
        operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [])
    daemon.mode = None
    if mode == "lost_absent":
        with pytest.raises(snapshot.SnapshotError, match="cleanup_unconfirmed"):
            operation.cleanup()
        assert not any(e["kind"] == "cleanup_verified" for e in operation.events)
    else:
        operation.cleanup()
        assert not daemon.objects
        assert any(e["kind"] == "ownership_discovered" for e in operation.events)
    assert sum(a[0] == "create" for a in daemon.calls) == 1


@pytest.mark.parametrize(
    "problem",
    ["image", "owner", "network", "extra_network", "address", "memory", "rw", "mount_extra"],
)
def test_changed_runtime_retains_owned_resources_for_review(owned, problem):
    operation, daemon = owned
    operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [])
    item = next(iter(daemon.objects.values()))
    original = copy.deepcopy(item)
    if problem == "image":
        item["image"] = "sha256:" + "0" * 64
    elif problem == "owner":
        item["labels"][runtime.LABEL] = "foreign"
    elif problem == "network":
        item["host"]["NetworkMode"] = "host"
    elif problem == "extra_network":
        item["networks"]["bridge"] = {}
    elif problem == "address":
        item["networks"]["none"]["IPAddress"] = "192.0.2.10"
    elif problem == "memory":
        item["host"]["Memory"] = 0
    elif problem == "rw":
        item["host"]["ReadonlyRootfs"] = False
    else:
        item["mounts"].append(
            {"Destination": "/docker", "Type": "bind", "Source": "/var/run/docker.sock", "RW": True}
        )
    with pytest.raises(snapshot.SnapshotError):
        operation.cleanup()
    assert daemon.objects and not any(a[0] == "rm" for a in daemon.calls)
    item.clear()
    item.update(original)


def test_cleanup_failure_keeps_workspace_and_deadline_does_not_block_cleanup(owned):
    operation, daemon = owned
    workspace = operation.scratch()
    operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [])
    operation.start("fixture")
    operation.deadline = 0
    daemon.mode = "cleanup_failed"
    with pytest.raises(snapshot.SnapshotError, match="cleanup_unconfirmed"):
        operation.cleanup()
    assert workspace.exists() and daemon.objects
    daemon.mode = None
    operation.cleanup()
    assert not workspace.exists() and not daemon.objects


@pytest.mark.parametrize(
    "mount",
    [
        runtime.mount("aegis-linux-lab_postgres-data", "/source", kind="volume"),
        runtime.mount("third-party", "/source", readonly=True, kind="volume"),
        runtime.mount("/var/run/docker.sock", "/socket"),
    ],
)
def test_original_rw_unknown_volume_and_foreign_host_mounts_are_rejected(owned, mount):
    operation, daemon = owned
    with pytest.raises(snapshot.SnapshotError):
        operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [mount])
    assert not any(a[0] == "create" for a in daemon.calls)


def test_changed_event_chain_is_not_a_resume_capability(owned):
    operation, _ = owned
    operation.event("observation", {"value": 1})
    target = operation.folder / "0001.json"
    data = json.loads(target.read_bytes())
    data["previous_sha256"] = "0" * 64
    target.write_text(json.dumps(data))
    with pytest.raises(snapshot.SnapshotError, match="chain"):
        runtime.Operation.load_cleanup(operation.folder, digest(operation.events[0]))


def test_same_schema_rows_require_matching_search_path_for_structural_inventory(prepared):
    engine, _, context, _, _ = prepared
    from sqlalchemy import text

    with engine.connect() as conn:
        first = snapshot.backup.inventory(
            lambda sql: conn.execute(text(sql)).scalars(), context.database_schema
        )
        conn.execute(text("SET LOCAL search_path=public"))
        second = snapshot.backup.inventory(
            lambda sql: conn.execute(text(sql)).scalars(), context.database_schema
        )
    assert first["tables"] == second["tables"]
    assert first["structure"] != second["structure"]


@pytest.mark.parametrize(
    "problem", ["provider", "encoding", "locale", "injection", "unknown", "version"]
)
def test_database_properties_reject_unreviewed_or_sql_like_input_before_restore(problem):
    value = {
        "format": "aegis-pg-database-properties/1",
        "encoding": "UTF8",
        "provider": "c",
        "lc_collate": "C.UTF-8",
        "lc_ctype": "C.UTF-8",
        "collation_version": None,
    }
    if problem == "provider":
        value["provider"] = "i"
    elif problem == "encoding":
        value["encoding"] = "LATIN1"
    elif problem == "locale":
        value["lc_collate"] = ""
    elif problem == "injection":
        value["lc_ctype"] = "C'; DROP DATABASE aegis; --"
    elif problem == "unknown":
        value["sql"] = "unreviewed"
    else:
        value["format"] = "unknown/2"
    with pytest.raises(snapshot.SnapshotError, match="properties_unsupported"):
        runtime.restore(None, None, None, None, value)


@pytest.mark.parametrize(
    "code", ["recovery_original_consumer_present", "recovery_transport_failed"]
)
def test_postgres_readiness_does_not_retry_a_failed_scope_gate(owned, code):
    operation, _ = owned
    root = runtime.postgres_files(operation, "fixture-source")
    checks = []

    def guard():
        checks.append(True)
        if len(checks) > 2:
            raise snapshot.SnapshotError(code)

    operation.before_effect = guard
    with pytest.raises(snapshot.SnapshotError, match=code):
        runtime.start_postgres(operation, "fixture-source", IMAGE, root, fresh=False)
    assert len(checks) == 3
