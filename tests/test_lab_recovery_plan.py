"""Closed native plans and failed-operation cleanup; daemon fixtures only."""

import contextlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from aegis.domain.validation import digest
from aegis.operations import lab_backup as snapshot
from test_lab_recovery import IMAGE, Daemon

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import lab_recovery as coordinator  # noqa: E402
import lab_recovery_runtime as runtime  # noqa: E402
import lab_recovery_transport as transport  # noqa: E402


@pytest.fixture(autouse=True)
def capped_host_fixture(monkeypatch):
    # Plan/daemon fixtures have no real data effects. The cgroup guard is tested
    # separately, including rejection before any original-volume access.
    monkeypatch.setattr(runtime, "check_host_budget", lambda: None)


def test_missing_specific_authorization_stops_before_any_metadata_or_effect(monkeypatch):
    monkeypatch.setattr(coordinator, "lock", lambda: pytest.fail("No work without authorization"))
    with pytest.raises(snapshot.SnapshotError, match="specific_authorization"):
        coordinator.run("a" * 32, "b" * 64, "c" * 64, True)
    with pytest.raises(snapshot.SnapshotError, match="specific_authorization"):
        coordinator.run("a" * 32, "b" * 64, "b" * 64, False)


def test_uncapped_host_stops_before_metadata_or_original_access(monkeypatch):
    def uncapped():
        raise snapshot.SnapshotError("recovery_host_disk_limit_required")

    monkeypatch.setattr(runtime, "check_host_budget", uncapped)
    monkeypatch.setattr(coordinator, "lock", lambda: pytest.fail("No uncapped data effects"))
    with pytest.raises(snapshot.SnapshotError, match="host_disk_limit_required"):
        coordinator.run("a" * 32, "b" * 64, "b" * 64, True)


@pytest.mark.parametrize(
    "problem", ["hash", "version", "expired", "code", "rw", "permission", "budget", "boolean_type"]
)
def test_plan_hash_expiration_code_and_closed_scope_are_not_authorization_shortcuts(
    tmp_path, monkeypatch, problem
):
    monkeypatch.setattr(coordinator, "ROOT", tmp_path)
    monkeypatch.setattr(coordinator, "source_hash", lambda: "a" * 64)
    identifier = "b" * 32
    folder = tmp_path / ".local/lab-recovery/plans" / identifier
    snapshot.vault.private_directory(folder)
    plan = {
        "format": coordinator.FORMAT,
        "id": identifier,
        "scope": dict(coordinator.SCOPE),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "coordinator_sha256": "a" * 64,
    }
    if problem == "version":
        plan["format"] = "unknown/2"
    elif problem == "expired":
        plan["expires_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    elif problem == "code":
        plan["coordinator_sha256"] = "c" * 64
    elif problem == "rw":
        plan["scope"]["original_mounts"] = "read_write"
    elif problem == "permission":
        plan["scope"]["normal_operation_permitted"] = True
    elif problem == "budget":
        plan["scope"]["minimum_available_memory"] = 0
    elif problem == "boolean_type":
        plan["scope"]["new_marker"] = 0
    snapshot.vault.write_json(folder / "plan.json", plan)
    with pytest.raises(snapshot.SnapshotError):
        coordinator.load(identifier, "0" * 64 if problem == "hash" else digest(plan))


def test_native_plan_is_one_use_and_prior_unknown_cleanup_blocks_new_work(tmp_path, monkeypatch):
    base, plan_folder = tmp_path / "base", tmp_path / "plan"
    snapshot.vault.private_directory(base / "operations")
    snapshot.vault.private_directory(plan_folder)
    monkeypatch.setattr(coordinator, "lock", contextlib.nullcontext)
    monkeypatch.setattr(coordinator, "load", lambda *_: (plan_folder, {}))
    monkeypatch.setattr(coordinator, "directories", lambda: base)
    monkeypatch.setattr(
        coordinator, "recheck", lambda *_: pytest.fail("No new original-volume access")
    )
    snapshot.vault.write_json(plan_folder / "requested.json", {"consumed": True})
    with pytest.raises(snapshot.SnapshotError, match="consumed_no_replay"):
        coordinator.run("a" * 32, "b" * 64, "b" * 64, True)
    (plan_folder / "requested.json").unlink()  # Synthetic fixture only, never production.
    (base / "operations/previous").mkdir(mode=0o700)
    with pytest.raises(snapshot.SnapshotError, match="prior_cleanup"):
        coordinator.run("c" * 32, "b" * 64, "b" * 64, True)


@pytest.mark.parametrize("problem", ["foreign_consumer", "project_container", "metadata_drift"])
def test_quiescence_checks_stopped_foreign_consumers_and_every_original(
    tmp_path, monkeypatch, problem
):
    monkeypatch.setattr(
        coordinator, "volume", lambda name, project, suffix: {"name": name, "identity": "original"}
    )

    def query(args, **_):
        assert args[0] == "ps" and "-a" in args
        value = args[-1]
        if problem == "foreign_consumer" and value.startswith("volume="):
            return b"f" * 64
        if problem == "project_container" and value.startswith("label="):
            return b"f" * 64
        return b""

    monkeypatch.setattr(transport, "run", query)
    expected = {
        project + "_" + suffix: {
            "name": project + "_" + suffix,
            "identity": "changed" if problem == "metadata_drift" else "original",
        }
        for project in coordinator.PROFILES.values()
        for suffix in ("postgres-data", "journal")
    }
    with pytest.raises(snapshot.SnapshotError):
        coordinator.quiescent(expected)


@pytest.mark.parametrize("failure", ["restore_failed", "interrupted", "cleanup_failed"])
def test_coordinator_failure_never_publishes_success_or_retries_source(
    tmp_path, monkeypatch, failure
):
    base, plan_folder = tmp_path / "base", tmp_path / "plan"
    snapshot.vault.private_directory(base / "operations")
    snapshot.vault.private_directory(plan_folder)
    plan = {"scope": dict(coordinator.SCOPE), "host_records": {}}
    monkeypatch.setattr(coordinator, "lock", contextlib.nullcontext)
    monkeypatch.setattr(coordinator, "load", lambda *_: (plan_folder, plan))
    monkeypatch.setattr(coordinator, "directories", lambda: base)
    monkeypatch.setattr(coordinator, "recheck", lambda *_: {})
    monkeypatch.setattr(coordinator, "roots", lambda: {})
    monkeypatch.setattr(coordinator.lab_archive, "capture_records", lambda *_: {})
    monkeypatch.setattr(
        coordinator.os, "statvfs", lambda *_: SimpleNamespace(f_bavail=8 * 1024**3, f_frsize=1)
    )
    original_read = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **kw: (
            "MemAvailable: 8388608 kB"
            if str(self) == "/proc/meminfo"
            else original_read(self, *a, **kw)
        ),
    )
    created = []

    def failed_profile(folder, key, received_plan, custody, deadline):
        assert (plan_folder / "requested.json").exists()
        operation = runtime.Operation(folder, digest(plan), deadline=deadline)
        snapshot.vault.write_json(
            folder.parent / (key + "-begin.json"), {"begin_sha256": digest(operation.events[0])}
        )
        daemon = Daemon(operation)
        monkeypatch.setattr(transport, "run", daemon)
        operation.scratch()
        operation.create("fixture", IMAGE, "/bin/tar", ["fixture"], [])
        created.append((operation, daemon))
        if failure == "cleanup_failed":
            daemon.mode = "cleanup_failed"
        if failure == "interrupted":
            raise KeyboardInterrupt()
        raise snapshot.SnapshotError("fixture_restore_failed")

    monkeypatch.setattr(coordinator, "profile", failed_profile)
    with pytest.raises(KeyboardInterrupt if failure == "interrupted" else snapshot.SnapshotError):
        coordinator.run("a" * 32, digest(plan), digest(plan), True)
    destination = next((base / "operations").iterdir())
    assert len(created) == 1 and not (destination / "verified.json").exists()
    assert (plan_folder / "requested.json").exists()
    failed = json.loads((destination / "failed.json").read_bytes())
    operation, daemon = created[0]
    assert failed["cleanup_verified"] is (failure != "cleanup_failed")
    assert (destination / "closed.json").exists() is (failure != "cleanup_failed")
    if failure == "cleanup_failed":
        assert operation.workspace.exists() and daemon.objects
        daemon.mode = None
        coordinator.cleanup_run(
            destination, digest(json.loads((destination / "begin.json").read_bytes()))
        )
    assert not daemon.objects and not operation.workspace.exists()


@pytest.mark.parametrize("problem", ["matching", "table_count", "old_revision"])
def test_native_original_profile_requires_exact_b7_context_without_migration(problem):
    descriptor = {
        "runner_id": str(uuid4()),
        "laboratory_id": str(uuid4()),
        "asset_id": str(uuid4()),
        "url": "https://192.168.253.2:8443",
        "server_ca_sha256": "a" * 64,
        "client_cert_sha256": "b" * 64,
        "protocol": "aegis-linux-runner/1",
        "test_id": "linux-file-marker/v1",
    }
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.mappings.return_value.all.return_value = [
        {
            "laboratory_id": descriptor["laboratory_id"],
            "configuration_hash": digest(descriptor),
            "environment_version": 6,
        }
    ]
    connection.scalars.return_value.all.side_effect = [
        [{"runner": descriptor}],
        ["b7f3c2d91a06" if problem != "old_revision" else "4b72c7bb8548"],
    ]
    connection.scalar.return_value = 34 if problem == "table_count" else 33
    images = {role: IMAGE for role in ("application", "runner", "postgres", "redis")}
    if problem != "matching":
        with pytest.raises(snapshot.SnapshotError, match="historical_b7"):
            coordinator.context_from_copy(engine, "aegis-linux-lab", images, "a" * 40)
    else:
        result = coordinator.context_from_copy(engine, "aegis-linux-lab", images, "a" * 40)
        assert result.schema_revision == "b7f3c2d91a06"
        assert result.descriptor == descriptor and result.environment_version == 6


@pytest.mark.parametrize("name", ["PGHOSTADDR", "PGSERVICE", "PGOPTIONS", "PGPASSFILE"])
def test_ambient_libpq_cannot_redirect_or_inject_before_any_work(monkeypatch, name):
    monkeypatch.setenv(name, "fixture-injected-environment")
    monkeypatch.setattr(
        coordinator, "lock", lambda: pytest.fail("No work before environment rejection")
    )
    with pytest.raises(snapshot.SnapshotError, match="libpq_environment_refused"):
        coordinator.run("a" * 32, "b" * 64, "b" * 64, True)
    with pytest.raises(snapshot.SnapshotError, match="libpq_environment_refused"):
        runtime.start_postgres(None, None, None, None, fresh=False)


@pytest.mark.parametrize(
    "problem", ["optional_missing", "postgres_extra_volume", "wrong_id", "wrong_os"]
)
def test_image_inventory_accepts_optional_absence_without_loosening_pg_profile(
    monkeypatch, problem
):
    values = {
        role: "sha256:" + code * 64
        for role, code in zip(("application", "runner", "postgres", "redis"), "abcd", strict=True)
    }

    def query(args, **_):
        assert args[:2] == ["image", "inspect"]
        identifier = args[-1]
        item = {
            "id": identifier,
            "os": "linux",
            "arch": "amd64",
            "volumes": {runtime.DATA: {}} if identifier == values["postgres"] else None,
        }
        if problem == "postgres_extra_volume" and identifier == values["postgres"]:
            item["volumes"]["/unexpected"] = {}
        elif problem == "wrong_id":
            item["id"] = "sha256:" + "0" * 64
        elif problem == "wrong_os":
            item["os"] = "windows"
        return json.dumps(item).encode()

    monkeypatch.setattr(transport, "run", query)
    images = {name: dict(values) for name in coordinator.PROFILES}
    if problem == "optional_missing":
        result = coordinator.image_metadata(images)
        assert result["linux"]["application"]["volumes"] is None
        assert result["wazuh"]["postgres"]["volumes"] == {runtime.DATA: {}}
    else:
        with pytest.raises(snapshot.SnapshotError):
            coordinator.image_metadata(images)
