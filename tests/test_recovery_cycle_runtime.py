"""Host orchestration failure paths; actual Docker rehearsal remains opt-in."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from aegis.operations import recovered_demo
from test_backup_cli import ID, backup_cli
from test_backup_cli import archive as _archive

archive = _archive
SPEC = importlib.util.spec_from_file_location(
    "recovery_cycle_runtime",
    Path(__file__).resolve().parents[1] / "scripts/recovery_cycle_runtime.py",
)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
TOKEN = "a" * 32
IMAGE = "sha256:" + "b" * 64
REDIS = "sha256:" + "c" * 64
PLAN = "d" * 64


class Driver:
    def __init__(self, failure=None):
        self.failure = failure
        self.calls = []
        self.exists = set()
        self.removed = []
        self.env_paths = []
        self.environments = []
        self.payload = None
        self.intents = {}
        self.sql = []
        fresh = recovered_demo.context(TOKEN)
        self.probe = {
            "format": recovered_demo.FORMAT,
            "synthetic": True,
            "state": "COMPLETED",
            "run_id": "12345678-1234-4234-8234-123456789012",
            "fresh_account_id": fresh["account_id"],
            "laboratory_id": fresh["laboratory_id"],
            "outcomes": {
                "DETECTED": 1,
                "OBSERVED_NOT_ALERTED": 1,
                "NO_TELEMETRY": 1,
                "INCONCLUSIVE": 1,
            },
            "new_lab_revoked": True,
            "session_closed": True,
            "report_sha256": "e" * 64,
        }

    def write_json(self, path, value):
        self.intents[path.name] = value

    def clone_json(self, name, token, statement):
        assert name == "aegis-recovery-" + TOKEN and token == TOKEN
        self.sql.append(statement)
        if len(self.sql) == 1:
            return {
                "format": recovered_demo.FORMAT,
                **{k: v for k, v in recovered_demo.context(TOKEN).items() if k.endswith("_id")},
                "baseline_rows": 128,
            }
        if self.failure == "closure":
            raise ValueError("Injected closure failure")
        return {
            "format": recovered_demo.FORMAT,
            "historical_rows_unchanged": True,
            "fresh_account_disabled": True,
            "fresh_sessions_remaining": 0,
            "pending_runs": 0,
            "baseline_rows": 128,
        }

    def configure_hba(self, role):
        assert role == "aegis_app"

    def remove_clone(self, name, token):
        assert token == TOKEN
        self.removed.append(name.split("-")[-2])
        self.exists.discard(name)
        return "removed"

    def docker(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "create":
            name = args[args.index("--name") + 1]
            role = name.split("-")[-2]
            assert TOKEN + "-cycle-" + role + ".json" in self.intents
            env_path = Path(args[args.index("--env-file") + 1])
            self.env_paths.append(env_path)
            assert env_path.stat().st_mode & 0o777 == 0o600
            environment = dict(line.split("=", 1) for line in env_path.read_text().splitlines())
            self.environments.append(environment)
            assert not any(key.startswith(("WAZUH_", "LINUX_RUNNER_")) for key in environment)
            assert "--network=container:aegis-recovery-" + TOKEN in args
            for option in (
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--pull=never",
                "--user=10001:10001",
            ):
                assert option in args
            assert not any(
                option in args for option in ("-p", "--publish", "--volume", "-v", "--mount")
            )
            if self.failure == "create-before-" + role:
                raise ValueError("Injected create failure")
            self.exists.add(name)
            if self.failure == "create-after-" + role:
                raise ValueError("Injected ambiguous create failure")
        if args[0] == "start" and self.failure == "start-" + args[1].split("-")[-2]:
            raise ValueError("Injected start failure")
        if args[0] == "ps":
            return next((n.encode() for n in self.exists if "name=^/" + n + "$" in args), b"")
        if args[0] == "inspect":
            return (
                "wrong" if self.failure == "ownership-" + args[-1].split("-")[-2] else TOKEN
            ).encode()
        if args[0] == "stop" and self.failure == "cleanup-" + args[-1].split("-")[-2]:
            raise ValueError("Injected stop failure")
        if args[0] == "exec":
            assert "aegis.operations.recovery_cycle_probe" in args
            self.payload = json.loads(kwargs["stdin"].read())
            if self.failure == "probe":
                raise ValueError("Injected probe failure")
            return json.dumps({**self.probe, "synthetic": self.failure != "bad-probe"}).encode()
        return b""


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "probe",
        "bad-probe",
        "closure",
        *[
            stage + "-" + role
            for stage in ("create-before", "create-after", "start", "cleanup", "ownership")
            for role in ("redis", "api", "worker")
        ],
    ],
)
def test_children_cleanup_secret_transport_and_dependency_retention(tmp_path, failure):
    driver = Driver(failure)
    state = {"attempted": False, "confirmed": False}
    if failure:
        with pytest.raises(ValueError):
            runtime.run_cycle(
                driver, "aegis-recovery-" + TOKEN, TOKEN, IMAGE, REDIS, tmp_path, PLAN, state
            )
    else:
        result = runtime.run_cycle(
            driver, "aegis-recovery-" + TOKEN, TOKEN, IMAGE, REDIS, tmp_path, PLAN, state
        )
        assert (
            result["normal_demo_cycle_verified"] and result["closure"]["historical_rows_unchanged"]
        )
    assert state["attempted"]
    cleanup_uncertain = bool(failure and failure.startswith(("cleanup-", "ownership-")))
    assert state["confirmed"] is not cleanup_uncertain
    assert not any(p.exists() for p in driver.env_paths)
    if not failure or failure == "closure":
        assert driver.removed == ["worker", "api", "redis"]
    if cleanup_uncertain:
        failed_role = failure.split("-")[-1]
        for dependency in {"worker": ("api", "redis"), "api": ("redis",), "redis": ()}[failed_role]:
            assert dependency not in driver.removed
    secrets = []
    for environment in driver.environments:
        secrets += [value for key, value in environment.items() if key.endswith("PASSWORD")]
        if "DATABASE_URL" in environment:
            secrets += [environment["DATABASE_URL"], environment["REDIS_URL"]]
    if driver.payload:
        secrets += [driver.payload["password"]]
    args = json.dumps(driver.calls)
    intents = json.dumps(driver.intents)
    assert all(secret not in args and secret not in intents for secret in secrets)


def test_invalid_cycle_destination_refuses_before_sql(tmp_path):
    driver = Driver()
    with pytest.raises(ValueError, match="identity refused"):
        runtime.run_cycle(driver, "aegis-db-1", TOKEN, IMAGE, REDIS, tmp_path, PLAN, {})
    assert not driver.calls and not driver.sql


@pytest.mark.parametrize(
    "options", [{"demo_cycle": True}, {"demo_cycle": True, "application": True}]
)
def test_cycle_requires_reconciliation_before_archive_or_docker(monkeypatch, options):
    monkeypatch.setattr(backup_cli, "load_backup", lambda *a: pytest.fail("Archive read"))
    with pytest.raises(backup_cli.BackupError, match="requires"):
        backup_cli.rehearse(ID, **options)


@pytest.mark.parametrize("failure", [None, "cycle", "uncertain-cleanup", "schema-drift"])
def test_final_receipt_requires_cycle_schema_and_all_cleanup(archive, monkeypatch, failure):
    folder, manifest = archive
    original = manifest["inventory"]
    original["structure"] = {"schema": "hash"}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    calls = []
    inventory_calls = 0
    monkeypatch.setattr(backup_cli, "application_image", lambda: IMAGE)
    monkeypatch.setattr(
        backup_cli,
        "docker",
        lambda *a, **kw: (
            REDIS.encode() if a[0] == "image" else b"postgres\n" if "cat" in a else b""
        ),
    )
    monkeypatch.setattr(backup_cli, "clone_reconciliation", lambda *a: {"plan_sha256": PLAN})
    monkeypatch.setattr(backup_cli, "compare_reconciled", lambda *a: None)
    monkeypatch.setattr(
        backup_cli,
        "boot_application",
        lambda *a, **kw: {"review": {"reconciliation_applied": True}},
    )
    monkeypatch.setattr(
        backup_cli, "remove_clone", lambda *a: calls.append("db-removed") or "removed"
    )

    def inventory(*a):
        nonlocal inventory_calls
        inventory_calls += 1
        return (
            {**original, "structure": {"schema": "changed"}}
            if failure == "schema-drift" and inventory_calls == 4
            else original
        )

    def run(*args):
        state = args[-1]
        state["attempted"] = True
        if failure == "uncertain-cleanup":
            raise ValueError("Unconfirmed cleanup")
        state["confirmed"] = True
        if failure == "cycle":
            raise ValueError("Cycle failed")
        return {"normal_demo_cycle_verified": True}

    monkeypatch.setattr(backup_cli, "inventory", inventory)
    monkeypatch.setitem(sys.modules, "recovery_cycle_runtime", SimpleNamespace(run_cycle=run))
    if failure:
        with pytest.raises((ValueError, backup_cli.BackupError)):
            backup_cli.rehearse(ID, application=True, reconcile_demo=True, demo_cycle=True)
        assert not list(folder.glob("*verification-*.json"))
    else:
        receipt = backup_cli.rehearse(ID, application=True, reconcile_demo=True, demo_cycle=True)
        assert (
            receipt["demo_cycle"]["normal_demo_cycle_verified"]
            and receipt["redis_image_id"] == REDIS
        )
        assert len(list(folder.glob("demo-cycle-verification-*.json"))) == 1
    assert ("db-removed" in calls) == (failure != "uncertain-cleanup")
