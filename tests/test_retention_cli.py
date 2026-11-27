import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from aegis.operations import vault
from test_retention_store import store as store

ROOT = Path(__file__).resolve().parents[1]


def run(root, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/history_retention.py"), "--store", str(root), *args],
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_cli_plan_and_dry_run_are_read_only_and_require_no_key(store, tmp_path):
    root, *_ = store
    before = {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = run(root, "plan")
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    path = tmp_path / "plan.json"
    vault.write_json(path, plan)
    result = run(
        root, "apply", "--plan", str(path), "--expected-sha256", plan["sha256"], "--dry-run"
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "dry_run"
    assert before == {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_cli_confirmation_without_approval_and_keys_refuses(store, tmp_path):
    root, *_ = store
    plan = json.loads(run(root, "plan").stdout)
    path = tmp_path / "plan.json"
    vault.write_json(path, plan)
    result = run(
        root,
        "apply",
        "--plan",
        str(path),
        "--expected-sha256",
        plan["sha256"],
        "--confirm-remove-copies",
    )
    assert result.returncode != 0 and "No sensitive details" in result.stderr
    assert not list((root / "receipts").iterdir())


def test_cli_does_not_print_raw_coordinator_errors_or_secrets(store, monkeypatch, capsys):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    cli = importlib.import_module("history_retention")
    monkeypatch.setattr(sys, "argv", ["history_retention.py", "--store", str(store[0]), "plan"])

    def sensitive(*args):
        raise RuntimeError("private-database-row-and-private-key")

    monkeypatch.setattr(cli.store, "build_plan", sensitive)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert "private-database-row" not in str(error.value)
    assert "No sensitive details" in str(error.value)
    assert "private-database-row" not in capsys.readouterr().out
