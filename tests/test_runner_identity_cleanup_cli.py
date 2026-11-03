"""Cleanup CLI lock/resume/pins boundaries; cloned private histories, no native daemon."""

import json
import shutil
import sys
from pathlib import Path

import pytest
from test_runner_identity_cleanup import code as code
from test_runner_identity_cleanup import context as context
from test_runner_identity_cleanup import material as material
from test_runner_identity_cleanup import prepared as prepared

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_cleanup as cli  # noqa: E402


def test_plan_and_run_resume_only_original_history_without_touching_live_fixture_history(
    prepared, tmp_path, monkeypatch
):
    c, world, runtime, *_ = prepared
    history = tmp_path / "history-clone"
    shutil.copytree(c.store.root, history)
    monkeypatch.setattr(cli, "ROOT", tmp_path / "cli-policies")
    originals = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in c.store.folder.iterdir()}
    report = cli.prepare_from_original(
        c.path,
        c.plan_sha256,
        c.operation,
        c.begin_sha256,
        intents_root=history,
        runtime_root=runtime,
    )
    assert world.effects == [] and report["cleanup_executed"] is False
    identifier = Path(report["plan_path"]).parent.name
    receipt = cli.run_from_ids(
        identifier,
        report["plan_sha256"],
        report["scope_sha256"],
        confirm_owned_cleanup=True,
        intents_root=history,
        docker=world,
        ownership_docker=world,
    )
    assert receipt["status"] == "identity_owned_cleanup_verified_and_closed"
    assert receipt["assay_resumed"] is False and world.effects == []
    assert c.store.review()["resources"]["network-isolated"]["state"] == "REQUESTED"
    assert originals == {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in c.store.folder.iterdir()
    }
    with pytest.raises((ValueError, OSError)):
        cli.run_from_ids(
            identifier,
            report["plan_sha256"],
            report["scope_sha256"],
            confirm_owned_cleanup=True,
            intents_root=history,
            docker=world,
            ownership_docker=world,
        )


def test_wrong_original_begin_hash_cannot_create_policy_or_lock_another_history(
    prepared, tmp_path, monkeypatch
):
    c, world, runtime, *_ = prepared
    history = tmp_path / "history-clone"
    shutil.copytree(c.store.root, history)
    root = tmp_path / "cli-policies"
    monkeypatch.setattr(cli, "ROOT", root)
    with pytest.raises(cli.ActivationError, match="origin_integrity_mismatch"):
        cli.prepare_from_original(
            c.path, c.plan_sha256, c.operation, "f" * 64, intents_root=history, runtime_root=runtime
        )
    assert not root.exists() and world.effects == []


@pytest.mark.parametrize("confirmation", [False, 1, None])
def test_run_confirmation_precedes_every_read_and_lock(monkeypatch, confirmation):
    monkeypatch.setattr(cli, "load", lambda *a: pytest.fail("no IO"))
    with pytest.raises(cli.ActivationError, match="explicit_confirmation_required"):
        cli.run_from_ids("a" * 32, "b" * 64, "c" * 64, confirm_owned_cleanup=confirmation)


def test_cli_plan_uses_only_fixed_original_root_and_explicit_pins(monkeypatch, capsys):
    calls = []

    def prepare(path, expected, operation, begin):
        calls.append((path, expected, operation, begin))
        return {"cleanup_executed": False, "normal_operation_permitted": False}

    monkeypatch.setattr(cli, "prepare_from_original", prepare)
    assert (
        cli.main(
            [
                "plan",
                "--original-plan-id",
                "a" * 32,
                "--original-plan-sha256",
                "b" * 64,
                "--operation-id",
                "c" * 32,
                "--begin-sha256",
                "d" * 64,
            ]
        )
        == 0
    )
    assert calls == [
        (
            cli.plan.ROOT / ".local/pki-activation-plans" / ("a" * 32) / "plan.json",
            "b" * 64,
            "c" * 32,
            "d" * 64,
        )
    ]
    assert json.loads(capsys.readouterr().out)["cleanup_executed"] is False


def arguments():
    return [
        "run",
        "--cleanup-plan-id",
        "a" * 32,
        "--expected-sha256",
        "b" * 64,
        "--authorized-scope-sha256",
        "c" * 64,
    ]


def test_cli_run_missing_confirmation_cannot_dispatch(monkeypatch):
    monkeypatch.setattr(cli, "run_from_ids", lambda *a, **kw: pytest.fail("no cleanup"))
    with pytest.raises(SystemExit) as caught:
        cli.main(arguments())
    assert caught.value.code == 2


@pytest.mark.parametrize("verified,exit_code", [(True, 0), (False, 1)])
def test_cli_run_pins_and_status_exit_are_not_inferred_from_plain_exit_zero(
    monkeypatch, capsys, verified, exit_code
):
    result = {"managed_resources_absence_verified": verified, "assay_resumed": False}

    def run(identifier, expected, scope, **kwargs):
        assert (identifier, expected, scope) == ("a" * 32, "b" * 64, "c" * 64)
        assert kwargs == {"confirm_owned_cleanup": True}
        return result

    monkeypatch.setattr(cli, "run_from_ids", run)
    assert cli.main([*arguments(), "--confirm-owned-cleanup"]) == exit_code
    assert json.loads(capsys.readouterr().out) == {
        "receipt": result,
        "receipt_body_sha256": cli.digest(result),
    }


def test_cli_redacts_native_or_path_exception_content(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "run_from_ids",
        lambda *a, **kw: (_ for _ in ()).throw(OSError("private-sensitive-sentinel")),
    )
    assert cli.main([*arguments(), "--confirm-owned-cleanup"]) == 1
    output = capsys.readouterr().out
    assert "private-sensitive-sentinel" not in output
    assert json.loads(output)["normal_operation_permitted"] is False
