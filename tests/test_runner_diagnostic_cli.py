"""Host entry-point boundaries with private fixture files/intents; no native Lab calls."""

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_build_review_runner import prepared as prepared
from test_runner_activation_image_source import repository as repository
from test_runner_diagnostic_plan import diagnostic as diagnostic

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_diagnostic as cli  # noqa: E402


@pytest.mark.parametrize(
    "scene", ["missing", "duplicate", "quoted", "interpolated", "mode", "link", "valid"]
)
def test_only_fixed_private_existing_runtime_credential_is_read(tmp_path, scene):
    repo = tmp_path / "repo"
    repo.mkdir(mode=0o700)
    content = "APP_DB_PASSWORD=" + "7" * 48 + "\n"
    if scene == "missing":
        content = "UNRELATED=ignored\n"
    elif scene == "duplicate":
        content += content
    elif scene == "quoted":
        content = 'APP_DB_PASSWORD="' + "7" * 48 + '"\n'
    elif scene == "interpolated":
        content = "APP_DB_PASSWORD=${UNTRUSTED}\n"
    path = repo / ".env"
    path.write_text(content)
    path.chmod(0o644 if scene == "mode" else 0o600)
    if scene == "link":
        path.rename(repo / "outside")
        path.symlink_to(repo / "outside")
    if scene == "valid":
        assert cli._password(repo) == "7" * 48
    else:
        with pytest.raises((ValueError, OSError)):
            cli._password(repo)


@pytest.mark.parametrize("confirmation", [False, 1, "yes", None])
def test_run_requires_explicit_boolean_confirmation_before_any_files_or_locks(
    monkeypatch, confirmation
):
    monkeypatch.setattr(cli.plan, "load", lambda *a: pytest.fail("No file read allowed"))
    with pytest.raises(ValueError, match="confirmation_required"):
        cli.run(Path("ignored"), "0" * 64, "0" * 64, confirm_original_database_start=confirmation)


def test_main_requires_confirmation_flag_without_loading_or_running(monkeypatch):
    monkeypatch.setattr(cli, "run", lambda *a, **k: pytest.fail("No execution allowed"))
    with pytest.raises(SystemExit) as caught:
        cli.main(
            [
                "run",
                "--plan-id",
                "0" * 32,
                "--expected-sha256",
                "0" * 64,
                "--authorized-scope-sha256",
                "0" * 64,
            ]
        )
    assert caught.value.code == 2


def test_run_refuses_other_scope_or_consumed_plan_before_credential_read(diagnostic, monkeypatch):
    folder, report, _, _, _ = diagnostic
    monkeypatch.setattr(cli, "_password", lambda *a: pytest.fail("No credential read allowed"))
    with pytest.raises(ValueError, match="scope_mismatch"):
        cli.run(folder, report["plan_sha256"], "0" * 64, confirm_original_database_start=True)
    cli.plan.image_build._write(folder / "diagnostic-requested.json", b"{}")
    with pytest.raises(ValueError, match="already_consumed"):
        cli.run(
            folder,
            report["plan_sha256"],
            report["scope_sha256"],
            confirm_original_database_start=True,
        )


def test_run_uses_shared_lock_rechecks_then_reads_secret_and_begins_pinned_intent(
    diagnostic, tmp_path, monkeypatch
):
    folder, report, _, _, options = diagnostic
    calls = []
    monkeypatch.setattr(cli, "DEFAULT_ROOT", tmp_path / "intents")
    monkeypatch.setattr(cli.plan, "ROOT", options["repo"])
    original = cli.plan.recheck

    def recheck(*args):
        calls.append("recheck")
        return original(*args, repo=options["repo"], docker=options["docker"])

    monkeypatch.setattr(cli.plan, "recheck", recheck)

    def password(repo):
        assert repo == options["repo"]
        calls.append("private_credential")
        return "private-sensitive-sentinel"

    monkeypatch.setattr(cli, "_password", password)

    def context(folder, sha, store, scope, expires):
        calls.append("context")
        assert store.review()["header"] == {
            "plan_id": report["plan_id"],
            "plan_sha256": report["plan_sha256"],
            "scope_sha256": report["scope_sha256"],
        }
        return SimpleNamespace(store=store)

    monkeypatch.setattr(cli.gates, "DiagnosticGates", context)

    def execute(context, password):
        calls.append("execute")
        assert password == "private-sensitive-sentinel"
        context.store.append("closed", {"evidence_sha256": "1" * 64})
        return {"diagnostic_verified": True}

    monkeypatch.setattr(cli.coordinator, "execute", execute)
    result = cli.run(
        folder, report["plan_sha256"], report["scope_sha256"], confirm_original_database_start=True
    )
    assert result["diagnostic_verified"]
    assert calls == ["recheck", "private_credential", "context", "execute"]


def test_owned_cleanup_remains_available_after_plan_expiry_without_secrets_or_new_work(
    diagnostic, tmp_path, monkeypatch
):
    folder, report, _, _, _ = diagnostic
    root = tmp_path / "intents"
    with cli.ActivationIntents(root) as store:
        begun = store.begin(report["plan_id"], report["plan_sha256"], report["scope_sha256"])
        request = {
            "plan_sha256": report["plan_sha256"],
            "scope_sha256": report["scope_sha256"],
            "operation_id": begun["id"],
            "begin_sha256": begun["begin_sha256"],
        }
        cli.plan.image_build._write(
            folder / "diagnostic-requested.json", json.dumps(request).encode()
        )
    monkeypatch.setattr(cli, "DEFAULT_ROOT", root)
    monkeypatch.setattr(cli.gates.database.server.policy, "DEFAULT_ROOT", tmp_path / "runtime")
    future = cli.plan.pki.clock() + timedelta(days=2)
    monkeypatch.setattr(cli.plan.pki, "clock", lambda: future)
    monkeypatch.setattr(cli, "_password", lambda *a: pytest.fail("Credentials forbidden"))
    monkeypatch.setattr(cli.plan, "recheck", lambda *a, **k: pytest.fail("New work forbidden"))
    with pytest.raises(ValueError):
        cli.plan.load(folder, report["plan_sha256"])
    result = cli.cleanup(folder, report["plan_sha256"], begun["id"], begun["begin_sha256"])
    assert result["managed_resources_absence_verified"] and result["operation_closed"]
    assert cli.cleanup(folder, report["plan_sha256"], begun["id"], begun["begin_sha256"])[
        "operation_closed"
    ]
    with pytest.raises(ValueError):
        cli.cleanup(folder, report["plan_sha256"], "0" * 32, begun["begin_sha256"])


def test_main_reports_static_errors_without_echoing_secrets(monkeypatch, capsys):
    def failed(*a, **k):
        raise ValueError("private-sensitive-sentinel")

    monkeypatch.setattr(cli, "run", failed)
    code = cli.main(
        [
            "run",
            "--plan-id",
            "0" * 32,
            "--expected-sha256",
            "0" * 64,
            "--authorized-scope-sha256",
            "0" * 64,
            "--confirm-original-database-start",
        ]
    )
    assert code == 1 and "private-sensitive-sentinel" not in capsys.readouterr().out


def test_import_does_not_read_secrets_spawn_or_connect():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('effect forbidden')
    if event == 'open' and isinstance(args[0], str) and (args[0].endswith('.env') or args[0].endswith('.key')):
        raise AssertionError('secret forbidden')
sys.addaudithook(guard)
import runner_diagnostic
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_context_failure_closes_only_its_fresh_empty_intent(diagnostic, tmp_path, monkeypatch):
    folder, report, _, _, _ = diagnostic
    root = tmp_path / "intents"
    monkeypatch.setattr(cli, "DEFAULT_ROOT", root)
    monkeypatch.setattr(cli.plan, "recheck", lambda *a: None)
    monkeypatch.setattr(cli, "_password", lambda *a: "private-sensitive-sentinel")

    def failed(*a, **k):
        raise ValueError("private-sensitive-sentinel")

    monkeypatch.setattr(cli.gates, "DiagnosticGates", failed)
    with pytest.raises(ValueError):
        cli.run(
            folder,
            report["plan_sha256"],
            report["scope_sha256"],
            confirm_original_database_start=True,
        )
    with cli.ActivationIntents(root) as store:
        histories = store._histories()
        assert len(histories) == 1
        assert all(state["closed"] and not state["resources"] for _, state in histories.values())


def test_prior_preparation_only_format_is_not_silently_executable(diagnostic):
    folder, report, _, _, _ = diagnostic
    artifact = cli.plan.load(folder, report["plan_sha256"])
    artifact["format"] = "aegis-runner-diagnostic-plan/2"
    path = folder / "plan.json"
    path.write_text(json.dumps(artifact))
    with pytest.raises(ValueError, match="policy_mismatch"):
        cli.plan.load(folder, cli.plan.digest(artifact))
