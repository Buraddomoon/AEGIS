"""Native CLI admission/one-use boundaries only; coordinator is an explicit fixture."""

import json
import sys
from pathlib import Path

import pytest
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_assay as cli  # noqa: E402
from runner_identity_artifacts import IdentityArtifacts  # noqa: E402

INPUTS = {"build_id": "a" * 32, "build_plan_sha256": "b" * 64, "build_receipt_sha256": "c" * 64}


@pytest.fixture
def prepared(material, code, tmp_path, monkeypatch):
    result, _ = prepare(material, tmp_path)
    path, calls = Path(result["plan_path"]), []
    monkeypatch.setattr(cli, "DEFAULT_ROOT", tmp_path / "intents")
    recheck = cli.plan.recheck

    def check(selected, expected):
        from test_runner_activation_metadata import FakeDocker

        calls.append("recheck")
        return recheck(selected, expected, docker=FakeDocker())

    def image(inputs, selected, commit, *, repo):
        assert inputs == INPUTS and repo == code and commit == cli.plan.tool_state()
        assert (
            selected
            == cli.plan.load_plan(path, result["plan_sha256"])["metadata"]["images"]["runner"]["id"]
        )
        calls.append("image")
        return {"explicit_sealed_boundary_fixture": True}

    monkeypatch.setattr(cli.plan, "recheck", check)
    monkeypatch.setattr(cli.image, "review", image)
    return path, result, calls, tmp_path


def run(prepared, **kwargs):
    path, result, _, _ = prepared
    return cli.run(
        path,
        result["plan_sha256"],
        result["scope_sha256"],
        INPUTS,
        confirm_identity_only_assay=True,
        **kwargs,
    )


@pytest.mark.parametrize("confirmation", [False, 1, None, "yes"])
def test_explicit_literal_confirmation_precedes_every_file_read_or_lock(monkeypatch, confirmation):
    monkeypatch.setattr(cli.plan, "load_plan", lambda *a: pytest.fail("no file IO"))
    with pytest.raises(cli.ActivationError, match="explicit_confirmation_required"):
        cli.run(
            Path("ignored"), "a" * 64, "b" * 64, INPUTS, confirm_identity_only_assay=confirmation
        )


def test_scope_mismatch_and_consumed_plan_fail_before_preflight_or_source_review(prepared):
    path, result, calls, _ = prepared
    with pytest.raises(cli.ActivationError, match="authorized_scope_mismatch"):
        cli.run(path, result["plan_sha256"], "f" * 64, INPUTS, confirm_identity_only_assay=True)
    fence = path.parent / "identity-assay-requested.json"
    fence.write_bytes(b"{}")
    fence.chmod(0o600)
    with pytest.raises(cli.ActivationError, match="plan_already_consumed"):
        run(prepared)
    assert calls == []


def test_scope_lock_preflight_source_review_and_original_budget_precede_coordinator(
    prepared, monkeypatch
):
    path, result, calls, root = prepared

    def execute(c, inputs):
        assert inputs == INPUTS and calls == ["recheck", "image"]
        assert c.plan_sha256 == result["plan_sha256"] and c.scope == result["scope_sha256"]
        assert c._guard()["header"]["plan_id"] == path.parent.name
        assert 0 < (c.expires - c.started_at).total_seconds() <= 240
        assert c.store.has_plan_history(c.plan_sha256) is True
        # Explicit coordinator fixture, not an assay/TLS result. Record its
        # consumption and close an empty intent without any native calls.
        with IdentityArtifacts(c, root=root / "records"):
            images = {key: c.artifact["metadata"]["images"][key]["id"] for key in cli.plan.IMAGES}
            cli.coordinator.closure.cleanup(c.store, images)
        calls.append("coordinator")
        return {
            "status": "identity_assay_inconclusive_and_closed",
            "normal_operation_permitted": False,
        }

    monkeypatch.setattr(cli.coordinator, "execute", execute)
    observed = run(prepared)
    assert observed["status"] == "identity_assay_inconclusive_and_closed"
    assert calls == ["recheck", "image", "coordinator"]
    with pytest.raises(cli.ActivationError, match="plan_already_consumed"):
        run(prepared)
    assert calls == ["recheck", "image", "coordinator"]


def test_closed_empty_failed_attempt_still_consumes_plan_history_without_fence(
    prepared, monkeypatch
):
    path, _, calls, _ = prepared
    monkeypatch.setattr(
        cli.coordinator, "execute", lambda *a: (_ for _ in ()).throw(OSError("fixture"))
    )
    with pytest.raises(OSError):
        run(prepared)
    assert not (path.parent / "identity-assay-requested.json").exists()
    assert calls == ["recheck", "image"]
    with pytest.raises(cli.ActivationError, match="plan_already_consumed"):
        run(prepared)
    assert calls == ["recheck", "image"]


def test_nonempty_interrupted_attempt_is_preserved_for_owned_recovery(prepared, monkeypatch):
    def interrupted(c, inputs):
        c.store.request("network-isolated")
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.coordinator, "execute", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run(prepared)
    with cli.ActivationIntents(cli.DEFAULT_ROOT) as store:
        states = store._histories()
        assert len(states) == 1
        assert (
            next(iter(states.values()))[1]["resources"]["network-isolated"]["state"] == "REQUESTED"
        )
        assert next(iter(states.values()))[1]["closed"] is False


def arguments():
    return [
        "--plan-id",
        "a" * 32,
        "--expected-sha256",
        "a" * 64,
        "--authorized-scope-sha256",
        "b" * 64,
        "--build-id",
        "c" * 32,
        "--build-plan-sha256",
        "d" * 64,
        "--build-receipt-sha256",
        "e" * 64,
    ]


def test_main_requires_identity_only_confirmation_flag_before_dispatch(monkeypatch):
    monkeypatch.setattr(cli, "run", lambda *a, **kw: pytest.fail("no execution"))
    with pytest.raises(SystemExit) as caught:
        cli.main(arguments())
    assert caught.value.code == 2


@pytest.mark.parametrize(
    "status,code",
    [("identity_assay_verified_and_closed", 0), ("identity_assay_inconclusive_and_closed", 1)],
)
def test_main_uses_fixed_plan_root_closed_build_inputs_and_explicit_status_exit(
    monkeypatch, capsys, status, code
):
    result = {"status": status, "normal_operation_permitted": False}

    def run(path, expected, authorized, inputs, **kwargs):
        assert path == cli.plan.ROOT / ".local/pki-activation-plans" / ("a" * 32) / "plan.json"
        assert expected == "a" * 64 and authorized == "b" * 64
        assert inputs == {
            "build_id": "c" * 32,
            "build_plan_sha256": "d" * 64,
            "build_receipt_sha256": "e" * 64,
        }
        assert kwargs == {"confirm_identity_only_assay": True}
        return result

    monkeypatch.setattr(cli, "run", run)
    assert cli.main([*arguments(), "--confirm-identity-only-assay"]) == code
    output = json.loads(capsys.readouterr().out)
    assert output == {"receipt": result, "receipt_body_sha256": cli.digest(result)}


def test_main_does_not_expose_arbitrary_exception_or_path(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "run", lambda *a, **kw: (_ for _ in ()).throw(OSError("private-sensitive-sentinel"))
    )
    assert cli.main([*arguments(), "--confirm-identity-only-assay"]) == 1
    output = capsys.readouterr().out
    assert "private-sensitive-sentinel" not in output
    assert json.loads(output)["normal_operation_permitted"] is False
