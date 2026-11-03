"""Expired plan integrity supports cleanup only; normal recheck still fails closed."""

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation as activation  # noqa: E402


@pytest.fixture
def saved(material, code, tmp_path):
    result, _ = prepare(material, tmp_path)
    path = Path(result["plan_path"])
    return path, result["plan_sha256"], activation.load_plan(path, result["plan_sha256"])


def test_historical_plan_remains_read_only_after_expiry_without_renewing_normal_admission(
    saved, monkeypatch
):
    path, expected, original = saved
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    expires = activation.datetime.fromisoformat(original["expires_at"])
    monkeypatch.setattr(activation.pki, "clock", lambda: expires + timedelta(days=60))
    monkeypatch.setattr(activation, "snapshot", lambda *a, **kw: pytest.fail("no native recheck"))
    read = activation.pki.read

    def plan_only(selected, **kwargs):
        assert selected == path  # No keys/descriptor/journal/credentials.
        return read(selected, **kwargs)

    monkeypatch.setattr(activation.pki, "read", plan_only)
    monkeypatch.setattr(activation.pki, "openssl", lambda *a, **kw: pytest.fail("no PKI"))
    assert activation.load_for_cleanup(path, expected) == original
    with pytest.raises(activation.ActivationError, match="expired_or_invalid_time"):
        activation.load_plan(path, expected)
    with pytest.raises(activation.ActivationError, match="expired_or_invalid_time"):
        activation.recheck(path, expected)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize(
    "scene", ["hash", "scope", "profile", "duration", "integer_flag", "format"]
)
def test_expiry_bypass_does_not_bypass_integrity_or_closed_plan_policy(saved, scene):
    path, expected, original = saved
    if scene == "hash":
        expected = "f" * 64
    else:
        if scene == "scope":
            original["scope_sha256"] = "f" * 64
        elif scene == "profile":
            original["profile"]["marker_permitted"] = True
        elif scene == "duration":
            original["expires_at"] = (
                activation.datetime.fromisoformat(original["created_at"]) + timedelta(days=1)
            ).isoformat()
        elif scene == "integer_flag":
            original["normal_operation_permitted"] = 0
        else:
            original["format"] = "aegis-runner-activation-plan/1"
        path.write_text(json.dumps(original))
        expected = activation.digest(original)
    with pytest.raises(activation.ActivationError):
        activation.load_for_cleanup(path, expected)
