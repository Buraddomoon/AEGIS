"""Private plans, real temporary PKI and Compose rendering; no lab lifecycle."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_cycle_prepare as package  # noqa: E402
from test_wazuh_pki_rotation import prepared as prepared  # noqa: E402
from wazuh_cycle_scope import IMAGE_ROLES  # noqa: E402


@pytest.fixture
def built(prepared, tmp_path, monkeypatch):
    source, services, services_sha, _, _ = prepared
    candidate = package.runner.prepare(
        source / "runner",
        package.runner.inspect(source / "runner")["inventory_sha256"],
        tmp_path / "runners",
    )
    images = {name: "sha256:" + str(i) * 64 for i, name in enumerate(sorted(IMAGE_ROLES))}
    # Daemon metadata is a fixture. Compose config still uses the real local CLI
    # with temporary credentials, and PKI verifies real keys/certificates.
    monkeypatch.setattr(
        package,
        "image_snapshot",
        lambda pins: {
            name: {"id": ref, "os": "linux", "architecture": "amd64", "user": "fixture"}
            for name, ref in pins.items()
        },
    )
    before = package.source_snapshot(source)
    result = package.prepare(
        source,
        Path(candidate["candidate_path"]),
        candidate["manifest_sha256"],
        services,
        services_sha,
        images,
        tmp_path / "packages",
    )
    assert package.source_snapshot(source) == before
    return Path(result["package_path"]), result["package_sha256"]


def test_private_package_rechecks_actual_pki_and_render_without_activation(built):
    directory, sha = built
    result = package.recheck(directory, sha)
    assert result["status"] == "offline_cycle_package_verified_not_authorized"
    assert result["marker_permitted"] is False
    plan = json.loads((directory / "plan.json").read_text())
    compose = json.loads((directory / "compose.json").read_text())
    assert set(directory.iterdir()) == {directory / "plan.json", directory / "compose.json"}
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())
    assert "migrate" not in compose["services"] and "controller" not in compose["services"]
    assert len(compose["volumes"]) == 9
    for name in ("effects_authorized", "services_started", "marker_permitted"):
        assert plan[name] is False


@pytest.mark.parametrize("change", ["compose", "hash", "extra", "profile", "source", "partial"])
def test_drift_partial_packages_and_changed_config_cannot_recheck(built, change):
    directory, sha = built
    if change == "compose":
        record = json.loads((directory / "compose.json").read_text())
        record["services"]["api"]["privileged"] = True
        (directory / "compose.json").write_text(json.dumps(record))
    elif change == "hash":
        sha = "0" * 64
    elif change == "extra":
        (directory / "unreviewed.json").write_text("{}")
    elif change == "partial":
        (directory / "plan.json").unlink()  # Only the test's own temporary plan.
    else:
        plan = json.loads((directory / "plan.json").read_text())
        if change == "source":
            plan["source_snapshot"]["protected"]["client.keys"] = "0" * 64
        else:
            plan["profile"]["images"]["application"] = "mutable-tag:latest"
        sha = package.digest(plan)
        (directory / "plan.json").write_text(json.dumps(plan))
    with pytest.raises((ValueError, OSError)):
        package.recheck(directory, sha)


def test_rejected_cli_redacts_private_diagnostics(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "wazuh_cycle_prepare.py",
            "recheck",
            "--package",
            "/not-read",
            "--expected-sha256",
            "0" * 64,
        ],
    )
    monkeypatch.setattr(
        package,
        "recheck",
        lambda *args: (_ for _ in ()).throw(ValueError("fixture-secret-must-not-escape")),
    )
    assert package.main() == 1
    assert "fixture-secret" not in capsys.readouterr().out
