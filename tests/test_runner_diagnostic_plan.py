"""Public PKI/temporary Git/private plans and native metadata fixtures, no Lab startup."""

import copy
import json
import stat
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_build_review_runner import prepared as prepared
from test_build_review_runner import simulate_build
from test_runner_activation_image_source import git
from test_runner_activation_image_source import repository as repository
from test_runner_activation_metadata import FakeDocker, images

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_diagnostic_plan as plan  # noqa: E402


@pytest.fixture
def diagnostic(prepared, repository, tmp_path, monkeypatch):
    built = prepared
    ignore = repository / ".gitignore"
    ignore.write_text(ignore.read_text() + ".local/\n")
    git(repository, "add", ".gitignore")
    git(repository, "commit", "-m", "test: ignore private diagnostic artifacts")
    origin = repository / ".local/linux-lab"
    plan.pki.initialize(origin)
    simulate_build(built, monkeypatch, "native_annotation_only")
    image = plan.image_build.build(built.folder, built.report["plan_sha256"])
    monkeypatch.setattr(plan.image_build, "ROOT", built.folder.parent)
    docker = FakeDocker()
    selected = images()
    previous = selected["runner"]
    selected["runner"] = image["native_image_id"]
    fixture = docker.responses.pop(("image", previous))
    fixture["id"] = selected["runner"]
    docker.responses["image", selected["runner"]] = fixture
    inputs = {
        "build_id": built.folder.name,
        "build_plan_sha256": built.report["plan_sha256"],
        "build_receipt_sha256": image["receipt_sha256"],
    }
    options = {"repo": repository, "output": tmp_path / "plans", "docker": docker}
    report = plan.prepare(selected, inputs, **options)
    folder = options["output"] / report["plan_id"]
    return folder, report, selected, inputs, options


def test_plan_pins_actual_reviewed_inputs_but_does_not_authorize_or_run(diagnostic, monkeypatch):
    folder, report, selected, inputs, options = diagnostic
    artifact = plan.load(folder, report["plan_sha256"])
    assert artifact["scope"] == plan.scope(artifact["snapshot"])
    assert artifact["snapshot"]["runner_build"] == inputs
    assert artifact["snapshot"]["metadata"]["images"]["runner"]["id"] == selected["runner"]
    assert artifact["scope"]["profile"]["database_volume_access"].startswith("read-write")
    assert artifact["scope"]["profile"]["journal_volume_access"] == "read-only"
    assert artifact["scope"]["profile"]["maximum_simultaneous_containers"] == 2
    assert not artifact["scope"]["profile"]["executor_implemented"]
    assert all(artifact[key] is False for key in plan.FLAGS)
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert stat.S_IMODE((folder / "plan.json").stat().st_mode) == 0o600
    assert b"private-sensitive-sentinel" not in (folder / "plan.json").read_bytes()
    # No build/lifecycle command can be reached during recheck.
    monkeypatch.setattr(plan.image_build, "_run", lambda *a: pytest.fail("build forbidden"))
    checked = plan.recheck(
        folder, report["plan_sha256"], repo=options["repo"], docker=options["docker"]
    )
    assert checked["status"] == "diagnostic_plan_revalidated_not_authorized"
    assert checked["scope_sha256"] == report["scope_sha256"]


@pytest.mark.parametrize("kind", ["daemon", "volume", "consumer", "worker", "network"])
def test_recheck_refuses_native_identity_drift_or_any_new_consumer(diagnostic, kind):
    folder, report, _, _, options = diagnostic
    docker = options["docker"]
    if kind == "daemon":
        docker.responses["daemon", None]["id"] = "22345678-1234-1234-1234-123456789012"
    elif kind == "volume":
        docker.responses["volume", "journal"]["created_at"] = "2026-10-22T12:00:00Z"
    elif kind == "consumer":
        docker.responses["consumers", "postgres-data"] = b"foreign-stopped-consumer"
    elif kind == "worker":
        docker.responses["containers", None] = b"unexpected-worker"
    else:
        docker.responses["network_name", "backend"] = b"unexpected-network"
    with pytest.raises(ValueError):
        plan.recheck(folder, report["plan_sha256"], repo=options["repo"], docker=docker)


@pytest.mark.parametrize("kind", ["dirty", "commit", "package", "lock", "project"])
def test_plan_recheck_requires_pinned_clean_code_and_current_image_sources(diagnostic, kind):
    folder, report, _, _, options = diagnostic
    repo = options["repo"]
    if kind == "commit":
        git(repo, "commit", "--allow-empty", "-m", "test: changed coordinator revision")
    else:
        path = (
            repo
            / {
                "dirty": "pyproject.toml",
                "package": "apps/api/aegis/models.py",
                "lock": "requirements.lock",
                "project": "pyproject.toml",
            }[kind]
        )
        path.write_text(path.read_text() + "\n# changed after plan\n")
        if kind != "dirty":
            git(repo, "add", str(path.relative_to(repo)))
            git(repo, "commit", "-m", "test: changed pinned diagnostic input")
    with pytest.raises(ValueError):
        plan.recheck(folder, report["plan_sha256"], repo=repo, docker=options["docker"])


@pytest.mark.parametrize(
    "kind", ["hash", "policy", "flags", "duration", "ttl", "expired", "future"]
)
def test_load_rejects_changed_policy_even_with_a_recomputed_hash(diagnostic, kind, monkeypatch):
    folder, report, _, _, _ = diagnostic
    path = folder / "plan.json"
    artifact = json.loads(path.read_bytes())
    expected = report["plan_sha256"]
    if kind == "hash":
        expected = "0" * 64
    elif kind == "policy":
        artifact["scope"]["profile"]["marker_permitted"] = True
        artifact["scope_sha256"] = plan.digest(artifact["scope"])
    elif kind == "flags":
        artifact["authorization_verified"] = 0
    elif kind == "duration":
        artifact["scope"]["profile"]["maximum_seconds"] = 1000
        artifact["scope_sha256"] = plan.digest(artifact["scope"])
    elif kind == "ttl":
        artifact["expires_at"] = (plan.pki.clock() + timedelta(days=2)).isoformat()
    else:
        shifted = plan.pki.clock() + (
            timedelta(days=2) if kind == "expired" else -timedelta(days=2)
        )
        monkeypatch.setattr(plan.pki, "clock", lambda: shifted)
    if kind not in {"hash", "expired", "future"}:
        path.write_text(json.dumps(artifact))
        expected = plan.digest(artifact)
    with pytest.raises(ValueError):
        plan.load(folder, expected)


def test_recheck_expiry_during_last_io_cannot_publish_success(diagnostic, monkeypatch):
    folder, report, _, _, options = diagnostic
    original = plan.snapshot

    def delayed(*args, **kwargs):
        observed = original(*args, **kwargs)
        future = plan.pki.clock() + timedelta(days=2)
        monkeypatch.setattr(plan.pki, "clock", lambda: future)
        return observed

    monkeypatch.setattr(plan, "snapshot", delayed)
    with pytest.raises(ValueError):
        plan.recheck(folder, report["plan_sha256"], repo=options["repo"], docker=options["docker"])


def test_public_expired_certificate_identity_is_not_tls_renewal(diagnostic, monkeypatch):
    folder, report, selected, inputs, options = diagnostic
    public, _ = plan.pki.inventory(options["repo"] / ".local/linux-lab")
    future = plan.pki.clock() + timedelta(days=10)
    monkeypatch.setattr(plan.pki, "clock", lambda: future)
    observed = plan.snapshot(selected, inputs, repo=options["repo"], docker=options["docker"])
    assert observed["old_descriptor_sha256"] == public["descriptor_sha256"]
    with pytest.raises(ValueError):
        plan.load(folder, report["plan_sha256"])


@pytest.mark.parametrize("kind", ["build_id", "build_plan_sha256", "build_receipt_sha256", "image"])
def test_plan_requires_independently_pinned_build_and_image(diagnostic, kind):
    _, _, selected, inputs, options = diagnostic
    selected, inputs = copy.deepcopy(selected), copy.deepcopy(inputs)
    if kind == "image":
        selected["runner"] = "sha256:" + "a" * 64
    else:
        inputs[kind] = "0" * (32 if kind == "build_id" else 64)
    with pytest.raises((ValueError, OSError)):
        plan.prepare(selected, inputs, **options)
