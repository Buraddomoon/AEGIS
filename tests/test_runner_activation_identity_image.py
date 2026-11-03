"""Existing sealed build with fixture image metadata; no real build, pull or container."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_build_review_runner import prepared as prepared
from test_build_review_runner import simulate_build
from test_runner_activation_image_source import git
from test_runner_activation_image_source import repository as repository

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_identity_image as image  # noqa: E402


@pytest.fixture
def built(prepared, repository, monkeypatch):
    simulate_build(prepared, monkeypatch, "native_annotation_only")
    reviewed = image.inputs.image_build.build(prepared.folder, prepared.report["plan_sha256"])
    monkeypatch.setattr(image.inputs.image_build, "ROOT", prepared.folder.parent)
    monkeypatch.setattr(
        image.inputs.image_build, "_run", lambda *a: pytest.fail("No new build permitted")
    )
    references = {
        "build_id": prepared.folder.name,
        "build_plan_sha256": prepared.report["plan_sha256"],
        "build_receipt_sha256": reviewed["receipt_sha256"],
    }
    return prepared, reviewed, references


def invoke(built, repository, *, commit=None, selected=None):
    _prepared, reviewed, references = built
    return image.review(
        references,
        selected or reviewed["native_image_id"],
        commit or image.source._state(repository),
        repo=repository,
    )


def test_current_source_proof_uses_existing_completed_build_without_operational_or_signature_claims(
    built, repository
):
    prepared, reviewed, references = built
    receipt = prepared.folder / "receipt.json"
    before = (receipt.read_bytes(), receipt.stat().st_mtime_ns)
    result = invoke(built, repository)
    assert result["native_image_id"] == reviewed["native_image_id"]
    assert result["build_receipt_sha256"] == references["build_receipt_sha256"]
    assert result["package_and_dependency_sources_current"] and result["build_client_exit_verified"]
    assert all(
        result[k] is False
        for k in (
            "publisher_signature_verified",
            "identity_mode_runtime_verified",
            "effects_authorized",
            "activation_verified",
            "normal_operation_permitted",
        )
    )
    assert (receipt.read_bytes(), receipt.stat().st_mtime_ns) == before
    assert "private-sensitive-sentinel" not in json.dumps(result)


def test_source_review_never_calls_the_build_receipt_publisher(built, repository, monkeypatch):
    monkeypatch.setattr(
        image.inputs.image_build, "_write", lambda *a, **kw: pytest.fail("no publication")
    )
    assert invoke(built, repository)["local_build_inputs_verified"] is True


def test_receipt_removed_after_outer_precheck_is_not_recreated(built, repository, monkeypatch):
    prepared, _, _ = built
    receipt = prepared.folder / "receipt.json"
    original = image.inputs._runner

    def removed(*args):
        receipt.unlink()  # Disposable fixture only, reproduces concurrent loss.
        return original(*args)

    monkeypatch.setattr(image.inputs, "_runner", removed)
    with pytest.raises((image.ActivationError, FileNotFoundError)):
        invoke(built, repository)
    assert not receipt.exists()


def test_receipt_removed_during_native_image_inspection_is_not_recreated(
    built, repository, monkeypatch
):
    prepared, _, _ = built
    receipt = prepared.folder / "receipt.json"
    original = image.inputs.image_build._execute

    def removed(*args, **kwargs):
        raw = original(*args, **kwargs)
        receipt.unlink(missing_ok=True)
        return raw

    monkeypatch.setattr(image.inputs.image_build, "_execute", removed)
    with pytest.raises((image.ActivationError, FileNotFoundError)):
        invoke(built, repository)
    assert not receipt.exists()


@pytest.mark.parametrize("scene", ["missing", "hash", "exit_false", "integer_exit", "other_image"])
def test_missing_or_unreviewed_receipt_is_not_generated_or_adopted(
    built, repository, monkeypatch, scene
):
    prepared, _reviewed, references = built
    receipt = prepared.folder / "receipt.json"
    if scene == "missing":
        receipt.unlink()  # Only this disposable fixture.
    elif scene == "hash":
        references["build_receipt_sha256"] = "f" * 64
    else:
        document = json.loads(receipt.read_bytes())
        document.update(
            {"native_image_id": "sha256:" + "a" * 64}
            if scene == "other_image"
            else {"build_client_exit_verified": 1 if scene == "integer_exit" else False}
        )
        receipt.write_text(json.dumps(document))
        references["build_receipt_sha256"] = image.digest(document)
    monkeypatch.setattr(
        image.inputs, "_runner", lambda *a: pytest.fail("No native reconciliation allowed")
    )
    with pytest.raises((image.ActivationError, FileNotFoundError)):
        invoke(built, repository)
    if scene == "missing":
        assert not receipt.exists()


@pytest.mark.parametrize("scene", ["package", "dependencies", "project"])
def test_old_image_cannot_become_current_by_pinning_a_new_clean_main_commit(
    built, repository, scene
):
    name = {
        "package": "apps/api/aegis/models.py",
        "dependencies": "requirements.lock",
        "project": "pyproject.toml",
    }[scene]
    path = repository / name
    path.write_text(path.read_text() + "\n# changed fixture source\n")
    git(repository, "add", name)
    git(repository, "commit", "-m", "fixture: change runtime input after sealed build")
    with pytest.raises(image.ActivationError, match="(source_outdated|dependencies_outdated)"):
        invoke(built, repository)


def test_dirty_source_or_another_image_id_cannot_pass_review(built, repository):
    before = image.source._state(repository)
    with pytest.raises(image.ActivationError, match="receipt_required"):
        invoke(built, repository, selected="sha256:" + "a" * 64)
    (repository / "unreviewed.py").write_text("# untracked\n")
    with pytest.raises(image.ActivationError, match="clean_worktree"):
        invoke(built, repository, commit=before)


def test_unknown_input_keys_and_replacement_tool_commit_are_refused(built, repository):
    _prepared, _reviewed, references = built
    references["command"] = "unreviewed"
    with pytest.raises(image.ActivationError, match="closed_build_inputs"):
        invoke(built, repository)
    del references["command"]
    with pytest.raises(image.ActivationError, match="tool_commit_drift"):
        invoke(built, repository, commit="f" * 40)


def test_import_does_not_connect_build_or_read_keys():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
sys.path.insert(0, 'scripts')
def guard(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'}:
        raise AssertionError('No effects permitted')
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('No secrets permitted')
sys.addaudithook(guard)
import runner_activation_identity_image
assert 'aegis.config' not in sys.modules
assert 'aegis.models' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
