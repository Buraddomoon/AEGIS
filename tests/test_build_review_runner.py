"""Reviewed build context and fake BuildKit outputs, no Docker effects or downloads."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from aegis.domain.validation import digest
from test_runner_activation_image_source import git
from test_runner_activation_image_source import repository as repository
from test_runner_image_base import Docker as BaseDocker
from test_runner_image_registry import Registry
from test_runner_image_wheels import RUNTIME, TOOLS, fake_download

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_review_runner as build  # noqa: E402
from runner_activation_probe_runtime import ENV_FIXED  # noqa: E402
from runner_image_registry import python_base  # noqa: E402


@pytest.fixture
def prepared(repository, tmp_path, monkeypatch):
    repo = repository
    (repo / "requirements.lock").write_bytes(RUNTIME)
    (repo / "requirements-image-build.lock").write_bytes(TOOLS)
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires=["setuptools>=80"]\nbuild-backend="setuptools.build_meta"\n[project]\nname="aegis-purple"\nversion="0.2.0"\n'
    )
    (repo / "scripts").mkdir()
    (repo / "scripts/runner_image_assert.py").write_text(
        "# Synthetic checker, never used in a real image\n"
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test: create synthetic build inputs")
    exported = build.source.prepare(repo=repo, output_root=tmp_path / "sources")
    monkeypatch.setattr(build.source, "DEFAULT_OUTPUT", tmp_path / "sources")
    monkeypatch.setattr(build.wheels, "download", fake_download)
    cached = build.wheels.prepare(
        RUNTIME, TOOLS, exported["source_sha256"], root=tmp_path / "wheels"
    )
    monkeypatch.setattr(build.wheels, "ROOT", tmp_path / "wheels")
    fixture = Registry()
    base = python_base(transport=httpx.MockTransport(fixture.handle))
    base_path = tmp_path / "base" / "registry.json"
    base_path.parent.mkdir(mode=0o700)
    build._write(base_path, json.dumps(base).encode())
    docker = BaseDocker(base)
    report = build.prepare(
        Path(exported["folder"]).name,
        exported["source_sha256"],
        Path(cached["folder"]).name,
        cached["receipt_sha256"],
        base_path,
        digest(base),
        repo=repo,
        output=tmp_path / "builds",
        base_docker=docker,
    )
    return SimpleNamespace(folder=Path(report["folder"]), report=report, base=base, docker=docker)


def test_context_contains_only_verified_source_wheels_and_fixed_build_recipe(prepared):
    plan = build.verify(prepared.folder, prepared.report["plan_sha256"])
    context = prepared.folder / "context"
    assert plan["context"] == build._files(context)
    assert not any(".env" in name or ".key" in name or ".git" in name for name in plan["context"])
    assert "Dockerfile" in plan["context"] and "source.json" in plan["context"]
    assert plan["tag"] == "aegis-runner-review:" + prepared.folder.name
    assert plan["base_native"]["local_registry_binding_verified"]
    assert not plan["lab_started"] and not plan["lab_authorization_verified"]
    body = (context / "Dockerfile").read_text()
    assert body.startswith("FROM " + prepared.base["reference"] + "\n")
    assert "--require-hashes" in body and "--no-index" in body
    assert "--no-build-isolation" in body and "--no-compile" in body
    assert "USER 10001:10001" in body
    assert "LABEL" not in body and "EXPOSE" not in body and "VOLUME" not in body
    assert (context / "build-id").read_text() == prepared.folder.name
    args = build.command(prepared.folder, plan, "/private-empty-config")
    assert args[:5] == (
        "/usr/bin/docker",
        "--config",
        "/private-empty-config",
        "--host",
        "unix:///var/run/docker.sock",
    )
    assert args[args.index("--network") + 1] == "none"
    assert "--pull=false" in args and "--provenance=false" in args
    assert "--push" not in args and "--load" in args


@pytest.mark.parametrize("field,value", [("lab_started", 0), ("build_client_exit_verified", 1)])
@pytest.mark.parametrize("reader", ["review", "review_existing"])
def test_rehashed_integer_receipt_flags_are_not_accepted_as_boolean_proof(
    prepared, monkeypatch, field, value, reader
):
    simulate_build(prepared, monkeypatch, "native_annotation_only")
    build.build(prepared.folder, prepared.report["plan_sha256"])
    path = prepared.folder / "receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    before = path.read_bytes()
    with pytest.raises(build.ActivationError, match="receipt_conflict"):
        getattr(build, reader)(prepared.folder, prepared.report["plan_sha256"])
    assert path.read_bytes() == before


@pytest.mark.parametrize("scene", ["changed", "extra", "symlink", "hardlink", "mode"])
def test_changed_or_polluted_context_never_reaches_a_build_effect(
    prepared, monkeypatch, tmp_path, scene
):
    path = prepared.folder / "context" / "Dockerfile"
    if scene == "changed":
        path.write_text("FROM untrusted.invalid/image\n")
    elif scene == "extra":
        (path.parent / ".env").write_text("private-sensitive-sentinel")
    elif scene == "symlink":
        target = tmp_path / "outside"
        path.rename(target)
        path.symlink_to(target)
    elif scene == "hardlink":
        os.link(path, tmp_path / "second-name")
    else:
        path.chmod(0o666)
    monkeypatch.setattr(build, "_execute", lambda *a, **k: pytest.fail("No daemon query allowed"))
    with pytest.raises((ValueError, OSError)):
        build.build(prepared.folder, prepared.report["plan_sha256"])
    assert not (prepared.folder / "build-requested.json").exists()


def simulate_build(prepared, monkeypatch, scene=None):
    original = build.base_review.review
    monkeypatch.setattr(
        build.base_review, "review", lambda base, **kwargs: original(base, docker=prepared.docker)
    )
    result_id, config_id = "sha256:" + "e" * 64, "sha256:" + "f" * 64

    def execute(args, **kwargs):
        assert args[0] == "image"
        if args[1] == "ls":
            return (result_id + "\n").encode() if scene == "tag_exists" else b""
        if '"user"' in args[3]:
            return json.dumps(
                {
                    "id": result_id,
                    "user": "10001:10001",
                    "volumes": None,
                    "ports": None,
                    "label_count": 3 if scene == "extra_labels" else 0,
                    "environment": [{"key": key, "valid": True} for key in ENV_FIXED],
                }
            ).encode()
        return json.dumps(
            {
                "id": result_id,
                "descriptor": {
                    "digest": "sha256:" + "d" * 64 if scene == "descriptor" else result_id,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "annotations": {"config.digest": config_id},
                },
            }
        ).encode()

    monkeypatch.setattr(build, "_execute", execute)

    def run(folder, plan):
        assert (folder / "build-requested.json").is_file()
        assert build.verify(folder, prepared.report["plan_sha256"]) == plan
        if scene == "rpc_failed":
            raise build.ActivationError("private-sensitive-sentinel")
        check = {
            "format": "aegis-runner-image-build-check/1",
            "source_sha256": plan["source_sha256"],
            "source_commit": plan["source_commit"],
            "package_files_verified": len(plan["expected_check"]["package_files"]),
            "runtime_versions_verified": plan["runtime_versions"],
            "build_versions_verified": plan["build_versions"],
            "installed_source_verified": True,
            "installed_versions_verified": True,
            "probe_imports_verified": True,
            "image_provenance_verified": False,
            "lab_started": False,
            "effects_authorized": False,
        }
        if scene == "source_check":
            check["source_sha256"] = "f" * 64
        elif scene == "bool_count":
            check["runtime_versions_verified"] = True
        log = "#10 0.1 " + json.dumps(check) + "\n"
        if scene == "no_fresh_check":
            log = "#10 CACHED\n"
        if scene == "duplicate_check":
            log += log
        build._write(folder / "build.log", log.encode())
        build._write(folder / "iid", (config_id + "\n").encode())
        build._write(
            folder / "build-metadata.json",
            json.dumps(
                {
                    "containerimage.digest": result_id,
                    **(
                        {}
                        if scene == "native_annotation_only"
                        else {"containerimage.config.digest": config_id}
                    ),
                }
            ).encode(),
        )

    monkeypatch.setattr(build, "_run", run)


def test_receipt_requires_positive_fresh_source_check_metadata_and_native_image_binding(
    prepared, monkeypatch
):
    simulate_build(prepared, monkeypatch)
    report = build.build(prepared.folder, prepared.report["plan_sha256"])
    assert report["image_built"] and report["local_build_inputs_verified"]
    assert report["native_image_id"] == report["result_digest"]
    assert report["config_digest"] != report["result_digest"]
    assert report["source_check"]["probe_imports_verified"]
    assert not report["publisher_signature_verified"] and not report["lab_authorization_verified"]
    assert (prepared.folder / "receipt.json").is_file()
    with pytest.raises(FileExistsError):
        build.build(prepared.folder, prepared.report["plan_sha256"])


@pytest.mark.parametrize(
    "scene",
    [
        "tag_exists",
        "extra_labels",
        "descriptor",
        "rpc_failed",
        "source_check",
        "bool_count",
        "no_fresh_check",
        "duplicate_check",
    ],
)
def test_unknown_or_inconsistent_build_never_publishes_success_receipt(
    prepared, monkeypatch, scene
):
    simulate_build(prepared, monkeypatch, scene)
    with pytest.raises(ValueError):
        build.build(prepared.folder, prepared.report["plan_sha256"])
    assert not (prepared.folder / "receipt.json").exists()


@pytest.mark.parametrize("scene", ["success", "nonzero", "overflow", "deadline"])
def test_build_transport_reaps_its_own_local_fixture_child_without_docker(
    prepared, monkeypatch, scene
):
    code = "print('synthetic build output')"
    if scene == "nonzero":
        code += ";raise SystemExit(1)"
    elif scene == "overflow":
        code = "import os;os.write(1,b'x'*(4*1024**2+1))"
    elif scene == "deadline":
        code = "import time;time.sleep(30)"
    monkeypatch.setattr(build, "command", lambda *a: (sys.executable, "-I", "-B", "-c", code))
    processes = []
    original = subprocess.Popen

    def spawn(*args, **kwargs):
        assert kwargs["env"] == build.ENV and kwargs["stdin"] == subprocess.DEVNULL
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(build.subprocess, "Popen", spawn)
    if scene == "deadline":
        ticks = iter([0.0, 181.0])
        monkeypatch.setattr(build, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    if scene == "success":
        build._run(prepared.folder, {})
    else:
        with pytest.raises(ValueError):
            build._run(prepared.folder, {})
    assert len(processes) == 1 and processes[0].poll() is not None
    assert processes[0].stdout.closed


def test_import_has_no_subprocess_network_or_secret_effect():
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
    if event == 'open' and isinstance(args[0], str) and ('.env' in args[0] or args[0].endswith('.key')):
        raise AssertionError('secret forbidden')
sys.addaudithook(guard)
import build_review_runner
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_new_context_material_has_declared_mode_under_a_restrictive_umask(tmp_path):
    import stat

    previous = os.umask(0o077)
    try:
        context = tmp_path / "private-context"
        build._write(context / "module.py", b"# nonsecret source\n", mode=0o644)
        build._write(context / "private-control.json", b"{}")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(context.stat().st_mode) == 0o700
    assert stat.S_IMODE((context / "module.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((context / "private-control.json").stat().st_mode) == 0o600


@pytest.mark.parametrize("scene", [None, "native_annotation_only"])
def test_review_existing_export_uses_only_image_inspection_and_does_not_replay(
    prepared, monkeypatch, scene
):
    simulate_build(prepared, monkeypatch, scene)
    plan = build.verify(prepared.folder, prepared.report["plan_sha256"])
    build._write(
        prepared.folder / "build-requested.json",
        json.dumps({"plan_sha256": prepared.report["plan_sha256"], "tag": plan["tag"]}).encode(),
    )
    build._run(prepared.folder, plan)  # FakeBuildKit fixture, no Docker invocation.
    monkeypatch.setattr(build, "_run", lambda *a: pytest.fail("Build replay forbidden"))
    queries = []
    original = build._execute

    def inspect_only(args, **kwargs):
        assert args[:2] == ("image", "inspect")
        queries.append(args)
        return original(args, **kwargs)

    monkeypatch.setattr(build, "_execute", inspect_only)
    result = build.review(prepared.folder, prepared.report["plan_sha256"])
    assert result["image_built"] and result["local_build_inputs_verified"]
    assert not result["build_client_exit_verified"]
    assert not result["lab_started"] and not result["lab_authorization_verified"]
    assert len(queries) == 3
    assert build.review(prepared.folder, prepared.report["plan_sha256"]) == result
    assert not (prepared.folder / "build-completed.json").exists()


def test_review_does_not_adopt_outputs_without_the_original_request(prepared, monkeypatch):
    simulate_build(prepared, monkeypatch)
    monkeypatch.setattr(build, "_run", lambda *a: pytest.fail("Build replay forbidden"))
    monkeypatch.setattr(build, "_execute", lambda *a: pytest.fail("No Docker query expected"))
    with pytest.raises(FileNotFoundError):
        build.review(prepared.folder, prepared.report["plan_sha256"])


@pytest.mark.parametrize("scene", ["completion", "receipt", "tag"])
def test_review_refuses_conflicting_completion_receipt_or_retargeted_tag(
    prepared, monkeypatch, scene
):
    simulate_build(prepared, monkeypatch)
    report = build.build(prepared.folder, prepared.report["plan_sha256"])
    assert report["build_client_exit_verified"]
    if scene == "tag":
        original = build._execute
        calls = []

        def replaced(args, **kwargs):
            calls.append(args)
            if len(calls) == 3:
                return json.dumps({"id": "sha256:" + "0" * 64}).encode()
            return original(args, **kwargs)

        monkeypatch.setattr(build, "_execute", replaced)
    else:
        path = prepared.folder / (
            "build-completed.json" if scene == "completion" else "receipt.json"
        )
        path.write_text("{}")
    monkeypatch.setattr(build, "_run", lambda *a: pytest.fail("Build replay forbidden"))
    with pytest.raises(ValueError):
        build.review(prepared.folder, prepared.report["plan_sha256"])


@pytest.mark.parametrize(
    "scene",
    [
        "native_only",
        "metadata_only",
        "top_level",
        "all",
        "legacy",
        "conflict",
        "invalid",
        "missing",
        "mixed",
        "descriptor",
    ],
)
def test_result_identity_has_explicit_native_and_legacy_digest_profiles(scene):
    result, config, other = ("sha256:" + value * 64 for value in ("e", "f", "d"))
    descriptor = {"digest": result, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
    metadata = {"containerimage.digest": result, "containerimage.descriptor": dict(descriptor)}
    item = {"id": result, "descriptor": dict(descriptor)}
    if scene in {"native_only", "all", "conflict", "invalid", "mixed", "descriptor"}:
        item["descriptor"]["annotations"] = {"config.digest": config}
    if scene in {"metadata_only", "all"}:
        metadata["containerimage.descriptor"]["annotations"] = {"config.digest": config}
    if scene in {"top_level", "all", "legacy"}:
        metadata["containerimage.config.digest"] = config
    if scene == "conflict":
        metadata["containerimage.config.digest"] = other
    elif scene == "invalid":
        item["descriptor"]["annotations"]["config.digest"] = "invalid"
    elif scene == "descriptor":
        metadata["containerimage.descriptor"]["digest"] = other
    elif scene == "mixed":
        item["id"] = config
    elif scene == "legacy":
        item = {"id": config, "descriptor": None}
    if scene in {"conflict", "invalid", "missing", "mixed", "descriptor"}:
        with pytest.raises(ValueError):
            build._result_identity(metadata, item)
    else:
        assert build._result_identity(metadata, item) == (config, result)
