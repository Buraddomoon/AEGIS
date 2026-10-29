"""Prepare/build only a source-verified local runner image; never launch a lab."""

import argparse
import hashlib
import io
import json
import os
import re
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from uuid import UUID, uuid4

import runner_activation_image_source as source
import runner_image_base as base_review
import runner_image_wheels as wheels
import runner_pki as pki
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError, _execute, _unique, document
from runner_image_assert import requirements

ROOT = source.ROOT / ".local/pki-runner-builds"
MAX_CONTEXT, MAX_FILES = 160 * 1024**2, 512
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
FLAGS = {
    "lab_started": False,
    "lab_authorization_verified": False,
    "normal_operation_permitted": False,
}


def sha(content):
    return hashlib.sha256(content).hexdigest()


def _id(value):
    if not isinstance(value, str) or UUID(hex=value).hex != value:
        raise ActivationError("runner_build_identifier_invalid")
    return value


def _json(path, maximum=256 * 1024):
    pki.private_directory(path.parent)
    return json.loads(pki.read(path, modes=(0o600,), maximum=maximum), object_pairs_hook=_unique)


def _write(path, content, *, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as output:
        os.fchmod(output.fileno(), mode)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    pki.sync(path.parent)


def _files(folder):
    pki.private_directory(folder)
    records, total = {}, 0
    for path in folder.rglob("*"):
        if path.is_symlink():
            raise ActivationError("runner_build_context_link")
        if path.is_dir():
            continue
        name = path.relative_to(folder).as_posix()
        allowed = name in {
            "Dockerfile",
            "runtime.lock",
            "build.lock",
            "source.json",
            "check.py",
            "build-id",
            "pyproject.toml",
        }
        allowed = allowed or (name.startswith(source.PACKAGE) and source._allowed(name))
        if name.startswith("wheels/") and len(Path(name).parts) == 2:
            try:
                wheels.parse_wheel_filename(path.name)
                allowed = True
            except ValueError:
                pass
        if not allowed:
            raise ActivationError("runner_build_context_path_invalid")
        if len(records) >= MAX_FILES:
            raise ActivationError("runner_build_context_limit")
        data = pki.read(path, modes=(0o644,), maximum=wheels.MAX_WHEEL)
        total += len(data)
        if total > MAX_CONTEXT:
            raise ActivationError("runner_build_context_limit")
        records[name] = {"bytes": len(data), "sha256": sha(data)}
    return dict(sorted(records.items()))


def _sync_tree(folder):
    for path in sorted(
        (path for path in folder.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        pki.sync(path)
    pki.sync(folder)
    pki.sync(folder.parent)


def dockerfile(base):
    reference = base_review.reference(base)
    return (
        "FROM " + reference + "\n"
        "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 LANG=C.UTF-8\n"
        "WORKDIR /app\n"
        "RUN groupadd --gid 10001 aegis && useradd --uid 10001 --gid aegis --no-create-home aegis && mkdir /state /work /observation-log && chown 10001:10001 /state /work /observation-log && chmod 700 /state /work /observation-log\n"
        "COPY runtime.lock build.lock /review/\n"
        "COPY wheels/ /review/wheels/\n"
        'RUN ["/usr/bin/env","PIP_CONFIG_FILE=/dev/null","NETRC=/dev/null","/usr/local/bin/python","-I","-m","pip","--isolated","--disable-pip-version-check","install","--no-index","--find-links=/review/wheels","--only-binary=:all:","--require-hashes","--no-deps","--no-compile","--no-cache-dir","-r","/review/runtime.lock","-r","/review/build.lock"]\n'
        "COPY pyproject.toml /app/\n"
        "COPY apps/ /app/apps/\n"
        'RUN ["/usr/bin/env","PIP_CONFIG_FILE=/dev/null","NETRC=/dev/null","/usr/local/bin/python","-I","-m","pip","--isolated","--disable-pip-version-check","install","--no-index","--no-build-isolation","--no-deps","--no-compile","--no-cache-dir","."]\n'
        "COPY source.json check.py build-id /review/\n"
        "USER 10001:10001\n"
        'RUN ["/usr/local/bin/python","-I","-B","/review/check.py"]\n'
        'ENTRYPOINT ["/usr/local/bin/python","-I","-B","-m","aegis.lab_runner.server"]\n'
        "CMD []\n"
    ).encode()


def prepare(
    source_id,
    source_sha,
    cache_id,
    cache_sha,
    base_path,
    base_sha,
    *,
    repo=source.ROOT,
    output=ROOT,
    base_docker=None,
):
    original = source._state(repo)
    source_folder = source.DEFAULT_OUTPUT / _id(source_id)
    source_doc = source.verify(source_folder, source_sha)
    cache_folder = wheels.ROOT / _id(cache_id)
    cache = wheels.verify(cache_folder, cache_sha)
    base = _json(base_path)
    if digest(base) != base_sha:
        raise ActivationError("runner_build_base_integrity_mismatch")
    native = base_review.review(base, docker=base_docker)
    raw = pki.read(source_folder / "context.tar", modes=(0o600,), maximum=source.MAX_CONTEXT)
    if sha(raw) != source_doc["context_sha256"]:
        raise ActivationError("runner_build_source_changed")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        files = {
            member.name: archive.extractfile(member).read(source.MAX_FILE + 1) for member in archive
        }
    runtime = files["requirements.lock"]
    tools = source._git(repo, "show", "HEAD:requirements-image-build.lock", maximum=65536)
    checker = source._git(repo, "show", "HEAD:scripts/runner_image_assert.py", maximum=65536)
    if (
        cache["source_sha256"] != source_sha
        or _json(cache_folder / "plan.json")["runtime_lock_sha256"] != sha(runtime)
        or _json(cache_folder / "plan.json")["build_lock_sha256"] != sha(tools)
    ):
        raise ActivationError("runner_build_dependency_context_mismatch")
    project = tomllib.loads(files["pyproject.toml"].decode())
    if (
        project.get("build-system")
        != {"requires": ["setuptools>=80"], "build-backend": "setuptools.build_meta"}
        or project.get("project", {}).get("name") != "aegis-purple"
        or not isinstance(project["project"].get("version"), str)
    ):
        raise ActivationError("runner_build_project_profile_invalid")
    package = {
        name.removeprefix(source.PACKAGE): meta
        for name, meta in source_doc["files"].items()
        if name.startswith(source.PACKAGE)
    }
    expected = {
        "format": "aegis-runner-image-package/1",
        "source_sha256": source_sha,
        "source_commit": source_doc["source_commit"],
        "project_version": project["project"]["version"],
        "package_files": package,
    }
    root = pki.private_directory(output, create=True)
    folder = root / uuid4().hex
    folder.mkdir(mode=0o700)
    pki.sync(root)
    context = folder / "context"
    context.mkdir(mode=0o700)
    for name, data in files.items():
        if name.startswith(source.PACKAGE) or name == "pyproject.toml":
            _write(context / name, data, mode=0o644)
    for name, data in [
        ("runtime.lock", runtime),
        ("build.lock", tools),
        ("source.json", json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()),
        ("check.py", checker),
        ("build-id", folder.name.encode()),
        ("Dockerfile", dockerfile(base)),
    ]:
        _write(context / name, data, mode=0o644)
    for record in cache["wheels"].values():
        content = pki.read(
            cache_folder / "wheels" / record["filename"], modes=(0o600,), maximum=wheels.MAX_WHEEL
        )
        if sha(content) != record["sha256"]:
            raise ActivationError("runner_build_wheel_changed")
        _write(context / "wheels" / record["filename"], content, mode=0o644)
    manifest = _files(context)
    _sync_tree(context)
    plan = {
        "format": "aegis-runner-image-build-plan/1",
        "id": folder.name,
        "tool_commit": original,
        "source_sha256": source_sha,
        "source_commit": source_doc["source_commit"],
        "wheel_cache_sha256": cache_sha,
        "registry_sha256": base_sha,
        "base": base,
        "base_native": native,
        "context": manifest,
        "tag": "aegis-runner-review:" + folder.name,
        "expected_check": expected,
        "runtime_versions": len(requirements(runtime)),
        "build_versions": len(requirements(tools)),
        **FLAGS,
    }
    _write(folder / "plan.json", json.dumps(plan, sort_keys=True, separators=(",", ":")).encode())
    if source._state(repo) != original:
        raise ActivationError("runner_build_tools_changed")
    verify(folder, digest(plan))
    return {
        "status": "runner_image_context_prepared_not_built",
        "id": folder.name,
        "folder": str(folder),
        "plan_sha256": digest(plan),
        "context_files": len(manifest),
        "image_built": False,
        **FLAGS,
    }


def verify(folder, expected_sha):
    folder = pki.private_directory(folder)
    plan = _json(folder / "plan.json")
    if (
        digest(plan) != expected_sha
        or plan.get("format") != "aegis-runner-image-build-plan/1"
        or plan.get("id") != _id(folder.name)
        or plan.get("tag") != "aegis-runner-review:" + folder.name
        or any(plan.get(key) is not False for key in FLAGS)
        or plan["registry_sha256"] != digest(plan["base"])
        or plan["base_native"]["registry_receipt_sha256"] != plan["registry_sha256"]
        or _files(folder / "context") != plan["context"]
    ):
        raise ActivationError("runner_build_plan_or_context_changed")
    base_review.reference(plan["base"])
    return plan


def command(folder, plan, config):
    return (
        "/usr/bin/docker",
        "--config",
        str(config),
        "--host",
        "unix:///var/run/docker.sock",
        "buildx",
        "build",
        "--builder",
        "default",
        "--network",
        "none",
        "--pull=false",
        "--progress",
        "plain",
        "--provenance=false",
        "--sbom=false",
        "--load",
        "--tag",
        plan["tag"],
        "--metadata-file",
        str(folder / "build-metadata.json"),
        "--iidfile",
        str(folder / "iid"),
        str(folder / "context"),
    )


def _run(folder, plan):
    fd = os.open(folder / "build.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with (
        os.fdopen(fd, "wb") as log,
        tempfile.TemporaryDirectory(prefix="aegis-runner-build-docker-") as config,
    ):
        process = subprocess.Popen(
            command(folder, plan, config),
            cwd=folder,
            env=ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            umask=0o077,
        )
        try:
            deadline, size = time.monotonic() + 180, 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ActivationError("runner_build_deadline")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > 4 * 1024**2:
                            raise ActivationError("runner_build_log_limit")
                        log.write(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise ActivationError("runner_build_unconfirmed")
            log.flush()
            os.fsync(log.fileno())
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()


def _output(path, maximum):
    # Docker outputs remain under0700; safely normalize their nonsecret mode.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            info.st_uid != os.getuid()
            or info.st_nlink != 1
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > maximum
        ):
            raise ActivationError("runner_build_output_invalid")
        os.fchmod(stream.fileno(), 0o600)
        os.fsync(stream.fileno())
        return stream.read(maximum + 1)


def _result_identity(metadata, item):
    """Bind exported manifest to native identity, with explicit legacy/containerd forms."""
    result = metadata.get("containerimage.digest")
    descriptors = [metadata.get("containerimage.descriptor"), item.get("descriptor")]
    configs = [metadata.get("containerimage.config.digest")]
    for descriptor in descriptors:
        if descriptor is None:
            continue
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("digest") != result
            or descriptor.get("mediaType") not in base_review.MANIFEST_TYPES
            or not isinstance(descriptor.get("annotations", {}), dict)
        ):
            raise ActivationError("runner_build_native_descriptor_mismatch")
        configs.append(descriptor.get("annotations", {}).get("config.digest"))
    configs = [value for value in configs if value is not None]
    if not configs or any(
        not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value)
        for value in [result, *configs]
    ):
        raise ActivationError("runner_build_result_digest_invalid")
    config = configs[0]
    if any(value != config for value in configs):
        raise ActivationError("runner_build_config_digest_conflict")
    if item.get("descriptor") is not None:
        if item.get("id") != result:
            raise ActivationError("runner_build_native_identity_mismatch")
    elif item.get("id") != config:
        raise ActivationError("runner_build_native_identity_mismatch")
    return config, result


def build(folder, expected_sha):
    plan = verify(folder, expected_sha)
    # Do not overwrite/adopt a pre-existing tag, even if its current ID looks useful.
    if _execute(
        ("image", "ls", "--quiet", "--no-trunc", "--filter", "reference=" + plan["tag"])
    ).strip():
        raise ActivationError("runner_build_output_tag_exists")
    native = base_review.review(plan["base"])
    if digest(native) != digest(plan["base_native"]):
        raise ActivationError("runner_build_base_changed")
    _write(
        folder / "build-requested.json",
        json.dumps({"plan_sha256": expected_sha, "tag": plan["tag"]}, sort_keys=True).encode(),
    )
    if verify(folder, expected_sha) != plan:
        raise ActivationError("runner_build_context_changed_before_effect")
    _run(folder, plan)
    _write(
        folder / "build-completed.json",
        json.dumps({"plan_sha256": expected_sha, "client_exit_code": 0}, sort_keys=True).encode(),
    )
    return review(folder, expected_sha)


def review(folder, expected_sha):
    """Reconcile existing build outputs using image inspection only, never replay the build."""
    plan = verify(folder, expected_sha)
    if _json(folder / "build-requested.json") != {
        "plan_sha256": expected_sha,
        "tag": plan["tag"],
    }:
        raise ActivationError("runner_build_request_mismatch")
    if digest(base_review.review(plan["base"])) != digest(plan["base_native"]):
        raise ActivationError("runner_build_base_changed")
    completed = folder / "build-completed.json"
    exit_verified = False
    try:
        completed.lstat()
    except FileNotFoundError:
        pass
    else:
        completion = _json(completed)
        if (
            completion != {"plan_sha256": expected_sha, "client_exit_code": 0}
            or type(completion.get("client_exit_code")) is not int
        ):
            raise ActivationError("runner_build_completion_mismatch")
        exit_verified = True
    metadata = json.loads(
        _output(folder / "build-metadata.json", 256 * 1024), object_pairs_hook=_unique
    )
    if not isinstance(metadata, dict):
        raise ActivationError("runner_build_metadata_invalid")
    item = document(
        _execute(
            (
                "image",
                "inspect",
                "--format",
                '{"id":{{json .Id}},"descriptor":{{json (index . "Descriptor")}}}',
                plan["tag"],
            )
        )
    )
    config_digest, result_digest = _result_identity(metadata, item)
    iid = _output(folder / "iid", 256).decode("ascii").strip()
    if iid not in {config_digest, result_digest}:
        raise ActivationError("runner_build_iid_unconfirmed")
    # Review final image without creating/running it. Exactly five ownership labels
    # will be supplied by the future authorized executor; image inherits none.
    # Avoid inventing a real activation intent: the image check itself is the same
    # closed runner image/env/ports policy with a fixture-free metadata projection.
    from runner_activation_probe_runtime import ENVIRONMENT_FORMAT

    image_format = (
        '{"id":{{json .Id}},"user":{{json (index .Config "User")}},"volumes":{{json (index .Config "Volumes")}},"ports":{{json (index .Config "ExposedPorts")}},"label_count":{{with (index .Config "Labels")}}{{len .}}{{else}}0{{end}},"environment":'
        + ENVIRONMENT_FORMAT
        + "}"
    )
    image = document(_execute(("image", "inspect", "--format", image_format, item["id"])))
    from runner_activation_probe_runtime import _validate_environment

    if (
        image["id"] != item["id"]
        or image["user"] != "10001:10001"
        or image["volumes"] not in (None, {})
        or image["ports"] not in (None, {})
        or type(image["label_count"]) is not int
        or image["label_count"] != 0
    ):
        raise ActivationError("runner_build_final_image_profile_mismatch")
    _validate_environment(image["environment"], image=True)
    checks = []
    for line in (
        pki.read(folder / "build.log", modes=(0o600,), maximum=4 * 1024**2)
        .decode("utf-8")
        .splitlines()
    ):
        position = line.find("{")
        if position < 0:
            continue
        try:
            check = json.loads(line[position:], object_pairs_hook=_unique)
        except ValueError:
            continue
        if isinstance(check, dict) and check.get("format") == "aegis-runner-image-build-check/1":
            checks.append(check)
    if len(checks) != 1:
        raise ActivationError("runner_build_fresh_source_check_unconfirmed")
    check = checks[0]
    if (
        set(check)
        != {
            "format",
            "source_sha256",
            "source_commit",
            "package_files_verified",
            "runtime_versions_verified",
            "build_versions_verified",
            "installed_source_verified",
            "installed_versions_verified",
            "probe_imports_verified",
            "image_provenance_verified",
            "lab_started",
            "effects_authorized",
        }
        or check.get("source_sha256") != plan["source_sha256"]
        or check.get("source_commit") != plan["source_commit"]
        or check.get("package_files_verified") != len(plan["expected_check"]["package_files"])
        or check.get("runtime_versions_verified") != plan["runtime_versions"]
        or check.get("build_versions_verified") != plan["build_versions"]
        or any(
            type(check.get(key)) is not int
            for key in (
                "package_files_verified",
                "runtime_versions_verified",
                "build_versions_verified",
            )
        )
        or any(
            check.get(key) is not True
            for key in (
                "installed_source_verified",
                "installed_versions_verified",
                "probe_imports_verified",
            )
        )
        or any(
            check.get(key) is not False
            for key in ("image_provenance_verified", "lab_started", "effects_authorized")
        )
    ):
        raise ActivationError("runner_build_source_check_mismatch")
    verify(folder, expected_sha)
    final = document(_execute(("image", "inspect", "--format", '{"id":{{json .Id}}}', plan["tag"])))
    if final.get("id") != item["id"]:
        raise ActivationError("runner_build_tag_changed_during_review")
    receipt = {
        "format": "aegis-reviewed-runner-image/1",
        "build_id": folder.name,
        "plan_sha256": expected_sha,
        "source_sha256": plan["source_sha256"],
        "source_commit": plan["source_commit"],
        "native_image_id": item["id"],
        "config_digest": config_digest,
        "result_digest": result_digest,
        "build_metadata_sha256": digest(metadata),
        "build_client_exit_verified": exit_verified,
        "source_check": check,
        "image_built": True,
        "local_build_inputs_verified": True,
        "publisher_signature_verified": False,
        **FLAGS,
    }
    try:
        _write(
            folder / "receipt.json",
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
        )
    except FileExistsError:
        if _json(folder / "receipt.json") != receipt:
            raise ActivationError("runner_build_receipt_conflict") from None
    return {
        "status": "runner_image_built_and_locally_verified",
        "receipt_sha256": digest(receipt),
        **receipt,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    for name in (
        "source-id",
        "source-sha256",
        "cache-id",
        "cache-sha256",
        "base-metadata",
        "base-sha256",
    ):
        create.add_argument("--" + name, required=True)
    for name in ("build", "review"):
        execute = commands.add_parser(name)
        execute.add_argument("--build-id", required=True)
        execute.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            report = prepare(
                args.source_id,
                args.source_sha256,
                args.cache_id,
                args.cache_sha256,
                Path(args.base_metadata),
                args.base_sha256,
            )
        else:
            action = build if args.command == "build" else review
            report = action(ROOT / _id(args.build_id), args.expected_sha256)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ):
        print(json.dumps({"status": "rejected", "code": "runner_image_build_unconfirmed", **FLAGS}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
