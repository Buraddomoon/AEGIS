"""Private committed runner build context; no build, pull, container or lab effects."""

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path
from uuid import UUID, uuid4

import runner_pki as pki
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError, _unique

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".local/pki-image-sources"
PACKAGE = "apps/api/aegis/"
OTHER = frozenset({"requirements.lock", "pyproject.toml", "labs/linux/Dockerfile"})
REQUIRED = OTHER | {
    PACKAGE + name
    for name in (
        "__init__.py",
        "models.py",
        "binding_review.py",
        "lab_runner/persisted_probe.py",
        "lab_runner/persisted_review.py",
        "lab_runner/journal_probe.py",
    )
}
MAX_FILES, MAX_FILE, MAX_SOURCE, MAX_CONTEXT = 256, 1024**2, 4 * 1024**2, 8 * 1024**2
FORMAT = "aegis-runner-image-source/1"
FLAGS = {"image_built": False, "image_provenance_verified": False, "effects_authorized": False}
GIT_ENV = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_NO_REPLACE_OBJECTS": "1",
}


def _git(repo, *arguments, maximum=MAX_CONTEXT):
    # Fixed builtins only, trusted local repository. No fetch/filter/hooks/config helpers.
    try:
        result = subprocess.run(
            [
                "/usr/bin/git",
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "submodule.recurse=false",
                *arguments,
            ],
            cwd=repo,
            env=GIT_ENV,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0 or len(result.stdout) > maximum:
            raise ActivationError("runner_source_git_query_failed")
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise ActivationError("runner_source_git_query_failed") from None


def _state(repo):
    if _git(repo, "symbolic-ref", "--short", "HEAD", maximum=128) != b"main\n":
        raise ActivationError("runner_source_main_required")
    if _git(
        repo, "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=all"
    ):
        raise ActivationError("runner_source_clean_worktree_required")
    commit = _git(repo, "rev-parse", "--verify", "HEAD", maximum=128).decode("ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ActivationError("runner_source_git_object_format_unsupported")
    return commit


def _allowed(path):
    if not isinstance(path, str) or len(path) > 200:
        return False
    if path in OTHER:
        return True
    return path.startswith(PACKAGE) and bool(
        re.fullmatch(
            r"(?:[A-Za-z_][A-Za-z0-9_]{0,79}/)*[A-Za-z_][A-Za-z0-9_]{0,79}\.py",
            path[len(PACKAGE) :],
        )
    )


def _collect(repo, commit):
    listing = _git(
        repo,
        "ls-tree",
        "-r",
        "-l",
        "-z",
        "--full-tree",
        commit,
        "--",
        PACKAGE,
        *sorted(OTHER),
        maximum=128 * 1024,
    )
    entries = listing.split(b"\0")
    if entries[-1] != b"" or not 1 <= len(entries) - 1 <= MAX_FILES:
        raise ActivationError("runner_source_file_count_invalid")
    files, size = {}, 0
    for entry in entries[:-1]:
        try:
            header, name = entry.split(b"\t", 1)
            mode, kind, oid, declared = header.split()
            path, count = name.decode("utf-8"), int(declared)
        except (ValueError, UnicodeError):
            raise ActivationError("runner_source_tree_invalid") from None
        if (
            not _allowed(path)
            or path in files
            or kind != b"blob"
            or mode != b"100644"
            or not re.fullmatch(rb"[a-f0-9]{40}", oid)
            or not 0 <= count <= MAX_FILE
        ):
            raise ActivationError("runner_source_tree_invalid")
        size += count
        if size > MAX_SOURCE:
            raise ActivationError("runner_source_content_limit")
        content = _git(repo, "cat-file", "blob", oid.decode("ascii"), maximum=MAX_FILE)
        native_hash = (
            hashlib.sha1(
                b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False
            )
            .hexdigest()
            .encode()
        )
        if len(content) != count or native_hash != oid:
            raise ActivationError("runner_source_blob_size_mismatch")
        files[path] = content
    if not REQUIRED <= set(files):
        raise ActivationError("runner_source_required_files_missing")
    return files


def _manifest(files):
    return {
        path: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for path, content in sorted(files.items())
    }


def _write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(*, repo=ROOT, output_root=DEFAULT_OUTPUT):
    """Export only tracked allowlisted blobs, never untracked/ignored working files."""
    commit = _state(repo)
    files = _collect(repo, commit)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, content in sorted(files.items()):
            member = tarfile.TarInfo(path)
            member.mode, member.size, member.mtime = 0o644, len(content), 0
            archive.addfile(member, io.BytesIO(content))
    context = output.getvalue()
    if len(context) > MAX_CONTEXT:
        raise ActivationError("runner_source_context_limit")
    manifest = _manifest(files)
    document = {
        "format": FORMAT,
        "source_commit": commit,
        "files": manifest,
        "source_tree_sha256": digest(manifest),
        "context_sha256": hashlib.sha256(context).hexdigest(),
        "context_bytes": len(context),
        **FLAGS,
    }
    if _state(repo) != commit:
        raise ActivationError("runner_source_changed_during_export")
    root = pki.private_directory(output_root, create=True)
    folder = root / uuid4().hex
    folder.mkdir(mode=0o700)
    pki.sync(folder)
    pki.sync(root)
    try:
        _write(folder / "context.tar", context)
        _write(
            folder / "source.json",
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
        )
        pki.sync(folder)
        if _state(repo) != commit:
            raise ActivationError("runner_source_changed_during_export")
        verify(folder, digest(document))
    except (ValueError, OSError):
        raise ActivationError("runner_source_export_unconfirmed") from None
    return {
        "status": "committed_runner_source_prepared_not_built",
        "folder": str(folder),
        "source_sha256": digest(document),
        "source_commit": commit,
        "source_tree_sha256": document["source_tree_sha256"],
        "files_exported": len(files),
        **FLAGS,
    }


def verify(folder, expected_sha256):
    """Independent SHA required; inspect tar in memory, never extract it to disk."""
    try:
        if not isinstance(expected_sha256, str) or not re.fullmatch(
            r"[a-f0-9]{64}", expected_sha256
        ):
            raise ActivationError("runner_source_hash_required")
        folder = pki.private_directory(folder)
        document = json.loads(
            pki.read(folder / "source.json", modes=(0o600,), maximum=256 * 1024),
            object_pairs_hook=_unique,
        )
        if (
            not isinstance(document, dict)
            or digest(document) != expected_sha256
            or set(document)
            != {
                "format",
                "source_commit",
                "files",
                "source_tree_sha256",
                "context_sha256",
                "context_bytes",
                *FLAGS,
            }
            or document["format"] != FORMAT
            or not re.fullmatch(r"[a-f0-9]{40}", document["source_commit"])
            or any(document[key] is not False for key in FLAGS)
            or type(document["context_bytes"]) is not int
            or not 1 <= document["context_bytes"] <= MAX_CONTEXT
        ):
            raise ActivationError("runner_source_manifest_invalid")
        context = pki.read(folder / "context.tar", modes=(0o600,), maximum=MAX_CONTEXT)
        if (
            len(context) != document["context_bytes"]
            or hashlib.sha256(context).hexdigest() != document["context_sha256"]
        ):
            raise ActivationError("runner_source_context_integrity_mismatch")
        files, total = {}, 0
        with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
            for member in archive:
                if (
                    member.type != tarfile.REGTYPE
                    or not _allowed(member.name)
                    or member.name in files
                    or member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.mtime != 0
                    or member.uname
                    or member.gname
                    or member.linkname
                    or member.pax_headers
                    or not 0 <= member.size <= MAX_FILE
                    or len(files) >= MAX_FILES
                ):
                    raise ActivationError("runner_source_archive_invalid")
                total += member.size
                if total > MAX_SOURCE:
                    raise ActivationError("runner_source_content_limit")
                stream = archive.extractfile(member)
                content = stream.read(MAX_FILE + 1)
                if len(content) != member.size:
                    raise ActivationError("runner_source_archive_invalid")
                files[member.name] = content
        manifest = _manifest(files)
        if (
            not REQUIRED <= set(files)
            or digest(manifest) != digest(document["files"])
            or digest(manifest) != document["source_tree_sha256"]
        ):
            raise ActivationError("runner_source_archive_manifest_mismatch")
        return document
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        tarfile.TarError,
    ):
        raise ActivationError("runner_source_verification_failed") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    check = commands.add_parser("verify")
    check.add_argument("--source-id", required=True)
    check.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            report = prepare()
        else:
            if UUID(hex=args.source_id).hex != args.source_id:
                raise ActivationError("runner_source_identifier_invalid")
            document = verify(DEFAULT_OUTPUT / args.source_id, args.expected_sha256)
            report = {
                "status": "committed_runner_source_verified_not_built",
                "source_commit": document["source_commit"],
                "source_sha256": args.expected_sha256,
                "source_tree_sha256": document["source_tree_sha256"],
                "files_exported": len(document["files"]),
                **FLAGS,
            }
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, AttributeError):
        print(
            json.dumps({"status": "rejected", "code": "runner_source_operation_rejected", **FLAGS})
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
