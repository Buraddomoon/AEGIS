"""Offline delivery checks against Git's index, without reading local secrets."""

import json
import posixpath
import re
import subprocess
import sys
import tomllib
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from check_staged import check_paths

LINK = re.compile(r"!?\[[^\]\n]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1\s*$")


def indexed(path: str) -> bytes:
    return subprocess.check_output(["git", "show", ":" + path], stderr=subprocess.DEVNULL)


def review(paths: list[str]) -> tuple[dict, list[str]]:
    errors = check_paths(paths)
    tracked = set(paths)
    backend = tomllib.loads(indexed("pyproject.toml").decode())["project"]["version"]
    frontend = json.loads(indexed("apps/web/package.json"))
    lock = json.loads(indexed("apps/web/package-lock.json"))
    if any(
        version != backend
        for version in (frontend["version"], lock["version"], lock["packages"][""]["version"])
    ):
        errors.append("Backend/frontend/lock versions differ")
    for group in ("dependencies", "devDependencies"):
        if frontend.get(group, {}) != lock["packages"][""].get(group, {}):
            errors.append("Frontend dependency declarations differ from lock root: " + group)
    links = 0
    markdown = [path for path in paths if path.endswith(".md")]
    for source in markdown:
        content = FENCE.sub("", indexed(source).decode("utf-8"))
        for match in LINK.finditer(content):
            destination = match.group(1) or match.group(2)
            parsed = urlsplit(destination)
            if parsed.scheme in {"http", "https", "mailto"}:
                continue  # No network requests or claims about external availability.
            if parsed.scheme or parsed.netloc:
                errors.append(source + ": unsupported local link scheme")
                continue
            if not parsed.path:
                continue  # Fragment validity requires a Markdown renderer.
            links += 1
            path = unquote(parsed.path)
            target = posixpath.normpath(str(PurePosixPath(source).parent / path))
            if path.startswith("/") or target == ".." or target.startswith("../"):
                errors.append(source + ": local link escapes repository")
            elif target not in tracked and not any(
                p.startswith(target.rstrip("/") + "/") for p in paths
            ):
                errors.append(source + ": missing tracked local target " + target)
    images = []
    for path in paths:
        if not path.startswith("docs/images/") or not path.endswith(".png"):
            continue
        content = indexed(path)
        if len(content) < 24 or content[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR":
            errors.append(path + ": invalid PNG header")
            continue
        width, height = int.from_bytes(content[16:20]), int.from_bytes(content[20:24])
        if width == 0 or height == 0:
            errors.append(path + ": empty PNG dimensions")
        images.append({"path": path, "width": width, "height": height})
    return {
        "format": "aegis-source-review/1",
        "source": "git-index",
        "version": backend,
        "tracked_files": len(paths),
        "markdown_files": len(markdown),
        "local_links": links,
        "screenshots": images,
        "limits": [
            "Pattern checks do not prove absence of secrets",
            "Markdown inline local file targets only; no fragment or external link validation",
            "PNG headers/dimensions do not prove screenshot provenance",
            "No install, tests, dependency audit, deployment or lab execution performed",
        ],
    }, errors


def main() -> int:
    try:
        paths = subprocess.check_output(["git", "ls-files", "-z"], text=True).split("\0")
        report, errors = review([path for path in paths if path])
        report["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        report["index_differs_from_head"] = (
            subprocess.run(["git", "diff", "--cached", "--quiet"]).returncode != 0
        )
        report["worktree_differs_from_index"] = (
            subprocess.run(["git", "diff", "--quiet"]).returncode != 0
        )
        report["status"] = "failed" if errors else "passed"
        report["errors"] = errors
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1 if errors else 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Source review failed: incomplete or invalid Git index/metadata", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
