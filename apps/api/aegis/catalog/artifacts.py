"""Private, bounded, host-only candidate preparation. Never downloads on import."""

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from aegis.catalog.document import (
    BASE,
    COMMIT,
    HEX64,
    MAX_BUNDLE,
    MAX_LICENSE,
    MAX_NORMALIZED,
    VERSION,
    Document,
    normalize,
    parse_json,
    source_url,
    timestamp,
)
from aegis.domain.validation import digest

FORMAT = "aegis-attack-candidate/1"
FILES = ("bundle.json", "LICENSE.txt", "document.json")
DOWNLOAD_BUDGET = 75


def private(path, create=False):
    if path.is_symlink():
        raise ValueError("Symlink catalog path refused")
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("Catalog directories must be owned by this user and mode0700")


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def encode(data):
    return (
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > limit
        ):
            raise ValueError("Unsafe catalog candidate file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Candidate file exceeds limit")
    return raw


async def download(client, url, limit, deadline):
    allowed = (
        re.escape(BASE)
        + COMMIT
        + r"/(?:LICENSE\.txt|enterprise-attack/enterprise-attack-"
        + VERSION
        + r"\.json)"
    )
    if not re.fullmatch(allowed, url):
        raise ValueError("Catalog download origin/path refused")
    if time.monotonic() > deadline:
        raise ValueError("Catalog download exceeded time budget")
    async with asyncio.timeout(max(0, deadline - time.monotonic())):
        async with client.stream(
            "GET",
            url,
            headers={"Accept-Encoding": "identity", "User-Agent": "AEGIS-catalog/1"},
            follow_redirects=False,
        ) as response:
            response.raise_for_status()
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ValueError("Encoded catalog response refused")
            declared = response.headers.get("content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > limit):
                raise ValueError("Catalog response exceeds limit")
            chunks = []
            size = 0
            async for chunk in response.aiter_raw():
                size += len(chunk)
                if size > limit or time.monotonic() > deadline:
                    raise ValueError("Catalog download exceeded size/time budget")
                chunks.append(chunk)
            raw = b"".join(chunks)
            if declared is not None and len(raw) != int(declared):
                raise ValueError("Incomplete catalog response")
            return raw


def load(root, identity):
    if not re.fullmatch(HEX64, identity):
        raise ValueError("Invalid candidate identity")
    private(root.parent)
    private(root)
    folder = root / identity
    private(folder)
    manifest = parse_json(read(folder / "manifest.json", 8192), 8192)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"format", "id", "created_at", "files"}
        or manifest["format"] != FORMAT
        or manifest["id"] != identity
        or set(manifest["files"]) != set(FILES)
    ):
        raise ValueError("Invalid catalog candidate manifest")
    timestamp(manifest["created_at"])
    raw = {
        name: read(
            folder / name,
            {
                "bundle.json": MAX_BUNDLE,
                "LICENSE.txt": MAX_LICENSE,
                "document.json": MAX_NORMALIZED,
            }[name],
        )
        for name in FILES
    }
    if any(
        hashlib.sha256(value).hexdigest() != manifest["files"][name] for name, value in raw.items()
    ):
        raise ValueError("Candidate bytes changed after preparation")
    document = Document.model_validate(parse_json(raw["document.json"], MAX_NORMALIZED))
    if document.provenance != "official_commit" or document.identity != identity:
        raise ValueError("Candidate provenance/identity mismatch")
    rebuilt = normalize(
        raw["bundle.json"], document.version, document.source_commit, raw["LICENSE.txt"]
    )
    if rebuilt != document:
        raise ValueError("Normalized candidate does not match its original source")
    return document


async def fetch(version, commit, transport=None):
    deadline = time.monotonic() + DOWNLOAD_BUDGET
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10, connect=5),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        raw = await download(client, source_url(version, commit), MAX_BUNDLE, deadline)
        license_raw = await download(client, BASE + commit + "/LICENSE.txt", MAX_LICENSE, deadline)
    return raw, license_raw


def prepare(root, version, commit, *, transport=None):
    # Fixed URLs and no asynchronous request can outlive the bounded facade.
    source_url(version, commit)
    private(root.parent, True)
    private(root, True)
    raw, license_raw = asyncio.run(fetch(version, commit, transport))
    document = normalize(raw, version, commit, license_raw)
    normalized = encode(document.model_dump(mode="json"))
    if len(normalized) > MAX_NORMALIZED:
        raise ValueError("Normalized candidate exceeds reviewed profile limit")
    temporary = Path(tempfile.mkdtemp(prefix=".preparing-", dir=root))
    identity = document.identity
    try:
        content = {"bundle.json": raw, "LICENSE.txt": license_raw, "document.json": normalized}
        for name, value in content.items():
            write(temporary / name, value)
        manifest = {
            "format": FORMAT,
            "id": identity,
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "files": {name: hashlib.sha256(value).hexdigest() for name, value in content.items()},
        }
        write(temporary / "manifest.json", encode(manifest))
        sync(temporary)
        destination = root / identity
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError:
            # Never overwrite a prepared candidate, even on an idempotent fetch.
            if load(root, identity) != document:
                raise ValueError("Existing candidate conflicts with download") from None
        else:
            # No overwrites; the manifest commits a complete candidate last.
            for name in FILES:
                os.link(temporary / name, destination / name, follow_symlinks=False)
            sync(destination)
            os.link(
                temporary / "manifest.json", destination / "manifest.json", follow_symlinks=False
            )
            sync(destination)
            sync(root)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return identity


def save_plan(root, plan):
    private(root.parent)
    private(root)
    identity = plan["plan_sha256"]
    if not re.fullmatch(HEX64, identity):
        raise ValueError("Invalid plan identity")
    if digest({k: v for k, v in plan.items() if k != "plan_sha256"}) != identity:
        raise ValueError("Invalid plan fingerprint")
    folder = root / "plans"
    private(folder, True)
    path = folder / (identity + ".json")
    raw = encode(plan)
    try:
        write(path, raw)
        sync(folder)
    except FileExistsError:
        if read(path, 12_000_000) != raw:
            raise ValueError("Existing review file changed") from None
    return path
