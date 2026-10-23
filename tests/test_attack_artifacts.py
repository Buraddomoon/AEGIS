"""HTTP/file safety using the reduced, explicitly synthetic STIX transport fixture."""

import asyncio
import hashlib
import json
import time

import httpx
import pytest
from aegis.catalog import artifacts
from aegis.domain.validation import digest
from test_attack_document import COMMIT, FIXTURE, LICENSE


@pytest.fixture
def cache(tmp_path):
    return tmp_path / ".local/attack-catalog"


def source_transport(handler=None):
    def default(request):
        raw = LICENSE if str(request.url).endswith("/LICENSE.txt") else FIXTURE.read_bytes()
        return httpx.Response(
            200, stream=httpx.ByteStream(raw), headers={"Content-Length": str(len(raw))}
        )

    return httpx.MockTransport(handler or default)


def download_for_test(transport, url, limit, deadline):
    async def call():
        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            return await artifacts.download(client, url, limit, deadline)

    return asyncio.run(call())


def test_prepared_artifact_is_exclusive_verified_and_private(cache):
    with source_transport() as client:
        identity = artifacts.prepare(cache, "20.0", COMMIT, transport=client)
        original = {p.name: p.read_bytes() for p in (cache / identity).iterdir()}
        assert artifacts.prepare(cache, "20.0", COMMIT, transport=client) == identity
    document = artifacts.load(cache, identity)
    assert document.identity == identity
    assert {p.name: p.read_bytes() for p in (cache / identity).iterdir()} == original
    assert (cache / identity).stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (cache / identity).iterdir())
    assert not list(cache.glob(".preparing-*"))


@pytest.mark.parametrize(
    "change", ["raw", "normalized", "manifest-path", "mode", "symlink", "partial"]
)
def test_tampered_or_unsafe_cache_is_never_accepted(cache, change):
    with source_transport() as client:
        identity = artifacts.prepare(cache, "20.0", COMMIT, transport=client)
    folder = cache / identity
    if change == "raw":
        (folder / "bundle.json").write_bytes(b"{}")
    elif change == "normalized":
        (folder / "document.json").write_bytes(b"{}")
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest["files"]["document.json"] = hashlib.sha256(b"{}").hexdigest()
        (folder / "manifest.json").write_bytes(artifacts.encode(manifest))
    elif change == "manifest-path":
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest["files"]["../../untrusted"] = "f" * 64
        (folder / "manifest.json").write_bytes(artifacts.encode(manifest))
    elif change == "mode":
        (folder / "bundle.json").chmod(0o644)
    elif change == "symlink":
        (folder / "bundle.json").unlink()
        (folder / "bundle.json").symlink_to(folder / "document.json")
    else:
        (folder / "manifest.json").unlink()
    with pytest.raises((ValueError, OSError)):
        artifacts.load(cache, identity)


def test_modified_normalized_source_is_checked_even_if_manifest_hash_is_updated(cache):
    with source_transport() as client:
        identity = artifacts.prepare(cache, "20.0", COMMIT, transport=client)
    folder = cache / identity
    document = json.loads((folder / "document.json").read_bytes())
    document["techniques"][0]["name"] = "Tampered transport fixture"
    raw = artifacts.encode(document)
    (folder / "document.json").write_bytes(raw)
    manifest = json.loads((folder / "manifest.json").read_bytes())
    manifest["files"]["document.json"] = hashlib.sha256(raw).hexdigest()
    (folder / "manifest.json").write_bytes(artifacts.encode(manifest))
    with pytest.raises(ValueError, match="identity mismatch"):
        artifacts.load(cache, identity)


@pytest.mark.parametrize(
    "headers,status,raw",
    [
        ({"content-encoding": "gzip"}, 200, b"not-inflated"),
        ({"content-length": "90000000"}, 200, b""),
        ({"location": "https://untrusted.invalid/"}, 302, b""),
        ({"content-length": "100"}, 200, b"{}"),
    ],
)
def test_redirect_encoding_declared_size_or_truncation_refused(cache, headers, status, raw):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(raw))

    with source_transport(handler) as client, pytest.raises((ValueError, httpx.HTTPError)):
        artifacts.prepare(cache, "20.0", COMMIT, transport=client)
    assert len(calls) == 1 and calls[0].startswith(
        "https://raw.githubusercontent.com/mitre-attack/"
    )
    assert not list(cache.glob("[a-f0-9]" * 64))


def test_actual_stream_size_and_deadline_enforced():
    def handler(request):
        return httpx.Response(200, stream=httpx.ByteStream(b"12345"))

    with source_transport(handler) as client:
        with pytest.raises(ValueError, match="budget"):
            download_for_test(
                client,
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                + COMMIT
                + "/LICENSE.txt",
                4,
                time.monotonic() + 1,
            )
        with pytest.raises(ValueError, match="time"):
            download_for_test(
                client,
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                + COMMIT
                + "/LICENSE.txt",
                4,
                time.monotonic() - 1,
            )


@pytest.mark.parametrize("identity", ["../", "f" * 63, "F" * 64])
def test_invalid_candidate_id_rejected_before_file_access(cache, identity):
    with pytest.raises(ValueError, match="identity"):
        artifacts.load(cache, identity)
    assert not cache.exists()


def test_review_files_are_hash_bound_and_never_overwritten(cache):
    with source_transport() as client:
        artifacts.prepare(cache, "20.0", COMMIT, transport=client)
    data = {"format": "fixture-plan", "changes": []}
    plan = {**data, "plan_sha256": digest(data)}
    path = artifacts.save_plan(cache, plan)
    assert artifacts.save_plan(cache, plan) == path
    assert path.stat().st_mode & 0o777 == 0o600
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        artifacts.save_plan(cache, plan)
    with pytest.raises(ValueError, match="fingerprint"):
        artifacts.save_plan(cache, {**plan, "changes": ["not-reviewed"]})


@pytest.mark.parametrize(
    "url",
    [
        "https://untrusted.invalid/anything",
        "http://raw.githubusercontent.com/mitre-attack/attack-stix-data/" + COMMIT + "/LICENSE.txt",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt",
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        + COMMIT
        + "/LICENSE.txt?redirect=1",
    ],
)
def test_downloader_refuses_arbitrary_origin_path_or_mutable_branch(url):
    with source_transport(lambda request: pytest.fail("Unexpected network request")) as client:
        with pytest.raises(ValueError, match="origin/path"):
            download_for_test(client, url, 100, time.monotonic() + 1)


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_global_budget_cancels_slow_headers_or_body_without_followup(cache, monkeypatch, phase):
    calls = []
    cancelled = []
    closed = []

    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"{"
            try:
                await asyncio.sleep(0.2)
            except asyncio.CancelledError:
                cancelled.append("body")
                raise
            yield b"}"

        async def aclose(self):
            closed.append(True)

    async def handler(request):
        calls.append(str(request.url))
        if phase == "headers":
            try:
                await asyncio.sleep(0.2)
            except asyncio.CancelledError:
                cancelled.append("headers")
                raise
        return httpx.Response(200, stream=SlowBody())

    monkeypatch.setattr(artifacts, "DOWNLOAD_BUDGET", 0.03)
    with source_transport(handler) as transport, pytest.raises(TimeoutError):
        artifacts.prepare(cache, "20.0", COMMIT, transport=transport)
    assert cancelled == [phase] and len(calls) == 1
    if phase == "body":
        assert closed == [True]
    assert not list(cache.glob("[a-f0-9]" * 64))
