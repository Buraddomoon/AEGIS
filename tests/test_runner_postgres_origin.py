"""Bounded official PostgreSQL metadata via HTTP/native fixtures; no pull or lab."""

import asyncio
import copy
import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from test_runner_image_registry import Registry, encode, sha

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_postgres_origin as origin  # noqa: E402


class Fixture:
    def __init__(self, scene=None):
        self.remote, self.calls = Registry(scene), []
        self.image = sha(encode(self.remote.index))
        self.item = {
            "id": self.image,
            "os": "linux",
            "architecture": "amd64",
            "repo_digests": ["postgres@" + self.image],
            "descriptor": {
                "digest": self.image,
                "mediaType": "application/vnd.oci.image.index.v1+json",
            },
        }

    def native(self, args):
        assert args == ("image", "inspect", "--format", origin.FORMAT, self.image)
        assert ".Config.Env" not in origin.FORMAT
        return json.dumps(self.item).encode()

    def query(self, kind, image):
        assert kind == "image" and image == self.image
        return json.dumps(
            {
                "id": image,
                "user": None,
                "volumes": {origin.inspection.server.DATA: {}},
                "exposed_ports": {"5432/tcp": {}},
                "onbuild": None,
                "label_count": 0,
                "environment": [{"key": key, "valid": True} for key in origin.inspection.ENV_FIXED],
            }
        ).encode()

    def handle(self, request):
        self.calls.append(request)
        assert request.method == "GET"
        assert request.headers["accept-encoding"] == "identity"
        if request.url.host == "auth.docker.io":
            assert dict(request.url.params) == {
                "service": "registry.docker.io",
                "scope": "repository:library/postgres:pull",
            }
            assert "authorization" not in request.headers
            translated = httpx.Request(
                "GET",
                request.url.copy_with(
                    params={
                        "service": "registry.docker.io",
                        "scope": "repository:library/python:pull",
                    }
                ),
                headers=request.headers,
            )
        else:
            assert request.url.host == "registry-1.docker.io"
            assert request.url.path in {
                "/v2/library/postgres/manifests/" + self.image,
                "/v2/library/postgres/manifests/" + self.remote.manifest_sha,
            }
            suffix = (
                "3.13-slim" if request.url.path.endswith(self.image) else self.remote.manifest_sha
            )
            translated = httpx.Request(
                "GET",
                "https://registry-1.docker.io/v2/library/python/manifests/" + suffix,
                headers=request.headers,
            )
        return self.remote.handle(translated)

    def capture(self):
        return origin.capture(
            self.image,
            docker=self.native,
            inspection_docker=self,
            transport=httpx.MockTransport(self.handle),
        )


def test_receipt_links_local_official_index_and_verified_remote_manifest_without_layers():
    fixture = Fixture()
    result = fixture.capture()
    assert result["image_id"] == fixture.image
    assert result["platform_manifest_digest"] == fixture.remote.manifest_sha
    assert result["registry_manifest_verified"] and result["local_official_reference_verified"]
    assert result["config_digest"] == "sha256:" + "a" * 64
    assert all(result[key] is False for key in origin.FLAGS)
    assert "private-sensitive-sentinel" not in json.dumps(result)
    assert len(fixture.calls) == 3
    assert all("/blobs/" not in str(request.url) for request in fixture.calls)
    assert origin.review(fixture.image, result, docker=fixture.native)["image_id"] == fixture.image


@pytest.mark.parametrize(
    "field,value",
    [
        ("repo_digests", []),
        ("repo_digests", ["untrusted.invalid/postgres@sha256:" + "1" * 64]),
        ("id", "sha256:" + "0" * 64),
        ("architecture", "arm64"),
        ("os", "windows"),
        ("descriptor", None),
        (
            "descriptor",
            {
                "digest": "sha256:" + "1" * 64,
                "mediaType": "application/vnd.oci.image.index.v1+json",
            },
        ),
    ],
)
def test_capture_rejects_unreviewed_native_profile_before_network(field, value):
    fixture = Fixture()
    fixture.item[field] = value
    with pytest.raises(ValueError):
        fixture.capture()
    assert not fixture.calls


@pytest.mark.parametrize(
    "scene",
    [
        "foreign_layer",
        "huge_layer",
        "image_limit",
        "bad_config",
        "config_urls",
        "bool_size",
        "foreign_media",
        "ambiguous",
        "missing_amd64",
        "platform_digest",
        "schema",
        "redirect",
        "bad_token",
        "duplicate_json",
        "oversize",
        "deep",
        "index_hash",
        "encoding",
        "child_hash",
    ],
)
def test_remote_metadata_cannot_expand_destinations_or_pass_inconsistent_hashes(scene):
    fixture = Fixture(scene)
    with pytest.raises(ValueError, match="postgres_registry_origin_unconfirmed") as caught:
        fixture.capture()
    assert "private-sensitive-sentinel" not in str(caught.value)
    assert all(
        request.url.host in {"auth.docker.io", "registry-1.docker.io"} for request in fixture.calls
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("publisher_signature_verified", True),
        ("registry_manifest_verified", 1),
        ("image_pulled", 0),
        ("compressed_layer_bytes", True),
        ("config_digest", "invalid"),
        ("repository", "untrusted.invalid/postgres"),
        ("checked_at", "2099-01-01T00:00:00+00:00"),
        ("checked_at", "2026-01-01T00:00:00"),
        ("token", "private-sensitive-sentinel"),
    ],
)
def test_tampered_receipt_is_not_adopted_even_before_a_native_query(field, value):
    fixture = Fixture()
    result = copy.deepcopy(fixture.capture())
    result[field] = value
    with pytest.raises(ValueError):
        origin.review(
            fixture.image, result, docker=lambda *a: pytest.fail("native query forbidden")
        )


def test_absolute_deadline_applies_across_requests(monkeypatch):
    fixture = Fixture()
    original = asyncio.timeout
    monkeypatch.setattr(origin.asyncio, "timeout", lambda _: original(0.05))

    async def slow(request):
        await asyncio.sleep(0.03)
        return fixture.handle(request)

    with pytest.raises(ValueError):
        origin.capture(
            fixture.image,
            docker=fixture.native,
            inspection_docker=fixture,
            transport=httpx.MockTransport(slow),
        )
    assert len(fixture.calls) < 3


def test_import_does_not_connect_spawn_or_load_application_settings():
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
sys.addaudithook(guard)
import runner_postgres_origin
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
