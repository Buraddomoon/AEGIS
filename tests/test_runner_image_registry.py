"""Official fixed-host registry flow using HTTP fixtures, no real registry or Docker."""

import asyncio
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_image_registry as registry  # noqa: E402


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class Registry:
    def __init__(self, scene=None):
        self.scene, self.calls = scene, []
        self.manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + "a" * 64,
                "size": 4096,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "b" * 64,
                    "size": 1024,
                }
            ],
        }
        if scene == "foreign_layer":
            self.manifest["layers"][0]["urls"] = ["https://untrusted.invalid/layer"]
        elif scene == "huge_layer":
            self.manifest["layers"][0]["size"] = 129 * 1024**2
        elif scene == "image_limit":
            self.manifest["layers"] = [copy.deepcopy(self.manifest["layers"][0]) for _ in range(3)]
            [item.update(size=128 * 1024**2) for item in self.manifest["layers"]]
        elif scene == "bad_config":
            self.manifest["config"]["digest"] = "https://untrusted.invalid"
        elif scene == "config_urls":
            self.manifest["config"]["urls"] = ["https://untrusted.invalid/config"]
        elif scene == "bool_size":
            self.manifest["layers"][0]["size"] = True
        elif scene == "foreign_media":
            self.manifest["layers"][0]["mediaType"] = "unexpected"
        self.raw_manifest = encode(self.manifest)
        self.manifest_sha = sha(self.raw_manifest)
        self.index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": self.manifest["mediaType"],
                    "digest": self.manifest_sha,
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "mediaType": self.manifest["mediaType"],
                    "digest": "sha256:" + "c" * 64,
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
            ],
        }
        if scene == "ambiguous":
            self.index["manifests"].append(copy.deepcopy(self.index["manifests"][0]))
        elif scene == "missing_amd64":
            self.index["manifests"].pop(0)
        elif scene == "platform_digest":
            self.index["manifests"][0]["digest"] = "https://untrusted.invalid"
        elif scene == "schema":
            self.index["schemaVersion"] = True

    def response(self, value, headers=None):
        raw = value if isinstance(value, bytes) else encode(value)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", **(headers or {})},
            stream=httpx.ByteStream(raw),
        )

    def handle(self, request):
        self.calls.append(request)
        assert request.method == "GET"
        assert request.headers["accept-encoding"] == "identity"
        if request.url.host == "auth.docker.io":
            assert dict(request.url.params) == {
                "service": "registry.docker.io",
                "scope": "repository:library/python:pull",
            }
            assert "authorization" not in request.headers
            if self.scene == "redirect":
                return httpx.Response(302, headers={"Location": "https://untrusted.invalid/token"})
            return self.response(
                {
                    "token": "invalid\nheader"
                    if self.scene == "bad_token"
                    else "private-sensitive-sentinel"
                }
            )
        assert request.url.host == "registry-1.docker.io"
        assert request.headers["authorization"] == "Bearer private-sensitive-sentinel"
        if request.url.path.endswith("/3.13-slim"):
            raw = encode(self.index)
            if self.scene == "duplicate_json":
                raw = b'{"schemaVersion":2,"schemaVersion":2}'
            elif self.scene == "oversize":
                raw = b"x" * (1024**2 + 1)
            elif self.scene == "deep":
                raw = b"[" * 2000 + b"]" * 2000
            headers = {
                "Docker-Content-Digest": "sha256:" + "f" * 64
                if self.scene == "index_hash"
                else sha(raw)
            }
            if self.scene == "encoding":
                headers["Content-Encoding"] = "gzip"
            return self.response(raw, headers)
        assert request.url.path == "/v2/library/python/manifests/" + self.manifest_sha
        return self.response(
            self.raw_manifest,
            {
                "Docker-Content-Digest": "sha256:" + "f" * 64
                if self.scene == "child_hash"
                else self.manifest_sha
            },
        )


def test_only_anonymous_official_pull_scope_and_exact_linux_amd64_manifest_are_reviewed():
    fixture = Registry()
    result = registry.python_base(transport=httpx.MockTransport(fixture.handle))
    assert result["reference"] == "docker.io/library/python@" + fixture.manifest_sha
    assert result["config_digest"] == "sha256:" + "a" * 64
    assert result["architecture"] == "amd64" and result["os"] == "linux"
    assert result["registry_manifest_verified"]
    assert all(
        result[key] is False
        for key in (
            "image_pulled",
            "image_built",
            "image_provenance_verified",
            "effects_authorized",
        )
    )
    assert "private-sensitive-sentinel" not in json.dumps(result)
    assert len(fixture.calls) == 3


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
def test_untrusted_response_cannot_expand_destinations_or_claim_base_verification(scene):
    fixture = Registry(scene)
    with pytest.raises(registry.ActivationError, match="registry_review_failed") as caught:
        registry.python_base(transport=httpx.MockTransport(fixture.handle))
    assert "private-sensitive-sentinel" not in str(caught.value)
    assert all(
        request.url.host in {"auth.docker.io", "registry-1.docker.io"} for request in fixture.calls
    )


def test_absolute_deadline_includes_all_requests_not_only_individual_read_timeout(monkeypatch):
    fixture = Registry()
    original = asyncio.timeout
    monkeypatch.setattr(registry.asyncio, "timeout", lambda _: original(0.05))

    async def slow(request):
        await asyncio.sleep(0.03)
        return fixture.handle(request)

    with pytest.raises(registry.ActivationError, match="registry_review_failed"):
        registry.python_base(transport=httpx.MockTransport(slow))
    assert len(fixture.calls) < 3


def test_import_performs_no_network_or_subprocess():
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
import runner_image_registry
assert 'aegis.config' not in sys.modules
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
