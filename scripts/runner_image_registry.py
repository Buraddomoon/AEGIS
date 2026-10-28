"""Read-only official Python registry manifest selection; no pull/build or credentials."""

import asyncio
import hashlib
import json
import re
from datetime import UTC, datetime

import httpx
from runner_activation_metadata import ActivationError, _unique

AUTH = "https://auth.docker.io/token"
REGISTRY = "https://registry-1.docker.io/v2/library/python/manifests/"
INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
CONFIG_TYPES = frozenset(
    {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}
)
LAYER_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    }
)
ACCEPT = ", ".join(sorted(INDEX_TYPES | MANIFEST_TYPES))


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise ActivationError("python_registry_digest_invalid")
    return value


async def _read(client, url, *, headers=None, params=None):
    async with client.stream(
        "GET", url, headers={"Accept-Encoding": "identity", **(headers or {})}, params=params
    ) as response:
        response.raise_for_status()
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise ActivationError("python_registry_encoding_invalid")
        content = bytearray()
        async for chunk in response.aiter_raw():
            if len(content) + len(chunk) > 1024**2:
                raise ActivationError("python_registry_metadata_limit")
            content.extend(chunk)
        data = json.loads(content, object_pairs_hook=_unique)
        return data, bytes(content), response.headers


async def _manifest(client, reference, token):
    data, raw, headers = await _read(
        client, REGISTRY + reference, headers={"Authorization": "Bearer " + token, "Accept": ACCEPT}
    )
    expected = _sha(headers.get("Docker-Content-Digest"))
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected:
        raise ActivationError("python_registry_manifest_integrity_mismatch")
    if reference.startswith("sha256:") and reference != expected:
        raise ActivationError("python_registry_selected_manifest_mismatch")
    if (
        not isinstance(data, dict)
        or type(data.get("schemaVersion")) is not int
        or data["schemaVersion"] != 2
    ):
        raise ActivationError("python_registry_schema_invalid")
    return data, expected


async def _python_base(transport):
    """Anonymous pull scope only, token stays in memory and never enters a receipt.

    Fixed official repository/tag and Linux amd64 profile. Transport injection is
    for local HTTP fixtures, never a configurable runtime connector or API input.
    """
    try:
        async with (
            asyncio.timeout(30),
            httpx.AsyncClient(
                verify=True,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(10),
                transport=transport,
            ) as client,
        ):
            auth, _, _ = await _read(
                client,
                AUTH,
                params={"service": "registry.docker.io", "scope": "repository:library/python:pull"},
            )
            token = auth.get("token") if isinstance(auth, dict) else None
            if (
                not isinstance(token, str)
                or not 1 <= len(token) <= 8192
                or any(char.isspace() for char in token)
            ):
                raise ActivationError("python_registry_anonymous_token_invalid")
            index, index_digest = await _manifest(client, "3.13-slim", token)
            if (
                index.get("mediaType") not in INDEX_TYPES
                or not isinstance(index.get("manifests"), list)
                or not 1 <= len(index["manifests"]) <= 64
            ):
                raise ActivationError("python_registry_index_invalid")
            candidates = [
                item
                for item in index["manifests"]
                if isinstance(item, dict)
                and item.get("platform", {}).get("os") == "linux"
                and item.get("platform", {}).get("architecture") == "amd64"
                and item.get("platform", {}).get("variant") in (None, "")
            ]
            if len(candidates) != 1 or candidates[0].get("mediaType") not in MANIFEST_TYPES:
                raise ActivationError("python_registry_platform_ambiguous")
            selected = _sha(candidates[0].get("digest"))
            manifest, actual_digest = await _manifest(client, selected, token)
            if manifest.get("mediaType") not in MANIFEST_TYPES:
                raise ActivationError("python_registry_manifest_invalid")
            config = manifest.get("config")
            layers = manifest.get("layers")
            if (
                not isinstance(config, dict)
                or config.get("mediaType") not in CONFIG_TYPES
                or type(config.get("size")) is not int
                or not 1 <= config["size"] <= 128 * 1024
                or config.get("urls")
                or not isinstance(layers, list)
                or not 1 <= len(layers) <= 32
            ):
                raise ActivationError("python_registry_image_invalid")
            total = 0
            for layer in layers:
                if (
                    not isinstance(layer, dict)
                    or layer.get("mediaType") not in LAYER_TYPES
                    or layer.get("urls")
                    or type(layer.get("size")) is not int
                    or not 1 <= layer["size"] <= 128 * 1024**2
                ):
                    raise ActivationError("python_registry_layer_invalid")
                _sha(layer.get("digest"))
                total += layer["size"]
            if total > 256 * 1024**2:
                raise ActivationError("python_registry_image_limit")
            return {
                "format": "aegis-python-registry-base/1",
                "checked_at": datetime.now(UTC).isoformat(),
                "repository": "docker.io/library/python",
                "tag_reviewed": "3.13-slim",
                "reference": "docker.io/library/python@" + actual_digest,
                "index_digest": index_digest,
                "platform_manifest_digest": actual_digest,
                "expected_image_id": _sha(config.get("digest")),
                "os": "linux",
                "architecture": "amd64",
                "compressed_layer_bytes": total,
                "registry_manifest_verified": True,
                "image_pulled": False,
                "image_built": False,
                "image_provenance_verified": False,
                "effects_authorized": False,
            }
    except (
        TimeoutError,
        httpx.HTTPError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
    ):
        raise ActivationError("python_registry_review_failed") from None


def python_base(*, transport=None):
    """Host-only synchronous entry point; one absolute30s deadline, no Docker IO."""
    return asyncio.run(_python_base(transport))
