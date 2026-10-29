"""Review the existing PostgreSQL image's official digest, without pulling or running it."""

import argparse
import asyncio
import json
import subprocess
from datetime import UTC, datetime

import httpx
import runner_activation_database_inspection as inspection
import runner_image_registry as registry
from runner_activation_metadata import ActivationError, _execute, document, image_id

FORMAT = (
    '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},'
    '"repo_digests":{{json .RepoDigests}},'
    '"descriptor":{{json (index . "Descriptor")}}}'
)
FLAGS = {
    "publisher_signature_verified": False,
    "local_layer_bytes_verified": False,
    "image_pulled": False,
    "lab_started": False,
    "effects_authorized": False,
}


def native(image, *, docker=None):
    image_id(image)
    raw = (docker or _execute)(("image", "inspect", "--format", FORMAT, image))
    value = document(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"id", "os", "architecture", "repo_digests", "descriptor"}
        or value["id"] != image
        or value["os"] != "linux"
        or value["architecture"] != "amd64"
        or not isinstance(value["repo_digests"], list)
        or not 1 <= len(value["repo_digests"]) <= 8
        or any(not isinstance(item, str) for item in value["repo_digests"])
        or not any(
            prefix + "@" + image in value["repo_digests"]
            for prefix in ("postgres", "library/postgres", "docker.io/library/postgres")
        )
        or not isinstance(value["descriptor"], dict)
        or value["descriptor"].get("digest") != image
        or value["descriptor"].get("mediaType") not in registry.INDEX_TYPES
    ):
        raise ActivationError("postgres_official_native_index_unconfirmed")
    return {
        "image_id": image,
        "repository": "docker.io/library/postgres",
        "os": "linux",
        "architecture": "amd64",
    }


async def _capture(image, transport):
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
            auth, _, _ = await registry._read(
                client,
                registry.AUTH,
                params={
                    "service": "registry.docker.io",
                    "scope": "repository:library/postgres:pull",
                },
            )
            token = auth.get("token") if isinstance(auth, dict) else None
            if (
                not isinstance(token, str)
                or not 1 <= len(token) <= 8192
                or any(c.isspace() for c in token)
            ):
                raise ActivationError("postgres_registry_token_invalid")
            index, root_digest = await registry._manifest(
                client, image, token, repository="postgres"
            )
            if (
                index.get("mediaType") not in registry.INDEX_TYPES
                or not isinstance(index.get("manifests"), list)
                or not 1 <= len(index["manifests"]) <= 64
            ):
                raise ActivationError("postgres_registry_index_invalid")
            candidates = [
                item
                for item in index["manifests"]
                if isinstance(item, dict)
                and isinstance(item.get("platform"), dict)
                and item["platform"].get("os") == "linux"
                and item["platform"].get("architecture") == "amd64"
                and item["platform"].get("variant") in (None, "")
            ]
            if (
                len(candidates) != 1
                or candidates[0].get("mediaType") not in registry.MANIFEST_TYPES
            ):
                raise ActivationError("postgres_registry_platform_ambiguous")
            selected = registry._sha(candidates[0].get("digest"))
            manifest, selected_digest = await registry._manifest(
                client, selected, token, repository="postgres"
            )
            config, layers = manifest.get("config"), manifest.get("layers")
            if (
                manifest.get("mediaType") not in registry.MANIFEST_TYPES
                or not isinstance(config, dict)
                or config.get("mediaType") not in registry.CONFIG_TYPES
                or type(config.get("size")) is not int
                or not 1 <= config["size"] <= 128 * 1024
                or config.get("urls")
                or not isinstance(layers, list)
                or not 1 <= len(layers) <= 32
            ):
                raise ActivationError("postgres_registry_image_invalid")
            total = 0
            for layer in layers:
                if (
                    not isinstance(layer, dict)
                    or layer.get("mediaType") not in registry.LAYER_TYPES
                    or layer.get("urls")
                    or type(layer.get("size")) is not int
                    or not 1 <= layer["size"] <= 128 * 1024**2
                ):
                    raise ActivationError("postgres_registry_layer_invalid")
                registry._sha(layer.get("digest"))
                total += layer["size"]
            if total > 256 * 1024**2:
                raise ActivationError("postgres_registry_image_limit")
            return {
                "format": "aegis-postgres-registry-origin/1",
                "checked_at": datetime.now(UTC).isoformat(),
                "image_id": root_digest,
                "repository": "docker.io/library/postgres",
                "os": "linux",
                "architecture": "amd64",
                "platform_manifest_digest": selected_digest,
                "config_digest": registry._sha(config.get("digest")),
                "compressed_layer_bytes": total,
                "registry_manifest_verified": True,
                "local_official_reference_verified": True,
                **FLAGS,
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
        raise ActivationError("postgres_registry_origin_unconfirmed") from None


def review(image, receipt, *, docker=None):
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {
            "format",
            "checked_at",
            "image_id",
            "repository",
            "os",
            "architecture",
            "platform_manifest_digest",
            "config_digest",
            "compressed_layer_bytes",
            "registry_manifest_verified",
            "local_official_reference_verified",
            *FLAGS,
        }
        or receipt.get("format") != "aegis-postgres-registry-origin/1"
        or receipt.get("image_id") != image_id(image)
        or receipt.get("repository") != "docker.io/library/postgres"
        or receipt.get("os") != "linux"
        or receipt.get("architecture") != "amd64"
        or receipt.get("registry_manifest_verified") is not True
        or receipt.get("local_official_reference_verified") is not True
        or any(receipt.get(key) is not False for key in FLAGS)
        or type(receipt.get("compressed_layer_bytes")) is not int
        or not 1 <= receipt["compressed_layer_bytes"] <= 256 * 1024**2
    ):
        raise ActivationError("postgres_origin_receipt_invalid")
    for key in ("image_id", "platform_manifest_digest", "config_digest"):
        registry._sha(receipt[key])
    stamp = datetime.fromisoformat(receipt["checked_at"])
    if stamp.utcoffset() != UTC.utcoffset(None) or stamp > datetime.now(UTC):
        raise ActivationError("postgres_origin_timestamp_invalid")
    return native(image, docker=docker)


def capture(image, *, transport=None, docker=None, inspection_docker=None):
    before = native(image, docker=docker)
    inspection.review_image(image, docker=inspection_docker)
    receipt = asyncio.run(_capture(image, transport))
    if review(image, receipt, docker=docker) != before:
        raise ActivationError("postgres_native_origin_changed")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(capture(args.image_id), sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        print(json.dumps({"status": "rejected", "code": "postgres_origin_unconfirmed", **FLAGS}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
