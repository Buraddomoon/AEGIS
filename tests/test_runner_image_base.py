"""Registry/native identity profiles using fixtures, never pull/build/lifecycle."""

import json
import sys
from pathlib import Path

import httpx
import pytest
from test_runner_image_registry import Registry

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_image_base as native  # noqa: E402
from runner_image_registry import python_base  # noqa: E402


@pytest.fixture
def base():
    fixture = Registry()
    return python_base(transport=httpx.MockTransport(fixture.handle))


class Docker:
    def __init__(self, base, legacy=False):
        self.calls = []
        self.item = {
            "id": base["config_digest"] if legacy else base["platform_manifest_digest"],
            "os": "linux",
            "architecture": "amd64",
            "user": None,
            "volumes": None,
            "ports": None,
            "onbuild": None,
            "rootfs_type": "layers",
            "label_count": 0,
            "repo_digests": ["python@" + base["platform_manifest_digest"]],
            "descriptor_digest": None if legacy else base["platform_manifest_digest"],
            "descriptor_media_type": None
            if legacy
            else "application/vnd.oci.image.manifest.v1+json",
        }

    def query(self, base):
        self.calls.append(native.command(base))
        return json.dumps(self.item).encode()


@pytest.mark.parametrize("legacy", [False, True])
def test_native_manifest_and_explicit_legacy_config_identity_are_distinguished(base, legacy):
    docker = Docker(base, legacy)
    result = native.review(base, docker=docker)
    assert result["native_identity_kind"] == (
        "legacy_config_digest" if legacy else "platform_manifest_digest"
    )
    assert result["config_digest"] == base["config_digest"]
    assert result["native_image_id"] == docker.item["id"]
    assert result["local_registry_binding_verified"]
    assert all(
        result[key] is False
        for key in (
            "image_built",
            "python_runtime_verified",
            "image_provenance_verified",
            "effects_authorized",
        )
    )
    assert docker.calls == [("image", "inspect", "--format", native.FORMAT, base["reference"])]
    assert ".Config.Env" not in native.FORMAT


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "sha256:" + "f" * 64),
        ("descriptor_digest", "sha256:" + "f" * 64),
        ("descriptor_media_type", "application/vnd.oci.image.index.v1+json"),
        ("repo_digests", []),
        ("repo_digests", ["untrusted.invalid/python@sha256:" + "f" * 64]),
        ("os", "windows"),
        ("architecture", "arm64"),
        ("user", "10001:10001"),
        ("volumes", {"/state": {}}),
        ("ports", {"8080/tcp": {}}),
        ("label_count", 3),
        ("label_count", False),
        ("onbuild", ["RUN unexpected"]),
        ("rootfs_type", "unexpected"),
    ],
)
def test_inconsistent_digest_native_metadata_or_inherited_effects_fail_closed(base, field, value):
    docker = Docker(base)
    docker.item[field] = value
    with pytest.raises(native.ActivationError):
        native.review(base, docker=docker)


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "aegis-python-registry-base/1"),
        ("reference", "untrusted.invalid/python:latest"),
        ("reference", "docker.io/library/python:3.13-slim"),
        ("repository", "untrusted.invalid/python"),
        ("registry_manifest_verified", 1),
        ("image_built", True),
        ("config_digest", "invalid"),
        ("token", "private-sensitive-sentinel"),
        ("compressed_layer_bytes", True),
    ],
)
def test_unreviewed_tag_or_different_receipt_contract_never_becomes_a_docker_query(
    base, field, value
):
    base[field] = value
    docker = Docker(base)
    with pytest.raises(native.ActivationError):
        native.review(base, docker=docker)
    assert docker.calls == []


def test_config_id_cannot_be_mixed_with_a_manifest_descriptor_to_ignore_store_semantics(base):
    docker = Docker(base)
    docker.item["id"] = base["config_digest"]
    with pytest.raises(native.ActivationError, match="identity_unconfirmed"):
        native.review(base, docker=docker)
