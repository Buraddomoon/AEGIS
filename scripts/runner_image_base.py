"""Bind fixed official registry metadata to an existing local native Docker image."""

import re

import runner_activation_probe_runtime as probe
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError, _execute, document
from runner_image_registry import MANIFEST_TYPES

FORMAT = (
    probe._projection(
        {
            "id": ".Id",
            "os": ".Os",
            "architecture": ".Architecture",
            "repo_digests": ".RepoDigests",
            "user": '(index .Config "User")',
            "volumes": '(index .Config "Volumes")',
            "ports": '(index .Config "ExposedPorts")',
            "onbuild": '(index .Config "OnBuild")',
            "rootfs_type": ".RootFS.Type",
        }
    )[:-1]
    + ',"label_count":{{with (index .Config "Labels")}}{{len .}}{{else}}0{{end}}'
    + ',"descriptor_digest":{{with (index . "Descriptor")}}{{json (index . "digest")}}{{else}}null{{end}}'
    + ',"descriptor_media_type":{{with (index . "Descriptor")}}{{json (index . "mediaType")}}{{else}}null{{end}}}'
)


def reference(base):
    if (
        not isinstance(base, dict)
        or set(base)
        != {
            "format",
            "checked_at",
            "repository",
            "tag_reviewed",
            "reference",
            "index_digest",
            "platform_manifest_digest",
            "config_digest",
            "os",
            "architecture",
            "compressed_layer_bytes",
            "registry_manifest_verified",
            "image_pulled",
            "image_built",
            "image_provenance_verified",
            "effects_authorized",
        }
        or base.get("format") != "aegis-python-registry-base/2"
        or base.get("registry_manifest_verified") is not True
        or base.get("repository") != "docker.io/library/python"
        or base.get("tag_reviewed") != "3.13-slim"
        or base.get("os") != "linux"
        or base.get("architecture") != "amd64"
        or type(base.get("compressed_layer_bytes")) is not int
        or not 1 <= base["compressed_layer_bytes"] <= 256 * 1024**2
        or any(
            base.get(key) is not False
            for key in (
                "image_pulled",
                "image_built",
                "image_provenance_verified",
                "effects_authorized",
            )
        )
    ):
        raise ActivationError("python_base_registry_profile_invalid")
    for key in ("index_digest", "platform_manifest_digest", "config_digest"):
        if not isinstance(base.get(key), str) or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", base[key]
        ):
            raise ActivationError("python_base_registry_profile_invalid")
    expected = "docker.io/library/python@" + base["platform_manifest_digest"]
    if base.get("reference") != expected:
        raise ActivationError("python_base_official_reference_required")
    return expected


def command(base):
    return ("image", "inspect", "--format", FORMAT, reference(base))


class BaseDocker:
    def query(self, base):
        return _execute(command(base))


def review(base, *, docker=None):
    """Metadata/hash binding only; image content, Python version/build are later checks."""
    expected_reference = reference(base)
    item = document((docker or BaseDocker()).query(base))
    fields = {
        "id",
        "os",
        "architecture",
        "repo_digests",
        "user",
        "volumes",
        "ports",
        "onbuild",
        "rootfs_type",
        "label_count",
        "descriptor_digest",
        "descriptor_media_type",
    }
    if (
        not isinstance(item, dict)
        or set(item) != fields
        or item["os"] != "linux"
        or item["architecture"] != "amd64"
        or item["user"] not in (None, "", "0", "0:0")
        or item["volumes"] not in (None, {})
        or item["ports"] not in (None, {})
        or item["onbuild"] not in (None, [])
        or item["rootfs_type"] != "layers"
        or type(item["label_count"]) is not int
        or item["label_count"] != 0
        or not isinstance(item["repo_digests"], list)
        or not 1 <= len(item["repo_digests"]) <= 8
        or any(not isinstance(value, str) for value in item["repo_digests"])
    ):
        raise ActivationError("python_base_local_image_mismatch")
    official = {
        prefix + "@" + base["platform_manifest_digest"]
        for prefix in ("python", "library/python", "docker.io/library/python")
    }
    if not official.intersection(item["repo_digests"]):
        raise ActivationError("python_base_local_reference_unconfirmed")
    if (
        item["id"] == base["platform_manifest_digest"]
        and item["descriptor_digest"] == base["platform_manifest_digest"]
        and item["descriptor_media_type"] in MANIFEST_TYPES
    ):
        kind = "platform_manifest_digest"
    elif (
        item["id"] == base["config_digest"]
        and item["descriptor_digest"] is None
        and item["descriptor_media_type"] is None
    ):
        kind = "legacy_config_digest"
    else:
        raise ActivationError("python_base_local_identity_unconfirmed")
    return {
        "format": "aegis-native-python-base-review/1",
        "reference": expected_reference,
        "registry_receipt_sha256": digest(base),
        "native_image_id": item["id"],
        "native_identity_kind": kind,
        "config_digest": base["config_digest"],
        "platform_manifest_digest": base["platform_manifest_digest"],
        "local_registry_binding_verified": True,
        "unexpected_image_volumes_ports_labels_excluded": True,
        "image_built": False,
        "python_runtime_verified": False,
        "image_provenance_verified": False,
        "effects_authorized": False,
    }
