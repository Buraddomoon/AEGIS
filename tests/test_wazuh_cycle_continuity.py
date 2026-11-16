"""Wazuh-specific read-only probe boundaries, fixtures and private SQLite only."""

import copy
import json
import sys
from pathlib import Path

import pytest
from aegis.domain.validation import digest
from aegis.lab_runner.protocol import RunnerIdentity
from test_runner_activation_probe_result import reply as reply  # noqa: F401
from test_runner_activation_probe_runtime import IMAGE, OBJECT, PLAN, PROOFS, projection
from test_runner_journal_continuity import journal as journal  # noqa: F401
from test_runner_persisted_review import bundle as bundle  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_cycle_continuity as continuity  # noqa: E402


@pytest.fixture
def native_recipe():
    return continuity.recipe("a" * 32, PLAN, "journal-before", IMAGE, PROOFS)


def test_recipe_cannot_mount_linux_or_start_a_runner(native_recipe):
    args = continuity.create_arguments("a" * 32, PLAN, "journal-before", IMAGE, PROOFS)
    assert args[:2] == ("container", "create")
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--memory") + 1] == "192m"
    assert "aegis-linux-lab" not in " ".join(args)
    assert args.count("--mount") == 1
    assert (
        args[args.index("--mount") + 1]
        == "type=volume,source=aegis-wazuh-lab_journal,target=/state,readonly,volume-nocopy"
    )
    assert "aegis.lab_runner.journal_probe" in args
    assert not {"start", "run", "exec", "-v", "--privileged"} & set(args)
    assert native_recipe["labels"]["com.docker.compose.project"] == continuity.PROJECT


@pytest.mark.parametrize(
    "change", [None, "writable", "linux", "copy", "network", "image", "role", "memory"]
)
def test_actual_runtime_must_match_fixed_wazuh_readonly_recipe(native_recipe, change):
    item = projection(native_recipe)
    item["mounts"][0]["name"] = continuity.VOLUME
    item["configured_mounts"][0]["source_name"] = continuity.VOLUME
    if change == "writable":
        item["mounts"][0]["writable"] = True
    elif change == "linux":
        item["mounts"][0]["name"] = "aegis-linux-lab_journal"
    elif change == "copy":
        item["configured_mounts"][0]["no_copy"] = False
    elif change == "network":
        item["host"]["NetworkMode"] = "host"
    elif change == "image":
        item["image"] = "sha256:" + "f" * 64
    elif change == "role":
        native_recipe["role"] = "runner"
    elif change == "memory":
        item["host"]["Memory"] = 0
    if change is None:
        continuity.validate(native_recipe, item, OBJECT, "created")
    else:
        with pytest.raises(ValueError):
            continuity.validate(native_recipe, item, OBJECT, "created")


def test_real_temporary_journal_proofs_bind_identity_and_do_not_claim_activation(reply, bundle):
    identity = RunnerIdentity.model_validate(bundle["identity"])
    raw = json.dumps(reply).encode()
    result = continuity.compare(
        raw, raw, bundle, digest(bundle), identity, bundle["old_descriptor_sha256"]
    )
    assert result["logical_inventories_match"] and not result["activation_verified"]
    changed = copy.deepcopy(bundle)
    changed["identity"]["asset_id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    with pytest.raises(ValueError, match="original_identity"):
        continuity.decode(raw, changed, digest(changed), identity, bundle["old_descriptor_sha256"])


def test_reviewed_source_labels_are_retained_and_arbitrary_image_labels_are_refused():
    labels = {
        "io.aegis.wazuh-source-review": "d" * 32,
        "io.aegis.wazuh-source-role": "runner",
        "org.opencontainers.image.revision": "e" * 40,
    }
    spec = continuity.recipe("a" * 32, PLAN, "journal-before", IMAGE, PROOFS, image_labels=labels)
    item = projection(spec)
    item["label_count"] = len(spec["labels"])
    item["mounts"][0]["name"] = continuity.VOLUME
    item["configured_mounts"][0]["source_name"] = continuity.VOLUME
    continuity.validate(spec, item, OBJECT, "created")
    assert all(key in continuity.CONTAINER_FORMAT for key in labels)
    with pytest.raises(ValueError, match="labels_unreviewed"):
        continuity.recipe(
            "a" * 32,
            PLAN,
            "journal-before",
            IMAGE,
            PROOFS,
            image_labels={**labels, "unreviewed": "value"},
        )
