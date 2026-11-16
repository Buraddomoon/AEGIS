"""Bounded profile tests: no native startup, volume access or marker authorization."""

import copy
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_wazuh_lab as inspector  # noqa: E402
import wazuh_cycle_resources as resources  # noqa: E402
import wazuh_cycle_scope as scope  # noqa: E402
from test_wazuh_cycle_scope import inspector_fixture as inspector_fixture  # noqa: E402
from test_wazuh_cycle_scope import profile as profile  # noqa: E402
from test_wazuh_pki_rotation import prepared as prepared  # noqa: E402
from test_wazuh_pki_rotation import rendered as rendered  # noqa: E402
from test_wazuh_runtime_inspection import snapshot as snapshot  # noqa: E402
from wazuh_host_preflight import Resources, failures  # noqa: E402


def test_bounded_floor_is_the_real_ceiling_plus_reserve_and_does_not_change_default():
    assert sum(resources.BOUNDED_MEMORY.values()) == 3360
    floor = (3360 + 512) * resources.MIB
    observed = Resources(4, floor, 50 * 1024**3, 262144)
    assert failures(observed)  # The original eight-GiB gate remains intact.
    result = resources.review(observed, resources.BOUNDED)
    assert not result["blockers"] and not result["effects_authorized"]
    assert result["container_ceiling_bytes"] + result["reserve_bytes"] == floor
    assert resources.review(replace(observed, available_bytes=floor - 1), resources.BOUNDED)[
        "blockers"
    ]
    for change in ({"cpus": 3}, {"docker_free_bytes": 50 * 1024**3 - 1}, {"max_map_count": 262143}):
        assert resources.review(replace(observed, **change), resources.BOUNDED)["blockers"]
    with pytest.raises(ValueError):
        resources.review(observed, "arbitrary-low-limit")


def test_bounded_compose_keeps_security_and_changes_only_closed_resource_settings(
    rendered, profile
):
    standard = scope.scoped_compose(rendered[0], profile)
    bounded_profile = replace(profile, resource_profile=resources.BOUNDED)
    bounded = scope.scoped_compose(rendered[0], bounded_profile)
    assert bounded["networks"] == standard["networks"]
    assert bounded["secrets"] == standard["secrets"] and bounded["volumes"] == standard["volumes"]
    assert bounded_profile.document()["resource_profile"] == resources.BOUNDED
    for name, item in bounded["services"].items():
        expected = copy.deepcopy(standard["services"][name])
        expected["mem_limit"] = expected["memswap_limit"] = (
            resources.BOUNDED_MEMORY[name] * resources.MIB
        )
        expected["labels"]["aegis.resource-profile"] = resources.BOUNDED
        if name == "wazuh.indexer":
            expected["environment"]["OPENSEARCH_JAVA_OPTS"] = resources.HEAP
        elif name == "db":
            expected["command"] = list(resources.DB_COMMAND)
        elif name == "redis":
            expected["command"] = list(resources.REDIS_COMMAND)
        assert item == expected
    with pytest.raises(ValueError, match="profile_unknown"):
        scope.scoped_compose(rendered[0], replace(profile, resource_profile="unreviewed"))


def test_bounded_runtime_checks_swap_heap_commands_and_exact_profile(snapshot, profile):
    profile = replace(profile, resource_profile=resources.BOUNDED)
    snapshot[0][:] = [item for item in snapshot[0] if item["service"] != "migrate"]
    mounts = inspector.expected_mounts(
        profile.source,
        runner_candidate=profile.runner_candidate,
        service_candidate=profile.service_candidate,
    )
    for item in snapshot[0]:
        name = item["service"]
        item["image_id"] = item["image_reference"] = profile.image_for(name)
        item["cycle_review"] = profile.review_id
        item["resource_profile"] = resources.BOUNDED
        item["host"]["Memory"] = item["host"]["MemorySwap"] = (
            resources.BOUNDED_MEMORY[name] * resources.MIB
        )
        item["bounded_heap_matches"] = [True, None]
        item["bounded_db_command"] = item["bounded_redis_command"] = True
        item["mounts"] = [
            {
                "Destination": target,
                "Type": spec[0],
                "Name": spec[1] if spec[0] == "volume" else None,
                "Source": spec[1],
                "RW": spec[2],
            }
            for target, spec in mounts[name].items()
        ]
    assert all(inspector.validate(*snapshot, private=profile.source, cycle=profile).values())
    indexer = next(item for item in snapshot[0] if item["service"] == "wazuh.indexer")
    for key, value in (
        ("bounded_heap_matches", [True, False, None]),
        ("resource_profile", "standard"),
    ):
        before = indexer[key]
        indexer[key] = value
        assert not all(
            inspector.validate(*snapshot, private=profile.source, cycle=profile).values()
        )
        indexer[key] = before
    indexer["host"]["MemorySwap"] += 1
    assert not all(inspector.validate(*snapshot, private=profile.source, cycle=profile).values())
