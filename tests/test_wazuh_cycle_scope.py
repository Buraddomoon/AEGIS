"""Compose and daemon fixtures only; no original volumes or Wazuh startup."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_wazuh_lab as inspector  # noqa: E402
import wazuh_cycle_scope as scope  # noqa: E402
from test_wazuh_pki_rotation import prepared as prepared  # noqa: E402
from test_wazuh_pki_rotation import rendered as rendered  # noqa: E402
from test_wazuh_runtime_inspection import snapshot as snapshot  # noqa: E402


@pytest.fixture(name="inspector")
def inspector_fixture():
    return inspector


@pytest.fixture
def profile(prepared, tmp_path):
    return scope.CycleProfile(
        "a" * 32,
        prepared[0],
        tmp_path / "runner",
        prepared[1],
        {name: "sha256:" + str(index) * 64 for index, name in enumerate(sorted(scope.IMAGE_ROLES))},
    )


def test_real_compose_renewal_uses_existing_volumes_and_never_migrates_or_seeds(rendered, profile):
    original = copy.deepcopy(rendered[0])
    result = scope.scoped_compose(rendered[0], profile)
    assert rendered[0] == original
    assert set(result["services"]) == scope.SERVICES
    for name, service in result["services"].items():
        assert service["image"] == profile.image_for(name)
        assert service["pull_policy"] == "never" and "build" not in service
        assert service["restart"] == "no"
        assert "migrate" not in service.get("depends_on", {})
        assert service["labels"]["aegis.cycle-review-id"] == profile.review_id
    assert len(result["volumes"]) == 9
    assert all(
        value == {"name": scope.PROJECT + "_" + key, "external": True}
        for key, value in result["volumes"].items()
    )
    assert result["services"]["observer"]["network_mode"] == "none"
    assert result["secrets"]["controller_connection"]["file"] == str(
        profile.runner_candidate / "connection.json"
    )
    assert result["secrets"]["wazuh_collection"]["file"] == str(profile.source / "collection.json")
    assert result["services"]["api"]["environment"] == original["services"]["api"]["environment"]
    assert "ca-key.pem" not in str(result) and "server-ca.key" not in str(result)


@pytest.mark.parametrize(
    "change",
    [
        "socket",
        "write",
        "mount",
        "privilege",
        "memory",
        "network",
        "port",
        "tls",
        "services",
        "label",
        "build-dependency",
    ],
)
def test_compile_refuses_scope_or_identity_expansion(rendered, profile, change):
    changed = copy.deepcopy(rendered[0])
    runner = changed["services"]["runner"]
    if change == "socket":
        runner["volumes"].append(
            {
                "type": "bind",
                "source": "/var/run/docker.sock",
                "target": "/socket",
                "bind": {"create_host_path": False},
            }
        )
    elif change == "write":
        changed["services"]["observer"]["volumes"][0]["read_only"] = False
    elif change == "mount":
        changed["secrets"]["controller_connection"]["file"] = "/unreviewed/connection.json"
    elif change == "privilege":
        runner["privileged"] = True
    elif change == "memory":
        runner["mem_limit"] = 0
    elif change == "network":
        runner["networks"]["isolated"]["ipv4_address"] = "172.30.89.2"
    elif change == "port":
        changed["services"]["api"]["ports"][0]["host_ip"] = "0.0.0.0"
    elif change == "tls":
        changed["networks"]["telemetry"]["internal"] = False
    elif change == "services":
        changed["services"]["unreviewed"] = {}
    elif change == "label":
        runner["labels"] = {"aegis.cycle-review-id": "b" * 32}
    else:
        runner["depends_on"] = {"controller": {"condition": "service_started"}}
    with pytest.raises(ValueError):
        scope.scoped_compose(changed, profile)


def test_cycle_runtime_rejects_legacy_tags_missing_image_id_and_original_mounts(snapshot, profile):
    containers, networks, volumes = snapshot
    containers[:] = [item for item in containers if item["service"] != "migrate"]
    mounts = inspector.expected_mounts(
        profile.source,
        runner_candidate=profile.runner_candidate,
        service_candidate=profile.service_candidate,
    )
    for item in containers:
        name = item["service"]
        item["image_reference"] = item["image_id"] = profile.image_for(name)
        item["cycle_review"] = profile.review_id
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
    checks = inspector.validate(*snapshot, private=profile.source, cycle=profile)
    assert checks and all(checks.values()), [key for key, value in checks.items() if not value]
    # The historical validator still expects the historical service/image profile.
    assert not all(inspector.validate(*snapshot, private=profile.source).values())
    runner = next(item for item in containers if item["service"] == "runner")
    for key, invalid in (
        ("image_reference", "aegis-wazuh-runner:local"),
        ("image_id", "sha256:" + "f" * 64),
        ("cycle_review", "b" * 32),
    ):
        original = runner[key]
        runner[key] = invalid
        assert not all(
            inspector.validate(*snapshot, private=profile.source, cycle=profile).values()
        )
        runner[key] = original
    mount = next(
        item
        for item in runner["mounts"]
        if item["Destination"] == "/run/secrets/runner_server_cert"
    )
    mount["Source"] = str(profile.source / "runner/runner-server.crt")
    assert not all(inspector.validate(*snapshot, private=profile.source, cycle=profile).values())
