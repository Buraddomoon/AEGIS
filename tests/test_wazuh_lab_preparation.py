import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from aegis.integrations.wazuh_config import WazuhCollectionConfig

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    path = tmp_path_factory.mktemp("wazuh-preparation") / "private"
    result = subprocess.run(
        [sys.executable, "scripts/prepare_wazuh_lab.py", "--output", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    return path, result.stdout + result.stderr


def test_preparation_is_private_and_does_not_print_credentials(prepared):
    path, output = prepared
    credentials = json.loads((path / "indexer-passwords.json").read_text())
    assert len(set(credentials.values())) == 3
    assert not any(value in output for value in credentials.values())
    for name in ("indexer-passwords.json", "lab.env"):
        assert stat.S_IMODE((path / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_policy_and_runner_share_new_identity_not_original_lab(prepared):
    path, _ = prepared
    policy = WazuhCollectionConfig.model_validate_json((path / "collection.json").read_text())
    runner = json.loads((path / "runner/connection.json").read_text())
    assert policy.laboratory_id == UUID(runner["laboratory_id"])
    assert policy.asset_id == UUID(runner["asset_id"])
    assert runner["url"] == "https://192.168.253.10:8443"
    assert policy.archives_index is None
    assert (path / "client.keys").read_text().split()[:3] == ["001", "aegis-marker", "any"]


@pytest.mark.parametrize(
    ("leaf", "ca", "address"),
    [
        ("pki/indexer.pem", "pki/root-ca.pem", "192.168.253.18"),
        ("runner/runner-server.crt", "runner/server-ca.crt", "192.168.253.10"),
    ],
)
def test_generated_certificates_verify_real_new_addresses(prepared, leaf, ca, address):
    path, _ = prepared
    subprocess.run(
        ["openssl", "verify", "-CAfile", str(path / ca), "-verify_ip", address, str(path / leaf)],
        check=True,
        capture_output=True,
        timeout=5,
    )


def test_indexer_node_identity_matches_certificate_distinguished_name(prepared):
    path, _ = prepared
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
            "-in",
            str(path / "pki/indexer.pem"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    subject = result.stdout.strip().removeprefix("subject=")
    config = yaml.safe_load((ROOT / "labs/wazuh/config/indexer.yml").read_text())
    assert subject in config["plugins.security.nodes_dn"]


def test_repeat_preparation_preserves_identity_and_secrets(prepared):
    path, _ = prepared
    original = (path / "runner/connection.json").read_bytes()
    credentials = (path / "indexer-passwords.json").read_bytes()
    result = subprocess.run(
        [sys.executable, "scripts/prepare_wazuh_lab.py", "--output", str(path)],
        cwd=ROOT,
        capture_output=True,
        env={**os.environ},
        timeout=5,
    )
    assert result.returncode != 0
    assert (path / "runner/connection.json").read_bytes() == original
    assert (path / "indexer-passwords.json").read_bytes() == credentials


def test_ingestion_bulk_is_separate_from_reader_and_security_administration():
    roles = yaml.safe_load((ROOT / "labs/wazuh/config/roles.yml").read_text())
    ingest, reader = roles["aegis_ingest"], roles["aegis_reader"]
    assert "indices:data/write/bulk*" in ingest["cluster_permissions"]
    assert ingest["index_permissions"][0]["index_patterns"] == ["wazuh-alerts-4.x-*"]
    assert reader["index_permissions"] == [
        {"index_patterns": ["wazuh-alerts-4.x-*"], "allowed_actions": ["read"]}
    ]
    assert reader["cluster_permissions"] == ["cluster:monitor/main", "indices:data/read/scroll*"]
    config = yaml.safe_load((ROOT / "labs/wazuh/config/indexer.yml").read_text())
    assert config["plugins.security.restapi.roles_enabled"] == ["aegis_admin"]


def test_rendered_compose_preserves_isolation_and_secret_boundaries(prepared):
    if not shutil.which("docker"):
        pytest.skip("Compose structural check requires Docker CLI, not daemon startup.")
    path, _ = prepared
    command = ["docker", "compose", "--env-file", str(path / "lab.env"), "-p", "aegis-wazuh-lab"]
    for file in (
        "docker-compose.yml",
        "labs/linux/compose.yml",
        "labs/linux/platform.yml",
        "labs/wazuh/compose.yml",
        "labs/wazuh/network.yml",
    ):
        command.extend(["-f", file])
    result = subprocess.run(
        [*command, "config", "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    config = json.loads(result.stdout)
    services = config["services"]
    pinned = json.loads((ROOT / "labs/wazuh/images.json").read_text())["images"]
    for name, reference in pinned.items():
        assert services[f"wazuh.{name}"]["image"] == reference
        assert services[f"wazuh.{name}"]["platform"] == "linux/amd64"
    for name in (
        "wazuh.indexer",
        "wazuh.manager",
        "wazuh.agent",
        "runner",
        "observer",
        "worker",
        "db",
        "redis",
    ):
        assert "ports" not in services[name]
    assert set(services["runner"]["networks"]) == {"isolated"}
    assert services["observer"]["network_mode"] == "none"
    assert services["observer"]["read_only"]
    observer_mounts = {item["target"]: item for item in services["observer"]["volumes"]}
    assert observer_mounts["/work"]["read_only"]
    assert not observer_mounts["/observation-log"].get("read_only", False)
    agent_mounts = {item["target"]: item for item in services["wazuh.agent"]["volumes"]}
    assert "/work" not in agent_mounts
    assert agent_mounts["/var/log/aegis"]["read_only"]
    for name in ("api", "worker"):
        assert services[name]["environment"]["WAZUH_ALLOWED_IP"] == "192.168.253.18"
        assert services[name]["environment"]["WAZUH_URL"] == "https://wazuh.indexer:9200"
        sources = {item["source"] for item in services[name]["secrets"]}
        assert not sources.intersection({"indexer_key", "filebeat_key"})
        assert services[name]["environment"]["WAZUH_USERNAME"] == "aegis_reader"
        assert "INDEXER_PASSWORD" not in services[name]["environment"]
    assert services["api"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert services["api"]["ports"][0]["published"] == "18786"
    for name in ("isolated", "telemetry"):
        assert config["networks"][name]["internal"]
        assert (
            config["networks"][name]["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"]
            == "isolated"
        )
    assert config["volumes"]["workspace"]["driver_opts"]["type"] == "tmpfs"
    assert "noexec,nosuid,nodev" in config["volumes"]["workspace"]["driver_opts"]["o"]
    assert all(value["name"].startswith("aegis-wazuh-lab_") for value in config["volumes"].values())
