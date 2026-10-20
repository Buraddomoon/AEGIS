import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import yaml
from aegis.domain.contracts import ExecutionContext
from aegis.domain.validation import validate
from aegis.integrations.wazuh import WazuhIndexerProvider
from aegis.integrations.yaml_import import AtomicMetadataProvider, parse_sigma, safe_document

SIGMA = """title: AEGIS laboratory shell marker
id: 6d2e4d91-0ff3-4569-a2e7-0bbb163f4421
status: experimental
description: Demonstrative local rule; not deployed to a SIEM
author: AEGIS
date: 2026-10-20
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: aegis-marker
  condition: selection
tags:
  - attack.execution
  - attack.t1059.004
level: informational
"""


def test_sigma_real_parser_and_no_disk_cache_path():
    result = parse_sigma(SIGMA)
    assert result["techniques"] == ["T1059.004"]
    assert result["sigma_id"] == "6d2e4d91-0ff3-4569-a2e7-0bbb163f4421"
    assert "diskcache" not in sys.modules, "Parsing must not import/use disk-backed pickle caching"


def test_sigma_title_rejected_before_database_length_error():
    with pytest.raises(ValueError, match="Título Sigma"):
        parse_sigma(SIGMA.replace("AEGIS laboratory shell marker", "x" * 241))


@pytest.mark.parametrize(
    "content",
    [
        "hello",
        "a: &x [1,2]\nb: *x",
        "!!python/object/apply:os.system [id]",
        "a: 1\n---\nb: 2",
        "x: " + "x" * 65536,
    ],
)
def test_unsafe_yaml_rejected(content):
    with pytest.raises((ValueError, yaml.YAMLError)):
        safe_document(content)


def test_atomic_metadata_never_grants_execution():
    metadata = AtomicMetadataProvider().import_metadata("""attack_technique: T1059.004
atomic_tests:
  - name: Metadata only
    auto_generated_guid: 91f6b8a9-8554-40c6-9bfc-193b00000001
    supported_platforms: [linux]
    executor:
      name: sh
      command: arbitrary-untrusted-content
      cleanup_command: arbitrary-cleanup
""")[0]
    assert not metadata["executable"] and not metadata["approved"]
    assert metadata["has_cleanup"]
    assert "command" not in metadata


@pytest.mark.parametrize(
    "url,ip",
    [
        ("http://siem.lab:9200", "192.0.2.10"),
        ("https://user:pass@siem.lab", "192.0.2.10"),
        ("https://siem.lab/x", "192.0.2.10"),
        ("https://siem.lab", "127.0.0.1"),
        ("https://siem.lab", "169.254.169.254"),
        ("https://siem.lab", "::1"),
        ("https://siem.lab", "::ffff:127.0.0.1"),
    ],
)
def test_wazuh_ssrf_configuration_rejected(url, ip):
    with pytest.raises(ValueError):
        WazuhIndexerProvider(url, "user", "secret", ip)


def context():
    timestamp = datetime(2026, 10, 20, 15, tzinfo=UTC)
    return ExecutionContext(
        "execution-fixture",
        "lab-fixture",
        "001",
        "aegis-fixture-marker",
        "unix-shell-marker",
        timestamp,
        timestamp,
        False,
        "100100",
    )


def test_wazuh_pagination_preserves_identity_and_correlates():
    hit = json.loads(Path("fixtures/wazuh-alert.json").read_text())
    requests = []

    def handle(request):
        requests.append(request)
        assert request.url.host == "192.0.2.10"
        assert request.headers["host"] == "siem.lab:9200"
        assert request.extensions["sni_hostname"] == b"siem.lab"
        if request.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True})
        if request.url.path == "/_search/scroll":
            return httpx.Response(200, json={"_scroll_id": "cursor", "hits": {"hits": []}})
        return httpx.Response(
            200,
            json={
                "_scroll_id": "cursor",
                "timed_out": False,
                "_shards": {"failed": 0},
                "hits": {"hits": [hit]},
            },
        )

    provider = WazuhIndexerProvider(
        "https://siem.lab:9200",
        "readonly",
        "secret",
        "192.0.2.10",
        transport=httpx.MockTransport(handle),
    )
    collection = provider.collect(context())
    assert collection.complete and collection.alerts_available
    assert len(requests) == 3
    assert collection.events[0].source_id == hit["_id"]
    assert collection.events[0].raw["_index"] == hit["_index"]
    assert not collection.events[0].synthetic
    assert validate(context(), collection, True).outcome == "DETECTED"


def test_wazuh_missing_marker_never_fills_identity():
    hit = json.loads(Path("fixtures/wazuh-alert.json").read_text())
    hit["_source"]["data"] = {}
    event = WazuhIndexerProvider.normalize(hit, "alert")
    assert event.execution_id == "" and event.marker == ""


def test_wazuh_unavailability_is_inconclusive():
    transport = httpx.MockTransport(lambda _: httpx.Response(503, json={"error": "unavailable"}))
    provider = WazuhIndexerProvider(
        "https://siem.lab:9200", "readonly", "secret", "192.0.2.10", transport=transport
    )
    collection = provider.collect(context())
    assert not collection.complete and not collection.alerts_available
    assert validate(context(), collection, True).outcome == "INCONCLUSIVE"


def test_sigma_versions_persist_and_deduplicate(admin):
    first = admin.post("/api/v1/rules", json={"content": SIGMA})
    assert first.status_code == 201, first.text
    rule = first.json()
    assert admin.post("/api/v1/rules", json={"content": SIGMA}).json()["unchanged"]
    changed = SIGMA.replace("level: informational", "level: low")
    assert admin.post("/api/v1/rules", json={"content": changed}).json()["latest_version"] == 2
    versions = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"]
    assert len(versions) == 2 and versions[0]["sha256"] != versions[1]["sha256"]
